//! Bounded rotating scans. Cursor progress co-commits with the cleanup decision.

use super::*;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Raw, SideKey, SideTable};

/// Rotating per-arm scan cursor: one row per [`CLEANUP_CHECKS`] entity type,
/// plus one literal `"attempt"` row for the completed-queue-record arm in
/// [`super::attempt_retention`]. Both suffix shapes share this one declared
/// prefix and cannot collide (1 byte vs 7 ASCII bytes).
pub(super) const SCAN_CURSOR: SideTable<ScanCursorTag, EntityId, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_SCAN_CURSOR);

#[derive(Clone, Copy)]
pub(super) enum ScanCursorTag {
    EntityType(u8),
    Attempt,
}

impl SideKey for ScanCursorTag {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::EntityType(byte) => out.push(*byte),
            Self::Attempt => out.extend_from_slice(b"attempt"),
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [byte] => Some(Self::EntityType(*byte)),
            b"attempt" => Some(Self::Attempt),
            _ => None,
        }
    }
}

pub(super) struct CleanupScan {
    pub(super) candidates: Vec<CleanupCandidate>,
    cursors: Vec<(ScanCursorTag, Option<EntityId>)>,
}

pub(super) fn scan_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    limit: usize,
) -> Result<CleanupScan> {
    let mut candidates = Vec::new();
    let mut cursors = Vec::new();
    for (type_byte, _, _) in CLEANUP_CHECKS {
        let tag = ScanCursorTag::EntityType(type_byte);
        let after = SCAN_CURSOR.get(&vault.store, txn, &tag)?;
        let mut last = None;
        let mut exhausted = true;
        for (examined, row) in vault
            .store
            .port_entity_ids_by_type(txn, type_byte, after)?
            .enumerate()
        {
            if examined == limit {
                exhausted = false;
                break;
            }
            let id = row?;
            last = Some(id);
            if let Some(kind) = zero_live_members_in_txn(vault, txn, &id)? {
                candidates.push(CleanupCandidate { entity: id, kind });
            }
        }
        cursors.push((tag, if exhausted { None } else { last }));
    }
    cursors.push(super::attempt_retention::scan(
        vault,
        txn,
        limit,
        &mut candidates,
    )?);
    Ok(CleanupScan {
        candidates,
        cursors,
    })
}

pub(super) fn run_with_limit(
    vault: &Vault,
    attempt: &AttemptId,
    limit: usize,
) -> Result<CleanupRunReport> {
    vault.with_write_txn(|txn| {
        if let Some(report) = run_record::read_in_txn(vault, txn, attempt)? {
            return Ok(report);
        }
        let CleanupScan {
            candidates,
            cursors,
        } = scan_in_txn(vault, txn, limit)?;
        let report = run_cleanup_candidates_in_txn(vault, txn, attempt, candidates)?;
        for (tag, after) in cursors {
            if let Some(id) = after {
                SCAN_CURSOR.put(&vault.store, txn, &tag, &id)?;
            } else {
                SCAN_CURSOR.delete(&vault.store, txn, &tag)?;
            }
        }
        run_record::put_in_txn(vault, txn, &report)?;
        Ok(report)
    })
}
