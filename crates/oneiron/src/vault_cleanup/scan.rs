//! Bounded rotating scans. Cursor progress co-commits with the cleanup decision.

use super::*;
use std::ops::Bound;

const CURSOR_PREFIX: &[u8] = b"vault_cleanup.scan.v1:";

pub(super) struct CleanupScan {
    pub(super) candidates: Vec<CleanupCandidate>,
    cursors: Vec<(Vec<u8>, Option<EntityId>)>,
}

pub(super) fn scan_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    limit: usize,
) -> Result<CleanupScan> {
    let mut candidates = Vec::new();
    let mut cursors = Vec::new();
    for (type_byte, _, _) in CLEANUP_CHECKS {
        let mut cursor_key = CURSOR_PREFIX.to_vec();
        cursor_key.push(type_byte);
        let after = vault
            .store
            .vault_meta
            .get(txn, &cursor_key)?
            .map(|raw| decode_id_bytes(&raw))
            .transpose()?;
        let start = after.map_or_else(
            || vec![type_byte],
            |id| crate::store::Store::encode_type_key(type_byte, &id).to_vec(),
        );
        let lower: Bound<&[u8]> = if after.is_some() {
            Bound::Excluded(&start)
        } else {
            Bound::Included(&start)
        };
        let upper: Bound<&[u8]> = Bound::Unbounded;
        let mut last = None;
        let mut exhausted = true;
        for (examined, row) in vault
            .store
            .type_index
            .range(txn, &(lower, upper))?
            .enumerate()
        {
            let (key, _) = row?;
            if key.first() != Some(&type_byte) {
                break;
            }
            if examined == limit {
                exhausted = false;
                break;
            }
            let id = decode_id_bytes(
                key.get(1..)
                    .ok_or(Error::CorruptedIndex("cleanup type key"))?,
            )?;
            last = Some(id);
            if let Some(kind) = zero_live_members_in_txn(vault, txn, &id)? {
                candidates.push(CleanupCandidate { entity: id, kind });
            }
        }
        cursors.push((cursor_key, if exhausted { None } else { last }));
    }
    Ok(CleanupScan {
        candidates,
        cursors,
    })
}

fn decode_id_bytes(raw: &[u8]) -> Result<EntityId> {
    let bytes = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("cleanup scan cursor"))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex("cleanup scan cursor"))
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
        for (key, after) in cursors {
            if let Some(id) = after {
                vault.store.vault_meta.put(txn, &key, id.as_bytes())?;
            } else {
                vault.store.vault_meta.delete(txn, &key)?;
            }
        }
        run_record::put_in_txn(vault, txn, &report)?;
        Ok(report)
    })
}
