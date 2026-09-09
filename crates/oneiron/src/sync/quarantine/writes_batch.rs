//! Quarantine row writes plus TerminalRejectionBatch.

use super::keys_classifier::{
    MAX_QUARANTINE_ROWS, MAX_QUARANTINE_ROWS_PER_PASS, QUARANTINE_BATCH_DROPS_KEY,
    QUARANTINE_MAX_AGE_SECS, QuarantineContainer, QuarantineRecord, crdt_key_metadata,
    decode_u64_le_counter, encode_quarantine_key, encode_record, payload_hash, reason_code_for,
};
use super::remat_markers::set_replay_remat_marker_in_txn;
use super::retention_reports::{allocate_next_quarantine_seq, enforce_retention_in_txn};
use crate::Vault;
use crate::error::{Error, Result};

// ─── Persistence ─────────────────────────────────────────────────────────────

/// Persists a quarantine record inside an existing write transaction.
///
/// Allocates a monotonic sequence via `m:last_quarantine_seq` (self-healing
/// against the max persisted `x:` seq, the SyncQueue metadata pattern),
/// writes the row, then enforces retention (row cap + age bound,
/// oldest-evicted-first, eviction counter incremented).
pub(in crate::sync) fn record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &QuarantineRecord,
) -> Result<u64> {
    tracing::warn!(
        window = %record.window_key,
        container = %record.container.as_str(),
        crdt_key_hash = record.crdt_key_hash,
        crdt_key_len = record.crdt_key_len,
        reason = %record.reason_code,
        "sync: remote op rejected by write gate — quarantined"
    );
    let seq = allocate_next_quarantine_seq(vault, wtxn)?;
    let key = encode_quarantine_key(seq);
    vault
        .store
        .sync_queue
        .put(wtxn, &key, &encode_record(record)?)?;
    enforce_retention_in_txn(
        vault,
        wtxn,
        MAX_QUARANTINE_ROWS,
        QUARANTINE_MAX_AGE_SECS,
        record.quarantined_at,
    )?;
    Ok(seq)
}

/// Entity whose window should be retried after this quarantine row is
/// written. Only replay surfaces with a stable entity scope participate:
/// `entities` rows name their entity directly, while `edges` rows retry by
/// source entity. Tombstone replay already has stricter purge-specific rm:
/// handling; lease rows are root-scoped and have no entity marker.
#[must_use]
pub(in crate::sync) fn remat_marker_entity_for_quarantine(
    container: QuarantineContainer,
    crdt_key: &str,
) -> Option<crate::entity_id::EntityId> {
    match container {
        QuarantineContainer::Entities => crate::entity_id::EntityId::from_hex(crdt_key).ok(),
        QuarantineContainer::Edges => {
            crate::sync::bridge::parse_edge_key(crdt_key).map(|(src, _, _)| src)
        }
        QuarantineContainer::Tombstones | QuarantineContainer::Leases => None,
    }
}

fn set_remat_marker_for_quarantine_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    container: QuarantineContainer,
    crdt_key: &str,
) -> Result<()> {
    if let Some(id) = remat_marker_entity_for_quarantine(container, crdt_key) {
        set_replay_remat_marker_in_txn(vault, wtxn, window_key, &id)?;
    }
    Ok(())
}

/// Builds and persists a quarantine record for a rejected remote op inside
/// an existing write transaction. `payload` is hashed, never stored. When
/// the rejected op has an entity/source scope, the same transaction also
/// writes the entity-scoped `rm:w:{window}:{entity_hex}` retry marker.
pub(in crate::sync) fn quarantine_rejected_op_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    container: QuarantineContainer,
    crdt_key: &str,
    error: &Error,
    payload: &[u8],
) -> Result<u64> {
    let (crdt_key_hash, crdt_key_len) = crdt_key_metadata(crdt_key);
    let seq = record_in_txn(
        vault,
        wtxn,
        &QuarantineRecord {
            window_key: window_key.to_string(),
            container,
            crdt_key_hash,
            crdt_key_len,
            reason_code: reason_code_for(error),
            payload_hash: payload_hash(payload),
            quarantined_at: crate::unix_seconds_now(),
        },
    )?;
    set_remat_marker_for_quarantine_in_txn(vault, wtxn, window_key, container, crdt_key)?;
    Ok(seq)
}

/// Builds and persists a quarantine record in its own write transaction.
pub(in crate::sync) fn quarantine_rejected_op(
    vault: &Vault,
    window_key: &str,
    container: QuarantineContainer,
    crdt_key: &str,
    error: &Error,
    payload: &[u8],
) -> Result<u64> {
    let mut wtxn = vault.store.env.write_txn()?;
    let seq = quarantine_rejected_op_in_txn(
        vault, &mut wtxn, window_key, container, crdt_key, error, payload,
    )?;
    wtxn.commit()?;
    Ok(seq)
}

/// One row a TERMINAL rejection pass refused, held until the pass commits.
struct TerminalRejection {
    container: QuarantineContainer,
    crdt_key_hash: u64,
    crdt_key_len: u32,
    reason_code: String,
    payload_hash: u64,
}

/// Accumulator for rows rejected TERMINALLY — refused by a door that never
/// admits them into any document, so no forward materialization pass can ever
/// re-run them.
///
/// TWO properties distinguish it from [`quarantine_rejected_op`], and both come
/// from the same fact: the peer, not the host, chooses how many rows one frame
/// carries.
///
/// * ONE txn per PASS, not per row. A per-row `write_txn` + commit hands a peer
///   an amplification primitive — N forged rows in one admission cost N fsyncs.
///   Rows accumulate in memory and land in the single [`Self::commit`] txn.
/// * NO `rm:` retry marker. The `rm:w:` marker means "a forward
///   rematerialization pass still owes work on this entity", and forward remat
///   heals by REPLAYING the row from the document. A terminally-rejected row is
///   never in a document, so no replay can ever discharge its marker: it would
///   pend forever and, because a pending `rm:` row is a GDPR
///   purge-may-have-failed signal, permanently poison [`sync_doctor`]'s
///   erasure-SLA channel with a row that has nothing to do with erasure.
///   Terminal-quarantine rows are complete evidence on their own — the `x:`
///   record IS the durable account.
///
/// Evidence is bounded at [`MAX_QUARANTINE_ROWS_PER_PASS`]; the remainder is
/// accounted by count. Nothing is silently dropped in either arm.
pub(in crate::sync) struct TerminalRejectionBatch {
    window_key: String,
    rows: Vec<TerminalRejection>,
    over_cap: u64,
}

impl TerminalRejectionBatch {
    pub(crate) fn new(window_key: &str) -> Self {
        Self {
            window_key: window_key.to_string(),
            rows: Vec::new(),
            over_cap: 0,
        }
    }

    /// Records one terminally-rejected row. Past
    /// [`MAX_QUARANTINE_ROWS_PER_PASS`] the row is counted rather than kept —
    /// H2 liveness is preserved either way because the ADMISSION continues
    /// regardless of how the rejection was accounted.
    pub(crate) fn push(
        &mut self,
        container: QuarantineContainer,
        crdt_key: &str,
        error: &Error,
        payload: &[u8],
    ) {
        if self.rows.len() >= MAX_QUARANTINE_ROWS_PER_PASS {
            self.over_cap = self.over_cap.saturating_add(1);
            return;
        }
        let (crdt_key_hash, crdt_key_len) = crdt_key_metadata(crdt_key);
        self.rows.push(TerminalRejection {
            container,
            crdt_key_hash,
            crdt_key_len,
            reason_code: reason_code_for(error),
            payload_hash: payload_hash(payload),
        });
    }

    /// Commits every accumulated row plus the over-cap counter in ONE write
    /// transaction. A pass that rejected nothing takes no transaction at all.
    pub(crate) fn commit(self, vault: &Vault) -> Result<()> {
        if self.rows.is_empty() && self.over_cap == 0 {
            return Ok(());
        }
        let quarantined_at = crate::unix_seconds_now();
        vault.with_write_txn(|wtxn| {
            for row in &self.rows {
                record_in_txn(
                    vault,
                    wtxn,
                    &QuarantineRecord {
                        window_key: self.window_key.clone(),
                        container: row.container,
                        crdt_key_hash: row.crdt_key_hash,
                        crdt_key_len: row.crdt_key_len,
                        reason_code: row.reason_code.clone(),
                        payload_hash: row.payload_hash,
                        quarantined_at,
                    },
                )?;
            }
            if self.over_cap > 0 {
                bump_batch_drop_counter_in_txn(vault, wtxn, self.over_cap)?;
            }
            Ok(())
        })
    }
}

/// Adds `count` to `m:quarantine_batch_drops`. Self-heals a malformed counter
/// row (diagnostics must never fail an admission closed), saturating so the
/// counter can never wrap a rejection into invisibility.
fn bump_batch_drop_counter_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    count: u64,
) -> Result<()> {
    let prior = vault
        .store
        .sync_queue
        .get(&*wtxn, QUARANTINE_BATCH_DROPS_KEY)?
        .and_then(|raw| decode_u64_le_counter(&raw))
        .unwrap_or(0);
    let total = prior.saturating_add(count);
    vault
        .store
        .sync_queue
        .put(wtxn, QUARANTINE_BATCH_DROPS_KEY, &total.to_le_bytes())?;
    tracing::warn!(
        dropped = count,
        total,
        "sync: terminal rejection evidence bound reached — rows accounted by count"
    );
    Ok(())
}
