//! Quarantine sink (`x:` family) + needs-rematerialization (`rm:`) retry
//! markers — no silent drops on the sync replay surface (ONE-1124).
//!
//! ARCH-0023b stream-class split: REMOTE divergent/malformed state is
//! "QUARANTINED … never silent LWW". Every remote-origin op rejected by a
//! write gate during Observer B materialization or forward
//! re-materialization persists a [`QuarantineRecord`] under
//! `x:{seq:8BE}` in `sync_queue` (db #25) — never a bare log line.
//!
//! The record is GDPR-inert by construction: it carries an `xxh3_64` HASH of
//! the rejected bytes plus metadata, never the bytes themselves. The CRDT
//! map key is attacker-controlled content too, so the record stores
//! `xxh3_64(key)` + byte length — never the key string (and never a prefix:
//! a prefix is still content). The `x:` family therefore does NOT become a
//! byte carrier and does NOT join the ARCH-0038 historical-carrier sweep
//! scope (OWNER-DECISION, see ONE-1124).
//!
//! LOCAL corruption (the engine's own LMDB read errors) is the opposite
//! stream class: a fail-closed typed error, NEVER quarantine-and-continue.
//! [`remote_rejection_reason`] is the classifier the replay sites use.
//!
//! The `rm:w:{window}:{entity_hex}` marker (ARCH-0023b sync_state
//! needs-rematerialization flag, ENTITY-scoped) is produced when a
//! CRDT-tombstone purge of that specific entity against the local active
//! store fails — a purge failure left hard-deleted content live, which is a
//! GDPR SLA breach signal until drained — and (ONE-1147) when an Observer-B
//! entity/edge materialization batch carrying that entity's op fails as a
//! whole txn (lost create/update writes = silent LMDB↔CRDT divergence).
//! The marker is cleared ONLY by that entity's own success — its purge for
//! tombstoned ids, or the actual healing write (entity body / edge from
//! that source) in forward remat; never byte-parity alone, and never an
//! unrelated entity's success. [`drain_remat_markers`] re-runs
//! `forward_rematerialize` for each flagged window. A row under `rm:` that
//! does not parse is fail-closed: it is treated as needs-remat and never
//! dropped.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::Vault;
use crate::error::{Error, ErrorKind, Result};
use crate::sync::bridge::Materializer;
use crate::sync::types::{WindowKey, parse_window_key_str};

/// Prefix for quarantine rows in `sync_queue` (db #25).
///
/// Distinct from `q:` (sync replay), `e:` (embed jobs), `h:` (ARCH-0038
/// hard-erase sweeps) and `m:` (metadata counters) — precedent: the `h:`
/// reservation in contracts.ts `hardEraseSweepQueue.distinctFrom`.
pub(crate) const QUARANTINE_PREFIX: &[u8] = b"x:";
/// Metadata key storing the last allocated quarantine sequence number
/// (u64 LE, the existing `m:` counter pattern).
pub(crate) const LAST_QUARANTINE_SEQ_KEY: &[u8] = b"m:last_quarantine_seq";
/// Metadata key storing the cumulative quarantine eviction counter (u64 LE).
/// An eviction is itself doctor-visible through this counter.
pub(crate) const QUARANTINE_EVICTIONS_KEY: &[u8] = b"m:quarantine_evictions";

/// Retention cap: maximum number of persisted quarantine rows.
pub const MAX_QUARANTINE_ROWS: usize = 4096;
/// Retention age bound: quarantine rows older than 30 days are evicted.
pub const QUARANTINE_MAX_AGE_SECS: u64 = 30 * 86_400;
/// Number of most-recent reason codes surfaced by [`sync_doctor`].
const RECENT_REASON_CODES: usize = 8;

/// Prefix for needs-rematerialization markers in `sync_state`. Full key
/// grammar (ONE-1124 fix wave 2, entity-scoped):
/// `rm:w:{window}:{entity_hex}` → `1 byte (marker)`, where `window` is
/// `YYYY-MM` and `entity_hex` is the 32-char lowercase entity id.
const REMAT_MARKER_PREFIX: &str = "rm:w:";

const ERR_QUARANTINE_ROW: &str = "sync quarantine row";

/// Which CRDT window-doc map the rejected op targeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineContainer {
    Entities,
    Edges,
    Tombstones,
    /// Root-doc `leases` registry entries (ONE-1140): a malformed lease
    /// value arriving through the root mirror is quarantined — never
    /// upserted over a previous good `ls:` row, never silently dropped.
    Leases,
}

impl QuarantineContainer {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entities => "entities",
            Self::Edges => "edges",
            Self::Tombstones => "tombstones",
            Self::Leases => "leases",
        }
    }
}

/// A persisted quarantine record. Hash + metadata ONLY — GDPR-inert, never
/// the rejected bytes themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// Window key (YYYY-MM) of the doc whose replay rejected the op.
    pub window_key: String,
    /// Which map the op targeted.
    pub container: QuarantineContainer,
    /// `xxh3_64` of the rejected op's CRDT map key bytes. The key itself is
    /// attacker-controlled and is NEVER stored — a crafted key string would
    /// smuggle content into the GDPR-inert `x:` family (and a prefix is
    /// still content). Hash + length only.
    pub crdt_key_hash: u64,
    /// Byte length of the rejected op's CRDT map key.
    pub crdt_key_len: u32,
    /// Typed error name of the rejecting gate (`ErrorKind` name, e.g.
    /// `InvalidEdgeWeight`, `InvalidTimeRange`, `EntityTypeImmutable`).
    pub reason_code: String,
    /// `xxh3_64` of the rejected value bytes (0-length input hashes the
    /// empty slice — e.g. a delete op carrying no payload).
    pub payload_hash: u64,
    /// Unix seconds when the op was quarantined.
    pub quarantined_at: u64,
}

/// `xxh3_64` of the rejected bytes — the only payload-derived field a
/// quarantine record may carry.
#[must_use]
pub(crate) fn payload_hash(bytes: &[u8]) -> u64 {
    xxh3_64(bytes)
}

/// Bounded, non-content metadata for an attacker-controlled CRDT map key:
/// (`xxh3_64` of the key's UTF-8 bytes, byte length). Same hash primitive
/// as [`payload_hash`]. The raw key must never be persisted in an `x:` row.
#[must_use]
pub(crate) fn crdt_key_metadata(key: &str) -> (u64, u32) {
    (
        xxh3_64(key.as_bytes()),
        u32::try_from(key.len()).unwrap_or(u32::MAX),
    )
}

/// Typed error name for a quarantine record (`ErrorKind` debug name).
#[must_use]
pub(crate) fn reason_code_for(error: &Error) -> String {
    format!("{:?}", error.kind())
}

/// Classifies a write-gate failure on the REMOTE replay path.
///
/// Returns `Some(reason_code)` when the error is a structural/validation
/// rejection of the remote op itself (quarantine-and-continue), `None` when
/// it is — or could be — the engine's own LOCAL failure (storage, IO,
/// ambiguous corruption), which must propagate as a fail-closed typed error
/// and NEVER be quarantined. Unknown kinds classify as local (fail closed).
#[must_use]
pub(crate) fn remote_rejection_reason(error: &Error) -> Option<String> {
    match error.kind() {
        ErrorKind::InvalidEntityType
        | ErrorKind::MaintenanceKindNotWritable
        | ErrorKind::ReservedPredicate
        | ErrorKind::EntityTypeImmutable
        | ErrorKind::InvalidTimeRange
        | ErrorKind::InvalidClaimBody
        | ErrorKind::InvalidPredicate
        | ErrorKind::InvalidEdgeWeight
        | ErrorKind::InvalidVad
        | ErrorKind::InvalidProvenanceBody
        | ErrorKind::ProvenanceOnStructuralEdge
        | ErrorKind::CycleDetected
        // A remote ChildOf op violating the single-parent pin is a pure
        // up-front validation rejection (validate_child_of_batch runs before
        // any byte is staged) — quarantine-and-continue, same class as
        // CycleDetected.
        | ErrorKind::ChildOfCardinality
        // ONE-1134: a remote type-120 blob failing the pinned
        // redactionAuditReceipt structural validation, or carrying divergent
        // bytes for an EXISTING receipt id (immutable audit record — keep
        // local, never silent LWW), is a remote rejection: quarantine the op
        // and continue the batch.
        | ErrorKind::InvalidRedactionReceiptBody
        | ErrorKind::RedactionReceiptDivergence
        // ONE-1140: a NEW type-120 receipt failing the origin predicate —
        // bad/transplanted attestation signature, unleased att_client, or a
        // revoked lease binding — is a remote rejection of the op itself:
        // quarantine (x: row) and continue. The rejected bytes stay in the
        // CRDT map, so the next forward rematerialization re-admits them
        // once the lease mirror catches up (OD-10 lazy re-admission).
        | ErrorKind::ReceiptAttestationInvalid
        | ErrorKind::ReceiptLeaseUnknown
        | ErrorKind::ReceiptLeaseRevoked => Some(reason_code_for(error)),
        _ => None,
    }
}

// ─── Key encoding ────────────────────────────────────────────────────────────

/// Encodes a quarantine key: `x:{seq:8BE}` (10 bytes).
pub(crate) fn encode_quarantine_key(seq: u64) -> [u8; 10] {
    let mut key = [0u8; 10];
    key[0..2].copy_from_slice(QUARANTINE_PREFIX);
    key[2..10].copy_from_slice(&seq.to_be_bytes());
    key
}

/// Decodes the sequence number from a quarantine key.
pub(crate) fn decode_quarantine_seq(key: &[u8]) -> Option<u64> {
    let seq = key.strip_prefix(QUARANTINE_PREFIX)?;
    Some(u64::from_be_bytes(seq.try_into().ok()?))
}

fn encode_record(record: &QuarantineRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("sync quarantine record encode"))
}

fn decode_record(value: &[u8]) -> Result<QuarantineRecord> {
    rmp_serde::from_slice(value).map_err(|_| Error::CorruptedIndex(ERR_QUARANTINE_ROW))
}

fn decode_u64_le_counter(raw: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = raw.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

// ─── Persistence ─────────────────────────────────────────────────────────────

/// Persists a quarantine record inside an existing write transaction.
///
/// Allocates a monotonic sequence via `m:last_quarantine_seq` (self-healing
/// against the max persisted `x:` seq, the SyncQueue metadata pattern),
/// writes the row, then enforces retention (row cap + age bound,
/// oldest-evicted-first, eviction counter incremented).
pub(crate) fn record_in_txn(
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

/// Builds and persists a quarantine record for a rejected remote op inside
/// an existing write transaction. `payload` is hashed, never stored.
pub(crate) fn quarantine_rejected_op_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    container: QuarantineContainer,
    crdt_key: &str,
    error: &Error,
    payload: &[u8],
) -> Result<u64> {
    let (crdt_key_hash, crdt_key_len) = crdt_key_metadata(crdt_key);
    record_in_txn(
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
    )
}

/// Builds and persists a quarantine record in its own write transaction.
pub(crate) fn quarantine_rejected_op(
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

fn allocate_next_quarantine_seq(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
    let metadata = vault
        .store
        .sync_queue
        .get(&*wtxn, LAST_QUARANTINE_SEQ_KEY)?
        .and_then(decode_u64_le_counter);
    let max_existing = max_quarantine_seq(vault, wtxn)?;
    let current = match metadata {
        Some(seq) if seq >= max_existing => seq,
        _ => max_existing,
    };
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("sync quarantine sequence"))?;
    vault
        .store
        .sync_queue
        .put(wtxn, LAST_QUARANTINE_SEQ_KEY, &next.to_le_bytes())?;
    Ok(next)
}

fn max_quarantine_seq(vault: &Vault, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
    let mut max_seq = 0_u64;
    let iter = vault
        .store
        .sync_queue
        .prefix_iter(wtxn, QUARANTINE_PREFIX)?;
    for entry in iter {
        let (key, _) = entry?;
        if let Some(seq) = decode_quarantine_seq(key) {
            max_seq = max_seq.max(seq);
        }
    }
    Ok(max_seq)
}

/// Enforces quarantine retention: rows past `max_age_secs` (relative to
/// `now`) are evicted, then the oldest rows beyond `max_rows` are evicted.
/// Rows whose value no longer decodes are evicted as well (they carry no
/// usable evidence). Every eviction increments `m:quarantine_evictions`.
fn enforce_retention_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    max_rows: usize,
    max_age_secs: u64,
    now: u64,
) -> Result<u64> {
    let mut survivors: Vec<Vec<u8>> = Vec::new();
    let mut evict: Vec<Vec<u8>> = Vec::new();
    {
        let iter = vault
            .store
            .sync_queue
            .prefix_iter(&*wtxn, QUARANTINE_PREFIX)?;
        for entry in iter {
            let (key, value) = entry?;
            if decode_quarantine_seq(key).is_none() {
                evict.push(key.to_vec());
                continue;
            }
            match decode_record(value) {
                Ok(rec) if rec.quarantined_at.saturating_add(max_age_secs) < now => {
                    evict.push(key.to_vec());
                }
                Ok(_) => survivors.push(key.to_vec()),
                Err(_) => evict.push(key.to_vec()),
            }
        }
    }
    // `x:{seq:8BE}` keys iterate in insertion order — survivors[0] is oldest.
    if survivors.len() > max_rows {
        let excess = survivors.len() - max_rows;
        evict.extend(survivors.drain(..excess));
    }

    let evicted = evict.len() as u64;
    if evicted == 0 {
        return Ok(0);
    }
    for key in &evict {
        vault.store.sync_queue.delete(wtxn, key)?;
    }
    // Self-heals a malformed counter row instead of failing the replay path:
    // the counter is diagnostics, and a quarantine-write failure here would
    // abort an otherwise-healthy materialization batch.
    let prior = vault
        .store
        .sync_queue
        .get(&*wtxn, QUARANTINE_EVICTIONS_KEY)?
        .and_then(decode_u64_le_counter)
        .unwrap_or(0);
    let total = prior.saturating_add(evicted);
    vault
        .store
        .sync_queue
        .put(wtxn, QUARANTINE_EVICTIONS_KEY, &total.to_le_bytes())?;
    tracing::warn!(evicted, total, "sync: quarantine retention evicted rows");
    Ok(evicted)
}

/// On-demand retention pass for the ONE-1087 sweep executor: evicts `x:`
/// rows past the pinned cap/age (4096 rows / ≤30 d) without requiring a new
/// quarantine write to trigger it. Hash-only rows are GDPR-inert, so this
/// is hygiene, not erasure safety. Returns the number of rows evicted.
pub(crate) fn expire_stale_rows(vault: &Vault, now: u64) -> Result<u64> {
    let mut wtxn = vault.store.env.write_txn()?;
    let evicted = enforce_retention_in_txn(
        vault,
        &mut wtxn,
        MAX_QUARANTINE_ROWS,
        QUARANTINE_MAX_AGE_SECS,
        now,
    )?;
    wtxn.commit()?;
    Ok(evicted)
}

// ─── Read surface ────────────────────────────────────────────────────────────

/// Returns all persisted quarantine records ordered by sequence number.
/// Read-only: rows that fail to decode are skipped (retention prunes them
/// on the next write), never silently repaired.
pub fn quarantined_records(vault: &Vault) -> Result<Vec<(u64, QuarantineRecord)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut records = Vec::new();
    let iter = vault
        .store
        .sync_queue
        .prefix_iter(&rtxn, QUARANTINE_PREFIX)?;
    for entry in iter {
        let (key, value) = entry?;
        let Some(seq) = decode_quarantine_seq(key) else {
            continue;
        };
        match decode_record(value) {
            Ok(rec) => records.push((seq, rec)),
            Err(_) => {
                tracing::warn!(seq, "sync: skipping undecodable quarantine row");
            }
        }
    }
    Ok(records)
}

/// Doctor/maintain surface for the sync quarantine + rematerialization
/// markers (ONE-1124 AC5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SyncQuarantineReport {
    /// Number of currently persisted quarantine rows.
    pub quarantine_count: usize,
    /// Most-recent reason codes, newest first (up to 8).
    pub recent_reason_codes: Vec<String>,
    /// Cumulative retention evictions (`m:quarantine_evictions`).
    pub eviction_count: u64,
    /// Windows with at least one pending `rm:w:{window}:{entity_hex}`
    /// marker — needs-rematerialization. Non-empty is an ERROR signal: a
    /// CRDT-tombstone purge failed, so hard-deleted content may still be
    /// live in the local active store (GDPR SLA breach signal) until
    /// [`drain_remat_markers`] succeeds. Unparsable `rm:` rows surface here
    /// too (fail closed — never dropped).
    pub rm_pending_windows: Vec<String>,
}

/// Builds the sync doctor report: quarantine count, most-recent reason
/// codes, eviction count, and pending `rm:` windows.
pub fn sync_doctor(vault: &Vault) -> Result<SyncQuarantineReport> {
    let records = quarantined_records(vault)?;
    let quarantine_count = records.len();
    let recent_reason_codes = records
        .iter()
        .rev()
        .take(RECENT_REASON_CODES)
        .map(|(_, rec)| rec.reason_code.clone())
        .collect();

    let rtxn = vault.store.env.read_txn()?;
    let eviction_count = vault
        .store
        .sync_queue
        .get(&rtxn, QUARANTINE_EVICTIONS_KEY)?
        .and_then(decode_u64_le_counter)
        .unwrap_or(0);
    drop(rtxn);

    let rm_pending_windows = pending_remat_windows(vault)?;
    let report = SyncQuarantineReport {
        quarantine_count,
        recent_reason_codes,
        eviction_count,
        rm_pending_windows,
    };
    if !report.rm_pending_windows.is_empty() {
        tracing::error!(
            windows = ?report.rm_pending_windows,
            "sync doctor: rm: markers pending — hard-deleted content may still be live locally (GDPR SLA breach signal)"
        );
    }
    Ok(report)
}

// ─── rm: needs-rematerialization markers ─────────────────────────────────────

/// Formats the entity-scoped needs-rematerialization marker key:
/// `rm:w:{window}:{entity_hex}` (32-char lowercase hex). Entity-scoped so
/// an unrelated entity's successful purge can never discharge another
/// entity's GDPR purge retry.
#[must_use]
pub(crate) fn remat_marker_key(window_key: &str, id: &crate::types::EntityId) -> String {
    format!("{REMAT_MARKER_PREFIX}{window_key}:{}", id.to_hex())
}

/// Sets `rm:w:{window}:{entity_hex}` (1-byte marker) in `sync_state` inside
/// an existing write transaction. Written when THAT entity's CRDT-tombstone
/// purge (or the read backing it) against the local active store fails, or
/// (ONE-1147) when an Observer-B entity/edge batch carrying that entity's
/// op fails as a whole txn.
pub(crate) fn set_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::types::EntityId,
) -> Result<()> {
    vault
        .store
        .sync_state
        .put(wtxn, &remat_marker_key(window_key, id), &[1u8])?;
    Ok(())
}

/// Sets `rm:w:{window}:{entity_hex}` in its own write transaction.
pub(crate) fn set_remat_marker(
    vault: &Vault,
    window_key: &str,
    id: &crate::types::EntityId,
) -> Result<()> {
    vault.with_write_txn(|wtxn| set_remat_marker_in_txn(vault, wtxn, window_key, id))
}

/// Clears `rm:w:{window}:{entity_hex}` inside an existing write
/// transaction. Only called when THAT entity's purge succeeded (or the
/// entity is verifiably absent — the purge goal state), or when forward
/// remat performed the actual healing write for that entity (ONE-1147).
pub(crate) fn clear_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::types::EntityId,
) -> Result<()> {
    vault
        .store
        .sync_state
        .delete(wtxn, &remat_marker_key(window_key, id))?;
    Ok(())
}

/// Lists DISTINCT windows currently flagged needs-rematerialization.
///
/// Fail closed: a row under `rm:` that is missing the entity segment (or
/// otherwise does not parse) is still surfaced — its whole remainder is
/// reported as the pending window. A needs-remat row is never dropped by a
/// read.
pub fn pending_remat_windows(vault: &Vault) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut windows = std::collections::BTreeSet::new();
    let iter = vault
        .store
        .sync_state
        .prefix_iter(&rtxn, REMAT_MARKER_PREFIX)?;
    for entry in iter {
        let (key, _) = entry?;
        let rest = &key[REMAT_MARKER_PREFIX.len()..];
        let window = match rest.split_once(':') {
            Some((window, _entity_hex)) => window,
            None => rest,
        };
        windows.insert(window.to_string());
    }
    Ok(windows.into_iter().collect())
}

/// Entity-hex segments of the `rm:w:{window}:{entity_hex}` markers for one
/// window. Rows whose entity segment is malformed are returned verbatim
/// (fail closed — never dropped); they can never be cleared by an
/// entity-scoped purge success and stay doctor-visible.
pub(crate) fn pending_remat_entities(vault: &Vault, window_key: &str) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = format!("{REMAT_MARKER_PREFIX}{window_key}:");
    let mut entities = Vec::new();
    let iter = vault.store.sync_state.prefix_iter(&rtxn, &prefix)?;
    for entry in iter {
        let (key, _) = entry?;
        entities.push(key[prefix.len()..].to_string());
    }
    Ok(entities)
}

/// Outcome of a [`drain_remat_markers`] pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RematDrainReport {
    /// Windows whose markers ALL cleared (every flagged entity's purge
    /// succeeded).
    pub drained: Vec<String>,
    /// Windows with at least one marker still set after the pass — a purge
    /// keeps failing, the flagged entity's tombstone is missing from the
    /// loaded doc, or a marker row does not parse (fail closed).
    /// ERROR-grade: hard-deleted content may still be live locally.
    pub still_pending: Vec<String>,
}

/// Drains `rm:` markers by re-running `forward_rematerialize` for each
/// flagged window. Each entity-scoped marker is cleared (inside
/// `forward_rematerialize`) only when that entity's own purge succeeds —
/// or, for ONE-1147 batch-failure markers, when its actual healing write
/// lands; a window with any surviving marker stays flagged and is reported
/// in `still_pending`.
pub fn drain_remat_markers(
    vault: &Arc<Vault>,
    user_id: &str,
    materializer: &Arc<Materializer>,
) -> Result<RematDrainReport> {
    let mut report = RematDrainReport::default();
    for window in pending_remat_windows(vault)? {
        if parse_window_key_str(&window).is_none() {
            tracing::error!(
                window = %window,
                "rm drain: malformed marker window key — cannot rematerialize, marker kept"
            );
            report.still_pending.push(window);
            continue;
        }
        let window_key = WindowKey::new(window.clone());
        let doc = match crate::sync::window::load_window_from_state(vault, user_id, &window_key) {
            Ok(doc) => doc,
            Err(Error::WindowNotFound { .. }) => {
                // No persisted snapshot (d:w: absent) — rebuild from
                // Observer A's durable update rows (u:w:) so the tombstone
                // whose purge failed can still be drained; otherwise a
                // hard-deleted entity stays live indefinitely behind the
                // missing snapshot. Fail closed: an empty rebuild carries
                // zero tombstones and `forward_rematerialize` keeps the
                // marker for such a doc.
                tracing::warn!(
                    window = %window,
                    "rm drain: no persisted doc for flagged window — rebuilding from pending update rows"
                );
                crate::sync::window::rebuild_window_from_updates(vault, user_id, &window_key)?
            }
            Err(err) => return Err(err),
        };
        crate::sync::window::forward_rematerialize(vault, &doc, materializer, &window_key)?;
        let still_flagged = pending_remat_windows(vault)?.contains(&window);
        if still_flagged {
            tracing::error!(
                window = %window,
                "rm drain: tombstone purge still failing — hard-deleted content may be live (GDPR SLA breach signal)"
            );
            report.still_pending.push(window);
        } else {
            report.drained.push(window);
        }
    }
    Ok(report)
}

// ─── ra: tombstone re-assertion markers (ONE-1156c) ──────────────────────────

/// Prefix for queued tombstone re-assertion markers in `sync_state`
/// (ONE-1156(c), WAVE-C design OD-11). Full key grammar, mirroring `rm:w:`:
/// `ra:w:{window}:{entity_hex}` → exactly the 25 B tombstone value
/// `[reason:1][deleted_at:8 LE][request_id:16]` to re-assert — byte-identical
/// to the `dt:` local hard-delete row (LE in the opaque value, per the dt:
/// convention). `window` is `YYYY-MM`; `entity_hex` is the 32-char lowercase
/// entity id.
///
/// Producers are Observer B tombstone callbacks observing doc-side delete
/// residue for a locally hard-deleted id: a tombstone REMOVAL delta, or a
/// soft value merged over the local hard truth (M4 handoff §8c.1). LMDB is
/// already safe (`dt:` gate + never-downgrade in the replay primitive), but
/// the window doc would keep propagating the residue. The re-entrancy bar —
/// no doc writes inside observer callbacks — means the re-assertion cannot
/// run at the producer; the durable marker defers it to a safe commit point
/// ([`drain_reassert_markers`]).
///
/// HARD-only by design (OD-11): without a `dt:` row there is no faithful
/// local value to re-assert, and a reconstructed soft value could HARD-purge
/// a user-kept shell at peers (decode mismatch) — soft-removal residue stays
/// quarantine-only (pinned residual R4).
const REASSERT_MARKER_PREFIX: &str = "ra:w:";

/// Formats the `ra:w:{window}:{entity_hex}` re-assertion marker key.
#[must_use]
pub(crate) fn reassert_marker_key(window_key: &str, id: &crate::types::EntityId) -> String {
    format!("{REASSERT_MARKER_PREFIX}{window_key}:{}", id.to_hex())
}

/// Enqueues the tombstone re-assertion marker for `id` IF the permanent
/// `dt:{entity_hex}` local hard-delete marker exists: ONE write transaction
/// reads the `dt:` row and writes `ra:w:{window}:{entity_hex}` with the
/// row's EXACT bytes — the value the drain re-asserts verbatim. Returns
/// whether a marker was written (`false` = no `dt:` row, nothing faithful
/// to re-assert — OD-11 HARD-only). Idempotent: same key, same dt:-derived
/// value.
pub(crate) fn enqueue_tombstone_reassert_marker(
    vault: &Vault,
    window_key: &str,
    id: &crate::types::EntityId,
) -> Result<bool> {
    vault.with_write_txn(|wtxn| {
        let dt_key = crate::deletion::local_hard_delete_key(id);
        let Some(dt_value) = vault.store.sync_state.get(wtxn, &dt_key)? else {
            return Ok(false);
        };
        let dt_value = dt_value.to_vec();
        vault
            .store
            .sync_state
            .put(wtxn, &reassert_marker_key(window_key, id), &dt_value)?;
        Ok(true)
    })
}

/// Lists DISTINCT windows with pending `ra:` re-assertion markers.
///
/// Fail closed like [`pending_remat_windows`]: a row under `ra:w:` missing
/// the entity segment (or otherwise unparsable) is still surfaced — its
/// whole remainder is reported as the pending window. A re-assertion intent
/// is never dropped by a read.
pub fn pending_reassert_windows(vault: &Vault) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut windows = std::collections::BTreeSet::new();
    let iter = vault
        .store
        .sync_state
        .prefix_iter(&rtxn, REASSERT_MARKER_PREFIX)?;
    for entry in iter {
        let (key, _) = entry?;
        let rest = &key[REASSERT_MARKER_PREFIX.len()..];
        let window = match rest.split_once(':') {
            Some((window, _entity_hex)) => window,
            None => rest,
        };
        windows.insert(window.to_string());
    }
    Ok(windows.into_iter().collect())
}

/// One parsed `ra:` marker: (full `sync_state` key, entity id, value bytes).
type ReassertMarker = (String, crate::types::EntityId, Vec<u8>);

/// The `ra:` markers for one window: `(marker_key, parsed_id, value)` for
/// every row whose entity segment parses, plus the count of malformed rows.
/// Malformed rows are NEVER returned for application and never deleted —
/// they keep the window `still_pending` (fail closed) and stay
/// doctor-visible via [`pending_reassert_windows`].
fn pending_reassert_markers(
    vault: &Vault,
    window_key: &str,
) -> Result<(Vec<ReassertMarker>, usize)> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = format!("{REASSERT_MARKER_PREFIX}{window_key}:");
    let mut markers = Vec::new();
    let mut malformed = 0usize;
    let iter = vault.store.sync_state.prefix_iter(&rtxn, &prefix)?;
    for entry in iter {
        let (key, value) = entry?;
        let hex = &key[prefix.len()..];
        match crate::types::EntityId::from_hex(hex) {
            Ok(id) => markers.push((key.to_string(), id, value.to_vec())),
            Err(_) => {
                tracing::error!(
                    marker = %key,
                    "ra drain: malformed re-assertion marker entity segment — marker kept (fail closed)"
                );
                malformed += 1;
            }
        }
    }
    Ok((markers, malformed))
}

/// Outcome of a [`drain_reassert_markers`] pass — same shape as
/// [`RematDrainReport`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReassertDrainReport {
    /// Windows whose `ra:` markers ALL re-asserted + cleared.
    pub drained: Vec<String>,
    /// Windows with at least one marker still set after the pass — the
    /// re-assertion keeps failing or a marker row does not parse (fail
    /// closed). ERROR-grade: doc-side delete residue keeps propagating.
    pub still_pending: Vec<String>,
}

/// Drains `ra:` tombstone re-assertion markers (ONE-1156(c), OD-11): per
/// flagged window, re-asserts each marker's exact tombstone value into the
/// window doc at a SAFE COMMIT POINT — handler/maintenance context, never
/// inside an observer callback (the §8c.1 re-entrancy bar the producers
/// respect).
///
/// Mirrors the `Vault::write_crdt_tombstone` dual path — live registry doc
/// (commit through the SHARED doc under the materializer lock) vs transient
/// load (`load_window_from_state`, with the rm:-drain
/// `rebuild_window_from_updates` fallback) — minus `pt:` bookkeeping and
/// minus the carrier-15 scrub: the LMDB purge already ran in the origin
/// txn; this is doc-side repair only (no `fr:` marker, no `q:` scrub).
///
/// Call sites: maintenance/doctor surfaces (alongside
/// [`drain_remat_markers`]) and inline in the bulk-transfer door
/// (`SyncClient::handle_bulk_transfer_done`), scoped to that window.
pub fn drain_reassert_markers(
    vault: &Arc<Vault>,
    user_id: &str,
    manager: &Arc<crate::sync::manager::WindowManager>,
) -> Result<ReassertDrainReport> {
    let mut report = ReassertDrainReport::default();
    for window in pending_reassert_windows(vault)? {
        if parse_window_key_str(&window).is_none() {
            tracing::error!(
                window = %window,
                "ra drain: malformed marker window key — cannot re-assert, marker kept"
            );
            report.still_pending.push(window);
            continue;
        }
        let window_key = WindowKey::new(window.clone());
        if drain_reassert_markers_for_window(vault, user_id, manager, &window_key)? {
            report.drained.push(window);
        } else {
            tracing::error!(
                window = %window,
                "ra drain: re-assertion markers still pending — doc-side delete residue keeps propagating"
            );
            report.still_pending.push(window);
        }
    }
    Ok(report)
}

/// Per-window `ra:` drain (see [`drain_reassert_markers`]). Returns `true`
/// when no marker remains for the window (every parsed marker re-asserted
/// and cleared; vacuously true when none were pending), `false` when a
/// malformed marker row was kept (fail closed).
///
/// The success transaction is atomic: the re-asserted window-doc snapshot
/// triple (`d:`/`sv:`/`svf:`), the delete-bearing queue row (`q:` +
/// `d:{seq:8BE}` sidecar — the re-asserted tombstone must propagate and
/// survive optimistic clears), and the `ra:` row deletions commit together.
/// Markers are deleted ONLY in this transaction; a failure anywhere leaves
/// them set for retry. Idempotent on double-drain: the second pass finds no
/// markers (and a re-applied hard value is downgrade-blocked/no-op at every
/// consumer — never-downgrade).
pub(crate) fn drain_reassert_markers_for_window(
    vault: &Arc<Vault>,
    user_id: &str,
    manager: &Arc<crate::sync::manager::WindowManager>,
    window_key: &WindowKey,
) -> Result<bool> {
    use crate::sync::bridge::BRIDGE_ORIGIN;
    use crate::sync::loro_support::{doc_version_vector, export_snapshot};
    use crate::sync::window::{
        apply_tombstone_to_window_doc, export_tombstone_commit_delta, load_window_from_state,
        merge_persisted_state_into_doc, persist_window_doc_in_txn, rebuild_window_from_updates,
    };
    use loro::CommitOptions;

    let (markers, malformed) = pending_reassert_markers(vault, window_key.as_str())?;
    if markers.is_empty() {
        return Ok(malformed == 0);
    }

    // Live vs transient doc routing — `write_crdt_tombstone`'s dual path.
    let live = manager.window(window_key);
    let (delete_update, snapshot, vv) = match &live {
        Some(window) => {
            // Clobber guard OUTSIDE the materializer lock: importing into
            // an observed doc fires Observer B, which takes the
            // (non-reentrant) lock itself. The commit + exports then run
            // UNDER the lock so a concurrent remote re-put cannot read the
            // tombstones map between this commit and the persist below
            // (mirrors `Vault::write_crdt_tombstone`; lock order
            // materializer → LMDB txn matches every other holder, and the
            // registry lock is NOT held here).
            merge_persisted_state_into_doc(vault, &window.doc, window_key)?;
            let _guard = manager.materializer().lock();
            let vv_before = window.doc.oplog_vv();
            for (_, id, value) in &markers {
                apply_tombstone_to_window_doc(&window.doc, id, value)?;
            }
            // BRIDGE_ORIGIN: Observer B must skip this commit — LMDB
            // already holds the delete truth (`dt:` + the origin purge
            // txn); Observer A still persists/broadcasts as usual.
            window
                .doc
                .commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            let delete_update = export_tombstone_commit_delta(&window.doc, &vv_before)?;
            (
                delete_update,
                export_snapshot(&window.doc)?,
                doc_version_vector(&window.doc),
            )
        }
        None => {
            // Transient: the loaded doc IS the merge of `d:w:` + pending
            // `u:w:` rows; no observers are attached, so no lock is needed.
            let doc = match load_window_from_state(vault, user_id, window_key) {
                Ok(doc) => doc,
                Err(Error::WindowNotFound { .. }) => {
                    // Same fallback as the rm: drain: a flagged window
                    // without a persisted snapshot can still carry its
                    // tombstones in Observer A's durable update rows.
                    rebuild_window_from_updates(vault, user_id, window_key)?
                }
                Err(err) => return Err(err),
            };
            let vv_before = doc.oplog_vv();
            for (_, id, value) in &markers {
                apply_tombstone_to_window_doc(&doc, id, value)?;
            }
            doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            let delete_update = export_tombstone_commit_delta(&doc, &vv_before)?;
            (
                delete_update,
                export_snapshot(&doc)?,
                doc_version_vector(&doc),
            )
        }
    };

    // ONE transaction: snapshot triple + delete-bearing queue row + marker
    // deletions. An empty delta (every apply was downgrade-blocked / no-op)
    // skips the queue push — nothing new to propagate.
    vault.with_write_txn(|wtxn| {
        persist_window_doc_in_txn(vault, wtxn, window_key, &snapshot, &vv)?;
        if let Some(update) = &delete_update {
            crate::sync::queue::push_delete_bearing_in_txn(
                vault,
                wtxn,
                window_key.as_str(),
                update,
            )?;
        }
        for (marker_key, _, _) in &markers {
            vault.store.sync_state.delete(wtxn, marker_key)?;
        }
        Ok(())
    })?;

    Ok(malformed == 0)
}

// ─── Test failure injection ──────────────────────────────────────────────────

// Test-only purge failure injection for the rm: round-trip tests. Counts
// down per purge attempt on the current thread (Loro observer callbacks
// fire synchronously on the committing thread).
#[cfg(test)]
thread_local! {
    pub(crate) static INJECT_PURGE_FAILURES: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
}

/// Applies a replayed tombstone on behalf of the sync tombstone paths —
/// the reason-aware primitive ([`Vault::apply_replayed_tombstone`],
/// ONE-1133) is the ONLY effect path, never a bare purge. In test builds a
/// thread-local injection hook can force failures to exercise the rm:
/// marker round-trip.
pub(crate) fn apply_replayed_tombstone_for_sync(
    vault: &Vault,
    id: &crate::types::EntityId,
    raw_value: &[u8],
) -> Result<crate::deletion::ReplayedTombstoneOutcome> {
    #[cfg(test)]
    {
        let inject = INJECT_PURGE_FAILURES.with(|cell| {
            let remaining = cell.get();
            if remaining > 0 {
                cell.set(remaining - 1);
                true
            } else {
                false
            }
        });
        if inject {
            return Err(Error::Io(std::io::Error::other(
                "injected purge failure (test hook)",
            )));
        }
    }
    vault.apply_replayed_tombstone(id, raw_value)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::Vault;
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::schema::create_window_doc;
    use crate::sync::window::{LoadedWindow, forward_rematerialize, reverse_rematerialize};
    use crate::types::{ENTITY_TYPE_TASK, EntityId, TimeRange, VaultConfig};
    use loro::LoroDoc;

    /// `learned_at` inside the 2026-03 window used throughout.
    const LEARNED_AT: u64 = 1_772_400_000;
    const WINDOW: &str = "2026-03";

    /// Small map_size + tempdir held for the vault's lifetime — macOS LMDB
    /// flake isolation. NOTE: the lib test binary sits near a per-process
    /// LMDB env-open budget on macOS (each test_vault is one env); the
    /// env-heavy observer table tests live in `tests/sync_quarantine.rs`
    /// (their own process) for exactly this reason. Keep in-lib env count
    /// minimal.
    fn test_vault_with_dir() -> (tempfile::TempDir, Arc<Vault>) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = VaultConfig::device();
        cfg.map_size = 16 * 1024 * 1024;
        let vault = Arc::new(Vault::open(dir.path(), cfg).unwrap());
        (dir, vault)
    }

    /// 25-byte envelope: type u8 + occurred_start/end + learned_at u64 BE.
    fn entity_blob(entity_type: u8, occurred: TimeRange, learned_at: u64, data: &[u8]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(25 + data.len());
        blob.push(entity_type);
        blob.extend_from_slice(&occurred.start.to_be_bytes());
        blob.extend_from_slice(&occurred.end.to_be_bytes());
        blob.extend_from_slice(&learned_at.to_be_bytes());
        blob.extend_from_slice(data);
        blob
    }

    /// Hand-built 24-byte SemanticBare edge value (weight + created_at +
    /// VAD), bypassing `encode_edge_value`'s own validation.
    fn semantic_edge_value(weight: f32) -> Vec<u8> {
        let mut value = Vec::with_capacity(24);
        value.extend_from_slice(&weight.to_le_bytes());
        value.extend_from_slice(&10u64.to_le_bytes());
        for _ in 0..3 {
            value.extend_from_slice(&0.5f32.to_le_bytes());
        }
        value
    }

    fn valid_time_range() -> TimeRange {
        TimeRange { start: 1, end: 2 }
    }

    // ─── Key family + record shape ───────────────────────────────────────────

    /// AC1 — `x:{seq:8BE}` literal layout: prefix byte-for-byte, big-endian
    /// sequence. A little-endian or differently-prefixed implementation
    /// fails here.
    #[test]
    fn quarantine_key_encoding_is_x_prefix_with_8be_seq() {
        assert_eq!(
            encode_quarantine_key(0x0102_0304_0506_0708),
            *b"x:\x01\x02\x03\x04\x05\x06\x07\x08"
        );
        assert_eq!(
            decode_quarantine_seq(b"x:\x00\x00\x00\x00\x00\x00\x00\x2a"),
            Some(42)
        );
        // Wrong family prefix and wrong lengths never decode.
        assert_eq!(
            decode_quarantine_seq(b"q:\x00\x00\x00\x00\x00\x00\x00\x2a"),
            None
        );
        assert_eq!(
            decode_quarantine_seq(b"x:\x00\x00\x00\x00\x00\x00\x2a"),
            None
        );
        for seq in [0u64, 1, 255, 65_535, u64::MAX] {
            assert_eq!(
                decode_quarantine_seq(&encode_quarantine_key(seq)),
                Some(seq)
            );
        }
    }

    /// Pinned retention decision: 4096 rows, ≤30 days.
    #[test]
    fn retention_constants_match_pinned_decision() {
        assert_eq!(MAX_QUARANTINE_ROWS, 4096);
        assert_eq!(QUARANTINE_MAX_AGE_SECS, 2_592_000);
    }

    /// AC1/OWNER-DECISION — the record is GDPR-inert: it stores the xxh3_64
    /// HASH of the rejected bytes, never the bytes. An implementation that
    /// embeds the payload (full-bytes alternative) fails the windows scan.
    /// Also pins the literal `x:` + 8BE row addressing in the raw store.
    #[test]
    fn quarantine_record_is_hash_only_never_payload_bytes() {
        let (_dir, vault) = test_vault_with_dir();
        // 24 bytes (< 25-byte envelope → undecodable blob) and distinctive.
        let payload = b"SECRET-PII-PAYLOAD-BYTES";
        assert_eq!(payload.len(), 24);

        let doc = LoroDoc::new();
        let materializer = Arc::new(Materializer::new());
        let _subs = crate::sync::bridge::register_observer_b(&doc, &vault, &materializer, WINDOW);
        let id = EntityId::now();
        map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), payload).unwrap();
        doc.commit();

        let records = quarantined_records(&vault).unwrap();
        assert_eq!(records.len(), 1);
        let (seq, rec) = &records[0];
        assert_eq!(*seq, 1);
        assert_eq!(rec.window_key, WINDOW);
        assert_eq!(rec.container, QuarantineContainer::Entities);
        assert_eq!(rec.crdt_key_hash, xxh3_64(id.to_hex().as_bytes()));
        assert_eq!(rec.crdt_key_len, 32);
        assert_eq!(rec.reason_code, "CorruptedIndex");
        assert_eq!(
            rec.payload_hash,
            xxh3_64(payload),
            "record must carry the xxh3_64 of the rejected bytes"
        );

        let rtxn = vault.store.env.read_txn().unwrap();
        let raw = vault
            .store
            .sync_queue
            .get(&rtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x01")
            .unwrap()
            .expect("row must live under the literal x: + 8BE key");
        assert!(
            !raw.windows(payload.len()).any(|w| w == payload),
            "x: row must never carry the rejected payload bytes (GDPR-inert)"
        );
    }

    // ─── Retention + doctor surface (AC5) ────────────────────────────────────

    /// Row-cap + age-bound retention (oldest evicted first, counter
    /// persists) and the doctor surface over the same vault.
    #[test]
    fn retention_evicts_oldest_first_and_doctor_reports_state() {
        let (_dir, vault) = test_vault_with_dir();
        for i in 0..5u64 {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            record_in_txn(
                &vault,
                &mut wtxn,
                &QuarantineRecord {
                    window_key: WINDOW.to_string(),
                    container: QuarantineContainer::Entities,
                    crdt_key_hash: i,
                    crdt_key_len: 2,
                    reason_code: "InvalidKey".to_string(),
                    payload_hash: i,
                    quarantined_at: 1_000 + i,
                },
            )
            .unwrap();
            wtxn.commit().unwrap();
        }

        // Cap sweep: 5 rows, cap 3 → the two oldest go.
        let mut wtxn = vault.store.env.write_txn().unwrap();
        let evicted = enforce_retention_in_txn(&vault, &mut wtxn, 3, u64::MAX, 2_000).unwrap();
        wtxn.commit().unwrap();
        assert_eq!(evicted, 2);
        let remaining: Vec<u64> = quarantined_records(&vault)
            .unwrap()
            .into_iter()
            .map(|(seq, _)| seq)
            .collect();
        assert_eq!(remaining, vec![3, 4, 5], "oldest rows must go first");

        // Age sweep through the production write path: a record older than
        // 30 days is evicted when the next record lands.
        let fresh_hash = 0xF8E5_u64;
        let mut wtxn = vault.store.env.write_txn().unwrap();
        record_in_txn(
            &vault,
            &mut wtxn,
            &QuarantineRecord {
                window_key: WINDOW.to_string(),
                container: QuarantineContainer::Edges,
                crdt_key_hash: fresh_hash,
                crdt_key_len: 5,
                reason_code: "InvalidEdgeWeight".to_string(),
                payload_hash: 9,
                quarantined_at: 1_004 + QUARANTINE_MAX_AGE_SECS + 1,
            },
        )
        .unwrap();
        wtxn.commit().unwrap();
        let records = quarantined_records(&vault).unwrap();
        assert_eq!(records.len(), 1, "rows past the age bound are evicted");
        assert_eq!(records[0].1.crdt_key_hash, fresh_hash);

        // Doctor surface: count, newest-first reasons, evictions, rm:.
        set_remat_marker(&vault, WINDOW, &EntityId::now()).unwrap();
        let report = sync_doctor(&vault).unwrap();
        assert_eq!(report.quarantine_count, 1);
        assert_eq!(
            report.recent_reason_codes,
            vec!["InvalidEdgeWeight".to_string()],
            "newest reason first"
        );
        assert_eq!(
            report.eviction_count,
            2 + 3,
            "cap sweep + age sweep evictions"
        );
        assert_eq!(report.rm_pending_windows, vec![WINDOW.to_string()]);

        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault
                .store
                .sync_queue
                .get(&rtxn, QUARANTINE_EVICTIONS_KEY)
                .unwrap(),
            Some(5u64.to_le_bytes().as_slice()),
            "eviction counter must persist (doctor-visible)"
        );
    }

    // ─── AC4 + AC7 — rm: round trip ──────────────────────────────────────────

    /// AC4/AC7 — full rm: round trip: injected purge failure on Observer B
    /// → `rm:w:{window}:{entity_hex}` marker (literal entity-scoped key +
    /// 1-byte value) → a failing drain keeps the marker (ERROR-grade in
    /// doctor) → a healthy drain purges, clears the marker, and reports it
    /// drained.
    #[test]
    fn rm_marker_round_trip_purge_failure_then_drain() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Arc::new(Materializer::new());
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TASK,
                valid_time_range(),
                LEARNED_AT,
                b"purge-me",
            )
            .unwrap();

        let window_key = WindowKey::new(WINDOW);
        let window = LoadedWindow::new("test-user", window_key.clone(), &vault, &materializer);
        let mirrored = reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
        assert_eq!(mirrored, 1);

        // Remote tombstone arrives; the active-store purge fails.
        INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
        map_insert_bytes(&window.doc.get_map("tombstones"), &id.to_hex(), b"1").unwrap();
        window.doc.commit();

        assert!(
            vault.get(&id).unwrap().is_some(),
            "precondition: failed purge left hard-deleted content live"
        );
        // Pinned literal grammar: rm:w:{window}:{entity_hex} → 1 byte.
        let marker_key = format!("rm:w:2026-03:{}", id.to_hex());
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &marker_key).unwrap(),
            Some([1u8].as_slice()),
            "purge failure must set the entity-scoped rm:w marker"
        );
        drop(rtxn);
        assert_eq!(
            sync_doctor(&vault).unwrap().rm_pending_windows,
            vec![WINDOW.to_string()]
        );

        // Persist the doc (with the tombstone) so the drain can load it.
        window.persist_state(&vault).unwrap();
        drop(window);

        // Drain while the purge KEEPS failing: marker survives (ERROR).
        INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
        let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
        assert_eq!(report.still_pending, vec![WINDOW.to_string()]);
        assert!(report.drained.is_empty());
        assert!(vault.get(&id).unwrap().is_some());

        // Healthy drain: purge succeeds, marker cleared only now.
        let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
        assert_eq!(report.drained, vec![WINDOW.to_string()]);
        assert!(report.still_pending.is_empty());
        assert!(
            vault.get(&id).unwrap().is_none(),
            "drain must complete the purge"
        );
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &marker_key).unwrap(),
            None,
            "marker cleared only on successful purge"
        );
        drop(rtxn);
        assert!(sync_doctor(&vault).unwrap().rm_pending_windows.is_empty());
    }

    /// AC4 — the forward-remat tombstone pass is itself an rm: producer, and
    /// (fail-closed) a doc with NO tombstones never vacuously discharges an
    /// rm: marker (the persisted state may predate the failed tombstone).
    #[test]
    fn forward_remat_tombstone_purge_failure_flags_rm_then_clears_on_success() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Materializer::new();
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TASK,
                valid_time_range(),
                LEARNED_AT,
                b"purge-me",
            )
            .unwrap();

        let window_key = WindowKey::new(WINDOW);
        let doc = create_window_doc("test-user", &window_key);
        map_insert_bytes(&doc.get_map("tombstones"), &id.to_hex(), b"1").unwrap();
        doc.commit();

        INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
        forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
        assert!(vault.get(&id).unwrap().is_some());
        assert_eq!(
            pending_remat_windows(&vault).unwrap(),
            vec![WINDOW.to_string()],
            "forward-remat purge failure must flag rm:w"
        );

        forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
        assert!(vault.get(&id).unwrap().is_none());
        assert!(
            pending_remat_windows(&vault).unwrap().is_empty(),
            "marker cleared after the purge pass fully succeeds"
        );

        // Stale-state guard: re-flag the entity, then run a doc carrying
        // ZERO tombstones — the marker must survive (clearing requires the
        // entity's own tombstone to succeed in the pass).
        set_remat_marker(&vault, WINDOW, &id).unwrap();
        let empty_doc = create_window_doc("test-user", &window_key);
        forward_rematerialize(&vault, &empty_doc, &materializer, &window_key).unwrap();
        assert_eq!(
            pending_remat_windows(&vault).unwrap(),
            vec![WINDOW.to_string()],
            "empty-tombstone doc must not clear the marker"
        );

        // A doc whose tombstones are ALL malformed must not clear the
        // marker either: only VALIDATED tombstones count toward the purge
        // pass that discharges it (a malformed-only doc would otherwise
        // vacuously discharge the GDPR retry).
        let malformed_doc = create_window_doc("test-user", &window_key);
        map_insert_bytes(&malformed_doc.get_map("tombstones"), "zzz-not-hex", b"1").unwrap();
        malformed_doc.commit();
        forward_rematerialize(&vault, &malformed_doc, &materializer, &window_key).unwrap();
        assert_eq!(
            pending_remat_windows(&vault).unwrap(),
            vec![WINDOW.to_string()],
            "malformed-only tombstone doc must not clear the marker"
        );
    }

    /// rm: drain for a flagged window with NO persisted snapshot (`d:w:`
    /// absent): the doc is rebuilt from Observer A's durable `u:w:` update
    /// rows, so the failed purge still drains — a hard-deleted entity must
    /// not stay live indefinitely behind a missing snapshot row.
    #[test]
    fn rm_drain_rebuilds_doc_from_pending_updates_when_snapshot_missing() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Arc::new(Materializer::new());
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TASK,
                valid_time_range(),
                LEARNED_AT,
                b"purge-me",
            )
            .unwrap();

        let window_key = WindowKey::new(WINDOW);
        let window = LoadedWindow::new("test-user", window_key.clone(), &vault, &materializer);
        let mirrored = reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
        assert_eq!(mirrored, 1);

        // Remote tombstone arrives; the active-store purge fails → rm: set.
        INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
        map_insert_bytes(&window.doc.get_map("tombstones"), &id.to_hex(), b"1").unwrap();
        window.doc.commit();
        assert!(vault.get(&id).unwrap().is_some());
        assert_eq!(
            pending_remat_windows(&vault).unwrap(),
            vec![WINDOW.to_string()]
        );

        // Drop WITHOUT persist_state: no d:w: snapshot, but Observer A
        // persisted the update rows durably.
        drop(window);
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_state.get(&rtxn, "d:w:2026-03").unwrap(),
            None,
            "precondition: no persisted snapshot"
        );
        let pending_updates = vault
            .store
            .sync_state
            .prefix_iter(&rtxn, "u:w:2026-03:")
            .unwrap()
            .count();
        assert!(pending_updates > 0, "precondition: u:w: rows persisted");
        drop(rtxn);

        // Drain rebuilds the doc from u:w: rows; the purge now succeeds.
        let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
        assert_eq!(report.drained, vec![WINDOW.to_string()]);
        assert!(report.still_pending.is_empty());
        assert!(
            vault.get(&id).unwrap().is_none(),
            "hard-deleted entity purged via the rebuilt doc"
        );
        assert!(pending_remat_windows(&vault).unwrap().is_empty());
    }

    /// ONE-1147 — Observer-B ENTITY batch whole-txn failure parity with the
    /// hardened tombstone path: a failed batch commit must set the durable
    /// entity-scoped marker under the LITERAL key `rm:w:{window}:{entity_hex}`
    /// with the LITERAL 1-byte value `[1u8]` for EVERY entity the dead txn
    /// had applied (never a bare error log), and a later
    /// `drain_remat_markers` must heal the divergence (entities present in
    /// LMDB) and clear the markers via the actual healing writes.
    #[test]
    fn rm_marker_round_trip_entity_batch_commit_failure_then_drain() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Arc::new(Materializer::new());
        let window_key = WindowKey::new(WINDOW);
        let window = LoadedWindow::new("test-user", window_key, &vault, &materializer);

        let a = EntityId::now();
        let b = EntityId::now();
        let blob_a = entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            b"one-1147-a",
        );
        let blob_b = entity_blob(
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            b"one-1147-b",
        );

        // One commit → one delta → ONE batch txn carrying BOTH ops; the
        // injected LOCAL error aborts it post-batch, hitting the Observer-B
        // swallow site (the whole-txn failure class: no surviving
        // per-entity failure point).
        crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
        let entities = window.doc.get_map("entities");
        map_insert_bytes(&entities, &a.to_hex(), &blob_a).unwrap();
        map_insert_bytes(&entities, &b.to_hex(), &blob_b).unwrap();
        window.doc.commit();

        // Divergence precondition: ops live in the CRDT doc, absent from LMDB.
        assert!(vault.get(&a).unwrap().is_none());
        assert!(vault.get(&b).unwrap().is_none());

        // Pinned literal grammar: `rm:w:{window}:{entity_hex}` → `[1u8]`,
        // one marker per batched entity.
        let rtxn = vault.store.env.read_txn().unwrap();
        for id in [&a, &b] {
            let marker_key = format!("rm:w:2026-03:{}", id.to_hex());
            assert_eq!(
                vault.store.sync_state.get(&rtxn, &marker_key).unwrap(),
                Some([1u8].as_slice()),
                "entity batch commit failure must set the entity-scoped rm:w marker"
            );
        }
        drop(rtxn);
        assert_eq!(
            pending_remat_windows(&vault).unwrap(),
            vec![WINDOW.to_string()]
        );

        // Persist (Observer A kept the ops durably) and drain: forward
        // remat performs the healing writes, which discharge the markers.
        window.persist_state(&vault).unwrap();
        drop(window);
        let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
        assert_eq!(report.drained, vec![WINDOW.to_string()]);
        assert!(report.still_pending.is_empty());
        assert_eq!(
            vault.get(&a).unwrap().as_deref(),
            Some(b"one-1147-a".as_slice()),
            "drain must heal the lost entity write"
        );
        assert_eq!(
            vault.get(&b).unwrap().as_deref(),
            Some(b"one-1147-b".as_slice()),
            "drain must heal the lost entity write"
        );
        let rtxn = vault.store.env.read_txn().unwrap();
        for id in [&a, &b] {
            let marker_key = format!("rm:w:2026-03:{}", id.to_hex());
            assert_eq!(
                vault.store.sync_state.get(&rtxn, &marker_key).unwrap(),
                None,
                "the healing write must clear the marker"
            );
        }
        drop(rtxn);
        assert!(pending_remat_windows(&vault).unwrap().is_empty());
    }

    /// ONE-1147 — Observer-B EDGE batch whole-txn failure parity: the
    /// marker is scoped to the edge's SOURCE entity (LITERAL
    /// `rm:w:{window}:{src_hex}` → `[1u8]`, and NO marker for the target),
    /// and the drain's healing edge write re-materializes the lost edge
    /// bytes verbatim and discharges the source marker — the byte-identical
    /// endpoint entities must NOT discharge it (parity never clears).
    #[test]
    fn rm_marker_round_trip_edge_batch_commit_failure_then_drain() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Arc::new(Materializer::new());
        let window_key = WindowKey::new(WINDOW);
        let window = LoadedWindow::new("test-user", window_key, &vault, &materializer);

        // Endpoints first, in their own SUCCESSFUL commit: Observer B
        // materializes them into LMDB so only the EDGE batch sees the
        // injected failure.
        let src = EntityId::now();
        let tgt = EntityId::now();
        let entities = window.doc.get_map("entities");
        map_insert_bytes(
            &entities,
            &src.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, b"src"),
        )
        .unwrap();
        map_insert_bytes(
            &entities,
            &tgt.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, b"tgt"),
        )
        .unwrap();
        window.doc.commit();
        assert!(
            vault.get(&src).unwrap().is_some() && vault.get(&tgt).unwrap().is_some(),
            "precondition: endpoints materialized"
        );

        let kind = crate::types::EdgeKind::Mentions;
        let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
        let edge_val = crate::sync::bridge::encode_edge_value_for_crdt(
            kind,
            0.75,
            12_345,
            Some(crate::types::Vad::NEUTRAL),
            None,
        )
        .unwrap();
        crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
        map_insert_bytes(&window.doc.get_map("edges"), &edge_key, &edge_val).unwrap();
        window.doc.commit();

        // Divergence precondition: the edge op lives in the CRDT doc,
        // absent from LMDB.
        let lmdb_edge_key = crate::store::Store::encode_edge_key(&src, kind, &tgt);
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.edges_out.get(&rtxn, &lmdb_edge_key).unwrap(),
            None,
            "precondition: failed batch left the edge unmaterialized"
        );
        // Pinned literal grammar, SOURCE-scoped.
        let src_marker = format!("rm:w:2026-03:{}", src.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &src_marker).unwrap(),
            Some([1u8].as_slice()),
            "edge batch commit failure must set the SOURCE-scoped rm:w marker"
        );
        let tgt_marker = format!("rm:w:2026-03:{}", tgt.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &tgt_marker).unwrap(),
            None,
            "edge markers are source-scoped — no marker for the target"
        );
        drop(rtxn);

        window.persist_state(&vault).unwrap();
        drop(window);

        // Drain: the endpoint entities are byte-identical (parity must not
        // discharge anything); the EDGE healing write does, and it restores
        // the lost edge bytes verbatim.
        let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
        assert_eq!(report.drained, vec![WINDOW.to_string()]);
        assert!(report.still_pending.is_empty());
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.edges_out.get(&rtxn, &lmdb_edge_key).unwrap(),
            Some(edge_val.as_slice()),
            "drain must re-materialize the lost edge bytes verbatim"
        );
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &src_marker).unwrap(),
            None,
            "the healing edge write must clear the source marker"
        );
        drop(rtxn);
        assert!(pending_remat_windows(&vault).unwrap().is_empty());
    }

    /// Inserts `src` + `tgt` entity blobs into a bare window doc and commits
    /// them BEFORE Observer B attaches, so they live in the CRDT entities map
    /// but never reached LMDB (forward remat is deliberately skipped — the
    /// `from_doc` doc-comment notes LMDB may lag a freshly-attached doc). This
    /// is the exact CRDT-present / LMDB-absent divergence the edge-batch
    /// endpoint-hydration path exists to repair: the FIRST edge referencing
    /// these endpoints is what hydrates-and-writes them. Mirrors the proven
    /// pre-registration pattern in `bridge.rs`'s fail-closed split test.
    fn window_with_unmaterialized_endpoints(
        vault: &Arc<Vault>,
        materializer: &Arc<Materializer>,
        endpoints: &[(EntityId, &[u8])],
    ) -> LoadedWindow {
        let window_key = WindowKey::new(WINDOW);
        let doc = create_window_doc("test-user", &window_key);
        let entities = doc.get_map("entities");
        for (id, data) in endpoints {
            map_insert_bytes(
                &entities,
                &id.to_hex(),
                &entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, data),
            )
            .unwrap();
        }
        doc.commit();
        // Attach observers only NOW — the endpoints above are already
        // committed, so the entity observer never sees them; only future
        // (edge) commits fire.
        let window = LoadedWindow::from_doc(doc, window_key, vault, materializer);
        for (id, _) in endpoints {
            assert!(
                vault.get(id).unwrap().is_none(),
                "precondition: endpoint is CRDT-only, absent from LMDB"
            );
        }
        window
    }

    fn one_1147_edge_value() -> Vec<u8> {
        crate::sync::bridge::encode_edge_value_for_crdt(
            crate::types::EdgeKind::Mentions,
            0.75,
            12_345,
            Some(crate::types::Vad::NEUTRAL),
            None,
        )
        .unwrap()
    }

    /// ONE-1147 fix-wave (BLOCKER) — an Observer-B edge batch whose endpoints
    /// it HYDRATES-AND-WRITES inside the txn, then rolls back as a whole,
    /// must flag a durable entity-scoped `rm:` marker for the rolled-back
    /// hydration write under the LITERAL key `rm:w:{window}:{hex}` → `[1u8]`.
    /// Pre-fix the swallow site iterated only `applied_edges` (edge SOURCES),
    /// so a hydrated endpoint's lost write was silently unmarked.
    #[test]
    fn edge_batch_in_txn_endpoint_hydration_rollback_marks_endpoint() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Arc::new(Materializer::new());

        let src = EntityId::now();
        let tgt = EntityId::now();
        let window = window_with_unmaterialized_endpoints(
            &vault,
            &materializer,
            &[(src, b"src"), (tgt, b"tgt")],
        );

        // The edge commit hydrates BOTH endpoints inside the batch txn, then
        // the injected failure rolls the whole txn back.
        let kind = crate::types::EdgeKind::Mentions;
        let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
        crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
        map_insert_bytes(
            &window.doc.get_map("edges"),
            &edge_key,
            &one_1147_edge_value(),
        )
        .unwrap();
        window.doc.commit();

        // (a) Precondition: the rolled-back hydration left BOTH endpoints
        // absent from LMDB.
        assert!(
            vault.get(&src).unwrap().is_none(),
            "rolled-back endpoint hydration: src absent from LMDB"
        );
        assert!(
            vault.get(&tgt).unwrap().is_none(),
            "rolled-back endpoint hydration: tgt absent from LMDB"
        );

        // (b) Both hydrated-and-rolled-back endpoints carry the LITERAL
        // marker. The SOURCE is also an `applied_edges` source, but the
        // shared `seen` set marks it exactly once.
        let rtxn = vault.store.env.read_txn().unwrap();
        for id in [&src, &tgt] {
            let marker = format!("rm:w:2026-03:{}", id.to_hex());
            assert_eq!(
                vault.store.sync_state.get(&rtxn, &marker).unwrap(),
                Some([1u8].as_slice()),
                "a hydrated-and-rolled-back edge endpoint must carry the rm:w marker"
            );
        }
        drop(rtxn);
        assert_eq!(
            pending_remat_windows(&vault).unwrap(),
            vec![WINDOW.to_string()]
        );
    }

    /// ONE-1147 fix-wave (DISCRIMINATING) — the SOURCE endpoint's hydration
    /// fails LOCALLY (injected) FIRST (bridge.rs:591), aborting the batch at
    /// the local-abort arm BEFORE `applied_edges.push`; the TARGET endpoint
    /// (hydrated second, bridge.rs:598) was already hydrated-and-WRITTEN, and
    /// that write is rolled back. The target must still be flagged for remat
    /// even though NO edge was ever tracked. A subset-only (applied_edges-
    /// only) implementation marks NOTHING here and FAILS this test.
    ///
    /// NB hydration order is src(:591) → tgt(:598); arming the LOCAL failure
    /// on `src` (so the partner `tgt` is the written-then-rolled-back
    /// endpoint) realizes the brief's role intent — target hydrated-and-
    /// marked, src carries the injected error — under the verified order.
    #[test]
    fn edge_batch_hydrated_target_only_rollback_marks_target() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Arc::new(Materializer::new());

        let src = EntityId::now();
        let tgt = EntityId::now();
        // Only TGT is in the CRDT-but-not-LMDB state; SRC's hydration is
        // injected to fail LOCALLY before it reads or writes anything.
        let window = window_with_unmaterialized_endpoints(&vault, &materializer, &[(tgt, b"tgt")]);

        let kind = crate::types::EdgeKind::Mentions;
        let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
        // Arm SRC (first-hydrated): its LOCAL failure aborts the batch at the
        // `(Err(e), _) if remote_rejection_reason(&e).is_none()` arm — AFTER
        // TGT (second-hydrated) was hydrated-and-written, BEFORE any
        // `applied_edges.push`.
        crate::sync::bridge::INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| cell.set(Some(src)));
        map_insert_bytes(
            &window.doc.get_map("edges"),
            &edge_key,
            &one_1147_edge_value(),
        )
        .unwrap();
        window.doc.commit();

        assert!(
            crate::sync::bridge::INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| cell.get().is_none()),
            "precondition: the local src failure was actually hit"
        );
        assert!(
            vault.get(&tgt).unwrap().is_none(),
            "rolled-back tgt hydration: absent from LMDB"
        );

        let rtxn = vault.store.env.read_txn().unwrap();
        // The TARGET — hydrated-and-written, then rolled back — is marked
        // even though no edge was tracked (applied_edges was empty).
        let tgt_marker = format!("rm:w:2026-03:{}", tgt.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &tgt_marker).unwrap(),
            Some([1u8].as_slice()),
            "hydrated-and-rolled-back TARGET must carry the rm:w marker with NO edge tracked"
        );
        // SRC never hydrated (errored first) and never reached applied_edges.
        let src_marker = format!("rm:w:2026-03:{}", src.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &src_marker).unwrap(),
            None,
            "src never hydrated nor tracked — no marker"
        );
        drop(rtxn);
    }

    /// ONE-1147 fix-wave (anti-over-mark) — an endpoint already PRESENT in
    /// LMDB takes the no-write `Ready` path (nothing lost) and must NOT be
    /// flagged by the hydration loop. Here SRC is hydrated-and-rolled-back
    /// (marked) while TGT is already present (must stay unmarked): a buggy
    /// impl that recorded `Ready` endpoints into `hydrated_endpoints` would
    /// over-mark TGT and FAIL.
    #[test]
    fn edge_batch_already_present_endpoint_not_overmarked() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Arc::new(Materializer::new());

        let src = EntityId::now();
        let tgt = EntityId::now();
        // SRC is CRDT-only (will be hydrated by the edge batch).
        let window = window_with_unmaterialized_endpoints(&vault, &materializer, &[(src, b"src")]);
        // TGT materializes SUCCESSFULLY through the now-attached observer →
        // already-present (no-write `Ready`) when the edge batch runs.
        map_insert_bytes(
            &window.doc.get_map("entities"),
            &tgt.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, b"tgt"),
        )
        .unwrap();
        window.doc.commit();
        assert!(
            vault.get(&tgt).unwrap().is_some(),
            "precondition: tgt already present in LMDB"
        );
        assert!(
            vault.get(&src).unwrap().is_none(),
            "precondition: src CRDT-only"
        );

        let kind = crate::types::EdgeKind::Mentions;
        let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
        crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
        map_insert_bytes(
            &window.doc.get_map("edges"),
            &edge_key,
            &one_1147_edge_value(),
        )
        .unwrap();
        window.doc.commit();

        let rtxn = vault.store.env.read_txn().unwrap();
        // SRC: hydrated-and-rolled-back → marked.
        let src_marker = format!("rm:w:2026-03:{}", src.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &src_marker).unwrap(),
            Some([1u8].as_slice()),
            "hydrated-and-rolled-back src is marked"
        );
        // TGT: already present, no in-batch write, nothing lost → the
        // hydration loop must NOT mark it (and it is not an edge source).
        let tgt_marker = format!("rm:w:2026-03:{}", tgt.to_hex());
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &tgt_marker).unwrap(),
            None,
            "an already-present endpoint (no write, nothing lost) must NOT be marked by the hydration loop"
        );
        drop(rtxn);
    }

    /// ONE-1147 fix-wave (heal round-trip) — after an endpoint-hydration
    /// rollback flags the markers, `drain_remat_markers` re-runs forward
    /// remat: the ENTITY pass performs the actual healing write for each
    /// endpoint (its body is in the CRDT entities map) and discharges that
    /// endpoint's marker on the write only (never on parity). Pins that the
    /// hydrated-endpoint markers route to a real heal.
    #[test]
    fn edge_batch_hydration_rollback_drain_heals() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Arc::new(Materializer::new());

        let src = EntityId::now();
        let tgt = EntityId::now();
        let window = window_with_unmaterialized_endpoints(
            &vault,
            &materializer,
            &[(src, b"src"), (tgt, b"tgt")],
        );

        let kind = crate::types::EdgeKind::Mentions;
        let edge_key = crate::sync::bridge::format_edge_key(&src, kind, &tgt);
        crate::sync::bridge::INJECT_BATCH_COMMIT_FAILURES.with(|cell| cell.set(1));
        map_insert_bytes(
            &window.doc.get_map("edges"),
            &edge_key,
            &one_1147_edge_value(),
        )
        .unwrap();
        window.doc.commit();

        // Precondition: both endpoints flagged, absent from LMDB.
        assert!(vault.get(&src).unwrap().is_none() && vault.get(&tgt).unwrap().is_none());
        assert_eq!(
            pending_remat_windows(&vault).unwrap(),
            vec![WINDOW.to_string()]
        );

        // Persist (the CRDT doc carries the endpoint bodies) and drain.
        window.persist_state(&vault).unwrap();
        drop(window);
        let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
        assert_eq!(report.drained, vec![WINDOW.to_string()]);
        assert!(report.still_pending.is_empty());

        // The entity pass re-materialized BOTH endpoints (the actual healing
        // writes) and discharged their markers.
        assert!(
            vault.get(&src).unwrap().is_some(),
            "drain heals the lost src hydration"
        );
        assert!(
            vault.get(&tgt).unwrap().is_some(),
            "drain heals the lost tgt hydration"
        );
        let rtxn = vault.store.env.read_txn().unwrap();
        for id in [&src, &tgt] {
            let marker = format!("rm:w:2026-03:{}", id.to_hex());
            assert_eq!(
                vault.store.sync_state.get(&rtxn, &marker).unwrap(),
                None,
                "the healing entity write discharges the endpoint marker"
            );
        }
        drop(rtxn);
        assert!(pending_remat_windows(&vault).unwrap().is_empty());
    }

    /// Forward remat quarantines gate-rejected CRDT rows instead of
    /// silently skipping them (window.rs silent-site inventory).
    #[test]
    fn forward_remat_quarantines_rejected_rows() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Materializer::new();
        let window_key = WindowKey::new(WINDOW);
        let doc = create_window_doc("test-user", &window_key);

        let good = EntityId::now();
        let entities = doc.get_map("entities");
        map_insert_bytes(
            &entities,
            &good.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, b"good"),
        )
        .unwrap();
        // Undecodable blob + unknown type byte + bad edge key.
        map_insert_bytes(&entities, &EntityId::now().to_hex(), b"short").unwrap();
        map_insert_bytes(
            &entities,
            &EntityId::now().to_hex(),
            &entity_blob(200, valid_time_range(), LEARNED_AT, b"bad"),
        )
        .unwrap();
        map_insert_bytes(
            &doc.get_map("edges"),
            "garbage-edge-key",
            &semantic_edge_value(0.5),
        )
        .unwrap();
        doc.commit();

        let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
        assert_eq!(count, 1, "only the good entity materializes");
        assert_eq!(
            vault.get(&good).unwrap().as_deref(),
            Some(b"good".as_slice())
        );

        let mut reasons: Vec<String> = quarantined_records(&vault)
            .unwrap()
            .into_iter()
            .map(|(_, rec)| rec.reason_code)
            .collect();
        reasons.sort();
        assert_eq!(
            reasons,
            vec![
                "CorruptedIndex".to_string(),
                "InvalidEntityType".to_string(),
                "InvalidKey".to_string()
            ]
        );
    }

    /// ONE-1124 fix wave 2 (item 3) — rm: retry markers are ENTITY-scoped:
    /// an unrelated entity's successful tombstone must NOT clear another
    /// entity's marker (pre-fix, any validated tombstone discharged the
    /// window-level marker, losing the GDPR purge retry); the entity's OWN
    /// success does clear it — here via a STRING-valued tombstone, pinning
    /// that the rm: bookkeeping runs through the tombstone-aware iterator
    /// (item 4: non-Binary = HARD input).
    #[test]
    fn unrelated_tombstone_success_does_not_clear_entity_scoped_rm_marker() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Materializer::new();
        let window_key = WindowKey::new(WINDOW);
        let x = EntityId::now();
        let y = EntityId::now();
        for (id, data) in [(&x, b"x".as_slice()), (&y, b"y".as_slice())] {
            vault
                .put_entity(id, ENTITY_TYPE_TASK, valid_time_range(), LEARNED_AT, data)
                .unwrap();
        }

        // Pass 1: X's tombstone, purge fails → rm:w:{window}:{x_hex} set.
        let doc_x = create_window_doc("test-user", &window_key);
        map_insert_bytes(&doc_x.get_map("tombstones"), &x.to_hex(), b"1").unwrap();
        doc_x.commit();
        INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
        forward_rematerialize(&vault, &doc_x, &materializer, &window_key).unwrap();

        let x_marker = format!("rm:w:{WINDOW}:{}", x.to_hex());
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &x_marker).unwrap(),
            Some([1u8].as_slice()),
            "X's purge failure must set X's entity-scoped marker"
        );
        drop(rtxn);

        // Pass 2: a doc carrying ONLY Y's (valid, succeeding) tombstone —
        // Y purges, but X's marker MUST survive.
        let doc_y = create_window_doc("test-user", &window_key);
        map_insert_bytes(&doc_y.get_map("tombstones"), &y.to_hex(), b"1").unwrap();
        doc_y.commit();
        forward_rematerialize(&vault, &doc_y, &materializer, &window_key).unwrap();
        assert!(vault.get(&y).unwrap().is_none(), "Y's tombstone purges Y");
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &x_marker).unwrap(),
            Some([1u8].as_slice()),
            "unrelated Y success must NOT clear X's marker"
        );
        drop(rtxn);
        assert_eq!(
            pending_remat_windows(&vault).unwrap(),
            vec![WINDOW.to_string()]
        );

        // Pass 3: X's own tombstone — as a STRING value (non-Binary = HARD
        // input through the tombstone-aware iterator). X purges and X's
        // marker clears.
        let doc_x2 = create_window_doc("test-user", &window_key);
        doc_x2
            .get_map("tombstones")
            .insert(&x.to_hex(), "string-valued-tombstone")
            .unwrap();
        doc_x2.commit();
        forward_rematerialize(&vault, &doc_x2, &materializer, &window_key).unwrap();
        assert!(
            vault.get(&x).unwrap().is_none(),
            "string-valued tombstone is HARD delete input"
        );
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &x_marker).unwrap(),
            None,
            "X's own success clears X's marker"
        );
        drop(rtxn);
        assert!(pending_remat_windows(&vault).unwrap().is_empty());
    }

    /// ONE-1124 fix wave 2 (item 3, fail-closed leg) — rm: rows that do not
    /// parse as `rm:w:{window}:{entity_hex}` are needs-remat, never
    /// dropped: the drain still re-runs the window's purge pass (the real
    /// retry drains: entity purged, its marker cleared), the malformed rows
    /// survive untouched, and the window stays ERROR-visible in the doctor
    /// report.
    #[test]
    fn malformed_rm_marker_rows_are_never_dropped_and_window_still_drains() {
        let (_dir, vault) = test_vault_with_dir();
        let materializer = Arc::new(Materializer::new());
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TASK,
                valid_time_range(),
                LEARNED_AT,
                b"purge-me",
            )
            .unwrap();

        let window_key = WindowKey::new(WINDOW);
        let window = LoadedWindow::new("test-user", window_key.clone(), &vault, &materializer);
        assert_eq!(
            reverse_rematerialize(&vault, &window.doc, &window_key).unwrap(),
            1
        );

        // Real retry: tombstone arrives, purge fails → entity marker set.
        INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
        map_insert_bytes(&window.doc.get_map("tombstones"), &id.to_hex(), b"1").unwrap();
        window.doc.commit();
        let real_marker = format!("rm:w:{WINDOW}:{}", id.to_hex());

        // Plant rows that do not parse: an entity-less row and one with a
        // garbage entity segment.
        vault
            .with_write_txn(|wtxn| {
                vault.store.sync_state.put(wtxn, "rm:w:2026-03", &[1u8])?;
                vault
                    .store
                    .sync_state
                    .put(wtxn, "rm:w:2026-03:zzz-not-hex", &[1u8])?;
                Ok(())
            })
            .unwrap();

        window.persist_state(&vault).unwrap();
        drop(window);

        let report = drain_remat_markers(&vault, "test-user", &materializer).unwrap();
        // The real retry drained despite the malformed siblings…
        assert!(
            vault.get(&id).unwrap().is_none(),
            "the flagged entity's purge must still drain"
        );
        let rtxn = vault.store.env.read_txn().unwrap();
        assert_eq!(
            vault.store.sync_state.get(&rtxn, &real_marker).unwrap(),
            None,
            "the drained entity's marker clears"
        );
        // …but the unparsable rows are never dropped (fail closed).
        assert_eq!(
            vault.store.sync_state.get(&rtxn, "rm:w:2026-03").unwrap(),
            Some([1u8].as_slice())
        );
        assert_eq!(
            vault
                .store
                .sync_state
                .get(&rtxn, "rm:w:2026-03:zzz-not-hex")
                .unwrap(),
            Some([1u8].as_slice())
        );
        drop(rtxn);
        assert_eq!(report.still_pending, vec![WINDOW.to_string()]);
        assert!(report.drained.is_empty());
        assert_eq!(
            sync_doctor(&vault).unwrap().rm_pending_windows,
            vec![WINDOW.to_string()],
            "doctor keeps the window ERROR-visible"
        );
    }

    /// ONE-1124 fix wave 2 (item 23) — the CRDT map key is
    /// attacker-controlled content: the x: row stores xxh3_64(key) + byte
    /// length ONLY. A crafted key string must be absent from the serialized
    /// record — no verbatim retention, no prefix.
    #[test]
    fn quarantine_record_never_retains_the_crdt_key_string() {
        let (_dir, vault) = test_vault_with_dir();
        let attacker_key = format!("SMUGGLED-CONTENT-Alice-deleted-this-{}", "x".repeat(256));
        let seq = quarantine_rejected_op(
            &vault,
            WINDOW,
            QuarantineContainer::Tombstones,
            &attacker_key,
            &Error::InvalidKey,
            &[],
        )
        .unwrap();
        assert_eq!(seq, 1);

        let records = quarantined_records(&vault).unwrap();
        assert_eq!(records.len(), 1);
        let (_, rec) = &records[0];
        assert_eq!(rec.crdt_key_hash, xxh3_64(attacker_key.as_bytes()));
        assert_eq!(rec.crdt_key_len, u32::try_from(attacker_key.len()).unwrap());

        let rtxn = vault.store.env.read_txn().unwrap();
        let raw = vault
            .store
            .sync_queue
            .get(&rtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x01")
            .unwrap()
            .expect("x: row present");
        let needle = b"SMUGGLED-CONTENT";
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "no fragment of the crdt key may reach the persisted x: row"
        );
    }
}
