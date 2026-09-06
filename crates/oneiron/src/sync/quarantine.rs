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
//! `remote_rejection_reason` is the classifier the replay sites use.
//!
//! The `rm:w:{window}:{entity_hex}` marker (ARCH-0023b sync_state
//! needs-rematerialization flag, ENTITY-scoped) is produced when a
//! CRDT-tombstone purge of that specific entity against the local active
//! store fails — a purge failure left hard-deleted content live, which is a
//! GDPR SLA breach signal until drained — when an Observer-B entity/edge
//! materialization batch carrying that entity's op fails as a whole txn
//! (lost create/update writes = silent LMDB↔CRDT divergence), and when an
//! entity/edge replay op is quarantined with no healing write (ONE-1167).
//! A row rejected TERMINALLY — refused by a door that never lets it into any
//! document, so no replay can ever heal it — takes no marker at all; see
//! `TerminalRejectionBatch`.
//! Replay/quarantine-origin markers also carry a sidecar provenance row so
//! terminal `x:` quarantine can discharge only non-delete retry work. An
//! unproven `rm:` row is delete-safety/unknown and must survive terminal
//! entity/edge quarantine. The marker is cleared ONLY by that entity's own
//! success — its purge for tombstoned ids, the actual healing write (entity
//! body / edge from that source) in forward remat, or terminal quarantine
//! when replay provenance already proves the marker is non-delete; never
//! byte-parity alone, and never an unrelated entity's success.
//! [`drain_remat_markers`] re-runs `forward_rematerialize` for each flagged
//! window. A row under `rm:` that does not parse is fail-closed: it is
//! treated as needs-remat and never dropped.

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
/// Metadata key storing the cumulative count of rejected rows accounted by
/// COUNT ONLY — rows past [`MAX_QUARANTINE_ROWS_PER_PASS`] in a single
/// terminal batch, which get no `x:` row of their own (u64 LE).
pub(crate) const QUARANTINE_BATCH_DROPS_KEY: &[u8] = b"m:quarantine_batch_drops";

/// Retention cap: maximum number of persisted quarantine rows.
pub const MAX_QUARANTINE_ROWS: usize = 4096;
/// Per-pass evidence bound for `TerminalRejectionBatch`: the maximum number
/// of `x:` rows ONE rejection pass may mint.
///
/// A peer controls how many rejectable rows one frame carries, so an unbounded
/// batch would let a single admission both cost O(N) row writes AND flush the
/// SHARED 4096-row ring, destroying unrelated evidence. Rows past this bound
/// are accounted by COUNT (`m:quarantine_batch_drops`, doctor-visible as
/// [`SyncQuarantineReport::batch_drop_count`]) instead of by row — the reason
/// code is uniform within a pass, so the (N - cap)th typed row carries no
/// information the first cap rows do not already carry.
pub const MAX_QUARANTINE_ROWS_PER_PASS: usize = 64;
/// Retention age bound: quarantine rows older than 30 days are evicted.
pub const QUARANTINE_MAX_AGE_SECS: u64 = 30 * 86_400;
/// Number of most-recent reason codes surfaced by [`sync_doctor`].
const RECENT_REASON_CODES: usize = 8;

/// Prefix for needs-rematerialization markers in `sync_state`. Full key
/// grammar (ONE-1124 fix wave 2, entity-scoped):
/// `rm:w:{window}:{entity_hex}` → `1 byte (marker)`, where `window` is
/// `YYYY-MM` and `entity_hex` is the 32-char lowercase entity id.
const REMAT_MARKER_PREFIX: &str = "rm:w:";
/// Sidecar provenance for `rm:w:` markers created by replay/quarantine
/// surfaces, not by delete-safety purge failures. Absence means unknown and
/// therefore fail-closed as delete-safety for terminal quarantine clearing.
const REPLAY_REMAT_MARKER_PROVENANCE_PREFIX: &str = "rmp:w:";

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
    if is_remote_secret_scan_rejection(error) {
        return Some(reason_code_for(error));
    }

    match error.kind() {
        ErrorKind::InvalidEntityType
        | ErrorKind::MaintenanceKindNotWritable
        | ErrorKind::ReservedPredicate
        | ErrorKind::EntityTypeImmutable
        | ErrorKind::InvalidTimeRange
        | ErrorKind::InvalidClaimBody
        | ErrorKind::InvalidPsychProfileBody
        | ErrorKind::InvalidSkillBody
        | ErrorKind::InvalidAgentDefBody
        | ErrorKind::InvalidTaskBody
        | ErrorKind::InvalidPredicate
        | ErrorKind::InvalidEdgeWeight
        | ErrorKind::InvalidVad
        | ErrorKind::InvalidProvenanceBody
        // FED-001/EIRI-004: a remote grant body failing its
        // pinned structural/policy validation is a rejection of that remote
        // op, not a local storage/index failure. Keep generic InvalidKey
        // unclassified; only the grant-specific typed error quarantines.
        | ErrorKind::InvalidFederationGrantBody
        | ErrorKind::InvalidAuthorityLogBody
        | ErrorKind::InvalidAccessGrantBody
        | ErrorKind::InvalidChannelIdentityBody
        | ErrorKind::InvalidCounterpartyContactBody
        | ErrorKind::InvalidCommRecordBody
        | ErrorKind::ProvenanceOnStructuralEdge
        | ErrorKind::CycleDetected
        // A remote ChildOf op violating the single-parent pin is a pure
        // up-front validation rejection (validate_child_of_batch runs before
        // any byte is staged) — quarantine-and-continue, same class as
        // CycleDetected.
        //
        // ONE-1871 (F5) narrowed WHAT reaches this arm, and deliberately did
        // not remove it. A VALID concurrent reparent of one child's single
        // parent slot is no longer a cardinality violation: it is resolved by
        // deterministic LWW in `batch::resolve_replicated_child_of_slots`
        // (ARCH-0016 I6) before validation runs, and the lower-precedence
        // candidate is omitted rather than rejected — a valid loser produces NO
        // `x:` row. This arm remains the rejection path for a genuinely invalid
        // strict op that still leaves a child with two parents, and must stay
        // classified remote so one such op cannot wedge the window.
        | ErrorKind::ChildOfCardinality
        // A remote companion register row duplicating a local active
        // `(scope, subject)` key is a rejection of that remote row, not a
        // local storage failure. Quarantine it so remat can continue.
        | ErrorKind::CompanionRecordAlreadyExists
        | ErrorKind::ChannelIdentityAlreadyExists
        | ErrorKind::CounterpartyContactAlreadyExists
        // ONE-1134: a remote REDACTION_AUDIT blob failing the pinned
        // redactionAuditReceipt structural validation, or carrying divergent
        // bytes for an EXISTING receipt id (immutable audit record — keep
        // local, never silent LWW), is a remote rejection: quarantine the op
        // and continue the batch.
        | ErrorKind::InvalidRedactionReceiptBody
        | ErrorKind::RedactionReceiptDivergence
        // ARCH-0055 (MS-01 trust perimeter): a remote type-76 blob failing
        // the pinned identity-topology body validation, or carrying
        // divergent bytes for an EXISTING event id (immutable single-writer
        // record — local bytes win, never silent LWW), is a remote
        // rejection: quarantine the row and continue the batch instead of
        // aborting it (one bad row must not wedge unrelated valid changes).
        // Stored-row decode failures surface as `CorruptedIndex` and stay
        // LOCAL/fail-closed, so this arm can never swallow on-disk
        // corruption.
        | ErrorKind::InvalidIdentityTopologyEventBody
        | ErrorKind::IdentityTopologyEventDivergence
        // ONE-1604-D1: a remote AUTHORITY_LOG row that is body-divergent at an
        // existing store key, or whose key does not match its content hash,
        // is a rejection of that remote op on the append-only authority
        // substrate — quarantine the payload, keep local bytes, continue.
        | ErrorKind::AuthorityLogAppendOnlyViolation
        | ErrorKind::AuthorityLogStoreKeyMismatch
        // ONE-1140: a NEW REDACTION_AUDIT receipt failing the origin predicate —
        // bad/transplanted attestation signature, unleased att_client, or a
        // revoked lease binding — is a remote rejection of the op itself:
        // quarantine (x: row) and continue. The rejected bytes stay in the
        // CRDT map, so the next forward rematerialization re-admits them
        // once the lease mirror catches up (OD-10 lazy re-admission).
        | ErrorKind::ReceiptAttestationInvalid
        | ErrorKind::ReceiptLeaseUnknown
        | ErrorKind::ReceiptLeaseRevoked
        // ARCH-0052 D2: a replicated op naming a live session-overlay member
        // is a rejection of that remote op. It must take the same Observer-B /
        // forward-remat quarantine-and-continue path as the other typed remote
        // write-door rejections.
        | ErrorKind::OffRecordTaintedBaseWrite
        // ONE-1326: a known-key maintenance-band flood that passes origin
        // validation but exceeds this device's local ingest budget is a
        // remote-op rejection. Quarantine keeps evidence and lets a later
        // rematerialization pass re-run the door when quota is under budget.
        | ErrorKind::MaintenanceIngestQuotaExceeded
        // ONE-1645: a replayed `FacetOf` edge whose endpoints fall outside
        // the write-time type table (`CLAIM | TURN | EVENT -> FACET`) is a
        // rejection of that remote op. The local batch door aborts on it,
        // but the replay arm (`BatchOp::EdgeWithCreatedAt`) is ungated by
        // H2 design, so forward remat runs the table itself and needs the
        // typed reason here — off-table stamp quarantined, window continues.
        // Endpoint types are read AFTER the endpoint-existence check, so a
        // not-yet-arrived endpoint defers instead of reaching this arm.
        | ErrorKind::InvalidFacetOfEdge
        // ONE-1686 (RT-04): a replicated MESSAGE is refused for every author
        // bucket — the sync door carries no verified source actor or peer
        // signer to run the witness ceiling against, so nothing there can bind
        // remote authorship (see
        // `gate::validate_replicated_witness_message_body`). That is a
        // rejection of THAT remote row, not a local storage failure:
        // quarantine and continue, so one refused transcript row cannot wedge
        // the window and the local bytes (if any) stay untouched. Locally
        // stored MESSAGE rows never surface this kind on the replay path, so
        // this arm cannot swallow on-disk corruption.
        | ErrorKind::InvalidWitnessMessageBody
        // SECRET-01 (ONE-1919): a replicated SECRET_CUSTODY (byte 77) carrier
        // is refused by the replay write wall until ONE-1865 arms the dial.
        // That refusal is a rejection of the remote op, not a local storage
        // failure — one poisoned custody row must not wedge every other change
        // in the window. Locally stored custody rows never surface this kind
        // on the replay path (a corrupt on-disk row reads as `CorruptedIndex`
        // through `read_secret_custody_in_txn`), so this arm cannot swallow
        // local corruption.
        | ErrorKind::InvalidSecretCustodyBody
        // ONE-1394 (GATE-14 layer 1): a replicated DIAGNOSTIC (byte 69) row
        // failing the pinned body grammar — or arriving in a non-canonical
        // encoding of it — is a rejection of that remote op, not a local
        // storage failure. One malformed self-heal finding must not abort the
        // whole window and wedge every unrelated valid change beside it:
        // quarantine the row (`x:`) and continue. Locally stored diagnostics
        // never surface this kind on the replay path (a corrupt on-disk row
        // reads as `CorruptedIndex`), so this arm cannot swallow local
        // corruption.
        | ErrorKind::InvalidDiagnosticBody => Some(reason_code_for(error)),
        _ => None,
    }
}

fn is_remote_secret_scan_rejection(error: &Error) -> bool {
    let Error::GateWriteRejected {
        outcome,
        reason_codes,
    } = error
    else {
        return false;
    };

    *outcome == "deny"
        && reason_codes
            .iter()
            .any(|code| code.starts_with("gate.secret_scan."))
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

/// Entity whose window should be retried after this quarantine row is
/// written. Only replay surfaces with a stable entity scope participate:
/// `entities` rows name their entity directly, while `edges` rows retry by
/// source entity. Tombstone replay already has stricter purge-specific rm:
/// handling; lease rows are root-scoped and have no entity marker.
#[must_use]
pub(crate) fn remat_marker_entity_for_quarantine(
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
pub(crate) struct TerminalRejectionBatch {
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

fn allocate_next_quarantine_seq(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
    let metadata = vault
        .store
        .sync_queue
        .get(&*wtxn, LAST_QUARANTINE_SEQ_KEY)?
        .and_then(|raw| decode_u64_le_counter(&raw));
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
        if let Some(seq) = decode_quarantine_seq(&key) {
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
            if decode_quarantine_seq(&key).is_none() {
                evict.push(key.to_vec());
                continue;
            }
            match decode_record(&value) {
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
        .and_then(|raw| decode_u64_le_counter(&raw))
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
        let Some(seq) = decode_quarantine_seq(&key) else {
            continue;
        };
        match decode_record(&value) {
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
    /// Cumulative rows a `TerminalRejectionBatch` accounted by COUNT rather
    /// than by `x:` row, because the pass exceeded
    /// [`MAX_QUARANTINE_ROWS_PER_PASS`] (`m:quarantine_batch_drops`). Nonzero
    /// means a peer sent a frame with more rejectable rows than one pass mints
    /// evidence for — the rejections happened and are accounted here.
    pub batch_drop_count: u64,
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
        .and_then(|raw| decode_u64_le_counter(&raw))
        .unwrap_or(0);
    let batch_drop_count = vault
        .store
        .sync_queue
        .get(&rtxn, QUARANTINE_BATCH_DROPS_KEY)?
        .and_then(|raw| decode_u64_le_counter(&raw))
        .unwrap_or(0);
    drop(rtxn);

    let rm_pending_windows = pending_remat_windows(vault)?;
    let report = SyncQuarantineReport {
        quarantine_count,
        recent_reason_codes,
        eviction_count,
        batch_drop_count,
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
pub(crate) fn remat_marker_key(window_key: &str, id: &crate::entity_id::EntityId) -> String {
    format!("{REMAT_MARKER_PREFIX}{window_key}:{}", id.to_hex())
}

fn replay_remat_marker_provenance_key(window_key: &str, id: &crate::entity_id::EntityId) -> String {
    format!(
        "{REPLAY_REMAT_MARKER_PROVENANCE_PREFIX}{window_key}:{}",
        id.to_hex()
    )
}

/// Sets `rm:w:{window}:{entity_hex}` (1-byte marker) in `sync_state` inside
/// an existing write transaction. Written when THAT entity's CRDT-tombstone
/// purge (or the read backing it) against the local active store fails.
/// Deletes any replay provenance sidecar so a later terminal `x:` row cannot
/// discharge delete-safety work without the entity's own tombstone success.
pub(crate) fn set_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    let marker_key = remat_marker_key(window_key, id);
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    vault.store.sync_state.put(wtxn, &marker_key, &[1u8])?;
    vault.store.sync_state.delete(wtxn, &provenance_key)?;
    Ok(())
}

/// Sets `rm:w:{window}:{entity_hex}` in its own write transaction.
#[cfg_attr(not(test), allow(dead_code))] // batch path writes markers in-txn (ONE-521)
pub(crate) fn set_remat_marker(
    vault: &Vault,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    vault.with_write_txn(|wtxn| set_remat_marker_in_txn(vault, wtxn, window_key, id))
}

/// Sets a replay/quarantine-origin `rm:w:{window}:{entity_hex}` marker plus
/// provenance sidecar. If an unproven marker already exists, preserve that
/// stronger delete-safety/unknown provenance and do not add the sidecar.
pub(crate) fn set_replay_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    let marker_key = remat_marker_key(window_key, id);
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    let marker_present = vault.store.sync_state.get(wtxn, &marker_key)?.is_some();
    let replay_provenance_present = vault.store.sync_state.get(wtxn, &provenance_key)?.is_some();

    vault.store.sync_state.put(wtxn, &marker_key, &[1u8])?;
    if !marker_present || replay_provenance_present {
        vault.store.sync_state.put(wtxn, &provenance_key, &[1u8])?;
    }
    Ok(())
}

/// Sets a replay/quarantine-origin `rm:w:{window}:{entity_hex}` marker in
/// its own write transaction.
pub(crate) fn set_replay_remat_marker(
    vault: &Vault,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    vault.with_write_txn(|wtxn| set_replay_remat_marker_in_txn(vault, wtxn, window_key, id))
}

/// Clears `rm:w:{window}:{entity_hex}` inside an existing write
/// transaction. Only called when THAT entity's purge succeeded (or the
/// entity is verifiably absent — the purge goal state), or when forward
/// remat performed the actual healing write for that entity (ONE-1147).
pub(crate) fn clear_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    let marker_key = remat_marker_key(window_key, id);
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    vault.store.sync_state.delete(wtxn, &marker_key)?;
    vault.store.sync_state.delete(wtxn, &provenance_key)?;
    Ok(())
}

/// True when an `rm:` marker is present without replay/quarantine
/// provenance. Terminal quarantine must treat this as delete-safety/unknown
/// provenance and leave it pending until the entity's tombstone goal holds.
pub(crate) fn unproven_remat_marker_exists_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
    let marker_key = remat_marker_key(window_key, id);
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    Ok(vault.store.sync_state.get(wtxn, &marker_key)?.is_some()
        && vault.store.sync_state.get(wtxn, &provenance_key)?.is_none())
}

/// Clears a marker only when its sidecar proves replay/quarantine origin.
/// Unproven markers survive terminal quarantine because they may represent
/// delete-safety work from a failed tombstone purge.
pub(crate) fn clear_replay_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    if vault.store.sync_state.get(wtxn, &provenance_key)?.is_none() {
        return Ok(false);
    }
    let marker_key = remat_marker_key(window_key, id);
    vault.store.sync_state.delete(wtxn, &marker_key)?;
    vault.store.sync_state.delete(wtxn, &provenance_key)?;
    Ok(true)
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
pub(crate) fn reassert_marker_key(window_key: &str, id: &crate::entity_id::EntityId) -> String {
    format!("{REASSERT_MARKER_PREFIX}{window_key}:{}", id.to_hex())
}

/// Enqueues the tombstone re-assertion marker for `id` IF the permanent
/// `dt:{entity_hex}` local hard-delete marker exists: reads the `dt:` row
/// and writes `ra:w:{window}:{entity_hex}` with the row's EXACT bytes — the
/// value the drain re-asserts verbatim. Returns whether a marker was written
/// (`false` = no `dt:` row, nothing faithful to re-assert — OD-11 HARD-only).
/// Idempotent: same key, same dt:-derived value.
///
/// Caller supplies the write transaction (batch parent or a thin one-txn
/// delegate). Soft-over-hard staging folds into `apply_tombstone_batch`'s
/// single top-level write txn so materialize never opens a per-item
/// committing helper for staged work (ONE-521).
pub(crate) fn enqueue_tombstone_reassert_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
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
}

/// Enqueues the tombstone re-assertion marker in its own write transaction.
/// Thin one-txn delegate over [`enqueue_tombstone_reassert_marker_in_txn`]
/// (same pattern as [`set_remat_marker`] / [`set_remat_marker_in_txn`]).
/// Used by pre-batch door paths (e.g. tombstone REMOVAL deltas) that are
/// not part of staged batch materialization.
pub(crate) fn enqueue_tombstone_reassert_marker(
    vault: &Vault,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
    vault.with_write_txn(|wtxn| {
        enqueue_tombstone_reassert_marker_in_txn(vault, wtxn, window_key, id)
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
type ReassertMarker = (String, crate::entity_id::EntityId, Vec<u8>);

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
        match crate::entity_id::EntityId::from_hex(hex) {
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
    use crate::sync::loro_support::doc_version_vector;
    use crate::sync::window::{
        apply_tombstone_to_window_doc, export_scrubbed_window_snapshot,
        export_tombstone_commit_delta, load_window_from_state, merge_persisted_state_into_doc,
        persist_window_doc_in_txn, rebuild_window_from_updates,
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
                export_scrubbed_window_snapshot(vault, window_key, &window.doc)?,
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
                export_scrubbed_window_snapshot(vault, window_key, &doc)?,
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
    /// Purge attempts to let THROUGH before [`INJECT_PURGE_FAILURES`] starts
    /// counting down. A batch applies N tombstones under one transaction
    /// (ONE-521), so targeting a specific item — the middle one — needs a
    /// skip count, not just a failure count.
    pub(crate) static INJECT_PURGE_FAILURES_SKIP: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
}

/// Consumes one purge attempt against the test-only injection hooks,
/// returning the injected error when this attempt is the one to fail.
#[cfg(test)]
fn maybe_inject_purge_failure() -> Result<()> {
    let skipped = INJECT_PURGE_FAILURES_SKIP.with(|cell| {
        let remaining = cell.get();
        if remaining > 0 {
            cell.set(remaining - 1);
            true
        } else {
            false
        }
    });
    if skipped {
        return Ok(());
    }
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
    Ok(())
}

/// Applies a replayed tombstone on behalf of the sync tombstone paths —
/// the reason-aware primitive ([`Vault::apply_replayed_tombstone`],
/// ONE-1133) is the ONLY effect path, never a bare purge. In test builds a
/// thread-local injection hook can force failures to exercise the rm:
/// marker round-trip.
///
/// This is the ONE-TRANSACTION entry point, for callers that own no write
/// transaction of their own (forward rematerialization's tombstone pass).
/// The batched Observer B path uses
/// [`apply_replayed_tombstone_for_sync_in_txn`] instead.
pub(crate) fn apply_replayed_tombstone_for_sync(
    vault: &Vault,
    id: &crate::entity_id::EntityId,
    raw_value: &[u8],
) -> Result<crate::deletion::ReplayedTombstoneOutcome> {
    #[cfg(test)]
    maybe_inject_purge_failure()?;
    vault.apply_replayed_tombstone_for_sync(id, raw_value)
}

/// [`apply_replayed_tombstone_for_sync`] against a caller-owned transaction
/// (ONE-521): same reason-aware primitive, same test injection, no commit of
/// its own. The caller decides the durability boundary — Observer B's
/// tombstone batch runs each item in a nested savepoint under ONE top-level
/// transaction, so an item's failure rolls back only that item.
pub(crate) fn apply_replayed_tombstone_for_sync_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &crate::entity_id::EntityId,
    raw_value: &[u8],
) -> Result<crate::deletion::ReplayedTombstoneOutcome> {
    #[cfg(test)]
    maybe_inject_purge_failure()?;
    vault.apply_replayed_tombstone_in_txn(wtxn, id, raw_value)
}

#[cfg(test)]
mod tests;
