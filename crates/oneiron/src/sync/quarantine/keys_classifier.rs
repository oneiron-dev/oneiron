//! Quarantine key codec plus remote/local rejection classifier.

use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::error::{Error, ErrorKind, Result};

/// Prefix for quarantine rows in `sync_queue` (db #25).
///
/// Distinct from `q:` (sync replay), `e:` (embed jobs), `h:` (ARCH-0038
/// hard-erase sweeps) and `m:` (metadata counters) — precedent: the `h:`
/// reservation in contracts.ts `hardEraseSweepQueue.distinctFrom`.
pub(super) const QUARANTINE_PREFIX: &[u8] = b"x:";

/// Metadata key storing the last allocated quarantine sequence number
/// (u64 LE, the existing `m:` counter pattern).
pub(in crate::sync) const LAST_QUARANTINE_SEQ_KEY: &[u8] = b"m:last_quarantine_seq";

/// Metadata key storing the cumulative quarantine eviction counter (u64 LE).
/// An eviction is itself doctor-visible through this counter.
pub(in crate::sync) const QUARANTINE_EVICTIONS_KEY: &[u8] = b"m:quarantine_evictions";

/// Metadata key storing the cumulative count of rejected rows accounted by
/// COUNT ONLY — rows past [`MAX_QUARANTINE_ROWS_PER_PASS`] in a single
/// terminal batch, which get no `x:` row of their own (u64 LE).
pub(super) const QUARANTINE_BATCH_DROPS_KEY: &[u8] = b"m:quarantine_batch_drops";

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
pub(super) const RECENT_REASON_CODES: usize = 8;

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
pub(in crate::sync) fn reason_code_for(error: &Error) -> String {
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
        // failing the pinned body grammar, canonical encoding, content-address
        // or occurrence binding, or diverging from an existing local blob,
        // is a rejection of that remote op, not a local
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
pub(in crate::sync) fn encode_quarantine_key(seq: u64) -> [u8; 10] {
    let mut key = [0u8; 10];
    key[0..2].copy_from_slice(QUARANTINE_PREFIX);
    key[2..10].copy_from_slice(&seq.to_be_bytes());
    key
}

/// Decodes the sequence number from a quarantine key.
pub(super) fn decode_quarantine_seq(key: &[u8]) -> Option<u64> {
    let seq = key.strip_prefix(QUARANTINE_PREFIX)?;
    Some(u64::from_be_bytes(seq.try_into().ok()?))
}

pub(super) fn encode_record(record: &QuarantineRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("sync quarantine record encode"))
}

pub(super) fn decode_record(value: &[u8]) -> Result<QuarantineRecord> {
    rmp_serde::from_slice(value).map_err(|_| Error::CorruptedIndex(ERR_QUARANTINE_ROW))
}

pub(super) fn decode_u64_le_counter(raw: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = raw.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}
