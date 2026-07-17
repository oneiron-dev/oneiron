//! ARCH-0038 deletion/redaction contract types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::Vault;
use crate::affect::VadAnnotationCleanup;
use crate::affect::delete_vad_annotation_metadata_for_type_in_txn;
use crate::affect::delete_vad_annotation_metadata_in_txn;
use crate::affect::vad_annotation_delete_scope_exists_in_txn;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::deindex_entity;
use crate::batch::deindex_lexical_query_hints_for_target;
use crate::batch::delete_from_phonetic_postings;
use crate::bm25;
use crate::claim::ClaimLifecycleStatus;
use crate::claim::ClaimSubject;
use crate::edge::EdgeActorClass;
use crate::edge::EdgeConfirmationStatus;
use crate::edge::EdgeKind;
use crate::edge::EdgeProvenanceFlags;
use crate::entity_id::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::ppr;
use crate::provenance::EdgeRef;
use crate::provenance::PREDICATE_EDGE_PROVENANCE;
use crate::provenance::ProvenancePrecedence;
use crate::provenance::StoredProvenanceClaim;
use crate::provenance::decode_edge_provenance_body;
use crate::provenance::downgrade_edge_to_bare;
use crate::provenance::restamp_edge_flags;
use crate::provenance::winner_index;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
use crate::store::{GateDecisionId, GateDecisionRecord, Store};
use crate::unix_seconds_now;

pub(crate) const HARD_ERASE_SWEEP_PREFIX: &[u8] = b"h:";
pub(crate) const LAST_HARD_ERASE_SWEEP_SEQ_KEY: &[u8] = b"m:last_hard_erase_sweep_seq";
pub(crate) const HARD_ERASE_SWEEP_SLA_SECS: u64 = 30 * 86_400;

const HISTORICAL_CARRIER_CLASSES: &[&str] = &[
    "historical_loro_updates",
    "historical_loro_snapshots",
    "derived_carriers",
];

/// CROSS-ARCH-0002a / ARCH-0038 delete reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeleteReason {
    UserDelete,
    UserHardDelete,
    GdprDelete,
    PolicyDelete,
}

// ─── Tombstone wire format v2 (ONE-1132 / ONE-1090 write side) ──────────────
//
// OWNER-DECISION (M4, fail-closed): the `tombstones` LoroMap value is
//
//   [reason:1][deleted_at:8 LE][request_id:16]            (25 bytes)
//
// reason ∈ {user_delete=1, user_hard_delete=2, gdpr_delete=3,
// policy_delete=4}; byte 0 is RESERVED and decodes as hard. Decode rule: a
// legacy 8-byte value (bare `deleted_at` u64 LE) or an unknown reason byte
// decodes as HARD — over-purge, never under-delete. `request_id` is the
// deletion request UUID (16 raw bytes) used for receipt correlation (M4-06).

/// Total length of a v2 tombstone wire value.
pub const TOMBSTONE_VALUE_V2_LEN: usize = 25;
/// Length of the legacy (pre-ONE-1132) tombstone value: bare `deleted_at`
/// u64 LE. Decodes as HARD (fail-closed).
pub const TOMBSTONE_VALUE_LEGACY_LEN: usize = 8;

/// Pinned tombstone wire reason (ONE-1132 OWNER-DECISION). Wire byte 0 is
/// RESERVED (= hard) and unknown bytes decode as hard; neither is
/// representable here — decoding them yields `reason: None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TombstoneReason {
    UserDelete = 1,
    UserHardDelete = 2,
    GdprDelete = 3,
    PolicyDelete = 4,
}

impl TombstoneReason {
    /// The pinned wire byte for this reason.
    #[must_use]
    pub const fn wire_byte(self) -> u8 {
        self as u8
    }

    /// Decodes a known wire byte; `None` for the reserved byte 0 and any
    /// unknown byte (both of which the caller must treat as HARD).
    #[must_use]
    pub const fn from_wire_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::UserDelete),
            2 => Some(Self::UserHardDelete),
            3 => Some(Self::GdprDelete),
            4 => Some(Self::PolicyDelete),
            _ => None,
        }
    }

    /// Receiver effect class: only `user_delete` is a soft (shell-keeping)
    /// delete; every other reason hard-purges (ARCH-0038 v1).
    #[must_use]
    pub const fn is_hard(self) -> bool {
        !matches!(self, Self::UserDelete)
    }
}

impl From<DeleteReason> for TombstoneReason {
    fn from(reason: DeleteReason) -> Self {
        match reason {
            DeleteReason::UserDelete => Self::UserDelete,
            DeleteReason::UserHardDelete => Self::UserHardDelete,
            DeleteReason::GdprDelete => Self::GdprDelete,
            DeleteReason::PolicyDelete => Self::PolicyDelete,
        }
    }
}

/// A v2 tombstone value the engine WRITES (writers always know the reason
/// and request id; only decoding has the legacy/unknown fallbacks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TombstoneValueV2 {
    pub reason: TombstoneReason,
    /// Unix seconds the deletion was requested.
    pub deleted_at: u64,
    /// Deletion request UUID, raw 16 bytes — correlates the tombstone with
    /// the REDACTION_AUDIT receipt's `request_id` (M4-06).
    pub request_id: [u8; 16],
}

/// Inputs committed together by the sync tombstone persistence transaction.
/// Grouping these values makes the TXN1 contract explicit: the request-keyed
/// window snapshot, queue mutation, and scrub commit as one unit after the
/// authority-required marker and recovery sidecar are durably staged.
#[cfg(feature = "sync")]
struct TombstonePersistence<'a> {
    snapshot: &'a [u8],
    version_vector: &'a [u8],
    tombstone: &'a TombstoneValueV2,
    delete_update: Option<&'a crate::sync::window::DeleteBearingUpdate>,
    scrubbed_update_keys: &'a [String],
}

impl TombstoneValueV2 {
    /// Encodes the pinned `[reason:1][deleted_at:8 LE][request_id:16]`
    /// layout.
    #[must_use]
    pub fn encode(&self) -> [u8; TOMBSTONE_VALUE_V2_LEN] {
        let mut out = [0_u8; TOMBSTONE_VALUE_V2_LEN];
        out[0] = self.reason.wire_byte();
        out[1..9].copy_from_slice(&self.deleted_at.to_le_bytes());
        out[9..25].copy_from_slice(&self.request_id);
        out
    }
}

/// A decoded tombstones-map value. `reason: None` means the value was a
/// legacy 8-byte value, carried the reserved byte 0, an unknown reason
/// byte, or was malformed — ALL of which are HARD (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedTombstoneValue {
    pub reason: Option<TombstoneReason>,
    /// Best-effort `deleted_at`: the bare u64 LE for legacy values, offset
    /// 1..9 for 25-byte values, 0 for malformed shapes.
    pub deleted_at: u64,
    /// Present only when the value had the 25-byte layout.
    pub request_id: Option<[u8; 16]>,
}

impl DecodedTombstoneValue {
    /// Receiver branch: hard unless the value decodes to a KNOWN soft
    /// reason. Fail-closed — over-purge, never under-delete.
    #[must_use]
    pub fn is_hard(&self) -> bool {
        self.reason.is_none_or(TombstoneReason::is_hard)
    }

    /// `request_id` recorded on the LOCAL receipt for a replayed HARD apply
    /// (ONE-1133 OWNER-DECISION): the wire value's request UUID when the
    /// value carried one; the NIL UUID for legacy / malformed values — an
    /// honest "no request id was on the wire", never a fabricated
    /// identifier pretending a request that never existed.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn receipt_request_id(&self) -> String {
        match self.request_id {
            Some(bytes) => Uuid::from_bytes(bytes).to_string(),
            None => Uuid::nil().to_string(),
        }
    }

    /// `reason` recorded on the LOCAL receipt for a replayed HARD apply
    /// (ONE-1133 OWNER-DECISION): the decoded hard reason verbatim;
    /// legacy / reserved-0 / unknown values map to `user_hard_delete` —
    /// the engine's destructive default (`Vault::delete_entity`), matching
    /// the fail-closed purge those values already received. Total so the
    /// replay path can never panic on wire bytes; the soft arm is
    /// unreachable behind the `is_hard()` guard and maps to the
    /// destructive default defensively.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn receipt_hard_reason(&self) -> DeleteReason {
        match self.reason {
            Some(TombstoneReason::GdprDelete) => DeleteReason::GdprDelete,
            Some(TombstoneReason::PolicyDelete) => DeleteReason::PolicyDelete,
            Some(TombstoneReason::UserHardDelete | TombstoneReason::UserDelete) | None => {
                DeleteReason::UserHardDelete
            }
        }
    }

    /// Encodes the pinned 25 B `dt:` local hard-delete marker value
    /// `[reason:1][deleted_at:8 LE][request_id:16]` for a replayed HARD
    /// apply. The byte layout is written directly (no shared codec — the
    /// format is the pin). PRESENCE-ONLY semantics: gates never decode
    /// this; the bytes are informational. Fallbacks mirror the receipt
    /// pins: legacy/reserved-0/unknown/malformed shapes record the
    /// destructive default reason (`user_hard_delete`) and the NIL
    /// request id — never a fabricated identifier.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn local_hard_delete_marker_value(&self) -> [u8; TOMBSTONE_VALUE_V2_LEN] {
        let mut out = [0_u8; TOMBSTONE_VALUE_V2_LEN];
        out[0] = match self.reason {
            Some(reason) => reason.wire_byte(),
            None => TombstoneReason::UserHardDelete.wire_byte(),
        };
        out[1..9].copy_from_slice(&self.deleted_at.to_le_bytes());
        out[9..25].copy_from_slice(&self.request_id.unwrap_or([0_u8; 16]));
        out
    }
}

/// What [`crate::Vault::apply_replayed_tombstone`] — the reason-aware
/// replay-delete primitive (M4-06 / ONE-1133) — applied to the LOCAL
/// active store.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) enum ReplayedTombstoneOutcome {
    /// Known-soft (`user_delete`) value: shell-preserving SoftErase.
    /// `changed` is `false` when there was nothing local to scrub (already
    /// a shell, already hard-purged, or never materialized) — a soft value
    /// NEVER recreates state, so soft-after-hard stays a no-op.
    SoftErased { changed: bool },
    /// Hard value (known hard reason, legacy 8-byte, reserved 0, unknown
    /// byte, malformed): destructive purge. `erased` is `false` when no
    /// local trace existed — then NO receipt and NO sweep row are written,
    /// keeping every-boot re-application receipt-free.
    HardPurged {
        erased: bool,
        receipt_id: Option<EntityId>,
        sweep_key: Option<Vec<u8>>,
    },
}

impl ReplayedTombstoneOutcome {
    /// Whether the apply changed any local active-store state.
    #[must_use]
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn changed_local_state(&self) -> bool {
        match self {
            Self::SoftErased { changed } => *changed,
            Self::HardPurged { erased, .. } => *erased,
        }
    }
}

/// Decodes a tombstones-map value. Total — never errors: any shape that is
/// not a well-formed v2 soft tombstone decodes as HARD (ONE-1132
/// OWNER-DECISION: fail-closed, over-purge, never under-delete).
#[must_use]
pub fn decode_tombstone_value(value: &[u8]) -> DecodedTombstoneValue {
    if value.len() == TOMBSTONE_VALUE_LEGACY_LEN {
        let mut ts = [0_u8; 8];
        ts.copy_from_slice(value);
        return DecodedTombstoneValue {
            reason: None,
            deleted_at: u64::from_le_bytes(ts),
            request_id: None,
        };
    }
    if value.len() == TOMBSTONE_VALUE_V2_LEN {
        let mut ts = [0_u8; 8];
        ts.copy_from_slice(&value[1..9]);
        let mut request_id = [0_u8; 16];
        request_id.copy_from_slice(&value[9..25]);
        return DecodedTombstoneValue {
            reason: TombstoneReason::from_wire_byte(value[0]),
            deleted_at: u64::from_le_bytes(ts),
            request_id: Some(request_id),
        };
    }
    DecodedTombstoneValue {
        reason: None,
        deleted_at: 0,
        request_id: None,
    }
}

// ─── Pending-tombstone marker (`pt:`) — cfg-off durability ──────────────────
//
// OWNER-DECISION (ONE-1132): deletion propagation intent must not depend on
// the `sync` cargo feature. The purge txn (and the user_delete shell-scrub
// txn) UNCONDITIONALLY writes a CRDT-independent `pt:{window}:{entity_hex}`
// marker into `sync_state`, value = the v2 tombstone wire value. It is
// cleared only after the CRDT commit + snapshot persistence succeed, so it
// doubles as the crash marker between the purge txn and the CRDT commit. A
// sync-enabled boot replays leftovers into the window doc
// (`sync::window::replay_pending_tombstones`) and then clears them.

/// `sync_state` key prefix for pending-tombstone markers.
pub(crate) const PENDING_TOMBSTONE_PREFIX: &str = "pt:";

/// Builds the `pt:{window}:{entity_hex}` marker key.
pub(crate) fn pending_tombstone_key(window_label: &str, id: &EntityId) -> String {
    format!("{PENDING_TOMBSTONE_PREFIX}{window_label}:{}", id.to_hex())
}

// ─── Local hard-delete marker (`dt:`) — durable local delete truth ──────────
//
// PINNED FORMAT (M4 fix wave, shared with the origin-side write): key =
// `dt:{entity_id_hex}` (32-char lowercase hex, GLOBAL — deliberately NO
// window segment, so a window-shuffled re-put cannot dodge it); value =
// 25 bytes `[reason:1][deleted_at:8 LE][request_id:16]`. Semantics are
// PRESENCE-ONLY: gates never decode the value (it is informational).
// Written ONLY on HARD outcomes, in the SAME LMDB txn as the active-store
// purge. PERMANENT — no GC: hard-once-seen must survive locally so a
// hostile peer that removes the CRDT tombstone (and re-puts the entity)
// cannot resurrect the body through the materialization gates.

/// `sync_state` key prefix for local hard-delete markers.
pub(crate) const LOCAL_HARD_DELETE_PREFIX: &str = "dt:";

/// Builds the GLOBAL `dt:{entity_hex}` local hard-delete marker key.
pub(crate) fn local_hard_delete_key(id: &EntityId) -> String {
    format!("{LOCAL_HARD_DELETE_PREFIX}{}", id.to_hex())
}

/// Formats the ARCH-0023b `YYYY-MM` window label for a unix-seconds
/// timestamp, clamping timestamps at or beyond year 10000 to the last
/// representable window `"9999-12"` (a larger year would produce a key the
/// validated sync readers reject, stranding rows written under it).
///
/// Lives in this always-compiled module because the deletion path needs the
/// window address for the `pt:` marker even in builds WITHOUT the `sync`
/// feature; `sync::types::WindowKey::from_timestamp` delegates here so the
/// two can never drift.
pub(crate) fn window_label_from_timestamp(ts: u64) -> String {
    // Stay in u64: an `as i64` cast would wrap negative for ts > i64::MAX
    // and silently yield "1970-01".
    let days = ts / 86_400;
    let mut year = 1970_i32;
    let mut remaining_days = days;

    loop {
        let days_in_year: u64 = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        if year == 9999 {
            // Clamp instead of walking one year per iteration toward an
            // astronomically large target (and emitting a >4-digit year
            // that breaks the YYYY-MM key format).
            return "9999-12".to_owned();
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let mut month = 1_u32;
    let month_days = [
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        month += 1;
    }

    format!("{year:04}-{month:02}")
}

pub(crate) const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

impl DeleteReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserDelete => "user_delete",
            Self::UserHardDelete => "user_hard_delete",
            Self::GdprDelete => "gdpr_delete",
            Self::PolicyDelete => "policy_delete",
        }
    }

    pub(crate) const fn writes_receipt(self) -> bool {
        match self {
            Self::UserDelete => false,
            Self::UserHardDelete | Self::GdprDelete | Self::PolicyDelete => true,
        }
    }

    pub(crate) const fn active_store_hard_purge_v1(self) -> bool {
        match self {
            Self::UserDelete => false,
            Self::UserHardDelete | Self::GdprDelete | Self::PolicyDelete => true,
        }
    }

    pub(crate) const fn queues_historical_sweep(self) -> bool {
        match self {
            Self::UserDelete => false,
            Self::UserHardDelete | Self::GdprDelete | Self::PolicyDelete => true,
        }
    }
}

/// Result for a reason-aware delete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEntityOutcome {
    pub existed: bool,
    pub receipt_id: Option<EntityId>,
    pub sweep_key: Option<Vec<u8>>,
}

/// Owner-authority evidence evaluated before a facade deletion starts.
///
/// The actor identity is intentionally recorded at today's strength: a
/// store-verified actor entity plus asserted class. Stronger identity minting
/// remains ONE-1604 and is not implied by this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeletionGateContext {
    actor: EntityId,
    actor_class: EdgeActorClass,
    policy_manifest_version: String,
    read_frontier_hash: [u8; 32],
}

impl DeletionGateContext {
    pub(crate) fn new(
        actor: EntityId,
        actor_class: EdgeActorClass,
        policy_manifest_version: String,
        read_frontier_hash: [u8; 32],
    ) -> Self {
        Self {
            actor,
            actor_class,
            policy_manifest_version,
            read_frontier_hash,
        }
    }

    fn decision_record(
        &self,
        request_id: [u8; 16],
        target: &EntityId,
        reason: DeleteReason,
        created_at: u64,
    ) -> GateDecisionRecord {
        let mut diff = Sha256::new();
        diff.update(b"oneiron.gate.deletion.v0");
        diff.update(self.actor.as_bytes());
        diff.update(target.as_bytes());
        diff.update([TombstoneReason::from(reason).wire_byte()]);
        GateDecisionRecord {
            version: 0,
            // The ledger key is the deletion request id, so recovery and
            // REDACTION_AUDIT correlation never need a second identifier.
            decision_id: GateDecisionId::from_bytes(request_id),
            created_at,
            outcome: "allow".to_owned(),
            reason_codes: vec!["gate.allow.owner_delete".to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: self.actor_class.gate_actor_class().to_owned(),
            actor_ref: Some(self.actor.to_hex()),
            content_kind: "deletion".to_owned(),
            policy_manifest_version: self.policy_manifest_version.clone(),
            claim_id: None,
            grant_ref: None,
            diff_handle: diff.finalize().to_vec(),
            read_frontier_hash: self.read_frontier_hash,
        }
    }
}

impl DeleteEntityOutcome {
    pub(crate) const fn missing() -> Self {
        Self {
            existed: false,
            receipt_id: None,
            sweep_key: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RedactionScope {
    pub entity_ids: Vec<String>,
    pub revision_ids: Vec<String>,
}

impl RedactionScope {
    pub(crate) fn entity(entity_id: &EntityId) -> Self {
        Self {
            entity_ids: vec![entity_id.to_hex()],
            revision_ids: Vec::new(),
        }
    }
}

/// The pinned REDACTION_AUDIT body shape (`rmp_serde::to_vec_named`, field
/// order = the pinned [`RECEIPT_BODY_KEYS`] order). `Deserialize` exists for
/// the ONE-1087 sweep executor, whose receipt finalization is the SINGLE
/// sanctioned mutation of an otherwise-immutable receipt: the monotone
/// `sweep_complete_at` None→Some transition on the OWN node's receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RedactionAuditReceipt {
    pub(crate) request_id: String,
    pub(crate) scope: RedactionScope,
    pub(crate) reason: String,
    pub(crate) requested_at: u64,
    pub(crate) soft_complete_at: u64,
    pub(crate) hard_purge_complete_at: u64,
    pub(crate) sweep_queued_at: Option<u64>,
    pub(crate) sweep_complete_at: Option<u64>,
    pub(crate) affected_revision_ids: Vec<String>,
    pub(crate) verification: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HardEraseSweepJob {
    pub(crate) scope: HardEraseSweepScope,
    pub(crate) retry_state: HardEraseRetryState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HardEraseSweepScope {
    pub(crate) entity_ids: Vec<String>,
    pub(crate) revision_ids: Vec<String>,
    /// ARCH-0038 delete-interplay seam: "body_snapshot_ref lets the queued
    /// historical-carrier sweep locate residual snapshot/update bytes"
    /// (contracts.ts retractionRules DELETE). Opaque lowercase-hex ids only;
    /// the consuming executor is ONE-1087/ONE-1091 phase 1 (whose window
    /// compaction is global, so the refs ride the job as audit context).
    pub(crate) body_snapshot_refs: Vec<String>,
    pub(crate) carrier_classes: Vec<String>,
}

/// Delete-interplay refs captured from an `edge.provenance` Claim BEFORE its
/// body is purged/SoftErased, riding the QUEUED sweep row's scope (ARCH-0038).
/// Opaque lowercase-hex identifiers only — never content, names, or predicate
/// strings. Empty for non-provenance deletes.
#[derive(Debug, Clone, Default)]
pub(crate) struct HardEraseSweepExtras {
    /// Captured `source_revision_ref`s — opaque revision UUIDs joining the
    /// scope's pinned `revision_ids` slot ("entity UUIDs / revision UUIDs").
    pub revision_ids: Vec<String>,
    /// Captured `body_snapshot_ref`s — pointers to the exact body bytes the
    /// actor saw, the sweep's residual-carrier locator.
    pub body_snapshot_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HardEraseRetryState {
    pub(crate) attempt_count: u32,
    pub(crate) next_attempt_at: u64,
    pub(crate) last_error_code: Option<String>,
    pub(crate) queued_at: u64,
    pub(crate) deadline_at: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct RedactionReceiptInput {
    pub request_id: String,
    pub scope: RedactionScope,
    pub reason: DeleteReason,
    pub requested_at: u64,
    pub soft_complete_at: u64,
    pub hard_purge_complete_at: u64,
    pub sweep_queued_at: Option<u64>,
}

// ─── Receipt origin attestation (ONE-1140, OD-6) ─────────────────────────────
//
// The receipt body's `verification` map — the M4-pinned extension point
// ("verification must be empty UNTIL the audit-chain proof schema is
// pinned") — now carries EXACTLY four attestation entries (this versions
// the M4 pin; values are lowercase-hex strings, BTreeMap iteration = sorted
// keys = deterministic encoding):
//
//   "att_client" → str(16)  client_id hex (BE nibble order, `{:016x}`)
//   "att_pk"     → str(64)  Ed25519 verifying key hex
//   "att_sig"    → str(128) Ed25519 signature hex
//   "att_v"      → str(1)   "1"
//
// Signature transcript (byte-exact):
//   msg = RECEIPT_ATT_DOMAIN || entity_id:16
//         || envelope_header:25 ([type:1][occurred_start:8 BE]
//            [occurred_end:8 BE][learned_at:8 BE], exactly the stored bytes)
//         || body_msgpack_with_verification_EMPTY
//
// The signer encodes with `verification = {}` (those bytes ARE the
// transcript tail), signs, then re-encodes with the four att_ entries. The
// verifier reconstructs the tail by splicing: `verification` is required to
// be the FINAL map entry in bytes (rmp_serde named-struct order guarantees
// it for the legitimate writer; the validator enforces it), so
// `body[..verification_value_offset] || 0x80` reproduces the signed bytes
// — same top-level map header both ways, no re-serialization
// canonicalization trap.

/// Attestation transcript domain separator (OD-6 literal).
pub(crate) const RECEIPT_ATT_DOMAIN: &[u8] = b"oneiron/receipt-att/v1";
pub(crate) const ATT_KEY_CLIENT: &str = "att_client";
pub(crate) const ATT_KEY_PK: &str = "att_pk";
pub(crate) const ATT_KEY_SIG: &str = "att_sig";
pub(crate) const ATT_KEY_V: &str = "att_v";
/// Attestation schema version literal carried in `att_v`.
pub(crate) const ATT_VERSION: &str = "1";
/// MessagePack fixmap(0) — the empty `verification` the transcript tail
/// carries in place of the four att_ entries.
#[cfg(feature = "sync")]
pub(crate) const ATT_EMPTY_MAP_BYTE: u8 = 0x80;

/// The pinned 25 B REDACTION_AUDIT envelope header: receipts are point
/// events (`occurred_start == occurred_end == learned_at`), all three
/// timestamps u64 BE. Shared by the receipt writer and the attestation
/// transcript so the signed header bytes are EXACTLY the stored bytes.
pub(crate) fn receipt_envelope_header(learned_at: u64) -> [u8; 25] {
    let mut header = [0u8; 25];
    header[0] = crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    header[1..9].copy_from_slice(&learned_at.to_be_bytes());
    header[9..17].copy_from_slice(&learned_at.to_be_bytes());
    header[17..25].copy_from_slice(&learned_at.to_be_bytes());
    header
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Encodes a REDACTION_AUDIT receipt body, signed by this device (OD-6).
///
/// `receipt_id` and `input.hard_purge_complete_at` (the envelope
/// `learned_at`) are bound into the transcript so a valid receipt cannot be
/// transplanted under another entity id or a shifted envelope.
pub(crate) fn encode_redaction_audit_receipt(
    input: RedactionReceiptInput,
    receipt_id: &EntityId,
    identity: &crate::identity::DeviceIdentity,
) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer;

    let envelope_learned_at = input.hard_purge_complete_at;
    let mut receipt = RedactionAuditReceipt {
        request_id: input.request_id,
        scope: input.scope,
        reason: input.reason.as_str().to_owned(),
        requested_at: input.requested_at,
        soft_complete_at: input.soft_complete_at,
        hard_purge_complete_at: input.hard_purge_complete_at,
        sweep_queued_at: input.sweep_queued_at,
        sweep_complete_at: None,
        affected_revision_ids: Vec::new(),
        verification: BTreeMap::new(),
    };

    // Transcript tail: the body bytes with verification EMPTY.
    let body_unsigned = rmp_serde::to_vec_named(&receipt)
        .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))?;
    let header = receipt_envelope_header(envelope_learned_at);
    let mut msg =
        Vec::with_capacity(RECEIPT_ATT_DOMAIN.len() + 16 + header.len() + body_unsigned.len());
    msg.extend_from_slice(RECEIPT_ATT_DOMAIN);
    msg.extend_from_slice(receipt_id.as_bytes());
    msg.extend_from_slice(&header);
    msg.extend_from_slice(&body_unsigned);
    let signature = identity.signing_key.sign(&msg);

    receipt.verification.insert(
        ATT_KEY_CLIENT.to_owned(),
        format!("{:016x}", identity.client_id),
    );
    receipt.verification.insert(
        ATT_KEY_PK.to_owned(),
        hex_lower(&identity.signing_key.verifying_key().to_bytes()),
    );
    receipt
        .verification
        .insert(ATT_KEY_SIG.to_owned(), hex_lower(&signature.to_bytes()));
    receipt
        .verification
        .insert(ATT_KEY_V.to_owned(), ATT_VERSION.to_owned());

    rmp_serde::to_vec_named(&receipt)
        .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))
}

pub(crate) fn encode_hard_erase_sweep_job(
    scope: RedactionScope,
    extras: HardEraseSweepExtras,
    queued_at: u64,
) -> Result<Vec<u8>> {
    let mut revision_ids = scope.revision_ids;
    revision_ids.extend(extras.revision_ids);
    let job = HardEraseSweepJob {
        scope: HardEraseSweepScope {
            entity_ids: scope.entity_ids,
            revision_ids,
            body_snapshot_refs: extras.body_snapshot_refs,
            carrier_classes: HISTORICAL_CARRIER_CLASSES
                .iter()
                .map(|class| (*class).to_owned())
                .collect(),
        },
        retry_state: HardEraseRetryState {
            attempt_count: 0,
            next_attempt_at: queued_at,
            last_error_code: None,
            queued_at,
            deadline_at: queued_at.saturating_add(HARD_ERASE_SWEEP_SLA_SECS),
        },
    };
    rmp_serde::to_vec_named(&job)
        .map_err(|_| Error::InvariantViolation("hard erase sweep job encode"))
}

/// Decodes a persisted `h:{seq:8BE}` job value. An undecodable job row is a
/// deletion obligation the executor can neither execute nor safely discard —
/// callers must KEEP the row and report loudly, never delete it.
pub(crate) fn decode_hard_erase_sweep_job(value: &[u8]) -> Result<HardEraseSweepJob> {
    rmp_serde::from_slice(value).map_err(|_| Error::CorruptedIndex("hard erase sweep job"))
}

/// Re-encodes a job after an in-place `retry_state` update (ONE-1087: the
/// row is REWRITTEN on failure, never deleted). Same encoder as the
/// original write (`rmp_serde::to_vec_named`), so the wire shape is stable.
pub(crate) fn encode_hard_erase_sweep_job_value(job: &HardEraseSweepJob) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(job)
        .map_err(|_| Error::InvariantViolation("hard erase sweep job encode"))
}

/// Decodes a REDACTION_AUDIT receipt BODY (post-envelope bytes).
pub(crate) fn decode_redaction_audit_receipt(body: &[u8]) -> Result<RedactionAuditReceipt> {
    rmp_serde::from_slice(body).map_err(|_| Error::CorruptedIndex("redaction audit receipt body"))
}

/// ONE-1087 replay-door exception for the SINGLE sanctioned receipt
/// mutation: the sweep executor's monotone `sweep_complete_at` None→Some
/// finalization on the OWN node's receipt (LMDB-only — the CRDT mirror
/// keeps the pre-finalization bytes by design).
///
/// Returns `true` iff `incoming` is the stale PRE-finalization echo of the
/// FINALIZED `local` receipt: identical 25 B entity envelope, decodable
/// bodies, `local.sweep_complete_at = Some(_)` vs
/// `incoming.sweep_complete_at = None`, and every OTHER field equal. The
/// doors treat that one shape as an idempotent skip (never quarantine,
/// never overwrite local) — without it every boot would re-quarantine the
/// own-receipt CRDT round-trip after a sweep. ANY other divergence —
/// including incoming `Some` over local `None`, which only a crafted
/// update can produce (replicas never finalize a foreign receipt) — stays
/// on the M4-07 quarantine path. Fail closed: any decode failure → `false`.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn redaction_receipt_is_stale_finalization_echo(local: &[u8], incoming: &[u8]) -> bool {
    use crate::batch::ENTITY_METADATA_HEADER_LEN as H;
    if local.len() < H || incoming.len() < H || local[..H] != incoming[..H] {
        return false;
    }
    let (Ok(local_rec), Ok(incoming_rec)) = (
        decode_redaction_audit_receipt(&local[H..]),
        decode_redaction_audit_receipt(&incoming[H..]),
    ) else {
        return false;
    };
    if local_rec.sweep_complete_at.is_none() || incoming_rec.sweep_complete_at.is_some() {
        return false;
    }
    let definalized = RedactionAuditReceipt {
        sweep_complete_at: None,
        ..local_rec
    };
    definalized == incoming_rec
}

/// Pinned contracts.ts `redactionAuditReceipt.fields` key set — the wire
/// shape every type-120 blob crossing a sync replay door must satisfy
/// (ONE-1134). Mirrors [`RedactionAuditReceipt`]'s `to_vec_named` encoding:
/// one string-keyed MessagePack map carrying exactly these fields.
///
/// Un-cfg'd since ONE-1087: the sweep executor's receipt finalization
/// self-validates its rewritten body on EVERY build, not just sync ones.
const RECEIPT_BODY_KEYS: [&str; 10] = [
    "request_id",
    "scope",
    "reason",
    "requested_at",
    "soft_complete_at",
    "hard_purge_complete_at",
    "sweep_queued_at",
    "sweep_complete_at",
    "affected_revision_ids",
    "verification",
];

/// Structurally validates a REDACTION_AUDIT (type 120) body arriving through
/// a sync replay door against the pinned contracts.ts
/// `redactionAuditReceipt` field set. Fail-closed rules:
///
/// * the body must be exactly one string-keyed MessagePack map (no
///   positional-array encoding, no trailing bytes);
/// * keys must be drawn from [`RECEIPT_BODY_KEYS`], no duplicates, no
///   unknown fields (a field outside the pinned set is a divergence from
///   the minimization contract — "opaque identifiers + timestamps only");
/// * required: every field except `sweep_queued_at` / `sweep_complete_at`
///   (the two contract-optional timestamps, which may also be nil);
/// * `request_id`, `scope.entity_ids[]`, `scope.revision_ids[]`, and
///   `affected_revision_ids[]` must parse as opaque UUIDs (GDPR Art. 5(2)
///   minimization: free text here would smuggle names/content into an
///   immutable, replicated audit record);
/// * `reason` must be one of the pinned receipt-writing DeleteReason
///   literals `user_hard_delete | gdpr_delete | policy_delete`
///   (`user_delete` writes no receipt, so it can never legitimately appear);
/// * the three completion timestamps must be non-negative integers;
/// * `verification` carries EXACTLY the four attestation entries pinned by
///   ONE-1140 (OD-6): `att_client` (16 lowercase hex), `att_pk` (64
///   lowercase hex), `att_sig` (128 lowercase hex), `att_v` (`"1"`) —
///   string values only, no other keys. This VERSIONS the M4 "must be
///   empty" pin; anything outside that grammar is still an unvalidated
///   content channel into the immutable record ("never retains what it
///   erased") and is rejected;
/// * `verification` must be the FINAL map entry in bytes: the attestation
///   transcript is the byte prefix up to the verification VALUE
///   (tail-splice, OD-6), so a body that orders it elsewhere can never
///   reproduce the signed bytes.
pub(crate) fn validate_redaction_receipt_body(body: &[u8]) -> Result<()> {
    use rmpv::Value;

    let mut cursor = std::io::Cursor::new(body);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidRedactionReceiptBody("body is not valid MessagePack"))?;
    if cursor.position() != body.len() as u64 {
        return Err(Error::InvalidRedactionReceiptBody(
            "trailing bytes after body map",
        ));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvalidRedactionReceiptBody(
            "body must be a string-keyed MessagePack map",
        ));
    };

    // OD-6 tail-splice precondition: `verification` is the FINAL entry in
    // bytes (decoded entry order IS byte order — the map was read from a
    // contiguous buffer with no trailing bytes).
    match entries.last() {
        Some((key, _)) if key.as_str() == Some("verification") => {}
        _ => {
            return Err(Error::InvalidRedactionReceiptBody(
                "verification must be the final body map entry",
            ));
        }
    }

    let mut seen = [false; RECEIPT_BODY_KEYS.len()];
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidRedactionReceiptBody(
                "body keys must be strings",
            ));
        };
        let Some(index) = RECEIPT_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidRedactionReceiptBody(
                "body key is not in the pinned redactionAuditReceipt field set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidRedactionReceiptBody("duplicate body key"));
        }
        seen[index] = true;

        match RECEIPT_BODY_KEYS[index] {
            "request_id" => {
                validate_opaque_uuid(&value, "request_id must be an opaque UUID string")?;
            }
            "scope" => validate_receipt_scope(value)?,
            "reason" => match value.as_str() {
                Some("user_hard_delete" | "gdpr_delete" | "policy_delete") => {}
                _ => {
                    return Err(Error::InvalidRedactionReceiptBody(
                        "reason must be user_hard_delete | gdpr_delete | policy_delete",
                    ));
                }
            },
            "requested_at" | "soft_complete_at" | "hard_purge_complete_at" => {
                if value.as_u64().is_none() {
                    return Err(Error::InvalidRedactionReceiptBody(
                        "timestamps must be non-negative integers",
                    ));
                }
            }
            "sweep_queued_at" | "sweep_complete_at" => {
                if !value.is_nil() && value.as_u64().is_none() {
                    return Err(Error::InvalidRedactionReceiptBody(
                        "optional sweep timestamps must be nil or non-negative integers",
                    ));
                }
            }
            "affected_revision_ids" => {
                validate_opaque_uuid_array(
                    &value,
                    "affected_revision_ids must be an array of opaque UUID strings",
                )?;
            }
            "verification" => {
                // ONE-1140 (OD-6): the M4 "must be empty" pin is VERSIONED —
                // verification now carries EXACTLY the four attestation
                // entries, hex-grammar-checked. Everything else stays an
                // unvalidated content channel into the immutable,
                // replicated, purge-exempt REDACTION_AUDIT record — the
                // divergence gate would then PROTECT smuggled erased
                // content (minimization: "never retains what it erased").
                validate_receipt_verification(value)?;
            }
            _ => unreachable!("index is drawn from RECEIPT_BODY_KEYS"),
        }
    }

    for (index, key) in RECEIPT_BODY_KEYS.iter().enumerate() {
        let optional = matches!(*key, "sweep_queued_at" | "sweep_complete_at");
        if !optional && !seen[index] {
            return Err(Error::InvalidRedactionReceiptBody(
                "missing required receipt field",
            ));
        }
    }
    Ok(())
}

/// Validates the receipt `scope` field: a map carrying exactly
/// `entity_ids` + `revision_ids`, both arrays of opaque UUID strings
/// (contracts.ts: "entity UUIDs / revision UUIDs … Opaque IDs only; no
/// names or content").
fn validate_receipt_scope(value: rmpv::Value) -> Result<()> {
    let rmpv::Value::Map(entries) = value else {
        return Err(Error::InvalidRedactionReceiptBody("scope must be a map"));
    };
    let mut seen_entity_ids = false;
    let mut seen_revision_ids = false;
    for (key, value) in entries {
        match key.as_str() {
            Some("entity_ids") => {
                if seen_entity_ids {
                    return Err(Error::InvalidRedactionReceiptBody("duplicate scope key"));
                }
                seen_entity_ids = true;
                validate_opaque_uuid_array(
                    &value,
                    "scope.entity_ids must be an array of opaque UUID strings",
                )?;
            }
            Some("revision_ids") => {
                if seen_revision_ids {
                    return Err(Error::InvalidRedactionReceiptBody("duplicate scope key"));
                }
                seen_revision_ids = true;
                validate_opaque_uuid_array(
                    &value,
                    "scope.revision_ids must be an array of opaque UUID strings",
                )?;
            }
            _ => {
                return Err(Error::InvalidRedactionReceiptBody(
                    "scope key is not entity_ids | revision_ids",
                ));
            }
        }
    }
    if !(seen_entity_ids && seen_revision_ids) {
        return Err(Error::InvalidRedactionReceiptBody(
            "scope must carry entity_ids and revision_ids",
        ));
    }
    Ok(())
}

/// Validates the receipt `verification` map against the ONE-1140 (OD-6)
/// attestation grammar: EXACTLY four string entries — `att_client` str(16),
/// `att_pk` str(64), `att_sig` str(128), all lowercase hex, plus
/// `att_v == "1"`. No duplicates, no unknown keys, no other shapes.
fn validate_receipt_verification(value: rmpv::Value) -> Result<()> {
    let rmpv::Value::Map(fields) = value else {
        return Err(Error::InvalidRedactionReceiptBody(
            "verification must be a map",
        ));
    };
    if fields.len() != 4 {
        return Err(Error::InvalidRedactionReceiptBody(
            "verification must carry exactly the four att_ entries",
        ));
    }
    let mut seen = [false; 4];
    for (key, value) in fields {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidRedactionReceiptBody(
                "verification keys must be strings",
            ));
        };
        let Some(value) = value.as_str() else {
            return Err(Error::InvalidRedactionReceiptBody(
                "verification values must be strings",
            ));
        };
        let index = match key {
            ATT_KEY_CLIENT => 0,
            ATT_KEY_PK => 1,
            ATT_KEY_SIG => 2,
            ATT_KEY_V => 3,
            _ => {
                return Err(Error::InvalidRedactionReceiptBody(
                    "verification key is not in the pinned att_ set",
                ));
            }
        };
        if seen[index] {
            return Err(Error::InvalidRedactionReceiptBody(
                "duplicate verification key",
            ));
        }
        seen[index] = true;
        match key {
            ATT_KEY_CLIENT if value.len() == 16 && is_lower_hex(value) => {}
            ATT_KEY_PK if value.len() == 64 && is_lower_hex(value) => {}
            ATT_KEY_SIG if value.len() == 128 && is_lower_hex(value) => {}
            ATT_KEY_V if value == ATT_VERSION => {}
            _ => {
                return Err(Error::InvalidRedactionReceiptBody(
                    "verification value fails the pinned att_ grammar",
                ));
            }
        }
    }
    Ok(())
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(feature = "sync")]
fn hex_decode_lower(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !is_lower_hex(s) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The attestation fields of a validated receipt body plus the byte offset
/// of the `verification` VALUE — the splice point for transcript
/// reconstruction (OD-6).
#[cfg(feature = "sync")]
pub(crate) struct ReceiptAttestationParts {
    pub(crate) client_id: u64,
    pub(crate) pubkey: [u8; 32],
    pub(crate) signature: [u8; 64],
    pub(crate) verification_value_offset: usize,
}

/// Reads a MessagePack map header (fixmap / map16 / map32) off the cursor.
/// The only low-level decode this module hand-rolls: rmpv reads whole
/// values, and the verifier needs the byte OFFSET of the final entry's
/// value, so the top-level header + per-entry walk track positions.
#[cfg(feature = "sync")]
fn read_msgpack_map_len(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u64> {
    use std::io::Read;
    let mut first = [0u8; 1];
    cursor
        .read_exact(&mut first)
        .map_err(|_| Error::InvalidRedactionReceiptBody("body is not valid MessagePack"))?;
    match first[0] {
        b @ 0x80..=0x8f => Ok(u64::from(b & 0x0f)),
        0xde => {
            let mut len = [0u8; 2];
            cursor
                .read_exact(&mut len)
                .map_err(|_| Error::InvalidRedactionReceiptBody("body is not valid MessagePack"))?;
            Ok(u64::from(u16::from_be_bytes(len)))
        }
        0xdf => {
            let mut len = [0u8; 4];
            cursor
                .read_exact(&mut len)
                .map_err(|_| Error::InvalidRedactionReceiptBody("body is not valid MessagePack"))?;
            Ok(u64::from(u32::from_be_bytes(len)))
        }
        _ => Err(Error::InvalidRedactionReceiptBody(
            "body must be a string-keyed MessagePack map",
        )),
    }
}

/// Cursor-parses a receipt body (already structurally validated by
/// [`validate_redaction_receipt_body`]) and extracts the attestation
/// fields plus the verification-value byte offset. The transcript tail is
/// then `body[..verification_value_offset] || ATT_EMPTY_MAP_BYTE` — sound
/// because the validator pinned `verification` as the FINAL entry in bytes
/// with no trailing bytes; a non-canonical re-encoding simply fails the
/// signature (fail closed), never a false accept.
#[cfg(feature = "sync")]
pub(crate) fn receipt_attestation_parts(body: &[u8]) -> Result<ReceiptAttestationParts> {
    const MALFORMED: Error =
        Error::InvalidRedactionReceiptBody("attestation fields failed re-parse");

    let mut cursor = std::io::Cursor::new(body);
    let entry_count = read_msgpack_map_len(&mut cursor)?;
    let mut parts: Option<ReceiptAttestationParts> = None;
    for _ in 0..entry_count {
        let key = rmpv::decode::read_value(&mut cursor).map_err(|_| MALFORMED)?;
        let is_verification = key.as_str() == Some("verification");
        let value_offset = usize::try_from(cursor.position()).map_err(|_| MALFORMED)?;
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| MALFORMED)?;
        if !is_verification {
            continue;
        }
        let rmpv::Value::Map(fields) = value else {
            return Err(MALFORMED);
        };
        let mut client_id = None;
        let mut pubkey = None;
        let mut signature = None;
        for (att_key, att_value) in &fields {
            let (Some(att_key), Some(att_value)) = (att_key.as_str(), att_value.as_str()) else {
                return Err(MALFORMED);
            };
            match att_key {
                ATT_KEY_CLIENT => {
                    client_id = Some(u64::from_str_radix(att_value, 16).map_err(|_| MALFORMED)?);
                }
                ATT_KEY_PK => {
                    let bytes: [u8; 32] = hex_decode_lower(att_value)
                        .ok_or(MALFORMED)?
                        .try_into()
                        .map_err(|_| MALFORMED)?;
                    pubkey = Some(bytes);
                }
                ATT_KEY_SIG => {
                    let bytes: [u8; 64] = hex_decode_lower(att_value)
                        .ok_or(MALFORMED)?
                        .try_into()
                        .map_err(|_| MALFORMED)?;
                    signature = Some(bytes);
                }
                _ => {}
            }
        }
        parts = Some(ReceiptAttestationParts {
            client_id: client_id.ok_or(MALFORMED)?,
            pubkey: pubkey.ok_or(MALFORMED)?,
            signature: signature.ok_or(MALFORMED)?,
            verification_value_offset: value_offset,
        });
    }
    if cursor.position() != body.len() as u64 {
        return Err(MALFORMED);
    }
    parts.ok_or(MALFORMED)
}

fn validate_opaque_uuid(value: &rmpv::Value, reason: &'static str) -> Result<()> {
    let valid = value
        .as_str()
        .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok());
    if !valid {
        return Err(Error::InvalidRedactionReceiptBody(reason));
    }
    Ok(())
}

fn validate_opaque_uuid_array(value: &rmpv::Value, reason: &'static str) -> Result<()> {
    let Some(items) = value.as_array() else {
        return Err(Error::InvalidRedactionReceiptBody(reason));
    };
    for item in items {
        validate_opaque_uuid(item, reason)?;
    }
    Ok(())
}

pub(crate) fn encode_hard_erase_sweep_key(seq: u64) -> [u8; 10] {
    let mut key = [0_u8; 10];
    key[..2].copy_from_slice(HARD_ERASE_SWEEP_PREFIX);
    key[2..].copy_from_slice(&seq.to_be_bytes());
    key
}

pub(crate) fn decode_hard_erase_sweep_seq(key: &[u8]) -> Option<u64> {
    let seq = key.strip_prefix(HARD_ERASE_SWEEP_PREFIX)?;
    Some(u64::from_be_bytes(seq.try_into().ok()?))
}

/// Stable deletion reason surfaced by short-id hydrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionReason {
    UserDelete,
    UserHardDelete,
    GdprDelete,
    PolicyDelete,
}

/// Where hydrate found deletion evidence for a short-id row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionSource {
    Tombstone,
    PendingTombstone,
    DanglingShortId,
}

/// Deletion metadata returned when a short-id row resolves to deleted state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HydratedShortIdDeletion {
    pub source: HydratedShortIdDeletionSource,
    pub reason: Option<HydratedShortIdDeletionReason>,
    pub deleted_at: Option<u64>,
    pub request_id: Option<String>,
    pub hard: bool,
}

/// Renderer-facing lifecycle state for one record in a memory timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTimelineRecordState {
    /// The record exists and is not closed by the supersession graph.
    Live,
    /// The record exists and has been superseded by at least one newer record.
    Superseded,
    /// The record exists as explicitly retracted claim history.
    Retracted,
    /// The record exists only as a deletion shell with tombstone metadata.
    Deleted,
    /// The graph still references an entity id whose record is absent locally.
    Missing,
}

/// One node in a bitemporal supersession timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimelineRecord {
    pub id: EntityId,
    pub state: MemoryTimelineRecordState,
    pub entity_type: Option<u8>,
    pub occurred_start: Option<u64>,
    pub occurred_end: Option<u64>,
    pub learned_at: Option<u64>,
    pub body_bytes: Option<usize>,
    pub deletion: Option<HydratedShortIdDeletion>,
    pub supersedes: Vec<EntityId>,
    pub superseded_by: Vec<EntityId>,
}

/// Stable, ordered supersession-chain data for one anchor entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimeline {
    pub anchor: EntityId,
    pub records: Vec<MemoryTimelineRecord>,
}

/// Human-readable memory verbs exposed by API surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedMemoryVerb {
    Remember,
    Supersede,
    Retract,
    Delete,
    HardDelete,
}

impl NamedMemoryVerb {
    /// Parses a public route verb, accepting stable aliases while resolving to
    /// one canonical typed operation family.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "remember" | "put" | "put_entity" => Some(Self::Remember),
            "supersede" | "replace" | "revise" | "supersede_claim" => Some(Self::Supersede),
            "retract" | "withdraw" | "retract_claim" => Some(Self::Retract),
            "delete" | "forget" | "soft_delete" | "user_delete" => Some(Self::Delete),
            "hard_delete" | "erase" | "purge" | "user_hard_delete" => Some(Self::HardDelete),
            _ => None,
        }
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Remember => "remember",
            Self::Supersede => "supersede",
            Self::Retract => "retract",
            Self::Delete => "delete",
            Self::HardDelete => "hard_delete",
        }
    }

    pub const fn operation_kind(self) -> MemoryOperationKind {
        match self {
            Self::Remember => MemoryOperationKind::PutEntity,
            Self::Supersede => MemoryOperationKind::SupersedeClaim,
            Self::Retract => MemoryOperationKind::RetractClaim,
            Self::Delete | Self::HardDelete => MemoryOperationKind::DeleteEntity,
        }
    }
}

/// Typed operation family selected by a named memory verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOperationKind {
    PutEntity,
    SupersedeClaim,
    RetractClaim,
    DeleteEntity,
}

/// Cap for renderer timeline expansion across supersession edges.
const MAX_MEMORY_TIMELINE_RECORDS: usize = 10_000;

/// ONE-1149 race-test rendezvous seam. The deterministic raced-delete harness
/// must order the deleter's lock-free `read_entity_header` read_txn (which does
/// NOT take the single LMDB write lock) BEFORE the eraser's commit, so the
/// headerful gate is forced to win the header read and the partial-residue leg
/// is exercised every run instead of nondeterministically diverting to the
/// headerless path. The only way to inject that ordering across the spawned
/// production call is a `#[cfg(test)]` signal emitted from inside
/// `delete_entity_with_reason` once the header is proven `Some`. It compiles
/// out of production entirely (the `#[cfg(not(test))]` shim is a no-op),
/// mirroring the established sweep-side fault-injection seam idiom.
#[cfg(test)]
static AFTER_HEADER_READ: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<()>>> =
    std::sync::Mutex::new(None);

/// Installs the one-shot rendezvous sender consumed by
/// [`signal_after_header_read`]. Called by the raced-delete harness before it
/// releases the deleter; the matching receiver `recv()`s on the eraser side
/// just before its commit.
#[cfg(test)]
pub(crate) fn install_after_header_read_signal(tx: std::sync::mpsc::SyncSender<()>) {
    *AFTER_HEADER_READ
        .lock()
        .expect("AFTER_HEADER_READ poisoned") = Some(tx);
}

/// Fires the rendezvous signal exactly once if a sender is installed, then
/// clears it so unrelated headerful deletes in the same serial run never block
/// on a stale rendezvous. A no-op when no harness installed a sender.
#[cfg(test)]
fn signal_after_header_read() {
    let sender = AFTER_HEADER_READ
        .lock()
        .expect("AFTER_HEADER_READ poisoned")
        .take();
    if let Some(sender) = sender {
        // The rendezvous (`sync_channel(0)`) blocks here until the eraser
        // `recv()`s; that recv is positioned immediately before its commit, so
        // the deleter's header read is provably ordered before the erase.
        let _ = sender.send(());
    }
}

/// Production no-op shim for the race-test rendezvous seam: compiles out the
/// signal entirely in non-test builds.
#[cfg(not(test))]
#[inline(always)]
fn signal_after_header_read() {}

#[cfg(all(test, feature = "sync"))]
thread_local! {
    static FAIL_AFTER_TOMBSTONE_BEFORE_PURGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_LIVE_TOMBSTONE_PERSIST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms a one-shot crash surrogate after TXN1 has durably persisted the CRDT
/// tombstone and request-keyed authority recovery sidecar, but before any
/// local scrub/purge.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn arm_fail_after_tombstone_before_purge() {
    FAIL_AFTER_TOMBSTONE_BEFORE_PURGE.with(|armed| armed.set(true));
}

/// Arms a one-shot TXN1 failure after the live Loro tombstone commits but
/// before its snapshot/update persistence transaction begins.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn arm_fail_live_tombstone_persist() {
    FAIL_LIVE_TOMBSTONE_PERSIST.with(|armed| armed.set(true));
}

#[cfg(all(test, feature = "sync"))]
fn maybe_fail_live_tombstone_persist() -> Result<()> {
    if FAIL_LIVE_TOMBSTONE_PERSIST.replace(false) {
        return Err(Error::InvariantViolation(
            "test failure persisting committed live deletion tombstone",
        ));
    }
    Ok(())
}

#[cfg(not(all(test, feature = "sync")))]
#[inline(always)]
fn maybe_fail_live_tombstone_persist() {}

#[cfg(all(test, feature = "sync"))]
fn maybe_fail_after_tombstone_before_purge() -> Result<()> {
    #[cfg(all(test, feature = "sync"))]
    if FAIL_AFTER_TOMBSTONE_BEFORE_PURGE.replace(false) {
        return Err(Error::InvariantViolation(
            "test crash after deletion TXN1 before purge",
        ));
    }
    Ok(())
}

#[cfg(not(all(test, feature = "sync")))]
#[inline(always)]
fn maybe_fail_after_tombstone_before_purge() {}

fn memory_timeline_record_cmp(
    left: &MemoryTimelineRecord,
    right: &MemoryTimelineRecord,
) -> std::cmp::Ordering {
    left.occurred_start
        .unwrap_or(u64::MAX)
        .cmp(&right.occurred_start.unwrap_or(u64::MAX))
        .then_with(|| {
            left.learned_at
                .unwrap_or(u64::MAX)
                .cmp(&right.learned_at.unwrap_or(u64::MAX))
        })
        .then_with(|| {
            left.occurred_end
                .unwrap_or(u64::MAX)
                .cmp(&right.occurred_end.unwrap_or(u64::MAX))
        })
        .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
}

/// ARCH-0038 delete-interplay refs captured from an `edge.provenance` Claim
/// BEFORE its body is purged or SoftErased: the subject EdgeRef whose cached
/// flags must be refreshed post-purge (D16), and the opaque refs the queued
/// historical-carrier sweep rides on (the ONE-1091 executor's seam).
struct CapturedProvenanceDelete {
    subject: EdgeRef,
    source_revision_ref: Option<[u8; 16]>,
    body_snapshot_ref: Option<[u8; 16]>,
}

/// Builds the queued sweep row's delete-interplay extras from a pre-purge
/// provenance capture: opaque lowercase-hex identifiers only — never content
/// or predicate strings. Empty for non-provenance deletes, so their queued
/// row shape gains nothing.
fn sweep_extras(captured: Option<&CapturedProvenanceDelete>) -> HardEraseSweepExtras {
    let Some(captured) = captured else {
        return HardEraseSweepExtras::default();
    };
    HardEraseSweepExtras {
        revision_ids: captured
            .source_revision_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
        body_snapshot_refs: captured
            .body_snapshot_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
    }
}

impl Vault {
    /// Deletes an entity blob by ID using the destructive user-hard-delete
    /// contract.
    pub fn delete_entity(&self, id: &EntityId) -> Result<bool> {
        Ok(self
            .delete_entity_with_reason(id, DeleteReason::UserHardDelete)?
            .existed)
    }

    /// Deletes an entity according to the pinned ARCH-0038 reason behavior.
    pub fn delete_entity_with_reason(
        &self,
        id: &EntityId,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        self.delete_entity_with_reason_impl(id, reason, None)
    }

    /// Facade delete seam carrying an owner gate evaluated before TXN1.
    pub(crate) fn delete_entity_with_reason_gated(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: DeletionGateContext,
    ) -> Result<DeleteEntityOutcome> {
        self.delete_entity_with_reason_impl(id, reason, Some(gate))
    }

    fn delete_entity_with_reason_impl(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: Option<DeletionGateContext>,
    ) -> Result<DeleteEntityOutcome> {
        let requested_at = unix_seconds_now();
        let Some(header) = self.read_entity_header(id)? else {
            return self.delete_entity_without_header(id, reason, requested_at, gate.as_ref());
        };
        if crate::registry::is_delete_protected_engine_record(header.entity_type) {
            return Err(Error::MaintenanceKindNotWritable(header.entity_type));
        }
        // ONE-1149 race-test rendezvous: the header is proven `Some` (the
        // lock-free `read_entity_header` read_txn has completed and committed
        // the headerful path) but no write lock is held yet. The deterministic
        // raced-delete harness recv()s here so the eraser commits AFTER this
        // header read, forcing the headerful leg every run. No-op in
        // production.
        signal_after_header_read();
        // ONE-1132: ONE deletion request UUID correlates the CRDT tombstone's
        // `request_id` with the REDACTION_AUDIT receipt's `request_id`.
        // ONE-1149: minted only AFTER the header read proves there is
        // something to erase — a delete that finds nothing must never mint a
        // request id (the headerless leg mints after its own scope probe).
        let request_uuid = Uuid::now_v7();

        let tombstone = TombstoneValueV2 {
            reason: reason.into(),
            deleted_at: requested_at,
            request_id: *request_uuid.as_bytes(),
        };
        let gate_decision = gate
            .as_ref()
            .map(|gate| gate.decision_record(*request_uuid.as_bytes(), id, reason, requested_at));
        let window_label = window_label_from_timestamp(header.learned_at);

        // ARCH-0038 DELETE interplay: an `edge.provenance` Claim's subject
        // EdgeRef and sweep refs are only readable PRE-purge (SoftErase
        // truncates the payload to the 25 B header) — capture them now.
        // `None` for every non-Claim / non-provenance entity: zero new
        // behavior on those paths.
        let captured = self.capture_provenance_delete(id)?;

        if !reason.active_store_hard_purge_v1() {
            // `user_delete` keeps the local 25 B shell (ARCH-0038 "Tombstone
            // revision (empty content); keep the message shell") but now
            // writes a reason=user_delete CRDT tombstone (ONE-1090 write
            // side): a soft delete with NO cross-device record would leave
            // the deleted body live on every other device.
            let mut wtxn = self.store.env.write_txn()?;
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(&mut wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            // D16: SoftErase tombstones the Claim, and "the derived edge
            // flag follows the Claim" — refresh in the SAME transaction.
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?;
            }
            if existed {
                // OWNER-DECISION (cfg-off durability): the pending-tombstone
                // marker rides the SAME txn as the shell scrub.
                self.put_pending_tombstone_in_txn(&mut wtxn, &window_label, id, &tombstone)?;
                if let Some(decision) = gate_decision.as_ref() {
                    self.store
                        .append_gate_decision_in_txn(&mut wtxn, decision)?;
                }
            }
            wtxn.commit()?;
            if existed {
                let crdt_persisted =
                    self.write_crdt_tombstone(id, header.learned_at, &tombstone, None)?;
                if crdt_persisted {
                    self.clear_pending_tombstone(&window_label, id)?;
                }
            }
            return Ok(DeleteEntityOutcome {
                existed,
                receipt_id: None,
                sweep_key: None,
            });
        }

        // LOCKED ordering (ARCH-0038): CRDT tombstone FIRST — prevents sync
        // resurrection before the destructive purge touches payloads.
        let crdt_persisted =
            self.write_crdt_tombstone(id, header.learned_at, &tombstone, gate_decision.as_ref())?;
        #[cfg(all(test, feature = "sync"))]
        maybe_fail_after_tombstone_before_purge()?;
        #[cfg(not(all(test, feature = "sync")))]
        maybe_fail_after_tombstone_before_purge();
        let tombstone_complete_at = unix_seconds_now();

        let soft_complete_at = if matches!(
            reason,
            DeleteReason::GdprDelete | DeleteReason::PolicyDelete
        ) {
            // The SoftErase scrubs the truth-Claim's body — the ONLY carrier
            // of the subject EdgeRef (D12) — so the D16 edge refresh MUST
            // commit atomically with it, mirroring the user_delete branch
            // above. Committing the SoftErase alone first would leave a
            // crash window in which a stale 26 B flag outlives its
            // truth-Claim and a RETRY cannot heal it (capture sees the
            // bodiless shell ⇒ `None`). The purge txn below re-runs the
            // refresh as an idempotent second pass.
            let mut wtxn = self.store.env.write_txn()?;
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(&mut wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?;
            }
            wtxn.commit()?;
            unix_seconds_now()
        } else {
            tombstone_complete_at
        };

        let receipt_id = EntityId::now();
        let scope = RedactionScope::entity(id);
        let mut wtxn = self.store.env.write_txn()?;
        let marker_key = local_hard_delete_key(id);
        // ONE-1149 ownership claim: probe the FULL delete scope INSIDE the
        // erasing txn. LMDB's single writer makes this race-free — if the
        // probe sees state, this txn's purge erases it; if a concurrent
        // delete raced everything away first, this delete must not claim it
        // erased anything (no receipt, no sweep row). Mirrors the
        // receiver-side `apply_replayed_tombstone` nothing-local branch:
        // ONLY the durable `dt:` marker is written (hard-once-seen — the
        // CRDT tombstone above is already published, so the id IS
        // hard-deleted), guarded so an existing marker is never overwritten.
        if !self.active_delete_scope_exists_in_txn(&wtxn, id)? {
            if self.store.sync_state.get(&wtxn, &marker_key)?.is_none() {
                self.store
                    .sync_state
                    .put(&mut wtxn, &marker_key, &tombstone.encode())?;
            }
            if crdt_persisted
                && let Some(decision) = gate_decision.as_ref()
                && !self.store.discard_pending_deletion_gate_decision_in_txn(
                    &mut wtxn,
                    decision.decision_id,
                    id.as_bytes(),
                    tombstone.reason.wire_byte(),
                )?
            {
                return Err(Error::CorruptedIndex("pending deletion gate decision"));
            }
            wtxn.commit()?;
            return Ok(DeleteEntityOutcome::missing());
        }
        // ONE-1122 `dt:` local hard-delete marker: the permanent local truth
        // the Observer-B materialization gate consults when a crafted update
        // REMOVES the CRDT tombstone (nothing else id-keyed survives a hard
        // delete locally — the receipt id is fresh, h: is seq-keyed, pt: is
        // cleared after replay). Written in the SAME txn as the active-store
        // purge. PRESENCE-ONLY for gates; the 25 B value body (the tombstone
        // wire bytes) is informational. Un-cfg'd on every build: `sync_state`
        // is unconditional and the marker is local delete truth, not
        // sync-only state (ONE-1132 cfg-off durability).
        self.store
            .sync_state
            .put(&mut wtxn, &marker_key, &tombstone.encode())?;
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;

        // ARCH-0038 DELETE: "The derived edge flag follows the Claim" — the
        // subject edge is refreshed in the SAME transaction as the purge.
        // Gated on `existed` (the entity record was erased by THIS txn): a
        // captured Claim whose record was raced away was already refreshed
        // by the racer's own delete txn.
        if existed && let Some(captured) = &captured {
            self.refresh_subject_edge_after_claim_delete_in_txn(&mut wtxn, id, &captured.subject)?;
        }

        // OWNER-DECISION (cfg-off durability): the pending-tombstone marker
        // rides the SAME txn as the active-store purge — on every build.
        self.put_pending_tombstone_in_txn(&mut wtxn, &window_label, id, &tombstone)?;
        self.append_deletion_gate_decision_in_purge_txn(
            &mut wtxn,
            crdt_persisted,
            gate_decision.as_ref(),
            id,
            tombstone.reason,
        )?;

        let hard_purge_complete_at = unix_seconds_now();
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id: request_uuid.to_string(),
                scope,
                reason,
                requested_at,
                soft_complete_at,
                hard_purge_complete_at,
                sweep_queued_at: reason
                    .queues_historical_sweep()
                    .then_some(hard_purge_complete_at),
            },
            sweep_extras(captured.as_ref()),
        )?;

        wtxn.commit()?;
        // The CRDT record (tombstone-first, above) is durable — the crash
        // marker has served its purpose. In non-`sync` builds the marker
        // STAYS: it is the deletion's only propagation intent until a
        // sync-enabled boot replays it.
        if crdt_persisted {
            self.clear_pending_tombstone(&window_label, id)?;
        }
        Ok(DeleteEntityOutcome {
            existed,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    fn delete_entity_without_header(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        requested_at: u64,
        gate: Option<&DeletionGateContext>,
    ) -> Result<DeleteEntityOutcome> {
        // Probe first so a fully-missing id stays a strict no-op — deleting
        // a nonexistent entity must not mint tombstones or receipts.
        {
            let rtxn = self.store.env.read_txn()?;
            if !self.active_delete_scope_exists_in_txn(&rtxn, id)? {
                return Ok(DeleteEntityOutcome::missing());
            }
        }
        // ONE-1149: the deletion request UUID is minted only AFTER the probe
        // above says there is something to erase.
        let request_uuid = Uuid::now_v7();

        // ONE-1132: headerless residue previously left NO CRDT record, so
        // the orphan id could re-sync forever. There is no `learned_at` to
        // address a window with, so the tombstone lands under
        // `WindowKey::from_timestamp(now)` — a propagation address, not a
        // truth claim.
        let tombstone = TombstoneValueV2 {
            reason: reason.into(),
            deleted_at: requested_at,
            request_id: *request_uuid.as_bytes(),
        };
        let gate_decision = gate
            .map(|gate| gate.decision_record(*request_uuid.as_bytes(), id, reason, requested_at));
        let window_label = window_label_from_timestamp(requested_at);
        let crdt_persisted =
            self.write_crdt_tombstone(id, requested_at, &tombstone, gate_decision.as_ref())?;
        #[cfg(all(test, feature = "sync"))]
        maybe_fail_after_tombstone_before_purge()?;
        #[cfg(not(all(test, feature = "sync")))]
        maybe_fail_after_tombstone_before_purge();

        let mut wtxn = self.store.env.write_txn()?;
        let marker_key = local_hard_delete_key(id);
        // ONE-1149 ownership claim: re-probe the FULL delete scope INSIDE
        // the erasing txn (race-free under LMDB's single writer). The read
        // probe above gated the tombstone publish; THIS probe gates the
        // erasure audit. A concurrent delete that raced the residue away
        // between the two means this delete erased nothing: no receipt, no
        // sweep row, no `pt:` marker — only the durable `dt:` marker for
        // hard reasons (hard-once-seen; the CRDT tombstone above is already
        // published), guarded exactly like the receiver-side
        // `apply_replayed_tombstone` nothing-local branch.
        if !self.active_delete_scope_exists_in_txn(&wtxn, id)? {
            if reason.active_store_hard_purge_v1()
                && self.store.sync_state.get(&wtxn, &marker_key)?.is_none()
            {
                self.store
                    .sync_state
                    .put(&mut wtxn, &marker_key, &tombstone.encode())?;
            }
            if crdt_persisted
                && let Some(decision) = gate_decision.as_ref()
                && !self.store.discard_pending_deletion_gate_decision_in_txn(
                    &mut wtxn,
                    decision.decision_id,
                    id.as_bytes(),
                    tombstone.reason.wire_byte(),
                )?
            {
                return Err(Error::CorruptedIndex("pending deletion gate decision"));
            }
            wtxn.commit()?;
            return Ok(DeleteEntityOutcome::missing());
        }
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;
        // OWNER-DECISION (cfg-off durability): marker in the SAME purge txn.
        self.put_pending_tombstone_in_txn(&mut wtxn, &window_label, id, &tombstone)?;
        self.append_deletion_gate_decision_in_purge_txn(
            &mut wtxn,
            crdt_persisted,
            gate_decision.as_ref(),
            id,
            tombstone.reason,
        )?;
        if reason.active_store_hard_purge_v1() {
            // `dt:` local hard-delete marker (pinned: presence-only 25 B
            // `[reason:1][deleted_at:8 LE][request_id:16]` value, GLOBAL
            // lowercase key, permanent, no GC), headerless leg — in the
            // SAME txn as the purge, mirroring the receiver-side hard
            // apply. The CRDT tombstone above is mutable remote-facing
            // state; without the local marker a hostile tombstone removal
            // + re-put would resurrect this id through the
            // materialization gates.
            self.store
                .sync_state
                .put(&mut wtxn, &marker_key, &tombstone.encode())?;
        }
        if !reason.writes_receipt() {
            wtxn.commit()?;
            if crdt_persisted {
                self.clear_pending_tombstone(&window_label, id)?;
            }
            return Ok(DeleteEntityOutcome {
                existed,
                receipt_id: None,
                sweep_key: None,
            });
        }

        let receipt_id = EntityId::now();
        let hard_purge_complete_at = unix_seconds_now();
        // A headerless residue has no decodable body, so no provenance
        // capture is possible (ARCH-0038: no body ⇒ no EdgeRef to refresh,
        // no refs for the sweep scope).
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id: request_uuid.to_string(),
                scope: RedactionScope::entity(id),
                reason,
                requested_at,
                soft_complete_at: hard_purge_complete_at,
                hard_purge_complete_at,
                sweep_queued_at: reason
                    .queues_historical_sweep()
                    .then_some(hard_purge_complete_at),
            },
            HardEraseSweepExtras::default(),
        )?;
        wtxn.commit()?;
        if crdt_persisted {
            self.clear_pending_tombstone(&window_label, id)?;
        }
        Ok(DeleteEntityOutcome {
            existed,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    /// Completes the deletion authority record in the same TXN3 write as the
    /// active-store purge and REDACTION_AUDIT receipt. Sync-enabled deletes
    /// stage recovery data before the tombstone commit; sync-disabled deletes
    /// append the evaluated record directly on their first durable purge.
    fn append_deletion_gate_decision_in_purge_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        crdt_persisted: bool,
        decision: Option<&GateDecisionRecord>,
        id: &EntityId,
        tombstone_reason: TombstoneReason,
    ) -> Result<()> {
        let Some(decision) = decision else {
            return Ok(());
        };
        if crdt_persisted {
            if self
                .store
                .append_pending_deletion_gate_decision_in_txn(
                    wtxn,
                    decision.decision_id,
                    id.as_bytes(),
                    tombstone_reason.wire_byte(),
                )?
                .is_none()
            {
                return Err(Error::CorruptedIndex("pending deletion gate decision"));
            }
        } else {
            self.store.append_gate_decision_in_txn(wtxn, decision)?;
        }
        Ok(())
    }

    /// Pre-purge ARCH-0038 capture for the local delete paths: decodes the
    /// entity ABOUT to be purged or SoftErased and, when it is an
    /// `edge.provenance` Claim, captures the subject EdgeRef (for the D16
    /// flag refresh) plus the `body_snapshot_ref` / `source_revision_ref`
    /// the queued historical-carrier sweep needs to locate residual
    /// snapshot/update bytes.
    ///
    /// Discrimination order — the hook stays inert for everything else:
    /// type byte FIRST (non-CLAIM ⇒ `None`), then the predicate (non-
    /// `edge.provenance` Claim ⇒ `None`). A bodiless 25 B Claim shell ⇒
    /// `None`: every local SoftErase commits the D16 edge refresh in the
    /// SAME transaction that scrubs the body, so a shell's subject edge is
    /// already consistent and the refs the sweep would need are gone with
    /// the body. A type-0 record whose NON-empty body fails
    /// claim/provenance decoding fails CLOSED with the decoder's typed error
    /// — the ONE-1104 invariant (every type-0 write is validated) is broken
    /// and the delete must not guess.
    fn capture_provenance_delete(&self, id: &EntityId) -> Result<Option<CapturedProvenanceDelete>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(None);
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if body.is_empty() {
            return Ok(None);
        }
        let wrapper = crate::claim::decode_claim_body(body, true)?;
        if wrapper.predicate != PREDICATE_EDGE_PROVENANCE {
            return Ok(None);
        }
        let ClaimSubject::Edge {
            source,
            kind,
            target,
        } = wrapper.subject
        else {
            return Err(Error::InvalidProvenanceBody(
                "edge.provenance claim subject is not a 33-byte EdgeRef",
            ));
        };
        let record = decode_edge_provenance_body(&wrapper.value)?;
        Ok(Some(CapturedProvenanceDelete {
            subject: EdgeRef::new(source, kind, target),
            source_revision_ref: record.source_revision_ref,
            body_snapshot_ref: record.body_snapshot_ref,
        }))
    }

    /// ARCH-0038 DELETE interplay (D16), run in the SAME transaction that
    /// purged / SoftErased the provenance Claim: refresh the subject edge's
    /// cached flags — restamp from the deterministic D14 winner among the
    /// REMAINING live Claims; else, when a RETRACTED `edge.provenance` Claim
    /// for the same EdgeRef still survives, KEEP the 26 B retracted dampening
    /// stamp (the withdrawn provenance must stay dampened — retractionRules
    /// RETRACT); only when NO provenance Claim of ANY lifecycle survives is
    /// the cached flag unauditable and the edge downgraded 26 B → 24 B bare.
    /// Both `edges_out` and `edges_in` carry identical bytes; when the edge
    /// bytes changed, the endpoints' PPR caches are invalidated and the graph
    /// version bumped. A subject edge that no longer exists (deleted
    /// independently of its Claims) leaves nothing to refresh — no-op.
    fn refresh_subject_edge_after_claim_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        deleted_claim_id: &EntityId,
        subject: &EdgeRef,
    ) -> Result<()> {
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(wtxn, &edge_key)?.is_none() {
            return Ok(());
        }
        let survivors =
            self.live_edge_provenance_claims_in_txn(wtxn, subject, Some(deleted_claim_id))?;
        let precedence: Vec<ProvenancePrecedence> = survivors
            .iter()
            .map(StoredProvenanceClaim::precedence)
            .collect();
        let changed = match winner_index(&precedence) {
            Some(index) => {
                restamp_edge_flags(&self.store, wtxn, subject, survivors[index].flags())?;
                true
            }
            // No ACTIVE survivor. "The derived edge flag follows the Claim"
            // (ARCH-0038 D16) — but a RETRACTED `edge.provenance` Claim is
            // still readable truth, so it KEEPS the 26 B retracted dampening
            // stamp rather than downgrading to a bare 24 B edge that would
            // re-enable PPR propagation of the WITHDRAWN provenance. Only when
            // no provenance Claim of ANY lifecycle survives is the flag
            // unauditable and the edge downgraded to bare.
            None => self.refresh_to_retracted_survivor_or_bare(wtxn, deleted_claim_id, subject)?,
        };
        if changed {
            ppr::invalidate_ppr_for_edge(&self.store, wtxn, &subject.source, &subject.target)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        Ok(())
    }

    /// D16 fallback when the deleted Claim left NO active survivor: if a
    /// RETRACTED `edge.provenance` Claim for `subject` still exists, restamp
    /// the edge with `confirmation_status` = retracted (3) and the retracted
    /// WINNER's persisted `actor_class` — keeping the 26 B retracted dampening
    /// stamp the contract mandates (retractionRules RETRACT), mirroring
    /// `retract_edge_provenance`'s own None-branch so the two paths agree.
    /// Otherwise downgrade 26 B → 24 B bare (no truth-Claim of any lifecycle
    /// survives ⇒ an unauditable cached flag). Returns whether the bytes
    /// changed.
    fn refresh_to_retracted_survivor_or_bare(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        deleted_claim_id: &EntityId,
        subject: &EdgeRef,
    ) -> Result<bool> {
        let retracted =
            self.retracted_edge_provenance_claims_in_txn(wtxn, subject, Some(deleted_claim_id))?;
        let precedence: Vec<ProvenancePrecedence> = retracted
            .iter()
            .map(StoredProvenanceClaim::precedence)
            .collect();
        match winner_index(&precedence) {
            Some(index) => {
                restamp_edge_flags(
                    &self.store,
                    wtxn,
                    subject,
                    EdgeProvenanceFlags {
                        confirmation_status: EdgeConfirmationStatus::Retracted,
                        actor_class: retracted[index].actor_class,
                    },
                )?;
                Ok(true)
            }
            None => downgrade_edge_to_bare(&self.store, wtxn, subject),
        }
    }

    fn purge_entity_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        // The content-hash index row is dropped by `deindex_entity` below;
        // ONE-1741 removed the verdict relocation that this hook also carried.
        let (existed, had_vector, had_graph_mutation, neighbors) =
            deindex_entity(&self.store, wtxn, id)?;
        crate::codebase::delete_codebase_snapshot_in_txn(&self.store, wtxn, id)?;
        ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &neighbors)?;
        if had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, wtxn)?;
        }
        Ok(existed)
    }

    fn soft_erase_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(bool, bool)> {
        let (hint_had_vector, hint_had_graph_mutation, _hint_neighbors) =
            deindex_lexical_query_hints_for_target(&self.store, wtxn, id)?;
        if hint_had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        bm25::deindex_text(&self.store, wtxn, id)?;
        delete_from_phonetic_postings(&self.store, wtxn, id)?;
        crate::code_revision::delete_code_revision_lifecycle_in_txn(&self.store, wtxn, id)?;
        crate::codebase::delete_codebase_snapshot_in_txn(&self.store, wtxn, id)?;
        let blob_cleanup =
            crate::blob_artifact::delete_blob_artifact_lifecycle_in_txn(&self.store, wtxn, id)?;
        if blob_cleanup.had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        self.store.clear_pending_embedding(wtxn, id)?;
        let entity_had_vector = self.store.vectors.delete(wtxn, id.as_bytes())?;
        let mut had_vector = hint_had_vector | entity_had_vector | blob_cleanup.had_vector;
        crate::hnsw::hnsw_deindex(&self.store, wtxn, id)?;

        let Some(entity_record) = self.store.entities.get(wtxn, id.as_bytes())? else {
            let cleanup = delete_vad_annotation_metadata_in_txn(&self.store, wtxn, id)?;
            had_vector |= cleanup.had_vector;
            if cleanup.had_graph_mutation {
                ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &cleanup.neighbors)?;
                ppr::increment_graph_version(&self.store, wtxn)?;
            }
            return Ok((false, had_vector));
        };
        let header = EntityMetadataHeader::parse(&entity_record)
            .ok_or(Error::CorruptedIndex("entity metadata"))?;
        let payload = entity_record[..ENTITY_METADATA_HEADER_LEN].to_vec();
        // Soft-erase truncates the body in place, so unlike the hard-purge path it
        // does not route through `deindex_entity`; drop any content-hash index row
        // here before the body is gone (ONE-1741: scan verdicts anchor to the
        // content bytes, so nothing to relocate). The maintenance helper no-ops for
        // kinds that keep no content-hash index, so the generic delete engine needs
        // no entity-kind branch of its own.
        self.maintain_skill_content_hash_index_on_delete_in_txn(wtxn, id)?;
        let mut cleanup = VadAnnotationCleanup::default();
        delete_vad_annotation_metadata_for_type_in_txn(
            &self.store,
            wtxn,
            id,
            header.entity_type,
            &mut cleanup,
        )?;
        had_vector |= cleanup.had_vector;
        if cleanup.had_graph_mutation {
            ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &cleanup.neighbors)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
        }

        crate::dreamer_runner::deindex_dreamer_milestone_claim(&self.store, wtxn, id)?;
        crate::llm::deindex_dreamer_step_claim(&self.store, wtxn, id)?;
        self.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        Ok((true, had_vector))
    }

    /// Reason-aware replay of a CRDT tombstone into the LOCAL active store —
    /// the ONE primitive every sync replay surface routes through (Observer
    /// B's tombstone phase and `forward_rematerialize`'s tombstone pass), so
    /// a remote delete can never diverge from the pinned ARCH-0038 reason
    /// semantics. OWNER-DECISION (M4-06 / ONE-1133, fail-closed): replay
    /// routes through this reason-aware delete primitive, never bare purge.
    ///
    /// * KNOWN-soft value (`reason = user_delete`) → shell-preserving
    ///   SoftErase: payload truncated to the 25 B entity header,
    ///   text/phonetic/vector/hnsw deindexed, and — when the entity was a
    ///   live `edge.provenance` Claim — the D16 subject-edge refresh
    ///   committed in the SAME transaction. No receipt, no sweep row
    ///   (contracts.ts `user_delete`: activeStoreHardPurgeV1 = false,
    ///   receipt = false).
    /// * Hard value (known hard reason, legacy 8-byte, reserved 0, unknown
    ///   byte, malformed) → destructive purge of the payload plus every
    ///   active index entry, the D16 refresh in the SAME transaction, and —
    ///   when local state was actually erased — a LOCAL `h:{seq:8BE}`
    ///   historical-carrier sweep row (`deadline_at` ≤ queued_at + 30 d,
    ///   GDPR Art. 12(3)) and a LOCAL REDACTION_AUDIT receipt whose
    ///   `request_id` comes from the wire value (OWNER-DECISION: Art. 5(2)
    ///   accountability attaches to each replica actually erasing, so N
    ///   devices yield N receipts for one request). Ambiguity resolves to
    ///   MORE deletion, never less.
    /// * Never-downgrade on receive: a soft value for an id this replica
    ///   already hard-purged finds no row to scrub and is a no-op — it
    ///   never recreates a shell.
    /// * Idempotent: after a completed hard apply the delete-scope probe
    ///   finds nothing, so re-application (every-boot forward
    ///   re-materialization, repeated delta delivery) is a receipt-free
    ///   no-op.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn apply_replayed_tombstone(
        &self,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        let decoded = decode_tombstone_value(raw_value);
        if let Some(header) = self.read_entity_header(id)?
            && crate::registry::is_delete_protected_engine_record(header.entity_type)
        {
            return Err(Error::MaintenanceKindNotWritable(header.entity_type));
        }
        // ARCH-0038 DELETE interplay: an `edge.provenance` Claim's subject
        // EdgeRef and sweep refs are only readable PRE-scrub.
        let captured = self.capture_provenance_delete(id)?;

        if !decoded.is_hard() {
            let mut wtxn = self.store.env.write_txn()?;
            let had_body = self
                .store
                .entities
                .get(&wtxn, id.as_bytes())?
                .is_some_and(|raw| raw.len() > ENTITY_METADATA_HEADER_LEN);
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(&mut wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            // D16: SoftErase tombstones the Claim, and "the derived edge
            // flag follows the Claim" — refresh in the SAME transaction.
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?;
            }
            wtxn.commit()?;
            return Ok(ReplayedTombstoneOutcome::SoftErased {
                changed: had_body || had_vector,
            });
        }

        let mut wtxn = self.store.env.write_txn()?;
        let marker_key = local_hard_delete_key(id);
        let marker_value = decoded.local_hard_delete_marker_value();
        // Probe the FULL delete scope (entity row, vectors, text, phonetic,
        // short-ids, edges): orphan residue without an entities row still
        // counts as local state to erase, mirroring the local
        // `delete_entity_without_header` semantics.
        if !self.active_delete_scope_exists_in_txn(&wtxn, id)? {
            // Hard-once-seen is durable LOCAL truth even when nothing local
            // was erased (never-materialized id): the permanent `dt:` marker
            // still gates a future re-put after hostile tombstone-map
            // manipulation. The guarded write keeps every-boot replay a
            // read-only no-op once the marker exists.
            if self.store.sync_state.get(&wtxn, &marker_key)?.is_none() {
                self.store
                    .sync_state
                    .put(&mut wtxn, &marker_key, &marker_value)?;
            }
            if let Some((request_id, tombstone_reason)) =
                decoded.request_id.zip(raw_value.first().copied())
            {
                let discarded_local_authority =
                    self.store.discard_pending_deletion_gate_decision_in_txn(
                        &mut wtxn,
                        GateDecisionId::from_bytes(request_id),
                        id.as_bytes(),
                        tombstone_reason,
                    )?;
                if discarded_local_authority {
                    tracing::debug!(
                        entity = %id.to_hex(),
                        "remote replay found no local state; discarded the matching local deletion authority sidecar"
                    );
                }
            }
            wtxn.commit()?;
            return Ok(ReplayedTombstoneOutcome::HardPurged {
                erased: false,
                receipt_id: None,
                sweep_key: None,
            });
        }
        self.purge_entity_active_store_in_txn(&mut wtxn, id)?;
        // Receiver-side `dt:` local hard-delete marker (pinned: presence-only
        // value, GLOBAL key, permanent, no GC) — written in the SAME txn as
        // the purge so local delete truth survives CRDT-map manipulation.
        self.store
            .sync_state
            .put(&mut wtxn, &marker_key, &marker_value)?;
        // ARCH-0038 DELETE: "The derived edge flag follows the Claim" — the
        // subject edge is refreshed in the SAME transaction as the purge.
        if let Some(captured) = &captured {
            self.refresh_subject_edge_after_claim_delete_in_txn(&mut wtxn, id, &captured.subject)?;
        }
        if let Some((request_id, tombstone_reason)) =
            decoded.request_id.zip(raw_value.first().copied())
        {
            let completed_local_authority =
                self.store.append_pending_deletion_gate_decision_in_txn(
                    &mut wtxn,
                    GateDecisionId::from_bytes(request_id),
                    id.as_bytes(),
                    tombstone_reason,
                )?;
            if completed_local_authority.is_some() {
                tracing::debug!(
                    entity = %id.to_hex(),
                    "remote replay completed a staged local deletion authority record"
                );
            }
        }
        let applied_at = unix_seconds_now();
        let receipt_id = EntityId::now();
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id: decoded.receipt_request_id(),
                scope: RedactionScope::entity(id),
                reason: decoded.receipt_hard_reason(),
                // The origin's request time, straight off the wire (0 for
                // malformed shapes); completion stamps are device-local
                // facts on the replica that erased.
                requested_at: decoded.deleted_at,
                soft_complete_at: applied_at,
                hard_purge_complete_at: applied_at,
                sweep_queued_at: Some(applied_at),
            },
            sweep_extras(captured.as_ref()),
        )?;
        wtxn.commit()?;
        Ok(ReplayedTombstoneOutcome::HardPurged {
            erased: true,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    #[cfg(feature = "sync")]
    pub(crate) fn apply_replayed_tombstone_for_sync(
        &self,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        if let Some(header) = self.read_entity_header(id)?
            && crate::registry::is_delete_protected_engine_record(header.entity_type)
        {
            return Ok(ReplayedTombstoneOutcome::HardPurged {
                erased: false,
                receipt_id: None,
                sweep_key: None,
            });
        }
        self.apply_replayed_tombstone(id, raw_value)
    }

    /// Presence-only check for the permanent `dt:{entity_hex}` local
    /// hard-delete marker. Materialization gates OR this with the CRDT
    /// tombstones-map presence so LOCAL delete truth survives hostile
    /// tombstone-map manipulation (a removed tombstone + re-put entity must
    /// not resurrect). The value is NEVER decoded (pinned presence-only
    /// semantics).
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn local_hard_delete_marker_exists_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(self
            .store
            .sync_state
            .get(txn, &local_hard_delete_key(id))?
            .is_some())
    }

    fn active_delete_scope_exists_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if self.store.entities.get(txn, id.as_bytes())?.is_some()
            || self.store.vectors.get(txn, id.as_bytes())?.is_some()
            || self.store.text_forward.get(txn, id.as_bytes())?.is_some()
            || self.store.text_meta.get(txn, id.as_bytes())?.is_some()
            || self
                .store
                .text_doc_field_lengths
                .get(txn, id.as_bytes())?
                .is_some()
            || self
                .store
                .phonetic_forward
                .get(txn, id.as_bytes())?
                .is_some()
            || self
                .store
                .short_ids_reverse
                .get(txn, id.as_bytes())?
                .is_some()
        {
            return Ok(true);
        }

        let mut edges_out = self.store.edges_out.prefix_iter(txn, id.as_bytes())?;
        if edges_out.next().transpose()?.is_some() {
            return Ok(true);
        }
        let mut edges_in = self.store.edges_in.prefix_iter(txn, id.as_bytes())?;
        if edges_in.next().transpose()?.is_some() {
            return Ok(true);
        }

        vad_annotation_delete_scope_exists_in_txn(&self.store, txn, id)
    }

    /// Writes the ARCH-0038 CRDT tombstone (v2 wire value, ONE-1132) into
    /// the window doc addressed by `window_ts`. In the SAME CRDT commit as
    /// the tombstone insert, the live `entities[id]` copy (an ACTIVE
    /// carrier, not history) and — for hard reasons — the entity's
    /// edges-map keys are removed; op-history bytes remain for the bounded
    /// `h:` sweep (ONE-1091). Returns whether the CRDT record was
    /// persisted: `false` only in non-`sync` builds, where the `pt:`
    /// pending-tombstone marker carries the deletion intent until a
    /// sync-enabled boot replays it.
    ///
    /// ONE-1135 (delete-propagation transport):
    /// - **Live routing**: when the window is OPEN (registry lookup via the
    ///   attached [`crate::sync::WindowManager`]), the tombstone commits
    ///   through the registry-owned live doc. Its synchronous Observer A
    ///   callback is suppressed for this one commit; an authority-required
    ///   marker + complete recovery sidecar are staged first, then the
    ///   deletion TXN1 persists the snapshot + outbound delta — never through
    ///   a parallel transient copy whose
    ///   `d:w:` export a live `persist_state` would clobber.
    /// - **Transient path** (window NOT open): the doc is import-merged
    ///   from the persisted snapshot + pending `u:` rows
    ///   ([`crate::sync::window::load_window_from_state`]) — never a blind
    ///   overwrite.
    /// - **Delete-bearing queue row**: the tombstone-commit delta is pushed
    ///   to the offline queue with the `d:{seq}` sidecar marker, so an
    ///   OFFLINE delete is delivered on next connect and survives the
    ///   optimistic clear until VV-confirmed (M4-12).
    /// - **Carrier-15 scrub** (hard reasons): pre-existing `q:` rows for
    ///   this window and the persisted `u:w:` rows the snapshot subsumed
    ///   are dropped, and the `fr:w:{key}` full-resync marker is set
    ///   (ARCH-0038 carriers 13–15; fail-closed — over-drop + full resync,
    ///   never leak).
    ///
    /// OWNER-DECISION (ONE-1601 live-path commit origin): the live-doc
    /// commit is tagged `DELETION_TOMBSTONE_ORIGIN`. Observer B skips it;
    /// Observer A is synchronously suppressed; the recovery sidecar is staged
    /// before the live mutation and TXN1 then persists its snapshot. The local
    /// delete path owns the LMDB purge under the pinned tombstone → purge →
    /// receipt ordering, and a B-side replay here would purge BEFORE the
    /// purge transaction, voiding the local receipt and the
    /// `DeleteEntityOutcome` (mirrors `replay_pending_tombstones`).
    #[cfg(feature = "sync")]
    fn write_crdt_tombstone(
        &self,
        id: &EntityId,
        window_ts: u64,
        value: &TombstoneValueV2,
        gate_decision: Option<&GateDecisionRecord>,
    ) -> Result<bool> {
        use crate::sync::bridge::{
            DELETION_TOMBSTONE_ORIGIN, with_deletion_tombstone_observer_a_suppressed,
        };
        use crate::sync::loro_support::doc_version_vector;
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::{
            apply_tombstone_to_window_doc, export_scrubbed_window_snapshot,
            export_tombstone_commit_delta, load_window_from_state, merge_persisted_state_into_doc,
        };
        use loro::CommitOptions;

        let window_key = WindowKey::from_timestamp(window_ts);

        if let Some((window, materializer, manager)) = self.live_window(&window_key) {
            // Live path: merge the on-disk record first (clobber guard —
            // a tombstone persisted transiently while this window was open
            // must survive the snapshot export below), then commit the
            // delete through the SHARED doc.
            //
            // The merge runs OUTSIDE the materializer lock: importing into
            // an observed doc fires Observer B synchronously on this
            // thread, and the callback takes the (non-reentrant) lock
            // itself.
            let merged_update_keys =
                merge_persisted_state_into_doc(self, &window.doc, &window_key)?;
            self.stage_deletion_gate_recovery(id, value, gate_decision)?;
            // The tombstone commit + exports run UNDER the materializer
            // lock: Observer B's tombstone-check + LMDB-materialize is
            // atomic under that lock, so a concurrent remote re-put can no
            // longer check the tombstones map BEFORE this commit and write
            // the deleted body back AFTER the purge txn that follows
            // (resurrection race). The deletion origin skips Observer B;
            // Observer A is synchronously suppressed just for this commit.
            // The authority-required marker + sidecar are already durable;
            // the snapshot and outbound delta land in TXN1 below. Lock order
            // materializer → LMDB txn matches every other holder; the
            // registry lock is NOT held here (manager lock-order pin).
            let (delete_update, snapshot, vv) = {
                let _guard = materializer.lock();
                let vv_before = window.doc.oplog_vv();
                apply_tombstone_to_window_doc(&window.doc, id, &value.encode())?;
                with_deletion_tombstone_observer_a_suppressed(|| {
                    window
                        .doc
                        .commit_with(CommitOptions::new().origin(DELETION_TOMBSTONE_ORIGIN));
                });
                let delete_update = export_tombstone_commit_delta(&window.doc, &vv_before)?;
                let snapshot = export_scrubbed_window_snapshot(self, &window_key, &window.doc)?;
                let vv = doc_version_vector(&window.doc);
                (delete_update, snapshot, vv)
            };
            #[cfg(all(test, feature = "sync"))]
            maybe_fail_live_tombstone_persist()?;
            #[cfg(not(all(test, feature = "sync")))]
            maybe_fail_live_tombstone_persist();
            self.finish_crdt_tombstone_persist(
                &window_key,
                TombstonePersistence {
                    snapshot: &snapshot,
                    version_vector: &vv,
                    tombstone: value,
                    delete_update: delete_update.as_ref(),
                    scrubbed_update_keys: &merged_update_keys,
                },
            )?;
            if let Some(update) = delete_update.as_ref() {
                manager
                    .outbound()
                    .route_live(window_key.as_str(), update.as_bytes());
            }
            return Ok(true);
        }

        // Transient path (window not open): the loaded doc IS the
        // import-merge of `d:w:` + pending `u:` rows.
        let merged_update_keys = self.sync_state_keys_with_prefix(&format!("u:w:{window_key}:"))?;
        let doc = match load_window_from_state(self, "local", &window_key) {
            Ok(doc) => doc,
            Err(Error::WindowNotFound { .. }) => create_window_doc("local", &window_key),
            Err(err) => return Err(err),
        };
        let vv_before = doc.oplog_vv();
        apply_tombstone_to_window_doc(&doc, id, &value.encode())?;
        self.stage_deletion_gate_recovery(id, value, gate_decision)?;
        doc.commit();
        let delete_update = export_tombstone_commit_delta(&doc, &vv_before)?;

        let snapshot = export_scrubbed_window_snapshot(self, &window_key, &doc)?;
        let vv = doc_version_vector(&doc);
        self.finish_crdt_tombstone_persist(
            &window_key,
            TombstonePersistence {
                snapshot: &snapshot,
                version_vector: &vv,
                tombstone: value,
                delete_update: delete_update.as_ref(),
                scrubbed_update_keys: &merged_update_keys,
            },
        )?;
        Ok(true)
    }

    /// Durably marks a locally gated tombstone as authority-required and
    /// stores its complete recovery sidecar before any shared live document
    /// can commit that tombstone. Remote/ungated tombstones deliberately do
    /// not create this marker and remain valid replay inputs.
    #[cfg(feature = "sync")]
    fn stage_deletion_gate_recovery(
        &self,
        id: &EntityId,
        value: &TombstoneValueV2,
        gate_decision: Option<&GateDecisionRecord>,
    ) -> Result<()> {
        let Some(decision) = gate_decision else {
            return Ok(());
        };
        self.with_write_txn(|wtxn| {
            self.store.put_pending_deletion_gate_decision_in_txn(
                wtxn,
                decision,
                id.as_bytes(),
                value.reason.wire_byte(),
            )
        })
    }

    /// One transaction for the delete path's sync_state / sync_queue
    /// bookkeeping (both DBs share the LMDB env): persist the window-doc
    /// snapshot triple, queue the delete-bearing update, and — for hard
    /// reasons — run the carrier-15 scrub + set the `fr:w:{key}`
    /// full-resync marker (consumer lands in M4-12).
    #[cfg(feature = "sync")]
    fn finish_crdt_tombstone_persist(
        &self,
        window_key: &crate::sync::WindowKey,
        persistence: TombstonePersistence<'_>,
    ) -> Result<()> {
        let is_hard = persistence.tombstone.reason.is_hard();
        self.with_write_txn(|wtxn| {
            crate::sync::window::persist_window_doc_in_txn(
                self,
                wtxn,
                window_key,
                persistence.snapshot,
                persistence.version_vector,
            )?;
            if is_hard {
                // ARCH-0038 carrier 15: pending `q:` rows for this window
                // may carry the deleted payload — drop them all (fail-closed
                // over-drop; delete-bearing rows are preserved inside the
                // scrub). The `u:w:` rows the snapshot just subsumed are
                // active payload carriers too.
                crate::sync::queue::scrub_window_updates_in_txn(self, wtxn, window_key.as_str())?;
                for update_key in persistence.scrubbed_update_keys {
                    self.store.sync_state.delete(wtxn, update_key)?;
                }
                // Carriers 13–14: this window's sync state is no longer a
                // faithful delta source — mark it for a full per-window
                // resync on the next connect.
                let fr_key = format!("fr:w:{window_key}");
                self.store.sync_state.put(wtxn, &fr_key, &[1_u8])?;
            }
            if let Some(update) = persistence.delete_update {
                // The live-doc path suppresses Observer A for the tombstone
                // commit, then writes its ordinary `u:w:` carrier here in
                // the snapshot TXN1. Authority recovery was durably staged
                // before the live mutation, so restart replay cannot observe
                // an authority-required tombstone without that requirement.
                crate::sync::bridge::persist_window_update_in_txn(
                    self,
                    wtxn,
                    window_key.as_str(),
                    update.as_bytes(),
                )?;
                crate::sync::queue::push_delete_bearing_in_txn(
                    self,
                    wtxn,
                    window_key.as_str(),
                    update,
                )?;
            }
            // svf LAST (ONE-1151): the hard branch scrubbed the merged u:w:
            // rows above; the soft branch kept them. Recompute freshness from
            // the FINAL u:w: set so a surviving row reads stale (the
            // fast-reconnect reader then full-opens instead of trusting an
            // sv:w: VV that omits the survivor's ops).
            crate::sync::window::write_window_svf_in_txn(self, wtxn, window_key)
        })
    }

    #[cfg(not(feature = "sync"))]
    #[allow(clippy::unnecessary_wraps)]
    fn write_crdt_tombstone(
        &self,
        _id: &EntityId,
        _window_ts: u64,
        _value: &TombstoneValueV2,
        _gate_decision: Option<&GateDecisionRecord>,
    ) -> Result<bool> {
        // No CRDT in this build — the `pt:` marker written in the purge /
        // scrub txn is the deletion's durable propagation intent.
        Ok(false)
    }

    /// Writes the CRDT-independent `pt:{window}:{entity_hex}` marker in the
    /// caller's purge / shell-scrub transaction (ONE-1132 OWNER-DECISION:
    /// deletion durability must not depend on the `sync` cargo feature).
    /// Value = the v2 tombstone wire value, so a sync-enabled boot can
    /// replay it verbatim.
    fn put_pending_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        let key = pending_tombstone_key(window_label, id);
        self.store.sync_state.put(wtxn, &key, &value.encode())?;
        Ok(())
    }

    /// Clears the pending-tombstone marker. Only called once the CRDT
    /// commit + snapshot persistence have succeeded — never before.
    fn clear_pending_tombstone(&self, window_label: &str, id: &EntityId) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let key = pending_tombstone_key(window_label, id);
            self.store.sync_state.delete(wtxn, &key)?;
            Ok(())
        })
    }

    /// Writes a REDACTION_AUDIT receipt as a normal entity-envelope record
    /// (contracts.ts `redactionAuditReceipt.storage`), maintaining the same
    /// index footprint `apply_put` gives every other envelope write. The
    /// receipt is a point event (`occurred_start == occurred_end ==
    /// learned_at`), so per the `apply_put` convention it gets a
    /// `temporal_occurred_start` row but NO `temporal_occurred_end` row and
    /// no `temporal_long_intervals` row. Maintenance kinds carry no short ID.
    fn put_redaction_audit_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()> {
        crate::off_record::FloorWrites::new(&self.store)
            .append_redaction_audit(wtxn, receipt_id, learned_at, body)
    }

    fn write_redaction_receipt_and_sweep_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        input: RedactionReceiptInput,
        sweep_extras: HardEraseSweepExtras,
    ) -> Result<Vec<u8>> {
        let sweep_key = if let Some(queued_at) = input.sweep_queued_at {
            self.enqueue_hard_erase_sweep_in_txn(
                wtxn,
                input.scope.clone(),
                sweep_extras,
                queued_at,
            )?
        } else {
            Vec::new()
        };

        // ONE-1140 (OD-2/OD-6): every receipt is signed at mint. The device
        // identity (client id + Ed25519 keypair) is lazily self-provisioned
        // in THIS txn — all receipt-mint paths funnel through here, so this
        // is the single in-txn hook.
        let identity = crate::identity::ensure_device_identity_in_txn(self, wtxn)?;
        let hard_purge_complete_at = input.hard_purge_complete_at;
        let body = encode_redaction_audit_receipt(input, receipt_id, &identity)?;
        self.put_redaction_audit_receipt_in_txn(wtxn, receipt_id, hard_purge_complete_at, &body)?;
        Ok(sweep_key)
    }

    fn enqueue_hard_erase_sweep_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        scope: RedactionScope,
        extras: HardEraseSweepExtras,
        queued_at: u64,
    ) -> Result<Vec<u8>> {
        let seq = self.allocate_next_hard_erase_sweep_seq(wtxn)?;
        let key = encode_hard_erase_sweep_key(seq);
        let value = encode_hard_erase_sweep_job(scope, extras, queued_at)?;
        self.store.sync_queue.put(wtxn, &key, &value)?;
        Ok(key.to_vec())
    }

    fn allocate_next_hard_erase_sweep_seq(&self, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
        let metadata_seq = match self
            .store
            .sync_queue
            .get(&*wtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY)?
        {
            Some(raw) if raw.len() == 8 => {
                Some(u64::from_le_bytes(raw.as_ref().try_into().map_err(
                    |_| Error::CorruptedIndex("hard erase sweep metadata"),
                )?))
            }
            Some(_) => return Err(Error::CorruptedIndex("hard erase sweep metadata")),
            None => None,
        };
        let current = match metadata_seq {
            Some(seq) => seq,
            None => self.max_hard_erase_sweep_seq(wtxn)?,
        };
        let next = current
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("hard erase sweep sequence"))?;
        if self
            .store
            .sync_queue
            .get(&*wtxn, &encode_hard_erase_sweep_key(next))?
            .is_some()
        {
            let repaired_current = self.max_hard_erase_sweep_seq(wtxn)?;
            let repaired_next = repaired_current
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("hard erase sweep sequence"))?;
            if self
                .store
                .sync_queue
                .get(&*wtxn, &encode_hard_erase_sweep_key(repaired_next))?
                .is_some()
            {
                return Err(Error::CorruptedIndex("hard erase sweep metadata"));
            }
            self.store.sync_queue.put(
                wtxn,
                LAST_HARD_ERASE_SWEEP_SEQ_KEY,
                &repaired_next.to_le_bytes(),
            )?;
            return Ok(repaired_next);
        }
        self.store
            .sync_queue
            .put(wtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY, &next.to_le_bytes())?;
        Ok(next)
    }

    fn max_hard_erase_sweep_seq(&self, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
        let mut max_seq = 0_u64;
        for row in self
            .store
            .sync_queue
            .prefix_iter(wtxn, HARD_ERASE_SWEEP_PREFIX)?
        {
            let (key, _) = row?;
            if let Some(seq) = decode_hard_erase_sweep_seq(&key) {
                max_seq = max_seq.max(seq);
            }
        }
        Ok(max_seq)
    }

    /// Returns stable, renderer-facing data for the supersession chain that
    /// contains `anchor`.
    pub fn memory_timeline(&self, anchor: &EntityId) -> Result<MemoryTimeline> {
        let mut ids = std::collections::BTreeSet::new();
        let mut edges = std::collections::BTreeMap::new();
        let mut stack = vec![*anchor];
        ids.insert(*anchor);

        while let Some(id) = stack.pop() {
            let older = self.targets(&id, EdgeKind::Supersedes, None)?;
            let newer = self.sources(&id, EdgeKind::Supersedes, None)?;
            edges.insert(id, (older.clone(), newer.clone()));
            for next in older.into_iter().chain(newer) {
                if ids.insert(next) {
                    if ids.len() > MAX_MEMORY_TIMELINE_RECORDS {
                        return Err(Error::IndexOverflow("memory_timeline"));
                    }
                    stack.push(next);
                }
            }
        }

        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            let (supersedes, superseded_by) = edges.remove(&id).unwrap_or_default();
            records.push(self.memory_timeline_record(&id, supersedes, superseded_by)?);
        }
        records.sort_unstable_by(memory_timeline_record_cmp);

        Ok(MemoryTimeline {
            anchor: *anchor,
            records,
        })
    }

    fn memory_timeline_record(
        &self,
        id: &EntityId,
        mut supersedes: Vec<EntityId>,
        mut superseded_by: Vec<EntityId>,
    ) -> Result<MemoryTimelineRecord> {
        supersedes.sort_unstable();
        superseded_by.sort_unstable();

        let Some(raw) = self.get_raw(id)? else {
            return Ok(MemoryTimelineRecord {
                id: *id,
                state: MemoryTimelineRecordState::Missing,
                entity_type: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body_bytes: None,
                deletion: None,
                supersedes,
                superseded_by,
            });
        };

        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let body_bytes = raw.len().saturating_sub(ENTITY_METADATA_HEADER_LEN);
        let deletion = if body_bytes == 0 {
            self.entity_deletion_metadata(id, header.learned_at)?
        } else {
            None
        };
        let lifecycle =
            if deletion.is_none() && header.entity_type == ENTITY_TYPE_CLAIM && body_bytes > 0 {
                self.get_claim(id)?.map(|claim| claim.lifecycle)
            } else {
                None
            };
        let state = if deletion.is_some() {
            MemoryTimelineRecordState::Deleted
        } else if lifecycle == Some(ClaimLifecycleStatus::Retracted) {
            MemoryTimelineRecordState::Retracted
        } else if lifecycle == Some(ClaimLifecycleStatus::Superseded) || !superseded_by.is_empty() {
            MemoryTimelineRecordState::Superseded
        } else {
            MemoryTimelineRecordState::Live
        };

        Ok(MemoryTimelineRecord {
            id: *id,
            state,
            entity_type: Some(header.entity_type),
            occurred_start: Some(header.occurred_start),
            occurred_end: Some(header.occurred_end),
            learned_at: Some(header.learned_at),
            body_bytes: Some(body_bytes),
            deletion,
            supersedes,
            superseded_by,
        })
    }

    pub(crate) fn entity_deletion_metadata(
        &self,
        id: &EntityId,
        learned_at: u64,
    ) -> Result<Option<HydratedShortIdDeletion>> {
        let window_label = window_label_from_timestamp(learned_at);
        let pending_key = pending_tombstone_key(&window_label, id);
        let rtxn = self.store.env.read_txn()?;
        if let Some(value) = self.store.sync_state.get(&rtxn, pending_key.as_str())? {
            return Ok(Some(Self::deletion_metadata_from_tombstone_value(
                HydratedShortIdDeletionSource::PendingTombstone,
                &value,
            )));
        }
        drop(rtxn);

        #[cfg(feature = "sync")]
        {
            use crate::sync::loro_support::tombstone_values_for_id;
            use crate::sync::types::WindowKey;

            let window_key = WindowKey::from_timestamp(learned_at);
            match crate::sync::window::load_window_from_state(self, "local", &window_key) {
                Ok(doc) => Ok(
                    Self::select_tombstone_metadata_value(&tombstone_values_for_id(
                        &doc.get_map("tombstones"),
                        id,
                    ))
                    .map(|value| {
                        Self::deletion_metadata_from_tombstone_value(
                            HydratedShortIdDeletionSource::Tombstone,
                            value,
                        )
                    }),
                ),
                Err(Error::WindowNotFound { .. }) => Ok(None),
                Err(error) => Err(error),
            }
        }

        #[cfg(not(feature = "sync"))]
        {
            Ok(None)
        }
    }

    fn deletion_metadata_from_tombstone_value(
        source: HydratedShortIdDeletionSource,
        value: &[u8],
    ) -> HydratedShortIdDeletion {
        let decoded = decode_tombstone_value(value);
        HydratedShortIdDeletion {
            source,
            reason: decoded.reason.map(Self::hydrate_deletion_reason),
            deleted_at: (decoded.deleted_at != 0).then_some(decoded.deleted_at),
            request_id: decoded
                .request_id
                .map(|request_id| Uuid::from_bytes(request_id).to_string()),
            hard: decoded.is_hard(),
        }
    }

    fn hydrate_deletion_reason(
        reason: crate::deletion::TombstoneReason,
    ) -> HydratedShortIdDeletionReason {
        match reason {
            crate::deletion::TombstoneReason::UserDelete => {
                HydratedShortIdDeletionReason::UserDelete
            }
            crate::deletion::TombstoneReason::UserHardDelete => {
                HydratedShortIdDeletionReason::UserHardDelete
            }
            crate::deletion::TombstoneReason::GdprDelete => {
                HydratedShortIdDeletionReason::GdprDelete
            }
            crate::deletion::TombstoneReason::PolicyDelete => {
                HydratedShortIdDeletionReason::PolicyDelete
            }
        }
    }

    #[cfg(feature = "sync")]
    fn select_tombstone_metadata_value(values: &[Vec<u8>]) -> Option<&[u8]> {
        values
            .iter()
            .find(|value| decode_tombstone_value(value).is_hard())
            .or_else(|| values.first())
            .map(Vec::as_slice)
    }
}

#[cfg(test)]
mod tests;
