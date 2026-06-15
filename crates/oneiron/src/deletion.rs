//! ARCH-0038 deletion/redaction contract types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::types::EntityId;

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
    header[0] = crate::types::ENTITY_TYPE_REDACTION_AUDIT;
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
#[cfg(feature = "sync")]
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
#[cfg(feature = "sync")]
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
#[cfg(feature = "sync")]
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

#[cfg(feature = "sync")]
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

#[cfg(feature = "sync")]
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
    if key.len() != 10 || !key.starts_with(HARD_ERASE_SWEEP_PREFIX) {
        return None;
    }
    Some(u64::from_be_bytes(key[2..10].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE-1132 OWNER-DECISION literals: reason wire bytes and their
    /// soft/hard effect class. A transposed byte table (e.g. gdpr=2) fails
    /// here, not at a remote receiver.
    #[test]
    fn tombstone_reason_wire_bytes_match_pinned_table() {
        let cases = [
            (TombstoneReason::UserDelete, 1_u8, false),
            (TombstoneReason::UserHardDelete, 2, true),
            (TombstoneReason::GdprDelete, 3, true),
            (TombstoneReason::PolicyDelete, 4, true),
        ];
        for (reason, wire_byte, hard) in cases {
            assert_eq!(reason.wire_byte(), wire_byte, "{reason:?} wire byte");
            assert_eq!(
                TombstoneReason::from_wire_byte(wire_byte),
                Some(reason),
                "{reason:?} round-trip"
            );
            assert_eq!(reason.is_hard(), hard, "{reason:?} effect class");
        }
        // Byte 0 is RESERVED (= hard) and every byte above the table is
        // unknown (= hard): neither may decode to a known reason.
        for unknown in [0_u8, 5, 17, 120, 255] {
            assert_eq!(
                TombstoneReason::from_wire_byte(unknown),
                None,
                "byte {unknown} must not decode to a known reason"
            );
        }
    }

    #[test]
    fn delete_reason_maps_onto_wire_reason() {
        let cases = [
            (DeleteReason::UserDelete, TombstoneReason::UserDelete),
            (
                DeleteReason::UserHardDelete,
                TombstoneReason::UserHardDelete,
            ),
            (DeleteReason::GdprDelete, TombstoneReason::GdprDelete),
            (DeleteReason::PolicyDelete, TombstoneReason::PolicyDelete),
        ];
        for (delete_reason, wire_reason) in cases {
            assert_eq!(TombstoneReason::from(delete_reason), wire_reason);
        }
    }

    /// Pinned layout `[reason:1][deleted_at:8 LE][request_id:16]` asserted
    /// byte-by-byte: a big-endian or offset-shifted encoder fails here.
    #[test]
    fn tombstone_value_v2_encodes_exact_byte_layout() {
        let value = TombstoneValueV2 {
            reason: TombstoneReason::GdprDelete,
            deleted_at: 0x0102_0304_0506_0708,
            request_id: *b"0123456789abcdef",
        };
        let encoded = value.encode();
        assert_eq!(encoded.len(), TOMBSTONE_VALUE_V2_LEN);
        assert_eq!(encoded[0], 3, "offset 0 = reason wire byte");
        assert_eq!(
            &encoded[1..9],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            "offsets 1..9 = deleted_at u64 LITTLE-endian"
        );
        assert_eq!(
            &encoded[9..25],
            b"0123456789abcdef",
            "offsets 9..25 = raw request UUID bytes"
        );
    }

    /// Table-driven decode: every non-v2-soft shape MUST decode as HARD
    /// (fail-closed: over-purge, never under-delete). The expectations are
    /// written as literals, never round-tripped through the encoder.
    #[test]
    fn decode_tombstone_value_table() {
        struct Case {
            name: &'static str,
            input: Vec<u8>,
            want_reason: Option<TombstoneReason>,
            want_hard: bool,
            want_deleted_at: u64,
            want_request_id: Option<[u8; 16]>,
        }

        let v2 = |reason_byte: u8| -> Vec<u8> {
            let mut out = vec![reason_byte];
            out.extend_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00]);
            out.extend_from_slice(&[0xA5; 16]);
            out
        };

        let cases = [
            Case {
                name: "v2 soft user_delete",
                input: v2(1),
                want_reason: Some(TombstoneReason::UserDelete),
                want_hard: false,
                want_deleted_at: 0xDEAD_BEEF,
                want_request_id: Some([0xA5; 16]),
            },
            Case {
                name: "v2 hard user_hard_delete",
                input: v2(2),
                want_reason: Some(TombstoneReason::UserHardDelete),
                want_hard: true,
                want_deleted_at: 0xDEAD_BEEF,
                want_request_id: Some([0xA5; 16]),
            },
            Case {
                name: "v2 hard gdpr_delete",
                input: v2(3),
                want_reason: Some(TombstoneReason::GdprDelete),
                want_hard: true,
                want_deleted_at: 0xDEAD_BEEF,
                want_request_id: Some([0xA5; 16]),
            },
            Case {
                name: "v2 hard policy_delete",
                input: v2(4),
                want_reason: Some(TombstoneReason::PolicyDelete),
                want_hard: true,
                want_deleted_at: 0xDEAD_BEEF,
                want_request_id: Some([0xA5; 16]),
            },
            Case {
                name: "reserved byte 0 decodes as hard",
                input: v2(0),
                want_reason: None,
                want_hard: true,
                want_deleted_at: 0xDEAD_BEEF,
                want_request_id: Some([0xA5; 16]),
            },
            Case {
                name: "unknown reason byte 5 decodes as hard",
                input: v2(5),
                want_reason: None,
                want_hard: true,
                want_deleted_at: 0xDEAD_BEEF,
                want_request_id: Some([0xA5; 16]),
            },
            Case {
                name: "unknown reason byte 255 decodes as hard",
                input: v2(255),
                want_reason: None,
                want_hard: true,
                want_deleted_at: 0xDEAD_BEEF,
                want_request_id: Some([0xA5; 16]),
            },
            Case {
                name: "legacy 8-byte value decodes as hard with LE deleted_at",
                input: vec![0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00],
                want_reason: None,
                want_hard: true,
                want_deleted_at: 0xDEAD_BEEF,
                want_request_id: None,
            },
            Case {
                name: "empty value decodes as hard",
                input: Vec::new(),
                want_reason: None,
                want_hard: true,
                want_deleted_at: 0,
                want_request_id: None,
            },
            Case {
                name: "24-byte value decodes as hard",
                input: vec![1; 24],
                want_reason: None,
                want_hard: true,
                want_deleted_at: 0,
                want_request_id: None,
            },
            Case {
                name: "26-byte value decodes as hard",
                input: vec![1; 26],
                want_reason: None,
                want_hard: true,
                want_deleted_at: 0,
                want_request_id: None,
            },
        ];

        for case in cases {
            let decoded = decode_tombstone_value(&case.input);
            assert_eq!(decoded.reason, case.want_reason, "{}: reason", case.name);
            assert_eq!(decoded.is_hard(), case.want_hard, "{}: effect", case.name);
            assert_eq!(
                decoded.deleted_at, case.want_deleted_at,
                "{}: deleted_at",
                case.name
            );
            assert_eq!(
                decoded.request_id, case.want_request_id,
                "{}: request_id",
                case.name
            );
        }
    }

    /// The window label used by the `pt:` marker must follow the pinned
    /// ARCH-0023b `YYYY-MM` format and clamp in BOTH feature sets —
    /// `sync::types::WindowKey::from_timestamp` delegates here.
    #[test]
    fn window_label_format_and_clamp() {
        // 2026-02-15 ≈ unix 1_771_027_200 (same literal as the sync-side
        // WindowKey test, so the delegation cannot drift unnoticed).
        assert_eq!(window_label_from_timestamp(1_771_027_200), "2026-02");
        assert_eq!(window_label_from_timestamp(0), "1970-01");
        for ts in [i64::MAX as u64, u64::MAX] {
            assert_eq!(window_label_from_timestamp(ts), "9999-12", "ts={ts}");
        }
    }

    #[test]
    fn pending_tombstone_key_layout() {
        let id = EntityId::from_bytes([0x7E; 16]).expect("valid id");
        assert_eq!(
            pending_tombstone_key("2026-02", &id),
            format!("pt:2026-02:{}", id.to_hex())
        );
    }

    /// Pinned `dt:` marker: GLOBAL key (no window segment) and the exact
    /// 25 B `[reason:1][deleted_at:8 LE][request_id:16]` value, asserted as
    /// literals — including the destructive-default/NIL fallbacks for
    /// legacy/malformed wire shapes.
    #[test]
    fn local_hard_delete_marker_layout() {
        let id = EntityId::from_bytes([0x7E; 16]).expect("valid id");
        assert_eq!(
            local_hard_delete_key(&id),
            format!("dt:{}", id.to_hex()),
            "key must be global — deliberately NO window segment"
        );
        assert_eq!(local_hard_delete_key(&id).len(), 3 + 32);

        // Known hard reason: wire fields verbatim.
        let mut wire = vec![3_u8]; // gdpr_delete
        wire.extend_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        wire.extend_from_slice(&[0xA5; 16]);
        let value = decode_tombstone_value(&wire).local_hard_delete_marker_value();
        assert_eq!(value.len(), TOMBSTONE_VALUE_V2_LEN);
        assert_eq!(value[0], 3, "offset 0 = reason wire byte");
        assert_eq!(
            &value[1..9],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            "offsets 1..9 = deleted_at u64 LITTLE-endian"
        );
        assert_eq!(&value[9..25], &[0xA5; 16], "offsets 9..25 = request id");

        // Malformed shape: destructive default reason + zeroed fields.
        let value = decode_tombstone_value(&[]).local_hard_delete_marker_value();
        assert_eq!(value[0], 2, "fallback reason = user_hard_delete");
        assert_eq!(&value[1..9], &[0_u8; 8]);
        assert_eq!(&value[9..25], &[0_u8; 16], "fallback request id = NIL");
    }

    /// ONE-1140 (OD-6) attestation transcript literal, verified against the
    /// engine's signer with a FIXED key and a hand-assembled transcript:
    /// `b"oneiron/receipt-att/v1" || entity_id:16 || envelope_header:25
    /// ([type 120][3 × u64 BE]) || body-with-verification-EMPTY` — where the
    /// empty-verification tail is rebuilt by SPLICING the stored body at the
    /// verification value and substituting fixmap(0) (0x80). A wrong domain
    /// string, header endianness, splice point, or att_ key ordering fails
    /// here against real Ed25519 verification.
    #[test]
    fn receipt_attestation_transcript_literal() {
        use ed25519_dalek::{Signature, SigningKey, Verifier};

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let identity = crate::identity::DeviceIdentity {
            client_id: 0x0123_4567_89ab_cdef,
            signing_key: signing_key.clone(),
        };
        let receipt_id = EntityId::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let subject = EntityId::from_hex("101112131415161718191a1b1c1d1e1f").unwrap();
        let input = RedactionReceiptInput {
            request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
            scope: RedactionScope::entity(&subject),
            reason: DeleteReason::GdprDelete,
            requested_at: 100,
            soft_complete_at: 101,
            hard_purge_complete_at: 0x0102_0304_0506_0708,
            sweep_queued_at: Some(102),
        };
        let body = encode_redaction_audit_receipt(input, &receipt_id, &identity).unwrap();

        // The verification map must be the FINAL entry in bytes, its four
        // att_ keys in sorted (BTreeMap) order. Locate the value by the
        // fixstr(12) "verification" key header — the splice point literal.
        let key_pattern: &[u8] = b"\xacverification";
        let key_pos = body
            .windows(key_pattern.len())
            .rposition(|window| window == key_pattern)
            .expect("verification key present");
        let value_offset = key_pos + key_pattern.len();
        assert_eq!(
            body[value_offset], 0x84,
            "verification value is a fixmap(4) of the att_ entries"
        );

        // Parse the verification map and pin the att_ literals.
        let parsed: rmpv::Value = rmpv::decode::read_value(&mut &body[..]).unwrap();
        let entries = match parsed {
            rmpv::Value::Map(entries) => entries,
            other => panic!("body must be a map, got {other:?}"),
        };
        let (last_key, last_value) = entries.last().expect("non-empty");
        assert_eq!(
            last_key.as_str(),
            Some("verification"),
            "verification must be the final body map entry (tail-splice pin)"
        );
        let att = match last_value {
            rmpv::Value::Map(att) => att,
            other => panic!("verification must be a map, got {other:?}"),
        };
        let att_keys: Vec<&str> = att.iter().filter_map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            att_keys,
            vec!["att_client", "att_pk", "att_sig", "att_v"],
            "att_ entries in sorted (BTreeMap) byte order"
        );
        assert_eq!(att[0].1.as_str(), Some("0123456789abcdef"));
        assert_eq!(
            att[1].1.as_str().unwrap(),
            hex_lower(&signing_key.verifying_key().to_bytes())
        );
        assert_eq!(att[3].1.as_str(), Some("1"));

        // Hand-assemble the transcript per the OD-6 literals and verify the
        // embedded signature with real Ed25519.
        let mut msg = Vec::new();
        msg.extend_from_slice(b"oneiron/receipt-att/v1");
        msg.extend_from_slice(receipt_id.as_bytes());
        msg.push(120u8); // ENTITY_TYPE_REDACTION_AUDIT
        for _ in 0..3 {
            // occurred_start == occurred_end == learned_at, u64 BE.
            msg.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        }
        msg.extend_from_slice(&body[..value_offset]);
        msg.push(0x80); // verification = {} in the signed tail
        let sig_hex = att[2].1.as_str().unwrap();
        assert_eq!(sig_hex.len(), 128);
        let sig_bytes: Vec<u8> = (0..128)
            .step_by(2)
            .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16).unwrap())
            .collect();
        let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        signing_key
            .verifying_key()
            .verify(&msg, &signature)
            .expect("att_sig must verify over the hand-assembled OD-6 transcript");

        // And the shared header helper emits exactly the bytes the test
        // assembled (the signer/storage single assembly point).
        assert_eq!(
            &receipt_envelope_header(0x0102_0304_0506_0708)[..],
            &msg[38..63]
        );
    }
}
