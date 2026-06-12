//! ARCH-0038 deletion/redaction contract types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::EntityId;

pub(crate) const HARD_ERASE_SWEEP_PREFIX: &[u8] = b"h:";
pub(crate) const LAST_HARD_ERASE_SWEEP_SEQ_KEY: &[u8] = b"m:last_hard_erase_sweep_seq";
pub(crate) const HARD_ERASE_SWEEP_SLA_SECS: u64 = 30 * 86_400;

/// Length of the `dt:` local hard-delete marker value:
/// `[reason:1][deleted_at:8 LE][request_id:16]`.
#[cfg(feature = "sync")]
pub(crate) const LOCAL_HARD_DELETE_MARKER_LEN: usize = 25;

/// `dt:` local hard-delete marker key (ONE-1122), stored in `sync_state`.
///
/// Key = `dt:{entity_id_hex}` (32-char lowercase hex, GLOBAL — deliberately
/// NO window segment, so a window-shuffled re-put cannot dodge the gate).
/// Written ONLY on HARD delete outcomes, in the SAME LMDB txn as the
/// active-store purge. Permanent, no GC. Semantics are PRESENCE-ONLY: gates
/// never decode the value; the 25-byte body is informational.
#[cfg(feature = "sync")]
pub(crate) fn local_hard_delete_marker_key(id: &EntityId) -> String {
    format!("dt:{}", id.to_hex())
}

/// Encodes the pinned `[reason:1][deleted_at:8 LE][request_id:16]` marker
/// value. Reason bytes follow the ONE-1132 pinned tombstone wire table
/// (`user_delete`=1 — soft, never written here; `user_hard_delete`=2;
/// `gdpr_delete`=3; `policy_delete`=4). Presence-only consumers must never
/// decode this.
#[cfg(feature = "sync")]
pub(crate) fn encode_local_hard_delete_marker(
    reason: DeleteReason,
    deleted_at: u64,
    request_id: &[u8; 16],
) -> [u8; LOCAL_HARD_DELETE_MARKER_LEN] {
    let reason_byte: u8 = match reason {
        DeleteReason::UserDelete => 1,
        DeleteReason::UserHardDelete => 2,
        DeleteReason::GdprDelete => 3,
        DeleteReason::PolicyDelete => 4,
    };
    let mut out = [0_u8; LOCAL_HARD_DELETE_MARKER_LEN];
    out[0] = reason_byte;
    out[1..9].copy_from_slice(&deleted_at.to_le_bytes());
    out[9..25].copy_from_slice(request_id);
    out
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Serialize)]
struct RedactionAuditReceipt {
    request_id: String,
    scope: RedactionScope,
    reason: String,
    requested_at: u64,
    soft_complete_at: u64,
    hard_purge_complete_at: u64,
    sweep_queued_at: Option<u64>,
    sweep_complete_at: Option<u64>,
    affected_revision_ids: Vec<String>,
    verification: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct HardEraseSweepJob {
    scope: HardEraseSweepScope,
    retry_state: HardEraseRetryState,
}

#[derive(Debug, Serialize)]
struct HardEraseSweepScope {
    entity_ids: Vec<String>,
    revision_ids: Vec<String>,
    /// ARCH-0038 delete-interplay seam: "body_snapshot_ref lets the queued
    /// historical-carrier sweep locate residual snapshot/update bytes"
    /// (contracts.ts retractionRules DELETE). Opaque lowercase-hex ids only;
    /// the consuming executor is ONE-1091 (deferred).
    body_snapshot_refs: Vec<String>,
    carrier_classes: Vec<String>,
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

#[derive(Debug, Serialize)]
struct HardEraseRetryState {
    attempt_count: u32,
    next_attempt_at: u64,
    last_error_code: Option<String>,
    queued_at: u64,
    deadline_at: u64,
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

pub(crate) fn encode_redaction_audit_receipt(input: RedactionReceiptInput) -> Result<Vec<u8>> {
    let receipt = RedactionAuditReceipt {
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
}
