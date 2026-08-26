use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entity_id::EntityId;

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
