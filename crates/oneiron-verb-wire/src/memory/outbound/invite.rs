//! Moved from `crates/oneiron/src/memory/outbound/invite.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Connector key the calendar invite surface schedules against. CAL-04
/// (ONE-1786) landed the `calendar` connector manifest, so
/// `outbound_verb_contract` now resolves this pair.
pub const CALENDAR_INVITE_OUTBOUND_CHANNEL: &str = "calendar";

/// Outbound verb the calendar invite surface schedules.
///
/// This string is the seam with CAL-04 (ONE-1786), which registered
/// `calendar.invite` in `COMMON_OUTBOUND_VERB_KINDS` and branches on it at the
/// dispatch chokepoint. A shorter local spelling would leave that branch dead
/// on arrival — the invite would schedule as a generic draft and never reach
/// the iMIP payload codec — so the value is pinned to CAL-04's, not to this
/// module's vocabulary.
pub const CALENDAR_INVITE_OUTBOUND_VERB: &str = "calendar.invite";

/// iMIP method the invite surface accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum CalendarInviteSurfaceMethod {
    /// `METHOD:REQUEST` — create or update an invitation.
    Request,
    /// `METHOD:CANCEL` — withdraw an invitation.
    Cancel,
}

impl CalendarInviteSurfaceMethod {
    /// Wire token (`REQUEST` / `CANCEL`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "REQUEST",
            Self::Cancel => "CANCEL",
        }
    }

    /// Parses the wire token. The set is closed: an unrecognized iMIP method is
    /// a typed rejection at the boundary, never a defaulted `REQUEST`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "REQUEST" => Some(Self::Request),
            "CANCEL" => Some(Self::Cancel),
            _ => None,
        }
    }
}

/// What issued one invite, as its host bound it (FIX 8796). It rides beside
/// the five-field body, never inside it, so no caller asserts its own
/// trigger or session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarInviteOrigin {
    /// A caller's own act (`agent_immediate`). `session_ref` is the session
    /// its host bound, when it bound one: the intent's trigger ref and its
    /// TASK's originating session. With none, the trigger ref is the invite
    /// revision's own ref.
    Immediate { session_ref: Option<String> },
    /// A Dreamer gap-queue job's act (`gap_queue`), fired by `queue_ref`.
    GapQueue { queue_ref: String },
}
