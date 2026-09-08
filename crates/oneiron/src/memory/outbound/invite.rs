//! Closed five-field calendar-invite payload and its draft encoding.

use serde::{Deserialize, Serialize};

use super::super::{MemoryError, MemoryResult};
use super::types::OutboundDraftInput;
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
/// module's vocabulary, and
/// `calendar::invite::tests::verb_and_channel_match_the_cal_09_surface_constants`
/// keeps the two spellings from drifting apart.
pub const CALENDAR_INVITE_OUTBOUND_VERB: &str = "calendar.invite";

/// iMIP method the invite surface accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// C7's exact five-field invite payload.
///
/// Closed on purpose: an [`OutboundDraftInput`] here would let a caller choose
/// its own channel, verb, and trigger, which is precisely the bypass the
/// invite-through-the-gate rule exists to prevent.
///
/// This type *is* the payload CAL-04 (ONE-1786) exact-decodes — five typed
/// fields, uppercase iMIP method, closed to unknown keys. It stays typed all
/// the way to [`Self::outbound_draft`]; nothing here re-parses a key back into
/// a method, uid, or sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarInviteSurfaceInput {
    /// iMIP method.
    pub method: CalendarInviteSurfaceMethod,
    /// EVENT UID the invite addresses.
    pub uid: String,
    /// iTIP SEQUENCE of this revision.
    pub sequence: u32,
    /// Blob ref of the rendered ICS payload.
    pub ics_blob_ref: String,
    /// Delivery target.
    pub recipient: String,
}

impl CalendarInviteSurfaceInput {
    /// Deterministic idempotency key: a retry of the same revision to the same
    /// recipient coalesces instead of scheduling a second invite.
    #[must_use]
    pub fn idempotency_key(&self) -> String {
        format!(
            "calendar.invite:{}:{}:{}:{}",
            self.method.as_str(),
            self.uid,
            self.sequence,
            self.recipient
        )
    }

    /// Trigger ref carried onto the intent.
    #[must_use]
    pub fn trigger_ref(&self) -> String {
        format!("calendar.invite:{}:{}", self.uid, self.sequence)
    }

    /// The generic outbound draft this invite schedules.
    ///
    /// One named site for the whole invite→draft encoding, so the seam CAL-04
    /// (ONE-1786) picks up is testable before its half exists. What is pinned
    /// here: the verb is CAL-04's `calendar.invite`, the channel is the
    /// `calendar` connector, and `recipient`/`ics_blob_ref` ride the typed
    /// `target`/`content_ref` fields.
    ///
    /// KNOWN HOLE, CLOSED BY CAL-04 (ONE-1786): `method`, `uid`, and
    /// `sequence` had no typed home on [`OutboundDraftInput`] or
    /// `OutboundIntentDraft` on the CAL-09 baseline, so they reached the
    /// chokepoint only inside the derived idempotency/trigger strings. CAL-04
    /// added the typed channel it owns —
    /// [`crate::calendar::CalendarInvitePayload`], carried beside the draft
    /// through `Self::frozen_payload` below — so nothing here re-parses a key
    /// back into a method, uid, or sequence and the public surface above is
    /// unchanged.
    #[must_use]
    pub fn outbound_draft(&self) -> OutboundDraftInput {
        OutboundDraftInput {
            verb: CALENDAR_INVITE_OUTBOUND_VERB.to_owned(),
            channel: CALENDAR_INVITE_OUTBOUND_CHANNEL.to_owned(),
            target: self.recipient.clone(),
            on_behalf_of: None,
            content_ref: Some(self.ics_blob_ref.clone()),
            idempotency_key: Some(self.idempotency_key()),
            dedupe_key: None,
            // This surface carries no session, so it uses the queue trigger
            // class rather than fabricating an originating-session ref.
            trigger: "gap_queue".to_owned(),
            trigger_ref: self.trigger_ref(),
            job_ref: None,
            occurred_at: None,
        }
    }

    /// The exact five-field body CAL-04 freezes beside the draft.
    ///
    /// The one fill site for the typed payload channel: the surface's own five
    /// typed fields become the invite layer's five typed fields, in order, with
    /// no string round-trip. Crate-private on purpose — the public invite
    /// surface is [`Self`] and nothing else, so no caller can hand the
    /// chokepoint a payload that disagrees with the draft it schedules.
    pub(crate) fn frozen_payload(&self) -> crate::calendar::CalendarInvitePayload {
        crate::calendar::CalendarInvitePayload {
            method: match self.method {
                CalendarInviteSurfaceMethod::Request => {
                    crate::calendar::CalendarInviteMethod::Request
                }
                CalendarInviteSurfaceMethod::Cancel => {
                    crate::calendar::CalendarInviteMethod::Cancel
                }
            },
            uid: self.uid.clone(),
            sequence: self.sequence,
            ics_blob_ref: self.ics_blob_ref.clone(),
            recipient: self.recipient.clone(),
        }
    }

    pub(super) fn validate(&self) -> MemoryResult<()> {
        for (field, value) in [
            ("uid", self.uid.as_str()),
            ("ics_blob_ref", self.ics_blob_ref.as_str()),
            ("recipient", self.recipient.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(MemoryError::bad_request_with(
                    format!("calendar invite {field} must not be blank"),
                    &["Supply method, uid, sequence, ics_blob_ref, and recipient."],
                ));
            }
        }
        Ok(())
    }
}
