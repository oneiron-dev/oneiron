//! Frozen five-field invite payload contract and its decoder.

use super::CalendarError;
use super::admission::refused;
use crate::outbound_intent_ledger::OutboundToolDescriptor;
use serde::{Deserialize, Serialize};

/// Connector key iMIP invites dispatch through.
///
/// Equal to [`crate::memory::CALENDAR_INVITE_OUTBOUND_CHANNEL`] by law — CAL-09
/// pinned the surface to CAL-04's spelling before CAL-04 existed, and
/// `tests::verb_and_channel_match_the_cal_09_surface_constants` keeps the two
/// from drifting.
pub const CALENDAR_INVITE_CHANNEL: &str = "calendar";

/// The outbound verb this adapter registers.
///
/// Sole-owner registration: this exact string is what CAL-04 appends to
/// `COMMON_OUTBOUND_VERB_KINDS` and what the `calendar` connector manifest
/// exposes. No other lane adds it.
pub const CALENDAR_INVITE_VERB: &str = "calendar.invite";

/// Media type of the iMIP part and of the blob artifact that carries it.
pub const CALENDAR_INVITE_MEDIA_TYPE: &str = "text/calendar";

/// Attachment filename the connector puts on the `text/calendar` part.
pub const CALENDAR_INVITE_PART_FILENAME: &str = "invite.ics";

/// OF-327 tool descriptor for `calendar.invite`.
///
/// `read_only_hint: Some(false)` keeps the ledger classifier on the Effectful
/// path — an invite is a real external effect and must earn a durable intent.
/// `idempotency_supported_hint: Some(true)` is the truth of iMIP: replaying the
/// same `(UID, SEQUENCE, METHOD)` to the same attendee is a no-op in every
/// conforming client, which is exactly why a retry may replay frozen bytes.
pub const CALENDAR_INVITE_TOOL_DESCRIPTOR: OutboundToolDescriptor = OutboundToolDescriptor {
    read_only_hint: Some(false),
    idempotency_supported_hint: Some(true),
};

/// iMIP method carried by one invite.
///
/// Closed on purpose. Outlook treats a `VEVENT` with no explicit `METHOD` as a
/// brand-new event rather than an update, so a defaulted method is a duplicate
/// meeting in the recipient's calendar — the set never widens silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CalendarInviteMethod {
    /// `METHOD:REQUEST` — create or update an invitation.
    Request,
    /// `METHOD:CANCEL` — withdraw an invitation.
    Cancel,
}

impl CalendarInviteMethod {
    /// Wire token (`REQUEST` / `CANCEL`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "REQUEST",
            Self::Cancel => "CANCEL",
        }
    }

    /// Parses the wire token; anything outside the closed set is `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "REQUEST" => Some(Self::Request),
            "CANCEL" => Some(Self::Cancel),
            _ => None,
        }
    }
}

/// C7's exact frozen invite payload.
///
/// Five typed fields in a fixed order, closed to unknown keys. This is what the
/// dispatch pipeline freezes beside the intent and what the connector-send side
/// exact-decodes; a forged sixth key (a caller-asserted `has_consent`, say) is a
/// decode failure, not an ignored extra.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarInvitePayload {
    /// iMIP method.
    pub method: CalendarInviteMethod,
    /// EVENT UID the invite addresses. Minted once, reused forever.
    pub uid: String,
    /// iTIP SEQUENCE of this revision. Strictly increasing on the same UID.
    pub sequence: u32,
    /// Blob-artifact ref of the rendered ICS payload. The bytes stay in the
    /// blob store; only this reference is ever frozen.
    pub ics_blob_ref: String,
    /// Delivery target.
    pub recipient: String,
}

impl CalendarInvitePayload {
    /// Rejects blank required fields before any vault work.
    pub(super) fn validate_shape(&self) -> Result<(), CalendarError> {
        for (field, value) in [
            ("uid", self.uid.as_str()),
            ("ics_blob_ref", self.ics_blob_ref.as_str()),
            ("recipient", self.recipient.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(refused(format!("{field} must not be blank")));
            }
        }
        Ok(())
    }
}

/// The frozen-payload envelope the dispatch pipeline writes.
///
/// The frozen bytes are the flattened intent plus optional sidecars; this
/// reader picks out the invite sidecar without re-deriving anything else, the
/// same discipline `frozen_payload_hygiene_headers` follows for CA-05 headers.
#[derive(Deserialize)]
struct FrozenInviteEnvelope {
    calendar_invite: CalendarInvitePayload,
}

/// Exact-decodes the invite payload out of frozen outbound bytes.
///
/// # Errors
///
/// [`CalendarError::InviteRefused`] when the bytes carry no invite sidecar, or
/// carry one the five-field contract does not accept. A `calendar.invite` call
/// whose payload the engine cannot vouch for never reaches the wire.
pub fn decode_frozen_calendar_invite(
    payload: &[u8],
) -> Result<CalendarInvitePayload, CalendarError> {
    let envelope: FrozenInviteEnvelope = serde_json::from_slice(payload)
        .map_err(|_| refused("frozen payload carries no exact five-field invite body"))?;
    envelope.calendar_invite.validate_shape()?;
    Ok(envelope.calendar_invite)
}
