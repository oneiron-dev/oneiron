//! Calendar admission at the outbound publication writer.

use super::admission::{CalendarInviteAdmission, admit_calendar_invite_in_txn, refused};
use super::payload::{CALENDAR_INVITE_VERB, CalendarInvitePayload};
use crate::calendar::CalendarError;
use crate::{EntityId, Vault};
use serde::Deserialize;

#[derive(Deserialize)]
struct InvitePublication {
    target: String,
    counterparty_ref: Option<String>,
    calendar_invite: CalendarInvitePayload,
}

/// Non-calendar effects may be non-JSON. An invite, however, must carry its
/// exact body and target, and can only publish through the calendar verb.
pub(crate) fn admit_frozen_calendar_invite_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    tool: &str,
    actor: Option<EntityId>,
    bytes: &[u8],
    now: u64,
) -> Result<Option<CalendarInviteAdmission>, CalendarError> {
    if tool != CALENDAR_INVITE_VERB {
        if serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .is_some_and(|value| value.get("calendar_invite").is_some())
        {
            return Err(refused("calendar invite sidecars require calendar.invite"));
        }
        return Ok(None);
    }
    let frozen: InvitePublication = serde_json::from_slice(bytes)
        .map_err(|_| refused("calendar.invite requires its exact frozen invite and target"))?;
    let recipient = frozen.calendar_invite.recipient.trim();
    if !frozen.target.trim().eq_ignore_ascii_case(recipient)
        || frozen
            .counterparty_ref
            .as_deref()
            .is_some_and(|party| !party.trim().eq_ignore_ascii_case(recipient))
    {
        return Err(refused("calendar.invite must go to its admitted recipient"));
    }
    let actor = actor.ok_or_else(|| refused("calendar.invite requires an acting principal"))?;
    admit_calendar_invite_in_txn(vault, txn, actor, &frozen.calendar_invite, now).map(Some)
}
