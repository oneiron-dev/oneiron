//! Builds the outbound dispatch for the first confirm's invite and commits its passport.

use super::authorization::{booking_page_invites_authorizes, confirmed_booking_binding};
use super::codec::{calendar_wrap, engine_failure, refused};
use super::mint::live_page_invite_grant;
use super::types::{BookingPageInviteContext, CONFIRM_INVITE_TZ_LABEL, ConfirmedBookingInvite};
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::blob_artifact::BlobVersionProvenance;
use crate::booking::constraint::BookingError;
use crate::booking::lifecycle::{ConfirmReceipt, hex_lower};
use crate::calendar::{
    CALENDAR_INVITE_CHANNEL, CALENDAR_INVITE_VERB, CalendarInviteAdmission, CalendarInviteMethod,
    CalendarInvitePayload, ImipEmitRequest, admit_calendar_invite, decode_frozen_calendar_invite,
    emit_imip_ics, persist_imip_blob,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::outbound_grant::StandingOutboundGrantStatus;
use crate::outbound_intent_ledger::{IntentId, intent_ledger_records};
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// Domain tag for the confirm invite's stable ledger identity. One booking's
/// first REQUEST has ONE logical send ref, so a repeated dispatch collapses
/// onto the intent it already froze rather than paying for a second one.
pub(super) const CONFIRM_INVITE_INTENT_DOMAIN: &[u8] = b"oneiron.booking.confirm_invite.v1\0";

/// Domain tag for the rendered invite's blob-artifact id.
pub(super) const CONFIRM_INVITE_BLOB_DOMAIN: &[u8] = b"oneiron.booking.confirm_invite_blob.v1\0";

/// The sink the lifecycle names when a turn carries no invite dispatch
/// context. It is never executed — the confirm hook only fires when a real
/// sink was threaded — and fails closed if a future path ever reaches it.
pub(crate) struct NoConfirmInviteSink;

impl OutboundExecutionSink for NoConfirmInviteSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::failed("booking lifecycle turn carries no invite connector")
    }
}

/// Carries one confirmed booking's `REQUEST` through the ordinary outbound
/// door and returns the durable intent it earned.
///
/// The fixed order, and why:
///
/// 1. Read the booking's persisted page/booker binding. The recipient is
///    never a parameter — a caller cannot redirect an invite.
/// 2. Verify the named grant is live and authorizes exactly this booking.
/// 3. Build CAL-04's frozen five fields, reusing the once-minted UID and the
///    receipt's current SEQUENCE.
/// 4. Admit through [`admit_calendar_invite`], so vault-only hygiene
///    hydration and the UID/SEQUENCE law run BEFORE the gate. A replay
///    (the same revision, same content) sends nothing and answers with the
///    intent the first pass recorded.
/// 5. Dispatch. Gate, opt-out wall, rate/budget, intent ledger, and connector
///    are the ordinary ones; a denied invite records no intent and therefore
///    fails here.
/// 6. Move the passport head only AFTER the frozen intent exists, so no
///    bumped SEQUENCE survives without the intent that spent it.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when the booking, the grant, the
/// hygiene rows, or the gate refuse; [`BookingError::SlotOracle`] on store
/// failures.
pub fn enqueue_confirm_invite(
    vault: &Vault,
    actor: EntityId,
    grant_ref: EntityId,
    invite: &ConfirmedBookingInvite<'_>,
    sink: &mut impl OutboundExecutionSink,
    now: u64,
) -> Result<IntentId, BookingError> {
    let Some(binding) = confirmed_booking_binding(vault, &invite.booking_ref)? else {
        return Err(refused(
            "this booking carries no confirmed page and booker binding",
        ));
    };
    let Some(grant) = vault
        .get_standing_outbound_grant(&grant_ref)
        .map_err(|error| engine_failure("standing grant read", error))?
    else {
        return Err(refused("the named booking page grant does not exist"));
    };
    if grant.status != StandingOutboundGrantStatus::Active || grant.revoked_at.is_some() {
        return Err(refused("the named booking page grant is not live"));
    }
    if !booking_page_invites_authorizes(
        vault,
        &grant.scope,
        &BookingPageInviteContext {
            booking_ref: invite.booking_ref,
            verb_kind: CALENDAR_INVITE_VERB,
            requested_recipient: &binding.recipient,
        },
    )? {
        return Err(refused(
            "the named grant does not authorize invites for this booking",
        ));
    }

    let payload = CalendarInvitePayload {
        method: CalendarInviteMethod::Request,
        uid: invite.uid.to_owned(),
        sequence: invite.sequence,
        ics_blob_ref: invite.ics_blob_ref.to_owned(),
        recipient: binding.recipient.clone(),
    };

    let admission = admit_calendar_invite(vault, actor, &payload, now).map_err(calendar_wrap)?;
    if !admission.moves_state() {
        // A replay of the exact revision. One booking earns one REQUEST, so
        // this answers with the intent already recorded rather than sending a
        // second copy of it.
        return recorded_intent_id(vault, &payload)?
            .ok_or_else(|| refused("this invite replayed with no recorded outbound intent"));
    }

    let intent_ref = confirm_invite_intent_ref(&invite.booking_ref, invite.uid, invite.sequence);
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(
            actor.to_hex(),
            CALENDAR_INVITE_VERB,
            CALENDAR_INVITE_CHANNEL,
            binding.recipient.clone(),
        )
        .idempotency_key(intent_ref.clone()),
        OutboundIntentTrigger::agent_immediate(format!("booking:{}", invite.booking_ref.to_hex())),
    );
    let request = OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        now,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(binding.recipient)
    .calendar_invite(payload.clone());
    vault
        .dispatch_outbound_intent(request, sink)
        .map_err(|error| refused(format!("calendar invite dispatch refused: {error}")))?;

    // Success IS the durable intent: a gate denial records none, so there is
    // nothing to return and nothing moved.
    let intent_id = recorded_intent_id(vault, &payload)?
        .ok_or_else(|| refused("the outbound door recorded no intent for this invite"))?;
    commit_invite_passport(vault, &admission, now)?;
    Ok(intent_id)
}

/// Assembles and dispatches the confirm-time invite from committed state.
///
/// The lifecycle's Booked arm holds only the confirm receipt, so everything
/// else is READ: the page/booker binding and the summary from booking claims,
/// the live page grant from the principal index, the organizer from the
/// actor's ACTIVE sending identity, and the instant from the EVENT's stored
/// occurrence. The document itself is rendered by CAL-04's emitter and stored
/// as a blob; booking holds the reference and never the media type.
///
/// Every missing fact refuses, which the caller swallows: a booking with no
/// live grant, no sending identity, or no readable binding simply sends no
/// invite.
pub(crate) fn dispatch_confirm_booking_invite(
    vault: &Vault,
    actor: EntityId,
    receipt: &ConfirmReceipt,
    sink: &mut impl OutboundExecutionSink,
    now: u64,
) -> Result<IntentId, BookingError> {
    let booking_ref = receipt.calendar.event_ref;
    let Some(binding) = confirmed_booking_binding(vault, &booking_ref)? else {
        return Err(refused(
            "this booking carries no confirmed page and booker binding",
        ));
    };
    let Some((grant_ref, _)) = live_page_invite_grant(vault, &actor.to_hex(), &binding.page_ref)?
    else {
        return Err(refused(
            "this page carries no live booking page invite grant",
        ));
    };
    let organizer = crate::booking::lifecycle::booking_invite_identity(vault, &booking_ref)?
        .map(|(organizer, _)| organizer)
        .or(sending_address(vault, actor)?);
    let Some(organizer) = organizer else {
        return Err(refused(
            "no active sending identity carries this booking's invite",
        ));
    };
    let occurrence = booking_occurrence(vault, &booking_ref)?;
    let ics = emit_imip_ics(&ImipEmitRequest {
        method: CalendarInviteMethod::Request,
        uid: receipt.calendar.uid.clone(),
        sequence: receipt.calendar.sequence,
        organizer,
        attendees: vec![binding.recipient.clone()],
        summary: binding.event_type,
        starts_at_utc: occurrence.start,
        ends_at_utc: occurrence.end,
        tz_label: CONFIRM_INVITE_TZ_LABEL.to_owned(),
        dtstamp_utc: now,
    })
    .map_err(calendar_wrap)?;
    // Persisted exactly the way CAL-04 persists an invite document: the
    // artifact id is derived from `(booking, sequence)`, so a confirm replay
    // re-renders byte-identical content, lands on the same head, and appends
    // no second version.
    let blob_ref = persist_imip_blob(
        vault,
        &confirm_invite_blob_id(&booking_ref, receipt.calendar.sequence)?,
        "booking confirm invite",
        &ics,
        &BlobVersionProvenance::UserUpload,
        WriteActor::new(actor, EdgeActorClass::Human),
        now,
    )
    .map_err(calendar_wrap)?;
    enqueue_confirm_invite(
        vault,
        actor,
        grant_ref,
        &ConfirmedBookingInvite {
            booking_ref,
            uid: &receipt.calendar.uid,
            sequence: receipt.calendar.sequence,
            ics_blob_ref: &blob_ref,
        },
        sink,
        now,
    )
}

/// The intent-ledger id whose frozen body is exactly this invite.
///
/// `OutboundDispatchResult` carries no intent id, so the ledger is read back
/// and matched on the exact five-field body. UID + SEQUENCE + recipient are
/// unique to one booking's first REQUEST, so the match is unambiguous.
fn recorded_intent_id(
    vault: &Vault,
    payload: &CalendarInvitePayload,
) -> Result<Option<IntentId>, BookingError> {
    let records = intent_ledger_records(vault)
        .map_err(|error| refused(format!("intent ledger read failed: {error}")))?;
    for record in records {
        if record.tool != CALENDAR_INVITE_VERB {
            continue;
        }
        let Ok(frozen) = decode_frozen_calendar_invite(record.payload()) else {
            continue;
        };
        if &frozen == payload {
            return Ok(Some(record.id));
        }
    }
    Ok(None)
}

/// Applies CAL-04's passport head in its own transaction, after the intent.
fn commit_invite_passport(
    vault: &Vault,
    admission: &CalendarInviteAdmission,
    now: u64,
) -> Result<(), BookingError> {
    let mut wtxn = vault
        .store
        .env
        .write_txn()
        .map_err(|error| engine_failure("invite passport writer", error))?;
    admission
        .commit_in_txn(vault, &mut wtxn, now)
        .map_err(calendar_wrap)?;
    wtxn.commit()
        .map_err(|error| engine_failure("invite passport commit", error))?;
    Ok(())
}

/// The stable logical-send ref one booking's first REQUEST dispatches under.
fn confirm_invite_intent_ref(booking_ref: &EntityId, uid: &str, sequence: u32) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONFIRM_INVITE_INTENT_DOMAIN);
    hasher.update(booking_ref.as_bytes());
    hasher.update(&(uid.len() as u64).to_le_bytes());
    hasher.update(uid.as_bytes());
    hasher.update(&sequence.to_be_bytes());
    format!(
        "intent:booking_invite:{}",
        hex_lower(hasher.finalize().as_bytes())
    )
}

/// The blob-artifact id one booking revision's rendered document lives at.
fn confirm_invite_blob_id(booking_ref: &EntityId, sequence: u32) -> Result<EntityId, BookingError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONFIRM_INVITE_BLOB_DOMAIN);
    hasher.update(booking_ref.as_bytes());
    hasher.update(&sequence.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(bytes).map_err(|error| engine_failure("invite blob id", error))
}

/// The EVENT's stored occurrence, as the half-open `[start, end)` the booking
/// lane works in.
fn booking_occurrence(vault: &Vault, booking_ref: &EntityId) -> Result<TimeRange, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, booking_ref.as_bytes())
        .map_err(|error| engine_failure("booking event read", error))?
        .ok_or_else(|| refused("this booking's EVENT no longer exists"))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| refused("this booking's EVENT header did not parse"))?;
    Ok(TimeRange {
        start: header.occurred_start,
        end: header.occurred_end.saturating_add(1),
    })
}

/// The address the invite will actually leave from: the calendar connector's
/// own identity when one exists, otherwise the ordinary email identity — the
/// same order CAL-04's hygiene hydration resolves the sender in. An ambiguous
/// pair on one channel refuses rather than guessing.
pub(crate) fn sending_address(
    vault: &Vault,
    actor: EntityId,
) -> Result<Option<String>, BookingError> {
    for channel_class in [CALENDAR_INVITE_CHANNEL, "email"] {
        if let Some(address) = active_identity_address(vault, actor, channel_class)? {
            return Ok(Some(address));
        }
    }
    Ok(None)
}

fn active_identity_address(
    vault: &Vault,
    actor: EntityId,
    channel_class: &str,
) -> Result<Option<String>, BookingError> {
    let wanted = crate::counterparty_contact::normalize_channel_class(channel_class);
    let mut found: Option<String> = None;
    for id in vault
        .entities_by_type(ENTITY_TYPE_CHANNEL_IDENTITY)
        .map_err(|error| engine_failure("channel identity scan", error))?
    {
        let Some(identity) = vault
            .get_channel_identity(&id)
            .map_err(|error| engine_failure("channel identity read", error))?
        else {
            continue;
        };
        if !identity.may_send()
            || crate::counterparty_contact::normalize_channel_class(&identity.channel) != wanted
            || identity.binding.actor_ref() != Some(actor)
        {
            continue;
        }
        if found.is_some() {
            return Err(refused("multiple sending identities on this channel"));
        }
        found = Some(identity.address_or_handle.clone());
    }
    Ok(found)
}
