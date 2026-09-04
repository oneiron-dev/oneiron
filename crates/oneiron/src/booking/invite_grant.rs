//! ONE-1814 [BK-A-3] the booking page's standing invite grant.
//!
//! One bounded authority, minted once per published page, that turns the
//! owner's repeated "yes, send the invite" into remembered consent — and
//! nothing else. It is deliberately NOT a second send path:
//!
//! * **The gate still runs.** [`enqueue_confirm_invite`] builds an ordinary
//!   [`OutboundDispatchRequest`] and hands it to
//!   [`crate::Vault::dispatch_outbound_intent`], so the external-effect gate,
//!   the opt-out wall, the rate/budget stage, the intent ledger, and the
//!   connector adapter all execute exactly as they do for every other send.
//!   The grant removes the PING, never the gate.
//! * **CAL-04 still admits.** The invite is admitted through
//!   [`crate::calendar::admit_calendar_invite`] BEFORE the gate, so vault-only
//!   hygiene hydration and the UID/SEQUENCE law are never bypassed. This
//!   module defines no invite payload, hygiene, or consent type of its own; it
//!   imports CAL-04's.
//! * **The page never authorizes a stranger.** The scope names a PAGE. The
//!   recipient binding lives here, in
//!   [`booking_page_grant_covers_recipient`], and answers only from persisted
//!   claims: a CONFIRMED booking on exactly that page whose recorded booker
//!   identity IS the recipient. No caller-supplied page or booker string is
//!   ever consulted, so a forged context cannot widen a grant.
//!
//! Batch CANCEL and SEQUENCE increments are ONE-1820's; the only move this
//! layer makes is the first confirm's single `REQUEST`.

use serde::de::DeserializeOwned;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::blob_artifact::BlobVersionProvenance;
use crate::booking::constraint::BookingError;
use crate::booking::lifecycle::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_EVENT_TYPE_REF_PREDICATE,
    BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE, BookingBookerContactValue,
    BookingEventTypeRefValue, BookingSourcePageValue, BookingStatus, BookingStatusValue,
    ConfirmReceipt, hex_lower,
};
use crate::calendar::{
    CALENDAR_INVITE_CHANNEL, CALENDAR_INVITE_VERB, CalendarError, CalendarInviteAdmission,
    CalendarInviteMethod, CalendarInvitePayload, ImipEmitRequest, admit_calendar_invite,
    decode_frozen_calendar_invite, emit_imip_ics, persist_imip_blob,
};
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState};
use crate::claim::ClaimLifecycleStatus;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::outbound_grant::{
    BookingPageInviteGrantMintIntent, StandingOutboundGrant, StandingOutboundGrantScope,
    StandingOutboundGrantStatus, standing_outbound_grant_principal_index_entity_id,
    standing_outbound_grant_principal_index_prefix,
};
use crate::outbound_intent_ledger::{IntentId, intent_ledger_records};
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// Domain tag for the deterministic page-grant entity id. Deriving the id from
/// the page is what makes a second publish land on
/// [`Error::OutboundGrantAlreadyExists`] instead of on a second live grant.
const PAGE_INVITE_GRANT_ID_DOMAIN: &[u8] = b"oneiron.booking.page_invite_grant.v1\0";

/// Domain tag for the confirm invite's stable ledger identity. One booking's
/// first REQUEST has ONE logical send ref, so a repeated dispatch collapses
/// onto the intent it already froze rather than paying for a second one.
const CONFIRM_INVITE_INTENT_DOMAIN: &[u8] = b"oneiron.booking.confirm_invite.v1\0";

/// Domain tag for the rendered invite's blob-artifact id.
const CONFIRM_INVITE_BLOB_DOMAIN: &[u8] = b"oneiron.booking.confirm_invite_blob.v1\0";

/// Synced-truth field naming a comm-owned PERSON's party. Mirrors the private
/// `comm.rs` constant exactly as `campaign/claims.rs` does: booking READS it
/// and never writes it.
const COMM_PARTY_KEY_FIELD: &str = "party_key";

/// Zone label the confirm-time invite document is rendered in.
///
/// A booking's stored occurrence is UTC and the visitor's wall zone lives on
/// the soft-hold row, which the confirm consumes and deletes. Rendering the
/// instant we actually persisted — rather than guessing a zone we no longer
/// hold — keeps the document a pure function of committed state.
const CONFIRM_INVITE_TZ_LABEL: &str = "UTC";

// -------------------------------------------------------------------------
// Seam types
// -------------------------------------------------------------------------

/// What one invite asks a booking-page grant to authorize.
///
/// Every field is a QUESTION, never an assertion: `booking_ref` names the
/// booking whose persisted claims are read, and the verb and recipient are
/// matched against those claims. Nothing here can grant anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookingPageInviteContext<'a> {
    /// The confirmed booking (its EVENT) the invite is for.
    pub booking_ref: EntityId,
    /// The outbound verb kind being attempted.
    pub verb_kind: &'a str,
    /// The delivery target the caller wants to reach.
    pub requested_recipient: &'a str,
}

/// The page-publish action that mints the standing grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishBookingPageGrantRequest {
    /// The page being published.
    pub page_ref: EntityId,
    /// The principal publishing it; the grant's actor binding.
    pub publisher_principal: EntityId,
    /// Mint time in Unix seconds.
    pub issued_at: u64,
}

/// The revision one confirmed booking asks the calendar door to send.
///
/// `uid` and `sequence` are READ from the confirm receipt's
/// [`crate::booking::CalendarRevision`] — never re-minted here and never
/// reset. `ics_blob_ref` borrows CAL-04's string blob reference
/// (`CalendarInvitePayload::ics_blob_ref` is a `String`); the raw `.ics` bytes
/// stay in the blob store and only this reference is ever frozen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedBookingInvite<'a> {
    /// The confirmed booking's EVENT.
    pub booking_ref: EntityId,
    /// The once-minted UID.
    pub uid: &'a str,
    /// The revision's current SEQUENCE.
    pub sequence: u32,
    /// Blob-artifact reference of the rendered ICS document.
    pub ics_blob_ref: &'a str,
}

/// The page/booker binding one confirmed booking persists.
struct BookingInviteBinding {
    page_ref: EntityId,
    /// Normalized identity of the recorded booker contact.
    recipient: String,
    /// The booking's host event type, used as the invitation SUMMARY.
    event_type: String,
}

/// The sink the lifecycle names when a turn carries no invite dispatch
/// context. It is never executed — the confirm hook only fires when a real
/// sink was threaded — and fails closed if a future path ever reaches it.
pub(crate) struct NoConfirmInviteSink;

impl OutboundExecutionSink for NoConfirmInviteSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::failed("booking lifecycle turn carries no invite connector")
    }
}

// -------------------------------------------------------------------------
// Authorization
// -------------------------------------------------------------------------

/// Whether one booking-page grant scope authorizes this exact invite.
///
/// Three independent walls, all of which must hold: the scope dial must cover
/// the verb (exactly `calendar.invite`), the booking must be persisted on
/// exactly the scoped page, and the requested recipient must equal the
/// booker identity that booking recorded. A scope of any other kind answers
/// `false` rather than falling through to a permissive default.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when committed state cannot be read;
/// [`BookingError::InvalidConstraint`] when a stored booking claim does not
/// decode — a booking whose evidence is unreadable authorizes nothing.
pub fn booking_page_invites_authorizes(
    vault: &Vault,
    scope: &StandingOutboundGrantScope,
    context: &BookingPageInviteContext<'_>,
) -> Result<bool, BookingError> {
    let StandingOutboundGrantScope::BookingPageInvites { page_ref } = scope else {
        return Ok(false);
    };
    if !scope.matches_effect(
        context.verb_kind,
        CALENDAR_INVITE_CHANNEL,
        Some(context.requested_recipient),
        None,
    ) {
        return Ok(false);
    }
    let Some(binding) = confirmed_booking_binding(vault, &context.booking_ref)? else {
        return Ok(false);
    };
    if binding.page_ref != *page_ref {
        return Ok(false);
    }
    Ok(identities_match(
        &binding.recipient,
        context.requested_recipient,
    ))
}

/// Whether a live grant on `page_ref` covers invites to `recipient`.
///
/// This is the predicate CAL-04's consent door calls for the
/// `BookingPageInvites` scope. It resolves ONLY from persisted claims — a
/// CONFIRMED `booking.status`, a `booking.source_page` equal to the scoped
/// page, and a `booking.booker_contact` whose stored identity is the
/// recipient — so neither a caller nor a forged hygiene context can widen the
/// grant. Absence of that evidence is `false`; unreadable evidence is an
/// error. Neither is ever fail-open.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when committed state cannot be read;
/// [`BookingError::InvalidConstraint`] when a stored booking claim does not
/// decode.
pub fn booking_page_grant_covers_recipient(
    vault: &Vault,
    page_ref: &EntityId,
    recipient: &str,
) -> Result<bool, BookingError> {
    for booking_ref in vault
        .entities_by_type(ENTITY_TYPE_EVENT)
        .map_err(|error| engine_failure("booking event scan", error))?
    {
        let Some(binding) = confirmed_booking_binding(vault, &booking_ref)? else {
            continue;
        };
        if binding.page_ref == *page_ref && identities_match(&binding.recipient, recipient) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The page/booker binding `booking_ref` carries, or `None` when this EVENT is
/// not a confirmed booking with a resolvable booker.
fn confirmed_booking_binding(
    vault: &Vault,
    booking_ref: &EntityId,
) -> Result<Option<BookingInviteBinding>, BookingError> {
    let mut page_ref = None;
    let mut status = None;
    let mut booker_contact = None;
    let mut event_type = None;
    for claim_id in vault
        .claims_for_subject(booking_ref)
        .map_err(|error| engine_failure("booking claim scan", error))?
    {
        let Some(body) = vault
            .get_claim(&claim_id)
            .map_err(|error| engine_failure("booking claim read", error))?
        else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        match body.predicate.as_str() {
            BOOKING_SOURCE_PAGE_PREDICATE => {
                page_ref = Some(
                    decode_claim_value::<BookingSourcePageValue>(&body.value, "source page")?
                        .page_ref,
                );
            }
            BOOKING_STATUS_PREDICATE => {
                status =
                    Some(decode_claim_value::<BookingStatusValue>(&body.value, "status")?.status);
            }
            BOOKING_BOOKER_CONTACT_PREDICATE => {
                booker_contact = Some(
                    decode_claim_value::<BookingBookerContactValue>(&body.value, "booker contact")?
                        .contact_ref,
                );
            }
            BOOKING_EVENT_TYPE_REF_PREDICATE => {
                event_type = Some(
                    decode_claim_value::<BookingEventTypeRefValue>(&body.value, "event type ref")?
                        .event_type
                        .0,
                );
            }
            _ => {}
        }
    }
    let (Some(page_ref), Some(BookingStatus::Confirmed), Some(booker_contact)) =
        (page_ref, status, booker_contact)
    else {
        return Ok(None);
    };
    let Some(recipient) = booker_identity(vault, &booker_contact)? else {
        return Ok(None);
    };
    Ok(Some(BookingInviteBinding {
        page_ref,
        recipient,
        event_type: event_type.unwrap_or_default(),
    }))
}

/// The identity string one recorded booker contact carries, read from the
/// stored PERSON row and nothing else.
fn booker_identity(vault: &Vault, contact_ref: &EntityId) -> Result<Option<String>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let Some(raw) = vault
        .store
        .entities
        .get(&rtxn, contact_ref.as_bytes())
        .map_err(|error| engine_failure("booker contact read", error))?
    else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(None);
    }
    Ok(person_identity(&raw[ENTITY_METADATA_HEADER_LEN..]))
}

/// Reads the identity a booker PERSON row carries.
///
/// Two stored spellings exist and both are synced truth: a comm-owned party
/// row carries a MessagePack map with `party_key`, and the booking-page booker
/// subject carries the address itself. Anything else yields `None`, which
/// denies.
fn person_identity(body: &[u8]) -> Option<String> {
    if let Ok(value) = rmpv::decode::read_value(&mut std::io::Cursor::new(body))
        && let rmpv::Value::Map(entries) = value
    {
        let party_key = entries.iter().find_map(|(key, value)| {
            if key.as_str() == Some(COMM_PARTY_KEY_FIELD) {
                value.as_str()
            } else {
                None
            }
        })?;
        if party_key.trim().is_empty() {
            return None;
        }
        return Some(party_key.to_owned());
    }
    let text = std::str::from_utf8(body).ok()?;
    if text.trim().is_empty() {
        return None;
    }
    Some(text.to_owned())
}

/// `MAILTO:` prefixes and casing are vendor spelling, not identity — the same
/// normalization CAL-04's attendee comparison uses.
fn identities_match(stored: &str, requested: &str) -> bool {
    normalize_identity(stored) == normalize_identity(requested)
}

fn normalize_identity(value: &str) -> String {
    let trimmed = value.trim();
    trimmed
        .strip_prefix("mailto:")
        .or_else(|| trimmed.strip_prefix("MAILTO:"))
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

// -------------------------------------------------------------------------
// Mint
// -------------------------------------------------------------------------

/// Mints — or returns — the ONE live invite grant for a published page.
///
/// Idempotent by construction, twice over: the principal index is read before
/// anything is written, and the grant id is DERIVED from the page, so a
/// concurrent second publish loses the `entities.get` race and is answered
/// with the grant that already exists. Equivalent grants never accumulate.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when the grant cannot be read or written;
/// [`BookingError::InvalidConstraint`] when a minted grant cannot be read back.
pub fn mint_publish_page_invite_grant(
    vault: &Vault,
    request: &PublishBookingPageGrantRequest,
) -> Result<StandingOutboundGrant, BookingError> {
    let principal_ref = request.publisher_principal.to_hex();
    if let Some((_, grant)) = live_page_invite_grant(vault, &principal_ref, &request.page_ref)? {
        return Ok(grant);
    }
    let id = page_invite_grant_id(&request.page_ref)?;
    let intent = BookingPageInviteGrantMintIntent {
        page_ref: request.page_ref,
        publisher_principal: request.publisher_principal,
    };
    match vault.mint_booking_page_invite_outbound_grant(&id, &intent, request.issued_at) {
        Ok(grant) => Ok(grant),
        Err(Error::OutboundGrantAlreadyExists) => vault
            .get_standing_outbound_grant(&id)
            .map_err(|error| engine_failure("page invite grant read", error))?
            .ok_or_else(|| refused("the existing booking page invite grant did not read back")),
        Err(error) => Err(engine_failure("page invite grant mint", error)),
    }
}

/// The live `BookingPageInvites` grant this principal holds for `page_ref`.
///
/// Converges on one deterministic grant if several ever coexist, exactly as
/// CAL-04's consent door does.
fn live_page_invite_grant(
    vault: &Vault,
    principal_ref: &str,
    page_ref: &EntityId,
) -> Result<Option<(EntityId, StandingOutboundGrant)>, BookingError> {
    // The index scan closes its read transaction before any grant is read:
    // LMDB gives a thread one read transaction at a time, and each grant read
    // opens its own.
    let ids = {
        let prefix = standing_outbound_grant_principal_index_prefix(principal_ref)
            .map_err(|error| engine_failure("grant principal prefix", error))?;
        let rtxn = vault
            .store
            .env
            .read_txn()
            .map_err(|error| engine_failure("read transaction", error))?;
        let mut ids = Vec::new();
        for entry in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, &prefix)
            .map_err(|error| engine_failure("grant principal scan", error))?
        {
            let (key, _) = entry.map_err(|error| engine_failure("grant principal scan", error))?;
            ids.push(
                standing_outbound_grant_principal_index_entity_id(&key, principal_ref)
                    .map_err(|error| engine_failure("grant principal key", error))?,
            );
        }
        ids
    };
    let wanted = StandingOutboundGrantScope::BookingPageInvites {
        page_ref: *page_ref,
    };
    let mut matched: Option<(EntityId, StandingOutboundGrant)> = None;
    for id in ids {
        let Some(grant) = vault
            .get_standing_outbound_grant(&id)
            .map_err(|error| engine_failure("standing grant read", error))?
        else {
            continue;
        };
        if grant.status != StandingOutboundGrantStatus::Active
            || grant.revoked_at.is_some()
            || grant.scope != wanted
        {
            continue;
        }
        if matched
            .as_ref()
            .is_none_or(|(current, _)| id.as_bytes() < current.as_bytes())
        {
            matched = Some((id, grant));
        }
    }
    Ok(matched)
}

/// The deterministic grant id one page's invite grant lives at.
fn page_invite_grant_id(page_ref: &EntityId) -> Result<EntityId, BookingError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PAGE_INVITE_GRANT_ID_DOMAIN);
    hasher.update(page_ref.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(bytes).map_err(|error| engine_failure("page invite grant id", error))
}

// -------------------------------------------------------------------------
// Dispatch
// -------------------------------------------------------------------------

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
    .counterparty_ref(binding.recipient.clone())
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
    let Some(organizer) = sending_address(vault, actor)? else {
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
        summary: binding.event_type.clone(),
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
fn sending_address(vault: &Vault, actor: EntityId) -> Result<Option<String>, BookingError> {
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
    let binding = ChannelIdentityBinding::agent(actor);
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
        if identity.state != ChannelIdentityState::Active
            || crate::counterparty_contact::normalize_channel_class(&identity.channel) != wanted
            || identity.binding != binding
        {
            continue;
        }
        if found.is_some() {
            return Ok(None);
        }
        found = Some(identity.address_or_handle.clone());
    }
    Ok(found)
}

// -------------------------------------------------------------------------
// Codec + errors
// -------------------------------------------------------------------------

/// The same `rmp_serde` ↔ `rmpv` bridge the rest of the booking lane uses.
fn decode_claim_value<T: DeserializeOwned>(
    value: &rmpv::Value,
    what: &str,
) -> Result<T, BookingError> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|error| {
        refused(format!(
            "stored booking {what} claim is unreadable: {error}"
        ))
    })?;
    rmp_serde::from_slice(&bytes).map_err(|error| {
        refused(format!(
            "stored booking {what} claim did not decode: {error}"
        ))
    })
}

fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}

fn engine_failure<E: Into<Error>>(what: &str, error: E) -> BookingError {
    let error = error.into();
    BookingError::SlotOracle(format!("booking invite grant {what} failed: {error}"))
}

/// Wraps a calendar failure OPAQUELY: no `CalendarError` variant is matched
/// and none is restated in booking's taxonomy, the stance the rest of the lane
/// takes.
fn calendar_wrap(error: CalendarError) -> BookingError {
    BookingError::InvalidConstraint(format!("booking invite calendar step refused: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use rmpv::Value;
    use serde::Serialize;

    use crate::booking::constraint::EventTypeKey;
    use crate::booking::lifecycle::{
        BOOKING_PASSPORT_SYSTEM, CalendarRevision, OpaqueLifecycleToken,
    };
    use crate::calendar::{
        CALENDAR_INVITE_MEDIA_TYPE, CalendarInviteConsentBasis, index_passport_uid,
    };
    use crate::campaign::claims::{
        CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
        encode_do_not_contact_value,
    };
    use crate::channel_identity::{ChannelIdentity, SelfHeldShape};
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
    use crate::config::VaultConfig;
    use crate::outbound_consent::DataClass;
    use crate::outbound_grant::{
        decode_standing_outbound_grant_body, encode_standing_outbound_grant_body,
    };
    use crate::outbound_intent_ledger::IntentLedgerRecord;
    use crate::registry::ENTITY_TYPE_OUTBOUND_GRANT;
    use crate::test_util::{entity, open_test_vault_with, put_policy_manifest_bytes};

    /// This module's own bytes, read back so the ownership oracles below can
    /// assert what booking does NOT contain.
    const SOURCE: &str = include_str!("invite_grant.rs");

    const NOW: u64 = 1_800_000_000;
    const RECIPIENT: &str = "booker@example.test";
    const STRANGER: &str = "stranger@example.test";
    const SENDER: &str = "host@primary.test";
    const EVENT_TYPE: &str = "intro";
    const SLOT_START: u64 = NOW + 3_600;
    const SLOT_END: u64 = NOW + 7_200;

    // ── fixtures ────────────────────────────────────────────────────────

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        actor: EntityId,
        page: EntityId,
        booking: EntityId,
        uid: String,
    }

    impl Fixture {
        fn grant(&self) -> EntityId {
            mint_publish_page_invite_grant(
                &self.vault,
                &PublishBookingPageGrantRequest {
                    page_ref: self.page,
                    publisher_principal: self.actor,
                    issued_at: crate::unix_seconds_now(),
                },
            )
            .expect("publish mints the page grant");
            page_invite_grant_id(&self.page).expect("page grant id")
        }
    }

    /// The OF-336 manifest shape the outbound spine's own tests use: an `auto`
    /// ceiling for this actor plus a scoped grant for the exact verb. Without
    /// a manifest the gate has no policy version and denies every effect, so
    /// this is what makes an ALLOW decidable in a test vault.
    fn policy_manifest(actor_ref: &str, channel: &str, verbs: &[&str]) -> Vec<u8> {
        let scoped_grants = verbs
            .iter()
            .map(|verb| {
                Value::Map(vec![
                    (Value::from("actor_ref"), Value::from(actor_ref)),
                    (
                        Value::from("effector"),
                        Value::from(format!("external:{verb}")),
                    ),
                    (
                        Value::from("scope"),
                        Value::Map(vec![(Value::from("channel"), Value::from(channel))]),
                    ),
                ])
            })
            .collect::<Vec<_>>();
        let entries = vec![
            (Value::from("schema_version"), Value::from("1.1")),
            (Value::from("pack_id"), Value::from("one-1814-test")),
            (Value::from("pack_version"), Value::from("v1")),
            (
                Value::from("min_engine_version"),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                Value::from("defaults"),
                Value::Map(vec![
                    (Value::from("criticality"), Value::from("normal")),
                    (Value::from("sensitivity"), Value::from("normal")),
                ]),
            ),
            (Value::from("rules"), Value::Array(Vec::new())),
            (
                Value::from("actor_ceilings"),
                Value::Array(vec![
                    Value::Map(vec![
                        (Value::from("actor_class"), Value::from("agent")),
                        (Value::from("actor_ref"), Value::from(actor_ref)),
                        (Value::from("ceiling"), Value::from("auto")),
                    ]),
                    // Class-wide rows so post-manifest fixture writes clear the
                    // ceiling axis: public `Vault::put_claim` carries no envelope
                    // (gate sees `first_party`, no ref) and blob persists ride a
                    // `Human` edge actor. Mirrors the engine default manifest
                    // (gate/default_manifest.rs first_party + human auto rows);
                    // omitting `actor_ref` is the established class-wide spelling
                    // (gate/decode.rs `parse_actor_ceilings` optional_string).
                    Value::Map(vec![
                        (Value::from("actor_class"), Value::from("first_party")),
                        (Value::from("ceiling"), Value::from("auto")),
                    ]),
                    Value::Map(vec![
                        (Value::from("actor_class"), Value::from("human")),
                        (Value::from("ceiling"), Value::from("auto")),
                    ]),
                ]),
            ),
            (Value::from("scoped_grants"), Value::Array(scoped_grants)),
        ];
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
        out
    }

    fn person(vault: &Vault, seed: u8, body: &[u8]) -> EntityId {
        let id = entity(seed);
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
                body,
            )
            .expect("put person");
        id
    }

    fn event(vault: &Vault, seed: u8) -> EntityId {
        let id = entity(seed);
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Value::Map(vec![(Value::from("name"), Value::from(EVENT_TYPE))]),
        )
        .expect("encode event body");
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_EVENT,
                TimeRange {
                    start: SLOT_START,
                    end: SLOT_END - 1,
                },
                NOW,
                &body,
            )
            .expect("put booking event");
        id
    }

    fn claim_value<T: Serialize>(value: &T) -> Value {
        let bytes = rmp_serde::to_vec_named(value).expect("encode claim value");
        rmpv::decode::read_value(&mut std::io::Cursor::new(bytes.as_slice()))
            .expect("decode claim value")
    }

    /// The four exact claims ONE-1813's confirm commits, written the way it
    /// writes them: engine-recorded, `Auto` approval, `Observed` source.
    fn put_booking_claims(
        vault: &Vault,
        base_seed: u8,
        booking: EntityId,
        page: EntityId,
        booker: EntityId,
        status: BookingStatus,
    ) {
        let values = [
            (
                BOOKING_EVENT_TYPE_REF_PREDICATE,
                claim_value(&BookingEventTypeRefValue {
                    event_type: EventTypeKey(EVENT_TYPE.to_owned()),
                }),
            ),
            (
                BOOKING_BOOKER_CONTACT_PREDICATE,
                claim_value(&BookingBookerContactValue {
                    contact_ref: booker,
                }),
            ),
            (
                BOOKING_SOURCE_PAGE_PREDICATE,
                claim_value(&BookingSourcePageValue { page_ref: page }),
            ),
            (
                BOOKING_STATUS_PREDICATE,
                claim_value(&BookingStatusValue {
                    status,
                    recorded_at: NOW,
                }),
            ),
        ];
        for (index, (predicate, value)) in values.into_iter().enumerate() {
            let mut body = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(booking),
                value,
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.source = Some(ClaimSource::Observed);
            body.valid_from = Some(NOW);
            let seed = base_seed
                .checked_add(u8::try_from(index).expect("claim index"))
                .expect("claim seed");
            vault
                .put_claim(
                    &entity(seed),
                    &body,
                    TimeRange {
                        start: NOW,
                        end: NOW,
                    },
                    NOW,
                )
                .expect("put booking claim");
        }
    }

    fn identity(vault: &Vault, seed: u8, actor: EntityId, channel: &str, address: &str) {
        let mut identity = ChannelIdentity::requested(
            channel,
            address,
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(actor),
            NOW,
        );
        identity.state = ChannelIdentityState::Active;
        vault
            .create_channel_identity(&entity(seed), &identity)
            .expect("create sending identity");
    }

    fn ics_blob(vault: &Vault, seed: u8, actor: EntityId, uid: &str, sequence: u32) -> String {
        let ics = emit_imip_ics(&ImipEmitRequest {
            method: CalendarInviteMethod::Request,
            uid: uid.to_owned(),
            sequence,
            organizer: SENDER.to_owned(),
            attendees: vec![RECIPIENT.to_owned()],
            summary: EVENT_TYPE.to_owned(),
            starts_at_utc: SLOT_START,
            ends_at_utc: SLOT_END,
            tz_label: CONFIRM_INVITE_TZ_LABEL.to_owned(),
            dtstamp_utc: NOW,
        })
        .expect("emit invite document");
        persist_imip_blob(
            vault,
            &entity(seed),
            "one-1814 invite",
            &ics,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(actor, EdgeActorClass::Human),
            NOW,
        )
        .expect("persist invite blob")
    }

    fn build(with_sender: bool) -> Fixture {
        let (dir, vault) = open_test_vault_with(VaultConfig::default());
        let actor = person(&vault, 0x71, b"one-1814 actor");
        let page = entity(0x72);
        let booker = person(&vault, 0x73, RECIPIENT.as_bytes());
        let booking = event(&vault, 0x74);
        put_booking_claims(
            &vault,
            0x75,
            booking,
            page,
            booker,
            BookingStatus::Confirmed,
        );
        if with_sender {
            identity(&vault, 0x79, actor, "email", SENDER);
        }
        let uid = format!("{}@{BOOKING_PASSPORT_SYSTEM}", booking.to_hex());
        index_passport_uid(&vault, &uid, &booking).expect("index booking uid");
        // Seeded BEFORE any mint: the grant binds to the policy floor in
        // effect when it was minted, and a floor that moves afterwards would
        // make it inert at the gate.
        put_policy_manifest_bytes(
            &vault,
            entity(0x7A),
            &policy_manifest(
                &actor.to_hex(),
                CALENDAR_INVITE_CHANNEL,
                &[CALENDAR_INVITE_VERB],
            ),
        )
        .expect("seed policy manifest");
        Fixture {
            _dir: dir,
            vault,
            actor,
            page,
            booking,
            uid,
        }
    }

    fn fixture() -> Fixture {
        build(true)
    }

    #[derive(Default)]
    struct SpySink {
        calls: usize,
        invite_methods: Vec<Option<CalendarInviteMethod>>,
    }

    impl OutboundExecutionSink for SpySink {
        fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
            self.calls += 1;
            self.invite_methods
                .push(request.calendar_invite.as_ref().map(|part| part.method));
            OutboundExecutionOutcome::delivered_to_channel("provider:invite:one")
        }
    }

    fn payload_for(fixture: &Fixture, blob_ref: &str, recipient: &str) -> CalendarInvitePayload {
        CalendarInvitePayload {
            method: CalendarInviteMethod::Request,
            uid: fixture.uid.clone(),
            sequence: 0,
            ics_blob_ref: blob_ref.to_owned(),
            recipient: recipient.to_owned(),
        }
    }

    fn invite_ledger_records(vault: &Vault) -> Vec<IntentLedgerRecord> {
        intent_ledger_records(vault)
            .expect("intent ledger")
            .into_iter()
            .filter(|record| record.tool == CALENDAR_INVITE_VERB)
            .collect()
    }

    fn frozen_invite(vault: &Vault, intent_id: IntentId) -> CalendarInvitePayload {
        let record = invite_ledger_records(vault)
            .into_iter()
            .find(|record| record.id == intent_id)
            .expect("the returned intent id names a ledger record");
        decode_frozen_calendar_invite(record.payload()).expect("frozen five-field body")
    }

    fn live_booking_page_grants(vault: &Vault) -> Vec<EntityId> {
        vault
            .entities_by_type(ENTITY_TYPE_OUTBOUND_GRANT)
            .expect("grants")
            .into_iter()
            .filter(|id| {
                vault
                    .get_standing_outbound_grant(id)
                    .expect("grant")
                    .is_some_and(|grant| {
                        grant.status == StandingOutboundGrantStatus::Active
                            && matches!(
                                grant.scope,
                                StandingOutboundGrantScope::BookingPageInvites { .. }
                            )
                    })
            })
            .collect()
    }

    fn seed_do_not_contact(vault: &Vault, seed: u8, party: &str) {
        let party_ref = crate::comm::resolve_or_create_comm_party(vault, party).expect("party");
        vault
            .put_claim(
                &entity(seed),
                &ClaimBody::new(
                    PREDICATE_COMM_DO_NOT_CONTACT,
                    ClaimSubject::Entity(party_ref),
                    encode_do_not_contact_value(&CommDoNotContactValue {
                        channel: Some(CALENDAR_INVITE_CHANNEL.to_owned()),
                        scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
                    }),
                    1.0,
                    ClaimApprovalStatus::Approved,
                    ClaimLifecycleStatus::Active,
                ),
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
            )
            .expect("put do-not-contact head");
    }

    fn context<'a>(
        booking: EntityId,
        verb: &'a str,
        recipient: &'a str,
    ) -> BookingPageInviteContext<'a> {
        BookingPageInviteContext {
            booking_ref: booking,
            verb_kind: verb,
            requested_recipient: recipient,
        }
    }

    // ── codec ───────────────────────────────────────────────────────────

    fn grant_with(scope: StandingOutboundGrantScope) -> StandingOutboundGrant {
        StandingOutboundGrant {
            principal_ref: "owner".to_owned(),
            origin_component_id: "one-1814".to_owned(),
            origin_action_id: "publish_booking_page".to_owned(),
            origin_receipt_ref: None,
            scope,
            status: StandingOutboundGrantStatus::Active,
            created_at: 10,
            revoked_at: None,
            last_used_at: None,
            binding_diff_handle: vec![0xA5; 32],
            read_frontier_hash: [0xB6; 32],
        }
    }

    /// Number of pairs the encoded body's nested `scope` map carries.
    fn scope_pairs(encoded: &[u8]) -> usize {
        let body = rmpv::decode::read_value(&mut std::io::Cursor::new(encoded))
            .expect("decode grant body");
        let Value::Map(entries) = body else {
            panic!("grant body must be a map");
        };
        let scope = entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("scope"))
            .map(|(_, value)| value)
            .expect("scope field");
        let Value::Map(pairs) = scope else {
            panic!("scope must be a map");
        };
        pairs.len()
    }

    #[test]
    fn booking_page_invite_scope_round_trips_without_retagging_existing_scopes() {
        let page = entity(0x72);
        let scopes = [
            StandingOutboundGrantScope::Contact {
                contact_ref: "contact:one".to_owned(),
            },
            StandingOutboundGrantScope::VerbClass {
                verb_class: "send".to_owned(),
            },
            StandingOutboundGrantScope::Channel {
                channel: "email".to_owned(),
            },
            StandingOutboundGrantScope::BriefVerbClass {
                brief_ref: "brief:one".to_owned(),
                verb_class: "send".to_owned(),
            },
            StandingOutboundGrantScope::ScopedMcp {
                server: "files".to_owned(),
                tool: "read_file".to_owned(),
                data_class_ceiling: DataClass::Personal,
                endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
            },
            StandingOutboundGrantScope::BookingPageInvites { page_ref: page },
        ];
        for scope in scopes {
            let is_new = matches!(scope, StandingOutboundGrantScope::BookingPageInvites { .. });
            let grant = grant_with(scope);
            let encoded = encode_standing_outbound_grant_body(&grant).expect("encode");
            let decoded = decode_standing_outbound_grant_body(&encoded).expect("decode");
            assert_eq!(decoded, grant, "a round trip must not retag a scope");
            assert_eq!(decoded.scope.dial_label(), grant.scope.dial_label());
            // Discriminating: a Nil tenth pair on the old scopes would move
            // their encoded bytes, which is exactly what append-only forbids.
            assert_eq!(
                scope_pairs(&encoded),
                if is_new { 10 } else { 9 },
                "only the booking-page scope carries the tenth key"
            );
        }
    }

    #[test]
    fn booking_page_invite_scope_without_its_page_fails_closed() {
        let grant = grant_with(StandingOutboundGrantScope::BookingPageInvites {
            page_ref: entity(0x72),
        });
        let encoded = encode_standing_outbound_grant_body(&grant).expect("encode");
        let mut body = rmpv::decode::read_value(&mut std::io::Cursor::new(&encoded))
            .expect("decode grant body");
        let Value::Map(entries) = &mut body else {
            panic!("grant body must be a map");
        };
        let scope = &mut entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("scope"))
            .expect("scope field")
            .1;
        let Value::Map(pairs) = scope else {
            panic!("scope must be a map");
        };
        pairs.retain(|(key, _)| key.as_str() != Some("page_ref"));
        let mut stripped = Vec::new();
        rmpv::encode::write_value(&mut stripped, &body).expect("re-encode");
        assert!(
            decode_standing_outbound_grant_body(&stripped).is_err(),
            "a booking-page row that names no page must authorize nothing"
        );
    }

    // ── mint ────────────────────────────────────────────────────────────

    #[test]
    fn publish_page_mints_one_live_booking_page_invite_grant() {
        let fixture = fixture();
        let request = PublishBookingPageGrantRequest {
            page_ref: fixture.page,
            publisher_principal: fixture.actor,
            issued_at: NOW,
        };
        let first =
            mint_publish_page_invite_grant(&fixture.vault, &request).expect("first publish mints");
        let second = mint_publish_page_invite_grant(&fixture.vault, &request)
            .expect("second publish reuses");
        assert_eq!(first, second, "publishing twice must not mint twice");
        assert_eq!(
            first.scope,
            StandingOutboundGrantScope::BookingPageInvites {
                page_ref: fixture.page
            }
        );
        assert_eq!(first.status, StandingOutboundGrantStatus::Active);
        assert_eq!(
            live_booking_page_grants(&fixture.vault).len(),
            1,
            "exactly one live grant per page"
        );
    }

    // ── authorize / deny matrix ─────────────────────────────────────────

    #[test]
    fn page_grant_authorizes_calendar_invite_for_confirmed_booker() {
        let fixture = fixture();
        let scope = StandingOutboundGrantScope::BookingPageInvites {
            page_ref: fixture.page,
        };
        assert!(
            booking_page_invites_authorizes(
                &fixture.vault,
                &scope,
                &context(fixture.booking, CALENDAR_INVITE_VERB, RECIPIENT),
            )
            .expect("authorize")
        );
    }

    #[test]
    fn page_grant_denies_different_page() {
        let fixture = fixture();
        let scope = StandingOutboundGrantScope::BookingPageInvites {
            page_ref: entity(0x7B),
        };
        assert!(
            !booking_page_invites_authorizes(
                &fixture.vault,
                &scope,
                &context(fixture.booking, CALENDAR_INVITE_VERB, RECIPIENT),
            )
            .expect("authorize")
        );
        assert!(
            !booking_page_grant_covers_recipient(&fixture.vault, &entity(0x7B), RECIPIENT)
                .expect("covers")
        );
    }

    #[test]
    fn page_grant_denies_different_recipient() {
        let fixture = fixture();
        let scope = StandingOutboundGrantScope::BookingPageInvites {
            page_ref: fixture.page,
        };
        assert!(
            !booking_page_invites_authorizes(
                &fixture.vault,
                &scope,
                &context(fixture.booking, CALENDAR_INVITE_VERB, STRANGER),
            )
            .expect("authorize")
        );
        assert!(
            !booking_page_grant_covers_recipient(&fixture.vault, &fixture.page, STRANGER)
                .expect("covers")
        );
    }

    #[test]
    fn page_grant_denies_non_calendar_verb() {
        let fixture = fixture();
        let scope = StandingOutboundGrantScope::BookingPageInvites {
            page_ref: fixture.page,
        };
        for verb in ["send", "send_media", "push", "calendar.invite.v2"] {
            assert!(
                !booking_page_invites_authorizes(
                    &fixture.vault,
                    &scope,
                    &context(fixture.booking, verb, RECIPIENT),
                )
                .expect("authorize"),
                "the page grant must authorize exactly one verb, not {verb}"
            );
        }
    }

    #[test]
    fn page_grant_denies_unbound_recipient_without_consent_basis() {
        let fixture = fixture();
        let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
        // No prior thread and no verified grant: the REQUEST is cold.
        assert!(
            admit_calendar_invite(
                &fixture.vault,
                fixture.actor,
                &payload_for(&fixture, &blob, RECIPIENT),
                NOW,
            )
            .is_err(),
            "an unbound recipient with no consent basis must refuse"
        );
        // A live grant for a DIFFERENT page changes nothing: it binds no
        // booking on this page and therefore no recipient.
        mint_publish_page_invite_grant(
            &fixture.vault,
            &PublishBookingPageGrantRequest {
                page_ref: entity(0x7B),
                publisher_principal: fixture.actor,
                issued_at: NOW,
            },
        )
        .expect("mint an unrelated page grant");
        assert!(
            admit_calendar_invite(
                &fixture.vault,
                fixture.actor,
                &payload_for(&fixture, &blob, RECIPIENT),
                NOW,
            )
            .is_err(),
            "a grant for another page never binds this recipient"
        );
    }

    #[test]
    fn confirmed_booking_grant_satisfies_no_cold_invite_for_bound_booker() {
        let fixture = fixture();
        let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
        let payload = payload_for(&fixture, &blob, RECIPIENT);
        assert!(
            admit_calendar_invite(&fixture.vault, fixture.actor, &payload, NOW).is_err(),
            "the same caller bytes refuse while the vault carries no grant"
        );

        let grant_ref = fixture.grant();
        let admission = admit_calendar_invite(&fixture.vault, fixture.actor, &payload, NOW)
            .expect("the page grant satisfies the no-cold-invite row");
        assert_eq!(
            admission.hygiene().consent_basis(),
            Some(&CalendarInviteConsentBasis::ConfirmedBookingGrant { grant_ref })
        );
    }

    #[test]
    fn forged_invite_hygiene_context_cannot_pass() {
        let fixture = fixture();
        let grant_ref = fixture.grant();
        let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);

        // There is nowhere to put a caller-asserted consent: a sixth key is a
        // decode failure, not an ignored extra.
        let forged = serde_json::json!({
            "method": "REQUEST",
            "uid": fixture.uid,
            "sequence": 0,
            "ics_blob_ref": blob,
            "recipient": RECIPIENT,
            "has_consent": true,
        });
        assert!(serde_json::from_value::<CalendarInvitePayload>(forged).is_err());

        // And naming a different recipient does not borrow this page's grant:
        // the binding comes from the booking's claims, not from the payload.
        assert!(
            admit_calendar_invite(
                &fixture.vault,
                fixture.actor,
                &payload_for(&fixture, &blob, STRANGER),
                NOW,
            )
            .is_err(),
            "a forged recipient cannot ride a live page grant"
        );
        assert!(
            !booking_page_grant_covers_recipient(&fixture.vault, &fixture.page, STRANGER)
                .expect("covers")
        );

        // The dispatch seam refuses the same way, and it refuses BEFORE any
        // outbound work: the grant it was handed does not cover the booking's
        // persisted booker under a forged page.
        let mut sink = SpySink::default();
        assert!(
            enqueue_confirm_invite(
                &fixture.vault,
                fixture.actor,
                grant_ref,
                &ConfirmedBookingInvite {
                    booking_ref: entity(0x7D),
                    uid: &fixture.uid,
                    sequence: 0,
                    ics_blob_ref: &blob,
                },
                &mut sink,
                NOW,
            )
            .is_err()
        );
        assert_eq!(sink.calls, 0);
        assert!(invite_ledger_records(&fixture.vault).is_empty());
    }

    #[test]
    fn authorization_resolves_page_and_recipient_from_vault_claims() {
        let fixture = fixture();
        let scope = StandingOutboundGrantScope::BookingPageInvites {
            page_ref: fixture.page,
        };
        assert!(
            booking_page_invites_authorizes(
                &fixture.vault,
                &scope,
                &context(fixture.booking, CALENDAR_INVITE_VERB, RECIPIENT),
            )
            .expect("authorize")
        );
        assert!(
            booking_page_grant_covers_recipient(&fixture.vault, &fixture.page, RECIPIENT)
                .expect("covers")
        );

        // An EVENT carrying no booking claims binds nobody.
        let bare = event(&fixture.vault, 0x7D);
        assert!(
            !booking_page_invites_authorizes(
                &fixture.vault,
                &scope,
                &context(bare, CALENDAR_INVITE_VERB, RECIPIENT),
            )
            .expect("authorize")
        );

        // A booking whose recorded booker contact resolves to no stored
        // identity binds nobody either: absent evidence denies.
        let ghost_page = entity(0x7E);
        let ghost = event(&fixture.vault, 0x7F);
        put_booking_claims(
            &fixture.vault,
            0x81,
            ghost,
            ghost_page,
            entity(0x85),
            BookingStatus::Confirmed,
        );
        assert!(
            !booking_page_grant_covers_recipient(&fixture.vault, &ghost_page, RECIPIENT)
                .expect("covers")
        );

        // A CANCELLED booking is not a confirmed one: its page binds nobody.
        let cancelled_page = entity(0x86);
        let cancelled = event(&fixture.vault, 0x87);
        put_booking_claims(
            &fixture.vault,
            0x88,
            cancelled,
            cancelled_page,
            person(&fixture.vault, 0x8C, RECIPIENT.as_bytes()),
            BookingStatus::Cancelled,
        );
        assert!(
            !booking_page_grant_covers_recipient(&fixture.vault, &cancelled_page, RECIPIENT)
                .expect("covers")
        );
    }

    // ── dispatch ────────────────────────────────────────────────────────

    #[test]
    fn confirm_invite_uses_frozen_calendar_payload_contract() {
        let fixture = fixture();
        let grant_ref = fixture.grant();
        let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
        let mut sink = SpySink::default();
        let intent_id = enqueue_confirm_invite(
            &fixture.vault,
            fixture.actor,
            grant_ref,
            &ConfirmedBookingInvite {
                booking_ref: fixture.booking,
                uid: &fixture.uid,
                sequence: 0,
                ics_blob_ref: &blob,
            },
            &mut sink,
            NOW,
        )
        .expect("the invite dispatches");

        let frozen = frozen_invite(&fixture.vault, intent_id);
        assert_eq!(frozen.method, CalendarInviteMethod::Request);
        assert_eq!(frozen.uid, fixture.uid);
        assert_eq!(frozen.sequence, 0);
        assert_eq!(frozen.ics_blob_ref, blob);
        assert_eq!(frozen.recipient, RECIPIENT);
        assert_eq!(frozen, payload_for(&fixture, &blob, RECIPIENT));

        // The frozen body carries the blob REFERENCE, never the document.
        let record = invite_ledger_records(&fixture.vault)
            .into_iter()
            .find(|record| record.id == intent_id)
            .expect("ledger record");
        assert!(
            !String::from_utf8_lossy(record.payload()).contains("BEGIN:VCALENDAR"),
            "the frozen body must reference the document, not carry it"
        );
    }

    #[test]
    fn confirm_invite_uses_once_minted_uid_and_current_sequence() {
        let fixture = fixture();
        fixture.grant();
        let receipt = ConfirmReceipt {
            calendar: CalendarRevision {
                event_ref: fixture.booking,
                uid: fixture.uid.clone(),
                sequence: 0,
            },
            reschedule_token: OpaqueLifecycleToken("reschedule".to_owned()),
            cancel_token: OpaqueLifecycleToken("cancel".to_owned()),
        };
        let mut sink = SpySink::default();
        let first = dispatch_confirm_booking_invite(
            &fixture.vault,
            fixture.actor,
            &receipt,
            &mut sink,
            NOW,
        )
        .expect("the first confirm emits one REQUEST");
        let frozen = frozen_invite(&fixture.vault, first);
        assert_eq!(
            frozen.uid, receipt.calendar.uid,
            "the UID is reused, never re-minted"
        );
        assert_eq!(frozen.sequence, receipt.calendar.sequence);

        // An idempotent confirm replay answers with the intent the first pass
        // recorded: no second UID, no second REQUEST, no bumped SEQUENCE.
        let second = dispatch_confirm_booking_invite(
            &fixture.vault,
            fixture.actor,
            &receipt,
            &mut sink,
            NOW,
        )
        .expect("a replay resolves to the recorded intent");
        assert_eq!(first, second);
        assert_eq!(sink.calls, 1, "one booking earns one REQUEST");
        assert_eq!(invite_ledger_records(&fixture.vault).len(), 1);
    }

    #[test]
    fn confirm_invite_calls_gate_before_ledger_and_connector() {
        // Denied: the gate refuses before anything is frozen, so there is no
        // ledger record to replay and the connector is never reached.
        let denied = fixture();
        let denied_grant = denied.grant();
        let denied_blob = ics_blob(&denied.vault, 0x7C, denied.actor, &denied.uid, 0);
        seed_do_not_contact(&denied.vault, 0x8A, RECIPIENT);
        let mut denied_sink = SpySink::default();
        assert!(
            enqueue_confirm_invite(
                &denied.vault,
                denied.actor,
                denied_grant,
                &ConfirmedBookingInvite {
                    booking_ref: denied.booking,
                    uid: &denied.uid,
                    sequence: 0,
                    ics_blob_ref: &denied_blob,
                },
                &mut denied_sink,
                NOW,
            )
            .is_err(),
            "a gate denial must not become an invite"
        );
        assert_eq!(denied_sink.calls, 0, "no connector call behind a denial");
        assert!(
            invite_ledger_records(&denied.vault).is_empty(),
            "no intent is frozen behind a denial"
        );

        // Allowed: exactly one frozen intent, then exactly one connector call
        // whose invitation part was resolved from those frozen bytes.
        let allowed = fixture();
        let allowed_grant = allowed.grant();
        let allowed_blob = ics_blob(&allowed.vault, 0x7C, allowed.actor, &allowed.uid, 0);
        let mut allowed_sink = SpySink::default();
        enqueue_confirm_invite(
            &allowed.vault,
            allowed.actor,
            allowed_grant,
            &ConfirmedBookingInvite {
                booking_ref: allowed.booking,
                uid: &allowed.uid,
                sequence: 0,
                ics_blob_ref: &allowed_blob,
            },
            &mut allowed_sink,
            NOW,
        )
        .expect("the invite dispatches");
        assert_eq!(invite_ledger_records(&allowed.vault).len(), 1);
        assert_eq!(allowed_sink.calls, 1);
        assert_eq!(
            allowed_sink.invite_methods,
            vec![Some(CalendarInviteMethod::Request)],
            "the connector received the part resolved from the frozen ref"
        );
    }

    #[test]
    fn standing_grant_removes_ping_not_gate() {
        let fixture = fixture();
        let grant_ref = fixture.grant();
        let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
        let mut sink = SpySink::default();
        enqueue_confirm_invite(
            &fixture.vault,
            fixture.actor,
            grant_ref,
            &ConfirmedBookingInvite {
                booking_ref: fixture.booking,
                uid: &fixture.uid,
                sequence: 0,
                ics_blob_ref: &blob,
            },
            &mut sink,
            NOW,
        )
        .expect("a live page grant needs no per-send prompt");
        // No owner ping: the send completed in ONE pass, with no pending
        // decision left for anyone to answer.
        assert_eq!(sink.calls, 1);
        // Every rail still ran: the ledger has its record...
        assert_eq!(invite_ledger_records(&fixture.vault).len(), 1);
        // ...and the passport head moved with it, which only the admitted
        // path writes.
        assert_eq!(
            crate::calendar::live_passports_for_event(&fixture.vault, &fixture.booking)
                .expect("passports")
                .len(),
            1
        );

        // Hygiene hydration still runs with a live grant: the same call with
        // no active sending identity in the vault refuses.
        let bare = build(false);
        let bare_grant = bare.grant();
        let bare_blob = ics_blob(&bare.vault, 0x7C, bare.actor, &bare.uid, 0);
        let mut bare_sink = SpySink::default();
        assert!(
            enqueue_confirm_invite(
                &bare.vault,
                bare.actor,
                bare_grant,
                &ConfirmedBookingInvite {
                    booking_ref: bare.booking,
                    uid: &bare.uid,
                    sequence: 0,
                    ics_blob_ref: &bare_blob,
                },
                &mut bare_sink,
                NOW,
            )
            .is_err(),
            "a standing grant never skips vault-only hygiene hydration"
        );
        assert_eq!(bare_sink.calls, 0);
    }

    #[test]
    fn gate_denial_prevents_invite_even_with_live_page_grant() {
        let fixture = fixture();
        let grant_ref = fixture.grant();
        let blob = ics_blob(&fixture.vault, 0x7C, fixture.actor, &fixture.uid, 0);
        // The grant is live and the recipient IS the persisted booker — and
        // the opt-out still wins.
        assert!(
            booking_page_grant_covers_recipient(&fixture.vault, &fixture.page, RECIPIENT)
                .expect("covers")
        );
        seed_do_not_contact(&fixture.vault, 0x8A, RECIPIENT);
        let mut sink = SpySink::default();
        assert!(
            enqueue_confirm_invite(
                &fixture.vault,
                fixture.actor,
                grant_ref,
                &ConfirmedBookingInvite {
                    booking_ref: fixture.booking,
                    uid: &fixture.uid,
                    sequence: 0,
                    ics_blob_ref: &blob,
                },
                &mut sink,
                NOW,
            )
            .is_err(),
            "opt-out denial outranks a live standing grant"
        );
        assert_eq!(sink.calls, 0);
        assert!(invite_ledger_records(&fixture.vault).is_empty());
        // Nothing moved behind the denial: no passport head, no spent SEQUENCE.
        assert!(
            crate::calendar::live_passports_for_event(&fixture.vault, &fixture.booking)
                .expect("passports")
                .is_empty()
        );
    }

    // ── ownership ───────────────────────────────────────────────────────

    #[test]
    fn calendar_invite_types_are_owned_by_cal04() {
        for forbidden in [
            concat!("struct ", "CalendarInvite"),
            concat!("enum ", "CalendarInvite"),
            concat!("struct ", "InvitePayload"),
            concat!("enum ", "InviteConsent"),
            concat!("struct ", "InviteHygiene"),
        ] {
            assert!(
                !SOURCE.contains(forbidden),
                "booking must import CAL-04's shapes, not define `{forbidden}`"
            );
        }
        assert!(SOURCE.contains("use crate::calendar::"));
        // CAL-04 registered the verb exactly once, and booking adds none.
        assert_eq!(
            crate::outbound::COMMON_OUTBOUND_VERB_KINDS
                .iter()
                .filter(|kind| kind.starts_with("calendar."))
                .count(),
            1
        );
        assert_eq!(CALENDAR_INVITE_VERB, "calendar.invite");
    }

    #[test]
    fn connector_owns_calendar_mime_assembly() {
        for forbidden in [
            concat!("text/", "calendar"),
            concat!("build_calendar_invite", "_mime_part"),
            concat!("CalendarInvite", "MimePart"),
        ] {
            assert!(
                !SOURCE.contains(forbidden),
                "booking must never assemble `{forbidden}`"
            );
        }
        // The media type is CAL-04's, and only its builder puts it on the wire.
        assert_eq!(CALENDAR_INVITE_MEDIA_TYPE, concat!("text/", "calendar"));
    }
}
