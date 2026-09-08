//! Whether a page's standing grant covers a recipient, read from persisted claims only.

use super::codec::{decode_claim_value, engine_failure};
use super::types::{BookingPageInviteContext, COMM_PARTY_KEY_FIELD};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::booking::constraint::BookingError;
use crate::booking::lifecycle::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_EVENT_TYPE_REF_PREDICATE,
    BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE, BookingBookerContactValue,
    BookingEventTypeRefValue, BookingSourcePageValue, BookingStatus, BookingStatusValue,
};
use crate::calendar::CALENDAR_INVITE_CHANNEL;
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::outbound_grant::StandingOutboundGrantScope;
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};

/// The page/booker binding one confirmed booking persists.
pub(super) struct BookingInviteBinding {
    pub(super) page_ref: EntityId,
    /// Normalized identity of the recorded booker contact.
    pub(super) recipient: String,
    /// The booking's host event type, used as the invitation SUMMARY.
    pub(super) event_type: String,
}

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
pub(super) fn confirmed_booking_binding(
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
pub(crate) fn booker_identity(
    vault: &Vault,
    contact_ref: &EntityId,
) -> Result<Option<String>, BookingError> {
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
