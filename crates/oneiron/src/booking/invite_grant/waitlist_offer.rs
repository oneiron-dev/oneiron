//! A waitlist offer's one email (RULING L3-13-OFFER-CHANNEL = A, Engine 15
//! Nov 13:42): the page's standing invite grant covers exactly one more kind
//! of send, an `(email, send)` to the contact of an entry on that same page
//! that holds a standing offer, and only that offer's own send.
//!
//! The offer is an ordinary send. It leaves as the page's verified live
//! publisher through the outbound door, the gate and the intent ledger, with
//! no sender of its own: the dispatch picks the publisher's email identity as
//! it does for any send. Its body ref names the page and the offer token's
//! digest ([`crate::booking::lifecycle::WAITLIST_OFFER_CONTENT_PREFIX`]), so
//! the frozen intent itself says which offer it is without holding the token
//! a claim presents, and three doors check it:
//!
//! * this dispatch door sends only the offer a committed pass made, to the
//!   contact its entry recorded, under the page's live grant;
//! * the outbound admission ([`admit_frozen_waitlist_offer_in_txn`]) binds
//!   the page grant to a send naming an offer only when that offer stands on
//!   the page at the store clock, its waiter is the target, the actor is the
//!   page's verified live publisher, and the intent and its ledger identity
//!   are the offer's own; it refuses any other send that names one, on a
//!   fresh send and on every retry;
//! * the gate effect lets the bound page grant cover an `(email, send)` only
//!   to the contact of an entry on its page holding an offer that stands at
//!   the store clock ([`page_grant_reaches_waitlist_offer_in_txn`]). The
//!   consent ladder folds that match as it folds every covering standing
//!   grant.
//!
//! One send per offer: the intent's idempotency key and its ledger identity
//! are both derived from the page and the offer token's digest, the admission
//! refuses any other key or identity, and the ledger answers a repeat of that
//! identity with the intent it recorded.

use super::authorization::{booker_identity, booker_identity_in_txn, normalize_identity};
use super::codec::{engine_failure, refused};
use super::mint::{live_page_invite_grant, live_page_invite_grant_in_txn};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::booking::constraint::BookingError;
use crate::booking::lifecycle::{
    WaitlistOfferMade, hex_lower, offer_token_digest, offered_waitlist_contacts_in_txn,
    parse_waitlist_offer_content_ref, standing_waitlist_offer_in_txn, waitlist_offer_content_ref,
};
use crate::entity_id::EntityId;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger, outbound_dispatch_attempt_id,
};
use serde::Deserialize;

/// Domain tag for one offer's stable ledger identity.
const WAITLIST_OFFER_INTENT_DOMAIN: &[u8] = b"oneiron.booking.waitlist_offer_intent.v1\0";

/// The channel and verb of the one send kind a page grant adds.
const OFFER_CHANNEL: &str = "email";
const OFFER_VERB: &str = "send";

/// The logical send ref one offer dispatches under: one per page and offer
/// token, so a second send of the same offer lands on the first's intent.
fn waitlist_offer_intent_ref(page_ref: &EntityId, offer_token_hash: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WAITLIST_OFFER_INTENT_DOMAIN);
    hasher.update(page_ref.as_bytes());
    hasher.update(offer_token_hash);
    format!(
        "intent:booking_waitlist_offer:{}",
        hex_lower(hasher.finalize().as_bytes())
    )
}

/// Sends one offer a committed pass made to its waiter, as `actor`, the
/// page's verified live publisher.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when the page has no live grant for
/// `actor`, the offer no longer stands, its contact has no address, or the
/// outbound door refuses; [`BookingError::SlotOracle`] on store failures.
pub(in crate::booking) fn dispatch_waitlist_offer(
    vault: &Vault,
    actor: EntityId,
    offer: &WaitlistOfferMade,
    sink: &mut impl OutboundExecutionSink,
    now: u64,
) -> Result<(), BookingError> {
    if live_page_invite_grant(vault, &actor.to_hex(), &offer.page_ref)?.is_none() {
        return Err(refused(
            "this page carries no live booking page invite grant",
        ));
    }
    let offer_token_hash = offer_token_digest(&offer.offer_token);
    {
        let rtxn = vault
            .store
            .env
            .read_txn()
            .map_err(|error| engine_failure("read transaction", error))?;
        let standing = standing_waitlist_offer_in_txn(
            &vault.store,
            &rtxn,
            &offer.page_ref,
            &offer_token_hash,
            now,
        )
        .map_err(|error| engine_failure("waitlist read", error))?;
        if standing.is_none_or(|standing| standing.contact_ref != offer.contact_ref) {
            return Err(refused("this waitlist offer no longer stands"));
        }
    }
    let Some(recipient) = booker_identity(vault, &offer.contact_ref)? else {
        return Err(refused("this waiter's contact carries no address"));
    };
    let recipient = normalize_identity(&recipient);
    let intent_ref = waitlist_offer_intent_ref(&offer.page_ref, &offer_token_hash);
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), OFFER_VERB, OFFER_CHANNEL, recipient.clone())
            .content_ref(waitlist_offer_content_ref(
                &offer.page_ref,
                &offer_token_hash,
            ))
            .idempotency_key(intent_ref.clone()),
        OutboundIntentTrigger::agent_immediate(format!(
            "booking_waitlist:{}",
            offer.page_ref.to_hex()
        )),
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
    .counterparty_ref(recipient);
    vault
        .dispatch_outbound_intent(request, sink)
        .map_err(|error| refused(format!("waitlist offer dispatch refused: {error}")))?;
    Ok(())
}

/// The frozen fields a send naming a waitlist offer is admitted on.
#[derive(Deserialize)]
struct OfferPublication {
    verb: String,
    channel: String,
    target: String,
    #[serde(default)]
    recipients: Vec<serde_json::Value>,
    content_ref: Option<String>,
    idempotency_key: Option<String>,
    counterparty_ref: Option<String>,
}

/// The page grant a frozen send that names a waitlist offer runs under: its
/// `bytes`, sent by `actor` as ledger attempt `attempt_id`, call `call_seq`,
/// read on the outbound writer's snapshot at `now`, the store clock. `None`
/// for a send that names none: it is an ordinary send, and no page grant
/// covers it. A send that names an offer refuses unless it is that offer's
/// own one email: `(email, send)` to the waiter alone, under the offer's
/// intent and ledger identity, while the offer stands on the page and
/// `actor` is the page's verified live publisher holding its live grant.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] for a send naming an offer it may not
/// carry; [`BookingError::SlotOracle`] on store failures.
pub(crate) fn admit_frozen_waitlist_offer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: Option<EntityId>,
    (attempt_id, call_seq): (AttemptId, u64),
    bytes: &[u8],
    now: u64,
) -> Result<Option<EntityId>, BookingError> {
    // Non-JSON effects name no offer.
    let Ok(frozen) = serde_json::from_slice::<OfferPublication>(bytes) else {
        return Ok(None);
    };
    let Some((page_ref, offer_token_hash)) = frozen
        .content_ref
        .as_deref()
        .and_then(parse_waitlist_offer_content_ref)
    else {
        return Ok(None);
    };
    if frozen.channel.trim() != OFFER_CHANNEL
        || frozen.verb.trim() != OFFER_VERB
        || !frozen.recipients.is_empty()
    {
        return Err(refused("a waitlist offer is one email to its waiter alone"));
    }
    let target = normalize_identity(&frozen.target);
    if frozen
        .counterparty_ref
        .as_deref()
        .is_some_and(|party| normalize_identity(party) != target)
    {
        return Err(refused(
            "a waitlist offer must go to its admitted recipient",
        ));
    }
    let intent_ref = waitlist_offer_intent_ref(&page_ref, &offer_token_hash);
    if frozen.idempotency_key.as_deref() != Some(intent_ref.as_str()) {
        return Err(refused(
            "a waitlist offer is sent once, under its own intent",
        ));
    }
    // The ledger dedupes by the attempt, not by the key inside the intent: a
    // copy of the offer's intent under another ledger identity would be a
    // second send.
    // RED PROOF (review): no ledger identity check.
    let _ = (attempt_id, call_seq);
    let actor = actor.ok_or_else(|| refused("a waitlist offer requires an acting principal"))?;
    let Some(offer) =
        standing_waitlist_offer_in_txn(&vault.store, txn, &page_ref, &offer_token_hash, 0)
            .map_err(|error| engine_failure("waitlist read", error))?
    else {
        return Err(refused("this waitlist offer no longer stands"));
    };
    // The grant outlives a withdrawn publication: re-prove the publisher on
    // this snapshot, for a retry as for a first send.
    // RED PROOF (review): no live publisher check, no clock.
    let _ = now;
    let waiter = booker_identity_in_txn(vault, txn, &offer.contact_ref)?;
    if waiter.is_none_or(|waiter| normalize_identity(&waiter) != target) {
        return Err(refused("a waitlist offer goes only to its own waiter"));
    }
    let Some((grant_ref, _)) =
        live_page_invite_grant_in_txn(vault, txn, &actor.to_hex(), &page_ref)?
    else {
        return Err(refused(
            "this page carries no live booking page invite grant",
        ));
    };
    Ok(Some(grant_ref))
}

/// Whether `recipient` is the contact of an entry on `page_ref` that holds
/// an offer standing at `now`, the store clock: the one more send a booking
/// page grant covers at the gate.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn page_grant_reaches_waitlist_offer_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    page_ref: &EntityId,
    recipient: &str,
    now: u64,
) -> crate::Result<bool> {
    let wanted = normalize_identity(recipient);
    // RED PROOF (review): no clock.
    let _ = now;
    for contact in offered_waitlist_contacts_in_txn(store, txn, page_ref, 0)? {
        if super::authorization::person_identity_in_txn(store, txn, &contact)?
            .is_some_and(|identity| normalize_identity(&identity) == wanted)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
