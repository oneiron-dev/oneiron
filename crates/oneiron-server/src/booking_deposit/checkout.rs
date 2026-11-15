//! A hold of a deposit event type opens its deposit checkout (BK-DEPOSITS;
//! Engine ruling 15 Nov 01:10: authorize at hold).
//!
//! The hold door asks this before it enqueues the hold: when the event
//! type's live configuration asks a deposit and the visitor presented no
//! open checkout's lease, Stripe creates the PaymentIntent (manual capture)
//! for those terms, and the engine records the deposit and mints a checkout
//! lease bound to the session and that payment. The hold then presents the
//! lease, so it lives to the checkout window's end, and the hold's answer
//! carries the client secret the visitor's Stripe.js authorizes the card
//! under. The hold door's own admission (its per-address windows) runs
//! before this, so a flood of holds is refused before any Stripe call.

use oneiron::booking::agent_api::BookingDepositCheckout;
use oneiron::booking::lifecycle::{DepositCheckoutStart, begin_deposit_checkout};
use oneiron::booking::{
    BookingError, EventTypeKey, OpaqueCheckoutLeaseToken, SessionKey, configured_deposit_terms,
};
use oneiron::{EntityId, Vault};

use super::stripe::{StripeCallError, StripeClient, publishable_key};

/// The Stripe idempotency domain of one hold's checkout.
const CHECKOUT_IDEMPOTENCY_DOMAIN: &[u8] = b"oneiron.booking.deposit_checkout.v1\0";

/// A checkout the hold opened: the lease it presents, and the visitor's
/// part.
pub(crate) struct OpenedCheckout {
    pub lease: OpaqueCheckoutLeaseToken,
    pub visitor: BookingDepositCheckout,
}

/// Why a hold of a deposit event type could not open its checkout.
#[derive(Debug)]
pub(crate) enum CheckoutFailure {
    /// The engine refused (the configuration or the checkout door).
    Booking(BookingError),
    /// Stripe is not set up on this server, or did not answer.
    Stripe(StripeCallError),
}

/// The Stripe idempotency key of one hold's checkout: the page, the
/// session, the event type and the hold's own replay key. A retried hold
/// finds the same PaymentIntent; a new hold of the session opens a new one,
/// and the old one is voided when its window ends.
fn checkout_idempotency_key(
    page_ref: EntityId,
    session_ref: &str,
    event_type: &EventTypeKey,
    hold_key: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHECKOUT_IDEMPOTENCY_DOMAIN);
    for part in [
        page_ref.as_bytes().as_slice(),
        session_ref.as_bytes(),
        event_type.0.as_bytes(),
        hold_key.as_bytes(),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    format!(
        "oneiron-deposit-checkout-{}",
        &hasher.finalize().to_hex()[..48]
    )
}

/// The hold a checkout is opened for.
pub(crate) struct HoldCheckout<'a> {
    pub page_ref: EntityId,
    pub event_type: &'a EventTypeKey,
    pub session_key: SessionKey,
    pub session_ref: &'a str,
    /// The hold's own replay key.
    pub hold_key: &'a str,
}

/// Opens the deposit checkout of one hold, when its event type asks a
/// deposit. `None` when it asks none: the hold is an ordinary one.
pub(crate) fn open_hold_checkout(
    vault: &Vault,
    stripe_base: &str,
    hold: &HoldCheckout<'_>,
    now: u64,
) -> Result<Option<OpenedCheckout>, CheckoutFailure> {
    let HoldCheckout {
        page_ref,
        event_type,
        session_key,
        session_ref,
        hold_key,
    } = *hold;
    let Some(terms) =
        configured_deposit_terms(vault, page_ref, event_type).map_err(CheckoutFailure::Booking)?
    else {
        return Ok(None);
    };
    let publishable = publishable_key(vault)
        .map_err(|error| CheckoutFailure::Stripe(StripeCallError::Setup(error)))?;
    let client = StripeClient::new(vault, stripe_base).map_err(CheckoutFailure::Stripe)?;
    let payment = client
        .create_deposit_payment(
            &terms,
            &checkout_idempotency_key(page_ref, session_ref, event_type, hold_key),
        )
        .map_err(CheckoutFailure::Stripe)?;
    let lease = begin_deposit_checkout(
        vault,
        &DepositCheckoutStart {
            page_ref,
            event_type: event_type.clone(),
            session_key,
            terms: terms.clone(),
            payment_id: payment.id,
        },
        now,
    )
    .map_err(CheckoutFailure::Booking)?;
    Ok(Some(OpenedCheckout {
        lease: lease.lease.clone(),
        visitor: BookingDepositCheckout {
            checkout_lease_token: lease.lease.0,
            client_secret: payment.client_secret.to_string(),
            publishable_key: publishable,
            amount_minor: terms.amount_minor,
            currency: terms.currency,
        },
    }))
}
