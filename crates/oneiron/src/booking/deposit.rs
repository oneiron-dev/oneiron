//! BK-DEPOSITS: the deposit an event type asks before a booking is
//! confirmed (ARCH-0062 §7 `v1.5` row, the R3 payment note).
//!
//! The owner sets the terms per event type, inside its configuration
//! ([`crate::booking::EventTypeConfig::deposit`]; Engine ruling, Sun 15 Nov
//! 01:10): the amount, the currency and the refund rule, with the defaults
//! stated below. The visitor's card is authorized when the hold is extended
//! to the checkout window, captured at confirm, and the authorization is
//! voided when the hold dies unconfirmed. The money is the visitor's, paid to
//! the owner's own Stripe account; Oneiron holds no funds.
//!
//! The public card carries the same terms
//! ([`crate::booking::EventTypeCard::deposit`]), and the live publication read
//! refuses a card whose terms differ from its configuration, so the terms a
//! visitor pays are the ones the owner published.

use crate::booking::BookingError;

#[doc(hidden)]
pub use oneiron_records::booking::deposit::{
    DEFAULT_DEPOSIT_FULL_REFUND_NOTICE_SECS, DepositRefundRule, DepositTerms,
    MAX_DEPOSIT_AMOUNT_MINOR,
};

/// The deposit the live configuration of `page_ref`'s event type `key` asks,
/// if it asks one: the terms a server creates the provider payment for
/// before the hold, which the checkout door then checks again in its writer.
///
/// # Errors
///
/// [`BookingError::InvalidConfig`] when the event type has no live
/// configuration; [`BookingError::SlotOracle`] on a store failure.
pub fn configured_deposit_terms(
    vault: &crate::Vault,
    page_ref: crate::EntityId,
    key: &crate::booking::EventTypeKey,
) -> Result<Option<DepositTerms>, BookingError> {
    crate::booking::config::load_event_type_config(vault, page_ref, key)
        .map(|config| config.deposit)
}

/// The provider idempotency domain of one hold's deposit checkout.
const CHECKOUT_IDEMPOTENCY_DOMAIN: &[u8] = b"oneiron.booking.deposit_checkout.v1\0";

/// The provider (Stripe) idempotency key of one hold's deposit checkout: the
/// page, the session, the event type, the hold's own replay key and the terms
/// the visitor accepted, each as its length (u64 little-endian) and its bytes,
/// under the checkout domain. A retried hold finds the same payment; a new
/// hold of the session, or a retry after the terms changed, opens a new one,
/// and an old one is voided when its window ends.
///
/// The digest is the booking lifecycle's domain-tagged one, so a server opens
/// no hasher of its own.
#[must_use]
pub fn deposit_checkout_idempotency_key(
    page_ref: crate::EntityId,
    session_ref: &str,
    event_type: &crate::booking::EventTypeKey,
    hold_key: &str,
    terms: &DepositTerms,
) -> String {
    let amount = terms.amount_minor.to_le_bytes();
    let notice = terms.refund.full_refund_notice_secs.to_le_bytes();
    let late = [terms.refund.late_cancel_refund_percent];
    let mut material = Vec::new();
    for part in [
        page_ref.as_bytes().as_slice(),
        session_ref.as_bytes(),
        event_type.0.as_bytes(),
        hold_key.as_bytes(),
        amount.as_slice(),
        terms.currency.as_bytes(),
        notice.as_slice(),
        late.as_slice(),
    ] {
        material.extend_from_slice(&(part.len() as u64).to_le_bytes());
        material.extend_from_slice(part);
    }
    let digest = super::lifecycle::digest_with(CHECKOUT_IDEMPOTENCY_DOMAIN, &material);
    format!(
        "oneiron-deposit-checkout-{}",
        &super::lifecycle::hex_lower(&digest)[..48]
    )
}
