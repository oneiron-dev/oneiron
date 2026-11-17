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

#[doc(hidden)]
pub use oneiron_records::booking::deposit::{
    DEFAULT_DEPOSIT_FULL_REFUND_NOTICE_SECS, DepositRefundRule, DepositTerms,
    MAX_DEPOSIT_AMOUNT_MINOR,
};
