//! BK-DEPOSITS PR 3: the server side of booking deposits, on Stripe.
//!
//! The owner's own Stripe account takes the visitor's deposit; Oneiron holds
//! no funds (Engine ruling, Sun 15 Nov 01:10). The engine half
//! (`oneiron::booking::lifecycle`'s deposit doors) records what Stripe was
//! asked and answered; this module asks it:
//!
//! - [`checkout`]: the public `POST /public/booking/{page}/deposit/checkout`
//!   creates the deposit's PaymentIntent with manual capture for the
//!   published terms and answers the checkout lease the hold presents, with
//!   the client secret Stripe.js authorizes the card under.
//! - [`webhook`]: the keyless, signed `POST /v1/hooks/stripe/booking-deposit`
//!   carries Stripe's word that the card was authorized, refused, or the
//!   payment cancelled.
//! - [`settle`]: the capture right after a confirm, and the worker that
//!   drains every queued capture, void and refund.
//!
//! Test mode only (the owner's word is needed for live money): [`stripe`]
//! refuses a live secret or publishable key before any request, and the
//! webhook refuses a live-mode event.
//!
//! The owner keeps three custody secrets, each bound to the
//! [`DEPOSIT_EFFECTOR`] door: [`STRIPE_SECRET_KEY_NAME`],
//! [`STRIPE_PUBLISHABLE_KEY_NAME`] and [`STRIPE_WEBHOOK_SECRET_NAME`]. A Stripe
//! key is a payment credential, so on a host whose runner fence is unproven
//! the custody door withholds it (L8-60) and deposits stay unavailable until
//! the self-hoster proves the fence or lifts the withholding.

pub(crate) mod checkout;
pub(crate) mod settle;
pub(crate) mod stripe;
pub(crate) mod webhook;

/// The credential door every deposit secret is used at.
pub(crate) const DEPOSIT_EFFECTOR: &str = "booking:deposit";

/// The owner's Stripe secret (or restricted) test key: `sk_test_` or
/// `rk_test_`.
pub(crate) const STRIPE_SECRET_KEY_NAME: &str = "booking.deposit.stripe_secret_key";

/// The owner's Stripe publishable test key (`pk_test_`), handed to the
/// visitor's Stripe.js beside the client secret.
pub(crate) const STRIPE_PUBLISHABLE_KEY_NAME: &str = "booking.deposit.stripe_publishable_key";

/// The signing secret (`whsec_`) of the owner's Stripe webhook endpoint for
/// [`webhook::STRIPE_DEPOSIT_WEBHOOK_PATH`].
pub(crate) const STRIPE_WEBHOOK_SECRET_NAME: &str = "booking.deposit.stripe_webhook_secret";

impl crate::server::SyncServer {
    /// The Stripe API origin booking deposits call.
    pub(crate) fn booking_deposit_stripe_base(&self) -> &str {
        &self.booking_deposit_stripe_base
    }
}
