//! The booking routes' deposit steps (BK-DEPOSITS): a hold of a deposit
//! event type opens its checkout, a confirm first reads Stripe's word on the
//! authorization, and a committed confirm captures. The money calls are
//! `crate::booking_deposit`'s; this module only fits them to the hold and
//! confirm stages and their refusals.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::booking::agent_api::{BookingDepositCheckout, BookingHoldInput};
use oneiron::booking::{HoldLeaseSpec, OpaqueCheckoutLeaseToken, SessionKey};

use super::helpers::booking_error;
use crate::booking_deposit::checkout::{CheckoutFailure, HoldCheckout, open_hold_checkout};
use crate::booking_deposit::settle::{capture_after_confirm, sync_hold_authorization};
use crate::booking_deposit::stripe::StripeCallError;
use crate::error::ApiError;
use crate::server::SyncServer;

/// The lease a hold presents, and the checkout it opened.
///
/// A presented lease is used as it is (a later hold of an open checkout,
/// or the server's own lease). Otherwise a deposit event type opens its
/// checkout here, and its hold presents the new lease; any other hold is an
/// ordinary one.
pub(super) async fn hold_lease(
    server: &Arc<SyncServer>,
    page_ref: EntityId,
    input: &BookingHoldInput,
    session_key: SessionKey,
    now: u64,
) -> Result<(HoldLeaseSpec, Option<BookingDepositCheckout>), ApiError> {
    if let Some(token) = &input.checkout_lease_token {
        return Ok((
            HoldLeaseSpec::CheckoutExtension {
                server_issued_lease: OpaqueCheckoutLeaseToken(token.clone()),
            },
            None,
        ));
    }
    let vault = Arc::clone(server.vault());
    let base = server.booking_deposit_stripe_base().to_owned();
    let event_type = input.event_type.clone();
    let session_ref = input.session_ref.clone();
    let hold_key = input.idempotency_key.clone();
    let shown_terms = input.deposit_terms.clone();
    let opened = tokio::task::spawn_blocking(move || {
        open_hold_checkout(
            &vault,
            &base,
            &HoldCheckout {
                page_ref,
                event_type: &event_type,
                session_key,
                session_ref: &session_ref,
                hold_key: &hold_key,
                shown_terms: shown_terms.as_ref(),
            },
            now,
        )
    })
    .await
    .map_err(|_| ApiError::internal_server_error("booking deposit checkout did not run"))?;
    match opened {
        Ok(Some(opened)) => Ok((
            HoldLeaseSpec::CheckoutExtension {
                server_issued_lease: opened.lease,
            },
            Some(opened.visitor),
        )),
        Ok(None) => Ok((HoldLeaseSpec::Ordinary, None)),
        Err(CheckoutFailure::Booking(error)) => Err(booking_error(error)),
        // The page shows the card again, with its live terms.
        Err(CheckoutFailure::TermsMissing) => Err(ApiError::invalid_state(Some(
            "booking_deposit_terms_required",
        ))),
        Err(CheckoutFailure::TermsChanged) => Err(ApiError::invalid_state(Some(
            "booking_deposit_terms_changed",
        ))),
        Err(CheckoutFailure::Stripe(StripeCallError::Setup(error))) => {
            tracing::warn!(%error, "a deposit event type was held on a server with no usable Stripe test key");
            Err(ApiError::invalid_state(Some("booking_deposit_unavailable")))
        }
        Err(CheckoutFailure::Stripe(error)) => {
            tracing::warn!(%error, "Stripe did not open a deposit checkout");
            Err(ApiError::invalid_state(Some(
                "booking_deposit_provider_unavailable",
            )))
        }
    }
}

/// Before a confirm: Stripe's own word on the hold's deposit, when the
/// webhook has not yet carried it. Nothing here refuses; the confirm writer
/// does, for a deposit still unauthorized.
pub(super) async fn before_confirm(server: &Arc<SyncServer>, session_key: SessionKey, now: u64) {
    let vault = Arc::clone(server.vault());
    let base = server.booking_deposit_stripe_base().to_owned();
    let _ = tokio::task::spawn_blocking(move || {
        sync_hold_authorization(&vault, &base, &session_key, now);
    })
    .await;
}

/// After a committed confirm: capture its deposit. A failure leaves the
/// capture to the settle worker and never fails the booking.
pub(super) async fn after_confirm(server: &Arc<SyncServer>, event_ref: EntityId, now: u64) {
    let vault = Arc::clone(server.vault());
    let base = server.booking_deposit_stripe_base().to_owned();
    let _ = tokio::task::spawn_blocking(move || {
        capture_after_confirm(&vault, &base, &event_ref, now);
    })
    .await;
}
