//! A deposit's money moves on the server: the authorization read at
//! confirm, the capture right after it, and the worker that drains every
//! queued capture, void and refund through Stripe.

use std::sync::Arc;
use std::time::Duration;

use oneiron::attempt_queue::{AttemptQueue, CleanupAttemptLeases};
use oneiron::booking::SessionKey;
use oneiron::booking::lifecycle::{
    BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND, BookingDepositSettlementDrain, DepositProviderEvent,
    DepositProviderEventKind, DepositSettleStep, DepositState, booking_deposit_for_session_hold,
    record_deposit_provider_event, run_booking_deposit_settlement, settle_booking_deposit,
};
use oneiron::{EntityId, Vault};

use super::stripe::StripeClient;
use crate::server::{HousekeepingAdmission, SyncServer};

/// The settle worker's lease owner on the attempt queue.
const SETTLE_LEASE_OWNER: &str = "booking-deposit-settle";

/// How often the worker drains due settle rows. A checkout window's end is
/// voided within this of the window closing.
const SETTLE_INTERVAL: Duration = Duration::from_secs(60);

/// How many settle rows one pass runs.
const SETTLE_PASS_LIMIT: usize = 32;

/// The Stripe status of a PaymentIntent whose card is authorized and
/// waits for capture.
const REQUIRES_CAPTURE: &str = "requires_capture";

/// Before a confirm runs: when the session's hold waits on a deposit Stripe
/// has not yet been heard to authorize, ask Stripe. The visitor's browser
/// usually confirms before the webhook arrives; Stripe's own answer over
/// the owner's key is the same word the webhook carries, recorded once.
/// Any failure leaves the deposit as it stands: the confirm writer then
/// refuses an unauthorized deposit as always.
pub(crate) fn sync_hold_authorization(
    vault: &Vault,
    stripe_base: &str,
    session_key: &SessionKey,
    now: u64,
) {
    let Ok(Some(deposit)) = booking_deposit_for_session_hold(vault, session_key, now) else {
        return;
    };
    if !matches!(
        deposit.state,
        DepositState::AwaitingAuthorization | DepositState::AuthorizationFailed
    ) {
        return;
    }
    let intent = match StripeClient::new(vault, stripe_base)
        .and_then(|client| client.payment_intent(&deposit.payment_id))
    {
        Ok(intent) => intent,
        Err(error) => {
            tracing::debug!(%error, "a deposit's authorization was not read from Stripe");
            return;
        }
    };
    if intent.livemode || intent.status != REQUIRES_CAPTURE {
        return;
    }
    let event = DepositProviderEvent {
        event_id: format!("sync_{}", intent.id),
        payment_id: intent.id,
        kind: DepositProviderEventKind::Authorized {
            amount_minor: intent.amount_capturable,
            currency: intent.currency,
        },
    };
    if let Err(error) = record_deposit_provider_event(vault, &event, now) {
        tracing::warn!(%error, "a deposit's authorization read from Stripe was not recorded");
    }
}

/// Right after a confirm committed: capture the booking's deposit. A
/// failure fails nothing: the booking stands, and its queued settle row
/// captures on the worker's next pass.
pub(crate) fn capture_after_confirm(
    vault: &Vault,
    stripe_base: &str,
    event_ref: &EntityId,
    now: u64,
) {
    let step = StripeClient::new(vault, stripe_base)
        .map_err(|error| error.to_string())
        .and_then(|mut client| {
            settle_booking_deposit(vault, event_ref, &mut client, now)
                .map_err(|error| error.to_string())
        });
    match step {
        Ok(DepositSettleStep::Nothing | DepositSettleStep::Moved(_)) => {}
        Ok(other) => tracing::info!(?other, "a deposit's capture waits for the settle worker"),
        Err(error) => tracing::warn!(%error, "a deposit's capture waits for the settle worker"),
    }
}

/// One settle pass: every due capture, void and refund through Stripe.
///
/// # Errors
///
/// The queue failure the pass met; a failed Stripe call settles its own row.
pub(crate) fn settle_deposits_once(
    vault: &Vault,
    stripe_base: &str,
    now: u64,
) -> anyhow::Result<BookingDepositSettlementDrain> {
    let mut client =
        StripeClient::new(vault, stripe_base).map_err(|error| anyhow::anyhow!("{error}"))?;
    run_booking_deposit_settlement(
        vault,
        SETTLE_LEASE_OWNER,
        &mut client,
        SETTLE_PASS_LIMIT,
        now,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))
}

/// Starts the settle worker: a pass every [`SETTLE_INTERVAL`], off the
/// runtime, each admitted through `admit` as a housekeeping pass is, so a
/// vault frozen for reap moves no money. A row a stopped host leased is
/// released before the first pass: this worker is the kind's only one.
pub(crate) fn spawn_deposit_settlement(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(SETTLE_INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut released = false;
        loop {
            ticks.tick().await;
            let Some(admission) = admit() else {
                continue;
            };
            let release = !std::mem::replace(&mut released, true);
            let vault = Arc::clone(server.vault());
            let base = server.booking_deposit_stripe_base().to_owned();
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                if release {
                    release_settle_leases(&vault)?;
                }
                settle_deposits_once(&vault, &base, vault.now_recorded_at())
            })
            .await;
            match pass {
                Ok(Ok(drain)) if drain != BookingDepositSettlementDrain::default() => {
                    tracing::info!(
                        captured = drain.captured,
                        voided = drain.voided,
                        refunded = drain.refunded,
                        retrying = drain.retrying,
                        pending = drain.pending,
                        failed = drain.failed,
                        "booking deposits settled"
                    );
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    let error = format!("{error:#}");
                    tracing::warn!(error = %error, "booking deposit settle pass failed");
                }
                Err(error) => tracing::warn!(%error, "booking deposit settle pass did not run"),
            }
        }
    })
}

/// Returns to the queue every settle row a stopped host leased and never
/// settled.
fn release_settle_leases(vault: &Vault) -> anyhow::Result<()> {
    AttemptQueue::new(vault).cleanup_kind_leases(
        BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND,
        CleanupAttemptLeases {
            now: vault.now_recorded_at(),
            lease_timeout_secs: 1,
        },
    )?;
    Ok(())
}
