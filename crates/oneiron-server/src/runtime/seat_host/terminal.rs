//! How the seat host settles a claimed run's end (FIX 9320).
//!
//! A plain BYOA attempt (no bound runner work, or a host whose owner names
//! no runner-seat policy) is captured as before
//! ([`ByoaDispatcher::capture_terminal_exhaust`]). An attempt carrying a
//! bound runner work is folded through the policy's atomic route door
//! ([`ByoaDispatcher::route_runner_terminal`]) at the seat that work's own
//! durable hop names for this attempt, never a seat guessed from the
//! current settings: a spent seat's work parks, takes the next seat, or
//! goes back to the internal models as the owner chose, in the capture's
//! own transaction. The run's typed [`ByoaError::SeatSpent`] goes to the
//! route as the spend it is, and a run that ended printing its limit keeps
//! its whole exhaust as the failure the route reads it from. A route the
//! door ordinarily refuses writes nothing, so the run is then captured as
//! before. TaskErased instead reports an already-committed byte-free native
//! settlement with child spend and seat quota; it must not fall back to capture.
//!
//! Once the end is captured, a bound runner work's attempt that landed
//! Completed, its work not moved on, ends the checkout epoch it reserved
//! through the engine's fail-closed teardown, under the attempt's own
//! reservation and with this server's checkout presence as its liveness
//! ([`ByoaDispatcher::end_runner_checkout`]; Engine RULING
//! EXPORTPROOF-RUNNER-CHECKOUT-END = A). Every other end keeps the lease.

use oneiron::checkout::CheckoutTeardownOutcome;
use oneiron::dispatch_byoa::{
    ByoaDispatcher, ByoaError, ByoaExecutionFence, ByoaExhaust, ByoaResult,
    ByoaTerminalDisposition, CaptureByoaExhaust, ProviderAdapterRegistry, RunnerSeatPolicy,
    SeatRoute, skipped_seats_note, spent_seat_in,
};
use oneiron_vault_contract::now_ts;

use super::super::seat_login::RunnerSeatPolicySettings;
use super::{NoEgress, NoEndpoints};
use crate::server::SyncServer;

/// The owner's policy, its registry, and the seat a bound work's attempt
/// runs on.
type Routing = (ProviderAdapterRegistry, RunnerSeatPolicy, usize);

/// Captures the claimed run under `fence` that ended as `ran`, routing a
/// bound work's end under `runner_seats` when its owner names one.
pub(super) fn settle_host_seat(
    dispatcher: &mut ByoaDispatcher<'_, NoEndpoints, NoEgress>,
    runner_seats: Option<&RunnerSeatPolicySettings>,
    fence: &ByoaExecutionFence,
    ran: ByoaResult<ByoaExhaust>,
) {
    let routing = runner_seats.and_then(|settings| routing_of(dispatcher, settings, fence));
    let (disposition, exhaust, reason, spent) = match ran {
        Ok(exhaust) => {
            // A routed run that printed its seat's limit is spent: its whole
            // exhaust is the failure the route reads the spend from.
            let spent = if routing.is_some() {
                spent_seat_in(&exhaust).unwrap_or_else(|error| {
                    tracing::warn!(%error, "a seat run's exhaust could not be read for a spend");
                    None
                })
            } else {
                None
            };
            match spent {
                Some(spent) => (ByoaTerminalDisposition::Failed, exhaust, None, Some(spent)),
                None => (ByoaTerminalDisposition::Completed, exhaust, None, None),
            }
        }
        Err(error) => {
            tracing::warn!(%error, "a seat run failed; its failure is captured");
            let reason = Some(error.to_string());
            let spent = match error {
                ByoaError::SeatSpent(spent) => Some(spent),
                _ => None,
            };
            (
                ByoaTerminalDisposition::Failed,
                ByoaExhaust::default(),
                reason,
                spent,
            )
        }
    };
    let capture = CaptureByoaExhaust {
        attempt_id: fence.attempt_id,
        lease_owner: fence.lease_owner.clone(),
        attempt_count: fence.attempt_count,
        disposition,
        exhaust,
        reason,
        now: now_ts(),
    };
    if let Some((registry, policy, seat)) = routing {
        match dispatcher.route_runner_terminal(&registry, &policy, seat, capture.clone(), spent) {
            Ok(route) => {
                note_route(&route);
                return;
            }
            Err(ByoaError::TaskErased) => return,
            // Every other refusal wrote nothing: capture as a plain run.
            Err(error) => {
                tracing::warn!(%error, "a seat run's route was refused; it is captured as it ended");
            }
        }
    }
    if let Err(error) = dispatcher.capture_terminal_exhaust(capture) {
        tracing::warn!(%error, "a seat run's exhaust was not captured");
    }
}

/// Ends the checkout `fence`'s attempt reserved, once its end is captured:
/// the engine judges whether the capture landed Completed with its work not
/// moved on, and tears the epoch down under the attempt's own reservation,
/// collecting the tree only with a pushed-head receipt, a clean tree and no
/// live occupant in `server`'s checkout presence. Any other end keeps the
/// lease; a refusal is logged and keeps it too.
pub(super) fn end_runner_checkout(
    dispatcher: &ByoaDispatcher<'_, NoEndpoints, NoEgress>,
    server: &SyncServer,
    fence: &ByoaExecutionFence,
) {
    match dispatcher.end_runner_checkout(fence, &mut server.checkout_presence()) {
        Ok(None) => {}
        Ok(Some(CheckoutTeardownOutcome::Collected { epoch, .. })) => {
            tracing::info!(epoch, "a runner attempt's checkout was collected");
        }
        Ok(Some(CheckoutTeardownOutcome::Retained { epoch, reason, .. })) => {
            tracing::info!(
                epoch,
                ?reason,
                "a runner attempt's checkout is retained for its holder"
            );
        }
        Err(error) => {
            tracing::warn!(%error, "a runner attempt's checkout was not torn down; its lease stays");
        }
    }
}

/// The owner's policy and the seat `fence`'s bound work runs on, when the
/// attempt carries one and the settings fold.
fn routing_of(
    dispatcher: &ByoaDispatcher<'_, NoEndpoints, NoEgress>,
    settings: &RunnerSeatPolicySettings,
    fence: &ByoaExecutionFence,
) -> Option<Routing> {
    let seat = match dispatcher.host_attempt_seat(fence.attempt_id) {
        Ok(seat) => seat?,
        Err(error) => {
            tracing::warn!(%error, "a seat run's bound work could not be read; it is captured plain");
            return None;
        }
    };
    let folded = settings
        .registry()
        .and_then(|registry| Ok((settings.policy()?, registry)));
    match folded {
        Ok((policy, registry)) => Some((registry, policy, seat)),
        Err(error) => {
            tracing::warn!(%error, "the runner-seat policy does not fold; the run is captured plain");
            None
        }
    }
}

/// Logs where a routed run's work went. The work's own durable hop record
/// carries it on: the next seat's attempt is queued, and a parked or
/// internal-models work is read by its owning Dreamer attempt.
fn note_route(route: &SeatRoute) {
    match route {
        SeatRoute::Settled(_) => {}
        SeatRoute::Park { until, receipt, .. } => tracing::info!(
            ?until,
            skipped = %skipped_seats_note(&receipt.skipped_seats),
            "a seat run's seat is spent; its work is parked"
        ),
        SeatRoute::NextSeat { seat, receipt, .. } => tracing::info!(
            seat,
            skipped = %skipped_seats_note(&receipt.skipped_seats),
            "a seat run's seat is spent; the next seat took its work"
        ),
        SeatRoute::InternalModels { .. } => {
            tracing::info!("a seat run's seat is spent; its work goes back to the internal models")
        }
        _ => tracing::info!("a seat run's work was routed"),
    }
}
