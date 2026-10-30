//! Admission observations wrap the original generated typed dispatch, not a
//! generic submit endpoint. The supplied invocation id is its public intent
//! handle. The original credential, context, gates and hooks stay intact.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use oneiron::receipt::admission::AdmissionTracker;
use oneiron::work_line::LineObserver;

use super::{FacadeApiError, FacadeCall, FacadeCallOutput, dispatch, facade_actor};
use crate::server::SyncServer;

tokio::task_local! {
    static OBSERVER: Arc<dyn LineObserver>;
}

pub(crate) fn admission_observer() -> Option<Arc<dyn LineObserver>> {
    OBSERVER.try_with(Arc::clone).ok()
}

struct Flight {
    tracker: AdmissionTracker,
    settled: bool,
}

impl Drop for Flight {
    fn drop(&mut self) {
        if !self.settled
            && let Err(error) = self.tracker.interrupt()
        {
            tracing::error!(%error, "admission interruption receipt failed");
        }
    }
}

/// Every admitted call still runs its original typed row. Owning the worker
/// keeps it and its permit alive if the HTTP client stops waiting. The
/// durable active fence prevents a second worker for the same intent even
/// when the outer transport's in-memory invocation claim has gone away. An
/// owner's erase or revoke keeps the restriction-only clock in its detached
/// worker too (FIX 11201).
pub(crate) fn call_verb<'a>(
    server: &'a Arc<SyncServer>,
    call: &'a FacadeCall<'a>,
    verb: &'a str,
    input: Result<serde_json::Value, FacadeApiError>,
) -> Pin<Box<dyn Future<Output = Result<FacadeCallOutput, FacadeApiError>> + Send + 'a>> {
    let restrictive = super::clock_ingress::restrictive_call(server, verb, input.as_ref().ok());
    Box::pin(super::clock_ingress::scoped(restrictive, async move {
        let named = call.invocation()?;
        // No receipt of an off-record sitting is ever kept. Session-bound
        // calls retain their original door and its own recording policy.
        if named.is_none()
            || call.session_ref().is_some()
            || oneiron::task_verb::sdk::NO_RECORD_ROWS.contains(&verb)
            || verb.starts_with("self.admission.")
            || !oneiron::task_verb::sdk::AgentVerb::from_name(verb)
                .is_some_and(oneiron::task_verb::sdk::AgentVerb::is_facade)
        {
            return dispatch::call_verb(server, call, verb, input).await;
        }
        let value = match input {
            Ok(value) => value,
            Err(error) => return dispatch::call_verb(server, call, verb, Err(error)).await,
        };
        // A row that binds no actor still runs under its original authority
        // gate. It has no actor-owned admission ledger to read back.
        let Ok((actor, class)) = facade_actor(server, call.auth()) else {
            return dispatch::call_verb(server, call, verb, Ok(value)).await;
        };
        let invocation = named.expect("named invocation checked above");
        let digest = oneiron::receipt::call_json_digest(&value);
        let room = call.room_turn()?.map(|id| id.to_hex()).unwrap_or_default();
        let fingerprint = crate::api::facade::invocation_body(
            Some(call.auth()),
            call.auth().locality(),
            &[verb.as_bytes(), room.as_bytes(), digest.as_bytes()],
        );
        let fingerprint = blake3::Hash::from_bytes(fingerprint).to_hex().to_string();
        let (server, call, verb) = (Arc::clone(server), call.owned(), verb.to_owned());
        let worker = super::clock_ingress::scoped(restrictive, async move {
            // The receipt and worker start inside the same detached task:
            // hanging up during the durable write cannot orphan an intent.
            let vault = Arc::clone(server.vault());
            let name = verb.clone();
            let tracker = super::clock_ingress::run_blocking(move || {
                AdmissionTracker::start(vault, actor, class, invocation, &name, digest, fingerprint)
            })
            .await
            .map_err(|_| super::host_doors::support::internal(&verb))??;
            let mut flight = Flight {
                tracker,
                settled: false,
            };
            let observer: Arc<dyn LineObserver> = Arc::new(flight.tracker.clone());
            let result = OBSERVER
                .scope(observer, async {
                    dispatch::call_verb(&server, &call.call(), &verb, Ok(value)).await
                })
                .await;
            let finish = match &result {
                Ok(output) => flight.tracker.finish(Ok(&output.value)),
                Err(error) => flight
                    .tracker
                    .finish(Err((&error.body.error.code, &error.body.error.message))),
            };
            finish?;
            flight.settled = true;
            result
        });
        // A code run's or an action's call keeps its origin and run writes
        // in the detached worker (FIX 10748).
        tokio::spawn(super::host_doors::support::carrying_calling_run(worker))
            .await
            .map_err(|_| super::host_doors::support::internal("admission"))?
    }))
}
