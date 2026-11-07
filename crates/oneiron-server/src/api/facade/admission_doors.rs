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

/// `work` under `observer`, the serving call's admission observer as the
/// task that spawned `work` held it: each wait `work` takes in a line is
/// reported on that call's receipt. No task-local crosses a spawn on its
/// own, so a task run for part of a call carries it there (FIX 4735).
pub(crate) async fn with_admission_observer<F: Future>(
    observer: Option<Arc<dyn LineObserver>>,
    work: F,
) -> F::Output {
    match observer {
        Some(observer) => OBSERVER.scope(observer, work).await,
        None => work.await,
    }
}

/// [`with_admission_observer`] with the observer this task holds now, taken
/// before `work` is spawned.
pub(crate) fn carrying_admission_observer<F: Future>(work: F) -> impl Future<Output = F::Output> {
    with_admission_observer(admission_observer(), work)
}

/// `run` on this thread under `observer`: a blocking hop's closure, whose
/// own spawns then carry the call's observer as an async task's do.
pub(crate) fn with_admission_observer_sync<R>(
    observer: Option<Arc<dyn LineObserver>>,
    run: impl FnOnce() -> R,
) -> R {
    match observer {
        Some(observer) => OBSERVER.sync_scope(observer, run),
        None => run(),
    }
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
/// worker too (FIX 11201). A custody row's value, on a transport that hands
/// its input decoded, leaves the args before any hook reads them and rides
/// to its door scoped (FIX 11665).
pub(crate) fn call_verb<'a>(
    server: &'a Arc<SyncServer>,
    call: &'a FacadeCall<'a>,
    verb: &'a str,
    input: Result<serde_json::Value, FacadeApiError>,
) -> Pin<Box<dyn Future<Output = Result<FacadeCallOutput, FacadeApiError>> + Send + 'a>> {
    let mut input = input;
    let secret = input
        .as_mut()
        .ok()
        .and_then(|value| super::secret_body::lift_custody_secret(verb, value));
    let restrictive = super::clock_ingress::restrictive_call(server, verb, input.as_ref().ok());
    let admitted = super::clock_ingress::scoped(restrictive, async move {
        let named = call.invocation()?;
        if named.is_none() || !tracks_admission(verb) {
            return dispatch::call_verb(server, call, verb, input).await;
        }
        let value = match input {
            Ok(value) => value,
            Err(error) => return dispatch::call_verb(server, call, verb, Err(error)).await,
        };
        // No receipt of an off-record sitting is ever kept (OF-063): a call
        // inside an anonymous off-record session its principal is verified
        // in, or one serving a room NOTE (FIX 4280), keeps none, judged on
        // arrival as its call receipt judges it. Any other session-bound
        // call keeps its admission receipt as anywhere else (FIX 4735).
        if keeps_no_record(server, call, verb, &value) {
            return dispatch::call_verb(server, call, verb, Ok(value)).await;
        }
        // A row that binds no actor still runs under its original authority
        // gate. It has no actor-owned admission ledger to read back.
        let Ok((actor, class)) = facade_actor(server, call.auth()) else {
            return dispatch::call_verb(server, call, verb, Ok(value)).await;
        };
        let invocation = named.expect("named invocation checked above");
        // Settlement's run of a held call reopens its held intent (FIX 8753).
        let resumed = call.drain().is_some();
        // A paced call the drain already ran answers its saved outcome to
        // the same caller's retry, before an admission intent starts again:
        // that intent is settled, and the effect never runs twice (FIX 8753).
        if !resumed {
            let ended = crate::server::blocking(|| {
                let memory = super::facade_invocation(
                    crate::api::credential_memory(server.vault(), Some(call.auth()), actor, class)
                        .at(call.auth().locality()),
                    call,
                )?;
                Ok::<_, FacadeApiError>(memory.ended_paced_verb_reply(verb))
            })?;
            match ended {
                Some(Ok(value)) => {
                    return Ok(FacadeCallOutput::listed(
                        value,
                        &oneiron::memory::ProducerRows::default(),
                    ));
                }
                Some(Err(error)) => return Err(error.into()),
                None => {}
            }
        }
        let digest = oneiron::receipt::call_json_digest(&value);
        let room = call.room_turn()?.map(|id| id.to_hex()).unwrap_or_default();
        let fingerprint = crate::api::facade::invocation_body(
            Some(call.auth()),
            call.auth().locality(),
            &[verb.as_bytes(), room.as_bytes(), digest.as_bytes()],
        );
        let fingerprint = blake3::Hash::from_bytes(fingerprint).to_hex().to_string();
        let (server, call, verb) = (Arc::clone(server), call.owned(), verb.to_owned());
        let store_key = crate::invocation_claims::invocation_claim_key(invocation);
        // The call this one runs inside, when it is nested (a skill's or an
        // action step's verb): its waits are that call's waits too.
        let outer = admission_observer();
        let worker = super::clock_ingress::scoped(restrictive, async move {
            // The receipt and worker start inside the same detached task:
            // hanging up during the durable write cannot orphan an intent.
            let vault = Arc::clone(server.vault());
            let name = verb.clone();
            let tracker = super::clock_ingress::run_blocking(move || {
                AdmissionTracker::start(
                    vault,
                    actor,
                    class,
                    invocation,
                    &name,
                    digest,
                    fingerprint,
                    resumed,
                )
            })
            .await
            .map_err(|_| super::host_doors::support::internal(&verb))??;
            let mut flight = Flight {
                tracker,
                settled: false,
            };
            let observer = tracker_observer(&flight.tracker, outer);
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
        // in the detached worker (FIX 10748), and a live-run hold it makes
        // names its attempt on the call's receipt: no task-local crosses a
        // spawn, so the collector rides there too (FIX 8107, FIX 10941).
        let collector = crate::api::call_receipt::attempt_collector();
        tokio::spawn(crate::api::call_receipt::with_attempt_collector(
            collector,
            super::host_doors::support::carrying_calling_run(
                crate::idempotency::run_under_intent_owned(store_key, worker),
            ),
        ))
        .await
        .map_err(|_| super::host_doors::support::internal("admission"))?
    });
    Box::pin(super::secret_body::with_custody_secret(secret, admitted))
}

/// The observer a tracked call's waits report to: its own receipt, and,
/// for a call nested in another tracked call (a skill's or an action step's
/// verb), that outer call's observer too, since the outer call waits with
/// it (FIX 4735).
pub(crate) fn tracker_observer(
    tracker: &AdmissionTracker,
    outer: Option<Arc<dyn LineObserver>>,
) -> Arc<dyn LineObserver> {
    match outer {
        Some(outer) => Arc::new(NestedObserver {
            own: tracker.clone(),
            outer,
        }),
        None => Arc::new(tracker.clone()),
    }
}

/// A nested tracked call's observer: each transition goes to its own
/// receipt and to the call it runs inside.
struct NestedObserver {
    own: AdmissionTracker,
    outer: Arc<dyn LineObserver>,
}

impl LineObserver for NestedObserver {
    fn queued(&self) {
        self.own.queued();
        self.outer.queued();
    }

    fn held(&self) {
        self.own.held();
        self.outer.held();
    }
}

/// Whether a named call of `verb` keeps an admission receipt, on every
/// transport that runs it: a facade row, other than an off-record session's
/// own rows and the admission reads themselves.
pub(crate) fn tracks_admission(verb: &str) -> bool {
    !oneiron::task_verb::sdk::NO_RECORD_ROWS.contains(&verb)
        && !verb.starts_with("self.admission.")
        && oneiron::task_verb::sdk::AgentVerb::from_name(verb)
            .is_some_and(oneiron::task_verb::sdk::AgentVerb::is_facade)
}

/// Whether `call` of `verb` with `input` sits off the record, so it keeps no
/// admission receipt: the same two signals its call receipt reads, the
/// anonymous off-record session its principal is verified in
/// ([`crate::api::call_receipt::session_is_anonymous_for`]) and a room NOTE
/// it serves ([`crate::api::call_receipt::room_notes::room_note_call`]).
fn keeps_no_record(
    server: &SyncServer,
    call: &FacadeCall<'_>,
    verb: &str,
    input: &serde_json::Value,
) -> bool {
    let principal = crate::api::call_receipt::request_principal(call.auth());
    let session = call.session_ref();
    crate::api::call_receipt::session_is_anonymous_for(server, session, principal)
        || crate::api::call_receipt::room_notes::room_note_call(
            server,
            session,
            principal,
            verb,
            Some(input),
        )
}
