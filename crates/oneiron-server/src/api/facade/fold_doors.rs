//! Public run-bound folds, through the caller's existing live-run action door.

use std::sync::Arc;

use axum::http::{Extensions, HeaderMap};
use oneiron::code_run::SelfDispatchOutcome;
use oneiron::code_run::actions::{ActionArgument, ActionJson};
use oneiron::code_run::fold_api::{
    FoldCompactRequest, FoldHistoryRequest, FoldMarkRequest, FoldRunRequest, FoldUnfoldRequest,
    RunAttachRequest, RunAttached,
};
use oneiron::code_run::live_run::LiveRunCredential;
use oneiron::compaction::{
    FoldCompactAsked, FoldDescription, FoldList, FoldMarked, FoldReply, FoldUnfolded,
};
use oneiron::engine_executor::history::{FoldHistory, read_fold_description, read_fold_history};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};
use serde::de::DeserializeOwned;
use serde_json::json;

use super::FacadeApiError;
use super::action_routes::{ActionRequest, action_bound, attach_run_as, invoke_action_dispatch};
use super::host_doors::support::{Listed, credential_listing, internal};
use crate::auth::CoreAuth;
use crate::server::{LiveRunCaller, LiveRunRefusal, SyncServer};

fn facade_error(error: FacadeApiError) -> MemoryError {
    let error = error.body.error;
    let suggestions: Vec<&str> = error.suggestions.iter().map(String::as_str).collect();
    MemoryError::new(&error.code, error.message, &suggestions)
}

fn run_error(refusal: LiveRunRefusal) -> MemoryError {
    MemoryError::new(refusal.code(), refusal.message(), &[refusal.suggestion()])
}

/// `self.run.attach`: binds the caller's credential to its leased run and
/// answers the opaque handle (`host_door_lists`). The attachment reads the
/// credential and its lease and serves no history text, so its list is
/// complete and empty; the fold and history doors list what they serve.
pub(crate) async fn self_run_attach(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: RunAttachRequest,
) -> Listed<RunAttached> {
    let answer = attach_run_as(server, auth, &input.run, input.rebind)
        .await
        .map(|live_run| RunAttached { live_run })
        .map_err(facade_error);
    (answer, Vec::new())
}

/// A fixed typed fold verb, not a public generic action escape hatch. The
/// action layer checks this credential, its ceiling and attached lease, takes
/// the run guard, then reaches FoldLedger::answer through its existing gate.
async fn fold_action<T: DeserializeOwned>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    invocation: Option<InvocationId>,
    verb: &'static str,
    live_run: String,
    args: serde_json::Value,
) -> MemoryResult<FoldReply<T>> {
    let key = match invocation {
        Some(invocation) => invocation.to_hex(),
        None => server.vault().new_entity_id()?.to_hex(),
    };
    let args = ActionJson::new(args)?;
    // No request reaches this door, so the verb rows the action posts run
    // as its caller, as a held card's event does.
    let dispatch = invoke_action_dispatch(
        server,
        auth,
        HeaderMap::new(),
        Extensions::new(),
        Some(auth.clone()),
        verb.to_owned(),
        ActionRequest {
            args: vec![ActionArgument::Json(args)],
            idempotency_key: key,
            live_run: Some(live_run),
        },
    )
    .await
    .map_err(facade_error)?;
    match dispatch.outcome {
        SelfDispatchOutcome::Fold(answer) => {
            serde_json::from_str(&answer).map_err(|_| internal(verb))
        }
        SelfDispatchOutcome::Denied(denied) => Err(MemoryError::new(
            &denied.outcome,
            "the run action was refused",
            &[],
        )),
        SelfDispatchOutcome::Failed(failed) => {
            Err(MemoryError::new(MEMORY_CODE_INTERNAL, failed.error, &[]))
        }
        _ => Err(internal(verb)),
    }
}

/// `self.fold` (`host_door_lists`): the reply is the pending mark's handle
/// and span, never the span's text, so the list is complete and empty.
pub(crate) async fn self_fold(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: FoldMarkRequest,
) -> Listed<FoldReply<FoldMarked>> {
    let answer = fold_action(
        server,
        auth,
        invocation,
        "self.fold",
        input.live_run,
        json!([[input.from, input.through], {"note": input.note}]),
    )
    .await;
    (answer, Vec::new())
}

/// `self.compact` (`host_door_lists`): the reply is the pending handles and
/// the step the batch applies at; the compaction itself runs later, so the
/// list is complete and empty.
pub(crate) async fn self_compact(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: FoldCompactRequest,
) -> Listed<FoldReply<FoldCompactAsked>> {
    let answer = fold_action(
        server,
        auth,
        invocation,
        "self.compact",
        input.live_run,
        json!({"note": input.note}),
    )
    .await;
    (answer, Vec::new())
}

/// `self.unfold` (`host_door_lists`): the reply is the fold's handle, span
/// and append step, not its raw turns (`self.history` serves and lists
/// those), so the list is complete and empty.
pub(crate) async fn self_unfold(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: FoldUnfoldRequest,
) -> Listed<FoldReply<FoldUnfolded>> {
    let answer = fold_action(
        server,
        auth,
        invocation,
        "self.unfold",
        input.live_run,
        json!({"fold": input.fold}),
    )
    .await;
    (answer, Vec::new())
}

/// `self.folds` (`host_door_lists`): the reply is the run's fold spans,
/// pending marks with their notes and failures, and the compact ask; no
/// fold's summary or sources (`self.folds.describe` lists those), so the
/// list is complete and empty.
pub(crate) async fn self_folds(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: FoldRunRequest,
) -> Listed<FoldReply<FoldList>> {
    let answer = fold_action(
        server,
        auth,
        invocation,
        "self.folds",
        input.live_run,
        json!({}),
    )
    .await;
    (answer, Vec::new())
}

/// The run's guard makes this a durable boundary, never a snapshot of the
/// executor's partially written entry. Every source is read with this call's
/// current credential; the reply lists those rows for its release checks.
async fn fold_read<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    verb: &'static str,
    live_run: &str,
    read: impl FnOnce(
        &oneiron::Vault,
        &oneiron::task_verb::HostBinding,
    ) -> oneiron::Result<(T, Vec<EntityId>)>
    + Send
    + 'static,
) -> Listed<T> {
    let resolved = (|| {
        // A history read records no owner act: the header-less surface.
        let bound = action_bound(server, auth, super::owner_binding::act_surface(auth))
            .map_err(facade_error)?
            .ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "history requires the caller's read key",
                    &[],
                )
            })?;
        server
            .live_runs
            .resolve(
                live_run,
                LiveRunCaller {
                    actor: bound.writes_as(),
                    credential: LiveRunCredential::of(
                        &auth.idempotency_principal(),
                        auth.locality(),
                    ),
                },
            )
            .map_err(run_error)
    })();
    let resolved = match resolved {
        Ok(run) => run,
        Err(error) => return (Err(error), Vec::new()),
    };
    let held = match resolved.hold(&server.live_runs, &server.vault).await {
        Ok(Ok(held)) => held,
        Ok(Err(refusal)) => return (Err(run_error(refusal)), Vec::new()),
        Err(error) => return (Err(error.into()), Vec::new()),
    };
    credential_listing(server, auth, caller, verb, move |server, _, memory| {
        let (answer, sources) = read(server.vault(), &held.proof())?;
        for source in sources {
            if memory.get_entity(&source.to_hex())?.value.is_none() {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "a run history source is no longer readable",
                    &[],
                ));
            }
        }
        Ok(answer)
    })
    .await
}

pub(crate) async fn self_history(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: FoldHistoryRequest,
) -> Listed<FoldHistory> {
    let handle = input.live_run.clone();
    fold_read(
        server,
        auth,
        caller,
        "self.history",
        &handle,
        move |vault, proof| read_fold_history(vault, proof, &input),
    )
    .await
}

pub(crate) async fn self_folds_describe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: FoldUnfoldRequest,
) -> Listed<FoldReply<FoldDescription>> {
    let handle = input.live_run.clone();
    fold_read(
        server,
        auth,
        caller,
        "self.folds.describe",
        &handle,
        move |vault, proof| read_fold_description(vault, proof, &input),
    )
    .await
}
