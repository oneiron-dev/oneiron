//! Public coordination doors over the caller's own live-run attachment.
use std::sync::Arc;

use oneiron::WriteActor;
use oneiron::code_run::live_run::LiveRunCredential;
use oneiron::code_run::{
    AgentSpawnInput, AgentSpawnOutput, HostSelfDispatcher, LeaderSplitInput, LeaderSplitOutput,
    ReportBlockedInput, ReportBlockedOutput, TaskRefuseInput, TaskRefuseOutput,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::LiveRunRequest;

use super::host_doors::internal;
use super::{FacadeApiError, facade_actor};
use crate::auth::CoreAuth;
use crate::server::{LiveRunCaller, LiveRunRefusal, SyncServer, seated_planner};

pub(crate) async fn tasks_refuse(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<TaskRefuseInput>,
) -> MemoryResult<TaskRefuseOutput> {
    on_live_run(
        server,
        auth,
        session,
        input.live_run,
        "tasks.refuse",
        move |dispatcher| dispatcher.refuse_task_from_host(input.spec),
    )
    .await
}

pub(crate) async fn self_report_blocked(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<ReportBlockedInput>,
) -> MemoryResult<ReportBlockedOutput> {
    on_live_run(
        server,
        auth,
        session,
        input.live_run,
        "self.report_blocked",
        move |dispatcher| dispatcher.report_blocked_from_host(input.spec),
    )
    .await
}

pub(crate) async fn self_agents_spawn(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<AgentSpawnInput>,
) -> MemoryResult<AgentSpawnOutput> {
    on_live_run(
        server,
        auth,
        session,
        input.live_run,
        "self.agents.spawn",
        move |dispatcher| dispatcher.spawn_agent_from_host(input.spec),
    )
    .await
}

pub(crate) async fn self_leader_split(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<LeaderSplitInput>,
) -> MemoryResult<LeaderSplitOutput> {
    on_live_run(
        server,
        auth,
        session,
        input.live_run,
        "self.leader.split",
        move |dispatcher| dispatcher.split_leader_from_host(input.spec),
    )
    .await
}

pub(crate) async fn vault_claims_supersede(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<oneiron::code_run::MemorySupersedeInput>,
) -> MemoryResult<oneiron::code_run::MemoryWriteOutput> {
    on_live_run(
        server,
        auth,
        session,
        input.live_run,
        "vault.claims.supersede",
        move |dispatcher| dispatcher.supersede_claim_from_host(input.spec),
    )
    .await
}

/// Batched child admission through the same attachment guard as single spawn.
pub(crate) async fn vault_fanout_spawn(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    input: LiveRunRequest<oneiron::task_verb::sdk::FanoutBatchInput>,
) -> super::host_doors::Listed<oneiron::task_verb::sdk::FanoutBatchView> {
    let decisions_server = Arc::clone(server);
    let locality = auth.locality();
    let proof = match auth.verified_slip() {
        Some(proof) => proof.clone(),
        None => {
            return super::host_doors::refused(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a batch requires the attached run's own verified credential",
                &[],
            ));
        }
    };
    let principal = match facade_actor(server, auth) {
        Ok((actor, _)) => actor,
        Err(error) => return super::host_doors::refused(error.into_memory_error()),
    };
    let answer = on_live_run(
        server,
        auth,
        session,
        input.live_run,
        "vault.fanout.spawn",
        move |dispatcher| {
            let deadline = oneiron::retrieval_depth::RetrievalDeadline::after(
                crate::decision_host::WAVE_FANOUT_BUDGET,
            );
            let host = decisions_server.decision_host();
            let decisions = host.wave_fanout_decisions(principal, &deadline);
            dispatcher.spawn_fanout_from_host(input.spec, &proof, locality, Some(&decisions))
        },
    )
    .await;
    super::host_doors::naming(answer, oneiron::task_verb::sdk::fanout_batch_rows)
}

/// Resolves exactly the attachment the caller presents, never a caller-named
/// attempt or a replacement credential. The existing live-run guard serializes
/// this call with executor entries and rechecks the lease and attachment.
async fn on_live_run<T, F>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    handle: String,
    verb: &'static str,
    call: F,
) -> MemoryResult<T>
where
    T: Send + 'static,
    F: FnOnce(HostSelfDispatcher<'_>) -> MemoryResult<T> + Send + 'static,
{
    let (writer, run, held) = hold_live_run(server, auth, session, &handle).await?;
    let actor = writer.entity_ref();
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        // Keep the run held until the engine call and all its writes finish.
        let _held = held;
        let binding = _held.proof();
        let mut dispatcher = HostSelfDispatcher::for_live_run(server.vault(), writer, &binding)?;
        let (settings, model) = run.planner();
        if let Some(settings) = settings {
            if let Some(planner) = seated_planner(
                server.vault(),
                settings,
                model,
                server.decision_host().host_planner_decisions(actor),
            )
            .map_err(MemoryError::bad_request)?
            {
                dispatcher = dispatcher.with_planner(planner);
            }
        }
        // The same configured signing identity the resident runner uses.
        let derived = match server.managed_issuer {
            Some(_) => None,
            None => server
                .config
                .auth_secret
                .as_deref()
                .filter(|secret| !secret.is_empty())
                .map(|secret| oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes()))
                .transpose()?,
        };
        if let Some(issuer) = server.managed_issuer.as_ref().or(derived.as_ref()) {
            dispatcher = dispatcher.with_slip_issuer(issuer);
        }
        call(dispatcher)
    })
    .await
    .map_err(|_| internal(verb))?
}

/// The shared admission for public calls on the caller's attached live run.
pub(super) async fn hold_live_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
    handle: &str,
) -> MemoryResult<(WriteActor, crate::server::ResolvedLiveRun, crate::server::HeldLiveRun)> {
    if session.is_some() {
        return Err(MemoryError::new(
            oneiron::memory::MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
            "live child admission requires the attached run's canonical storage",
            &[],
        ));
    }
    let (actor, class) = facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a live-run call requires this agent's own verified credential",
            &["Present the same credential that attached to the run."],
        )
    };
    let proof = auth.verified_slip().ok_or_else(refused)?;
    // As on attach and actions, an unbound credential borrows no run.
    server
        .vault()
        .credential_read_key(proof)?
        .ok_or_else(refused)?;
    let writer = WriteActor::new(actor, class);
    let run = server
        .live_runs
        .resolve(
            handle,
            LiveRunCaller {
                actor: writer,
                credential: LiveRunCredential::of(&auth.idempotency_principal(), auth.locality()),
            },
        )
        .map_err(live_refusal)?;
    let held = run
        .hold(&server.live_runs, &server.vault)
        .await?
        .map_err(live_refusal)?;
    Ok((writer, run, held))
}

fn live_refusal(refusal: LiveRunRefusal) -> MemoryError {
    MemoryError::new(refusal.code(), refusal.message(), &[refusal.suggestion()])
}
