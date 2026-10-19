//! Typed owner-only retrieval diagnostics. Every transport takes the caller's
//! own owner proof before hooks, then the engine revalidates it on this vault.
//! The ledger is local side-table evidence, not replicated truth or a new search.
use std::sync::Arc;

use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk;

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_retrieval_runs(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::RetrievalRunsRequest,
) -> Listed<Vec<oneiron::task_verb::sdk::RetrievalRunEvidence>> {
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, "vault.retrieval.runs")?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.runs",
        move |_, _, memory| sdk::retrieval_runs_as_owner(&memory, &owner, input),
    )
    .await
}

pub(crate) async fn vault_retrieval_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::RetrievalRunRequest,
) -> Listed<Option<oneiron::task_verb::sdk::RetrievalRunEvidence>> {
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, "vault.retrieval.run")?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.run",
        move |_, _, memory| sdk::retrieval_run_as_owner(&memory, &owner, input),
    )
    .await
}

pub(crate) async fn vault_retrieval_turn(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::RetrievalTurnRequest,
) -> Listed<Vec<oneiron::task_verb::sdk::RetrievalRunEvidence>> {
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, "vault.retrieval.turn")?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.turn",
        move |_, _, memory| sdk::retrieval_turn_as_owner(&memory, &owner, input),
    )
    .await
}

pub(crate) async fn vault_retrieval_outcomes_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::store::RetrievalOutcome,
) -> Listed<Vec<oneiron::store::RetrievalOutcomeRecord>> {
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, "vault.retrieval.outcomes.put")?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.outcomes.put",
        move |_, _, memory| sdk::retrieval_outcomes_put_as_owner(&memory, &owner, input),
    )
    .await
}

pub(crate) async fn vault_retrieval_outcomes_end(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::store::RetrievalEndOutcome,
) -> Listed<Vec<oneiron::task_verb::sdk::RetrievalRunEvidence>> {
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, "vault.retrieval.outcomes.end")?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.outcomes.end",
        move |_, _, memory| sdk::retrieval_outcomes_end_as_owner(&memory, &owner, input),
    )
    .await
}

pub(crate) async fn vault_retrieval_trace(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::RetrievalTraceRequest,
) -> Listed<Option<oneiron::store::RetrievalTrace>> {
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, "vault.retrieval.trace")?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.trace",
        move |_, _, memory| sdk::retrieval_trace_as_owner(&memory, &owner, input),
    )
    .await
}

pub(crate) async fn vault_retrieval_export(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::RetrievalDiagnosticRequest,
) -> Listed<oneiron::task_verb::sdk::RetrievalDiagnosticExport> {
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, "vault.retrieval.export")?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.export",
        move |_, _, memory| sdk::retrieval_export_as_owner(&memory, &owner, input),
    )
    .await
}

pub(crate) async fn vault_retrieval_replay(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::RetrievalDiagnosticRequest,
) -> Listed<oneiron::task_verb::sdk::RetrievalDiagnosticReplay> {
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, "vault.retrieval.replay")?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.replay",
        move |_, _, memory| sdk::retrieval_replay_as_owner(&memory, &owner, input),
    )
    .await
}

/// The diagnostic SDK takes the whole recall request; the host still embeds,
/// budgets, narrows and finalizes through the one existing serving door. Its
/// caller proved the owner, so an opened device asks its home as the owner
/// (FIX 2905).
pub(crate) async fn vault_retrieval_recall(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: sdk::RecallRequest,
) -> Listed<oneiron::memory::MemoryPack> {
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, "vault.retrieval.recall")?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        owner.revalidate(server.vault())?;
        Ok(caller)
    };
    let (actor, class) = match admitted() {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    server
        .recall_home_listing(
            actor,
            class,
            auth.verified_slip().cloned(),
            auth.locality(),
            None,
            input,
            oneiron::memory::HomeRecallCaller::owner(),
        )
        .await
}
