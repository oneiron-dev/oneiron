//! Credential-bound host projections of the typed symbol lease, proposal
//! submit and oplog doors (DOOR-137). HTTP, SDK, MCP and code mode all take
//! the owner's proof here; the engine door revalidates it and acts as that
//! caller.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::code_doors::*;
use oneiron::memory::{Memory, MemoryError, MemoryResult};

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn owner_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    super::owner_binding::facade_owner(server, auth, verb)
}

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let admitted = || {
        let owner = owner_proof(server, auth, verb)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok::<_, MemoryError>((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        act(&memory, &owner)
    })
    .await
}

pub(crate) async fn vault_code_symbols_declare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeSymbolsDeclareRequest,
) -> Listed<CodeSymbolsDeclared> {
    as_owner(
        server,
        auth,
        "vault.code.symbols.declare",
        move |memory, owner| memory.code_symbols_declare_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_symbols_renew(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeSymbolsTaskRequest,
) -> Listed<CodeSymbolLeaseView> {
    as_owner(
        server,
        auth,
        "vault.code.symbols.renew",
        move |memory, owner| memory.code_symbols_renew_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_symbols_release(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeSymbolsTaskRequest,
) -> Listed<CodeSymbolsReleased> {
    as_owner(
        server,
        auth,
        "vault.code.symbols.release",
        move |memory, owner| memory.code_symbols_release_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_proposal_submit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeProposalSubmitRequest,
) -> Listed<CodeProposalSubmitted> {
    as_owner(
        server,
        auth,
        "vault.code.proposal_submit",
        move |memory, owner| memory.code_proposal_submit_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_oplog(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRepoRequest,
) -> Listed<CodeMutationLog> {
    as_owner(server, auth, "vault.code.oplog", move |memory, owner| {
        memory.code_mutation_log_as(owner, input)
    })
    .await
}

pub(crate) async fn vault_code_conflict_record(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeConflictRecordRequest,
) -> Listed<CodeConflictView> {
    as_owner(
        server,
        auth,
        "vault.code.conflict_record",
        move |memory, owner| memory.code_conflict_record_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_conflict_view(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeConflictViewRequest,
) -> Listed<CodeConflictHistory> {
    as_owner(
        server,
        auth,
        "vault.code.conflict_view",
        move |memory, owner| memory.code_conflict_history_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_proposal_resolve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeProposalResolveRequest,
) -> Listed<CodeProposalSubmitted> {
    as_owner(
        server,
        auth,
        "vault.code.proposal_resolve",
        move |memory, owner| memory.code_proposal_resolve_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_proposal_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeProposalReviewRequest,
) -> Listed<CodeProposalSettlementView> {
    as_owner(
        server,
        auth,
        "vault.code.proposal_review",
        move |memory, owner| memory.code_proposal_review_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_proposal_settle(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeProposalSettleRequest,
) -> Listed<CodeProposalSettlementView> {
    as_owner(
        server,
        auth,
        "vault.code.proposal_settle",
        move |memory, owner| memory.code_proposal_settle_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_proposal_settlement(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeProposalSettlementRequest,
) -> Listed<CodeProposalSettlementView> {
    as_owner(
        server,
        auth,
        "vault.code.proposal_settlement",
        move |memory, owner| memory.code_proposal_settlement_as(owner, input),
    )
    .await
}
