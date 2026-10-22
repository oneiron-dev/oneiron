//! SUMMARY writes on the caller's own credential. Only creation queues a model call;
//! patch and regeneration take authored output, never synthesize it in a handler.

use std::sync::Arc;

use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::scope_summary::{
    SummaryCreateRequest, SummaryEditRequest, SummaryKeepRequest, SummaryKeepResult,
    SummaryMutationResult, SummaryPatchRequest, SummaryProposalRequest, SummaryProposalView,
    SummaryQueued, SummaryRegenerateRequest,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn write_as_caller<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    verb: &'static str,
    write: impl FnOnce(Memory<'_>) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    credential_listing(server, auth, caller, verb, move |server, auth, memory| {
        if auth.is_owner_grade() {
            let owner = owner_proof(auth, server, verb)?;
            write(memory.with_owner_authorship(&owner))
        } else {
            write(memory)
        }
    })
    .await
}

pub(crate) async fn vault_summaries_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SummaryCreateRequest,
) -> Listed<SummaryQueued> {
    credential_listing(
        server,
        auth,
        caller,
        "vault.summaries.create",
        move |server, _, memory| {
            server.ai.summary_writer().map_err(|reason| {
                MemoryError::new(oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE, reason, &[])
            })?;
            let queued = memory.create_summary(&input)?;
            server.ai.attempt_queued();
            Ok(queued)
        },
    )
    .await
}

pub(crate) async fn vault_summaries_keep(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SummaryKeepRequest,
) -> Listed<SummaryKeepResult> {
    write_as_caller(
        server,
        auth,
        caller,
        "vault.summaries.keep",
        move |memory| memory.set_summary_keep(&input),
    )
    .await
}

pub(crate) async fn vault_summaries_edit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SummaryEditRequest,
) -> Listed<SummaryProposalView> {
    write_as_caller(
        server,
        auth,
        caller,
        "vault.summaries.edit",
        move |memory| memory.edit_summary(&input),
    )
    .await
}

pub(crate) async fn vault_summaries_patch(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SummaryPatchRequest,
) -> Listed<SummaryMutationResult> {
    write_as_caller(
        server,
        auth,
        caller,
        "vault.summaries.patch",
        move |memory| memory.patch_summary(&input),
    )
    .await
}

pub(crate) async fn vault_summaries_regenerate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SummaryRegenerateRequest,
) -> Listed<SummaryMutationResult> {
    write_as_caller(
        server,
        auth,
        caller,
        "vault.summaries.regenerate",
        move |memory| memory.regenerate_summary(&input),
    )
    .await
}

pub(crate) async fn vault_summaries_proposals_merge(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SummaryProposalRequest,
) -> Listed<SummaryProposalView> {
    write_as_caller(
        server,
        auth,
        caller,
        "vault.summaries.proposals.merge",
        move |memory| {
            memory.settle_summary_proposal(&input, oneiron::entity_doc::SettleVerb::Merge)
        },
    )
    .await
}

pub(crate) async fn vault_summaries_proposals_switch(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SummaryProposalRequest,
) -> Listed<SummaryProposalView> {
    write_as_caller(
        server,
        auth,
        caller,
        "vault.summaries.proposals.switch",
        move |memory| {
            memory.settle_summary_proposal(&input, oneiron::entity_doc::SettleVerb::Switch)
        },
    )
    .await
}

pub(crate) async fn vault_summaries_proposals_reject(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: SummaryProposalRequest,
) -> Listed<SummaryProposalView> {
    write_as_caller(
        server,
        auth,
        caller,
        "vault.summaries.proposals.reject",
        move |memory| {
            memory.settle_summary_proposal(&input, oneiron::entity_doc::SettleVerb::Reject)
        },
    )
    .await
}
