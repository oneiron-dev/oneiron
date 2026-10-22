//! The public `vault.repo.*` run doors (FIX 6867, G1 PR3b): an external
//! agent's own attached live run reads and works the repos its Grant
//! names, through the very engine doors a native run's `self.code.*` rows
//! call.
//!
//! Every door resolves exactly the attachment its caller presents through
//! `hold_live_run`, which verifies the same credential and holds the run's
//! guard until the engine call and all its writes finish. The run binding
//! is the host's ([`RepoRunBinding::for_live_host`], from that held lease
//! proof), reading on the credential's own lane; no actor, TASK, lease or
//! owner proof is decoded from the request. The engine door then judges
//! the run against its Grant in each snapshot and writer, and the answer
//! lists the rows it was read from. A channel-bound credential reaches no
//! lane door, here as over MCP. No owner door is called.
use std::sync::Arc;

use oneiron::memory::repo_doors::{
    OwnerProposalReviewPolicy, RepoCheckoutBindInput, RepoCheckoutBindOutput, RepoExportInput,
    RepoExportOutput, RepoMergeQueueEnqueueInput, RepoMergeQueueEnqueueOutput,
    RepoMergeQueueObserveInput, RepoMergeQueueObserveOutput, RepoProposalSubmitInput,
    RepoProposalSubmitOutput, RepoReviewPolicy, RepoRunAnswer, RepoRunBinding,
    RepoSnapshotsGetInput, RepoSnapshotsGetOutput, RepoSnapshotsIngestInput,
    RepoSnapshotsIngestOutput, RepoSnapshotsReadInput, RepoSnapshotsReadOutput,
    RepoSymbolsDeclareInput, RepoSymbolsDeclareOutput, RepoSymbolsDefinitionsInput,
    RepoSymbolsDefinitionsOutput, RepoSymbolsReleaseInput, RepoSymbolsReleaseOutput,
    RepoSymbolsRenewInput, RepoSymbolsRenewOutput, RepoViewsGetInput, RepoViewsGetOutput,
    RepoViewsReadInput, RepoViewsReadOutput, RepoWorkOpenInput, RepoWorkOpenOutput,
    repo_provenance_unwitnessed,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::LiveRunRequest;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, internal};
use super::live_run_doors::hold_live_run;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The caller a caller door is handed; the repo doors act as the attached
/// run's actor, which `hold_live_run` checks is this same credential's.
type Caller = (EntityId, EdgeActorClass);

/// One repo run door: the attachment held, the run bound from its held
/// proof and the credential's lane, `call` run on the credential's own
/// memory handle, and the answer released only while the credential still
/// reads. Its rows are listed in order, once each.
async fn on_repo_run<I, O, F>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    invocation: Option<InvocationId>,
    verb: &'static str,
    input: LiveRunRequest<I>,
    call: F,
) -> Listed<O>
where
    I: Send + 'static,
    O: Send + 'static,
    F: FnOnce(&Memory<'_>, &RepoRunBinding, I) -> MemoryResult<RepoRunAnswer<O>> + Send + 'static,
{
    let answer = async {
        // MCP's filtered gate judges no channel caveat; the facade's lane
        // guard does. Both doors meet it here.
        auth.require_lane_record_scope().map_err(|_| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a channel-bound credential reaches no repo run door",
                &[],
            )
        })?;
        let (writer, _run, held) = hold_live_run(server, auth, session, &input.live_run).await?;
        let refused = || {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a repo run door requires the attached run's own live credential",
                &[],
            )
        };
        let proof = auth.verified_slip().cloned().ok_or_else(refused)?;
        let (server, auth) = (Arc::clone(server), auth.clone());
        tokio::task::spawn_blocking(move || {
            let lease = held.proof();
            let vault = server.vault();
            let reader = vault.credential_read_key(&proof)?.ok_or_else(refused)?;
            let binding = RepoRunBinding::for_live_host(vault, writer, &lease, reader)?;
            let memory = crate::api::credential_memory(
                vault,
                Some(&auth),
                writer.entity_ref(),
                writer.actor_class(),
            )
            .at(auth.locality());
            let memory = match invocation {
                Some(invocation) => memory.with_invocation(invocation),
                None => memory,
            };
            let answer = call(&memory, &binding, input.spec)?;
            // Release no answer to a credential revoked while the run acted.
            vault.credential_read_key(&proof)?.ok_or_else(refused)?;
            drop(held);
            Ok(answer)
        })
        .await
        .map_err(|_| internal(verb))?
    }
    .await;
    match answer {
        Ok(RepoRunAnswer { output, mut rows }) => {
            rows.sort_unstable();
            rows.dedup();
            (Ok(output), rows)
        }
        Err(error) => (Err(error), Vec::new()),
    }
}

/// `vault.repo.snapshots.get` (`self.code.snapshots.get`'s public door).
pub(crate) async fn vault_repo_snapshots_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoSnapshotsGetInput>,
) -> Listed<RepoSnapshotsGetOutput> {
    let verb = "vault.repo.snapshots.get";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_snapshots_get_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.snapshots.read`.
pub(crate) async fn vault_repo_snapshots_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoSnapshotsReadInput>,
) -> Listed<RepoSnapshotsReadOutput> {
    let verb = "vault.repo.snapshots.read";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_snapshots_read_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.symbols.definitions`.
pub(crate) async fn vault_repo_symbols_definitions(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoSymbolsDefinitionsInput>,
) -> Listed<RepoSymbolsDefinitionsOutput> {
    let verb = "vault.repo.symbols.definitions";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_symbols_definitions_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.views.get`.
pub(crate) async fn vault_repo_views_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoViewsGetInput>,
) -> Listed<RepoViewsGetOutput> {
    let verb = "vault.repo.views.get";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_views_get_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.views.read`.
pub(crate) async fn vault_repo_views_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoViewsReadInput>,
) -> Listed<RepoViewsReadOutput> {
    let verb = "vault.repo.views.read";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_views_read_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.merge_queue.observe`.
pub(crate) async fn vault_repo_merge_queue_observe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoMergeQueueObserveInput>,
) -> Listed<RepoMergeQueueObserveOutput> {
    let verb = "vault.repo.merge_queue.observe";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_merge_queue_observe_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.snapshots.ingest`.
pub(crate) async fn vault_repo_snapshots_ingest(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoSnapshotsIngestInput>,
) -> Listed<RepoSnapshotsIngestOutput> {
    let verb = "vault.repo.snapshots.ingest";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_snapshots_ingest_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.work.open`.
pub(crate) async fn vault_repo_work_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoWorkOpenInput>,
) -> Listed<RepoWorkOpenOutput> {
    let verb = "vault.repo.work.open";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_work_open_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.symbols.declare`.
pub(crate) async fn vault_repo_symbols_declare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoSymbolsDeclareInput>,
) -> Listed<RepoSymbolsDeclareOutput> {
    let verb = "vault.repo.symbols.declare";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_symbols_declare_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.symbols.renew`.
pub(crate) async fn vault_repo_symbols_renew(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoSymbolsRenewInput>,
) -> Listed<RepoSymbolsRenewOutput> {
    let verb = "vault.repo.symbols.renew";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_symbols_renew_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.symbols.release`.
pub(crate) async fn vault_repo_symbols_release(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoSymbolsReleaseInput>,
) -> Listed<RepoSymbolsReleaseOutput> {
    let verb = "vault.repo.symbols.release";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_symbols_release_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.proposal_submit`: held to the vault's own review policy
/// (FIX 8268; none set, the same checked queue lands it on green). The host
/// holds no witness of an external agent's model request, so the proposal
/// holds as `repo_provenance_required`, its work kept: no author is made up.
pub(crate) async fn vault_repo_proposal_submit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoProposalSubmitInput>,
) -> Listed<RepoProposalSubmitOutput> {
    let verb = "vault.repo.proposal_submit";
    let policy = OwnerProposalReviewPolicy::new(Arc::clone(&server.vault));
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        move |memory, binding, spec| {
            memory.repo_proposal_submit_for_run(
                binding,
                spec,
                Some(&policy as &dyn RepoReviewPolicy),
                |_| Err(repo_provenance_unwitnessed()),
            )
        },
    )
    .await
}

/// `vault.repo.merge_queue.enqueue`.
pub(crate) async fn vault_repo_merge_queue_enqueue(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoMergeQueueEnqueueInput>,
) -> Listed<RepoMergeQueueEnqueueOutput> {
    let verb = "vault.repo.merge_queue.enqueue";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_merge_queue_enqueue_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.checkout.bind`.
pub(crate) async fn vault_repo_checkout_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoCheckoutBindInput>,
) -> Listed<RepoCheckoutBindOutput> {
    let verb = "vault.repo.checkout.bind";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_checkout_bind_for_run(binding, spec),
    )
    .await
}

/// `vault.repo.export`: held as `repo_publication_policy_required` unless
/// one Grant lists `publish` over the revision's paths.
pub(crate) async fn vault_repo_export(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    _caller: Caller,
    invocation: Option<InvocationId>,
    input: LiveRunRequest<RepoExportInput>,
) -> Listed<RepoExportOutput> {
    let verb = "vault.repo.export";
    on_repo_run(
        server,
        auth,
        session,
        invocation,
        verb,
        input,
        |memory, binding, spec| memory.repo_export_for_run(binding, spec),
    )
    .await
}
