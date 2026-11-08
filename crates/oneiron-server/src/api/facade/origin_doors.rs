//! Credential-bound host projections of the typed origin and checkout doors
//! (DOOR-139). HTTP, SDK, MCP and code mode all take the owner's proof here;
//! export and binding then take the owner's own live checkout lease inside
//! the engine door. The two export preview doors (FIX 6869, G4 PR3) bind
//! the caller instead: a live Owner's proof, or the credential's own
//! principal, whose one Grant the engine door judges.
use std::sync::Arc;

use oneiron::memory::origin_doors::*;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::owner_action::as_owner;
use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_code_export(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeExportRequest,
) -> Listed<CodeExportResult> {
    as_owner(server, auth, "vault.code.export", move |memory, owner| {
        memory.code_export_as(owner, input)
    })
    .await
}

pub(crate) async fn vault_code_import(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRepoImportRequest,
) -> Listed<CodeRepoImportView> {
    as_owner(server, auth, "vault.code.import", move |memory, owner| {
        memory.code_repo_import_as(owner, input)
    })
    .await
}

pub(crate) async fn vault_code_origin_authority_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginRepoRequest,
) -> Listed<OriginAuthorityView> {
    as_owner(
        server,
        auth,
        "vault.code.origin.authority.get",
        move |memory, owner| memory.origin_authority_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_authority_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginAuthoritySetRequest,
) -> Listed<OriginAuthorityView> {
    as_owner(
        server,
        auth,
        "vault.code.origin.authority.set",
        move |memory, owner| memory.origin_authority_set_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_publications(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginPublicationsRequest,
) -> Listed<OriginPublicationsView> {
    as_owner(
        server,
        auth,
        "vault.code.origin.publications",
        move |memory, owner| memory.origin_publications_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_secrets_purge_request(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RepoSecretPurgeRequest,
) -> Listed<RepoSecretPurgePlan> {
    as_owner(
        server,
        auth,
        "vault.code.secrets.purge.request",
        move |memory, owner| memory.code_secrets_purge_request_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_secrets_purge_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RepoSecretPurgeIdRequest,
) -> Listed<RepoSecretPurgeView> {
    as_owner(
        server,
        auth,
        "vault.code.secrets.purge.get",
        move |memory, owner| memory.code_secrets_purge_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_secrets_purge_execute(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RepoSecretPurgeIdRequest,
) -> Listed<RepoSecretPurgeReceipt> {
    as_owner(
        server,
        auth,
        "vault.code.secrets.purge.execute",
        move |memory, owner| memory.code_secrets_purge_execute_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_checkout_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckoutDoorBindRequest,
) -> Listed<CheckoutDoorBinding> {
    as_owner(
        server,
        auth,
        "vault.code.checkout.bind",
        move |memory, owner| memory.checkout_door_bind_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_register(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginRegisterRequest,
) -> Listed<OriginRegistered> {
    as_owner(
        server,
        auth,
        "vault.code.origin.register",
        move |memory, owner| memory.origin_register_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_mirror_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginRepoRequest,
) -> Listed<OriginMirrorView> {
    as_owner(
        server,
        auth,
        "vault.code.origin.mirror.get",
        move |memory, owner| memory.origin_mirror_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_mirror_plan(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::origin::publish::OriginMirrorPlanRequest,
) -> Listed<oneiron::origin::publish::OriginMirrorPlanView> {
    as_owner(
        server,
        auth,
        "vault.code.origin.mirror.plan",
        move |memory, owner| memory.origin_mirror_plan_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_mirror_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginMirrorSetRequest,
) -> Listed<oneiron::origin::mirror::OriginMirrorTarget> {
    as_owner(
        server,
        auth,
        "vault.code.origin.mirror.set",
        move |memory, owner| memory.origin_mirror_set_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_mirror_strategy(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginMirrorStrategyRequest,
) -> Listed<oneiron::origin::mirror::OriginMirrorTarget> {
    as_owner(
        server,
        auth,
        "vault.code.origin.mirror.strategy",
        move |memory, owner| memory.origin_mirror_strategy_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_mirror_clear(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginRepoRequest,
) -> Listed<OriginMirrorCleared> {
    as_owner(
        server,
        auth,
        "vault.code.origin.mirror.clear",
        move |memory, owner| memory.origin_mirror_clear_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_mirror_push(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginRepoRequest,
) -> Listed<oneiron::origin::mirror::OriginMirrorRun> {
    as_owner(
        server,
        auth,
        "vault.code.origin.mirror.push",
        move |memory, owner| memory.origin_mirror_push_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_repos_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeRepoGetRequest,
) -> Listed<Option<CodeRepoView>> {
    as_owner(
        server,
        auth,
        "vault.code.repos.get",
        move |memory, owner| memory.code_repo_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_forks_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodeForkGetRequest,
) -> Listed<Option<CodeForkView>> {
    as_owner(
        server,
        auth,
        "vault.code.forks.get",
        move |memory, owner| memory.code_fork_get_as(owner, input),
    )
    .await
}

pub(crate) async fn vault_code_ingress_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CodePushIngressGetRequest,
) -> Listed<Option<CodePushIngressView>> {
    as_owner(
        server,
        auth,
        "vault.code.ingress.get",
        move |memory, owner| memory.code_push_ingress_get_as(owner, input),
    )
    .await
}

fn not_a_previewer(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} is a live Owner's, or a Grant holder's whose Grant covers the preview"),
        &["Present an Owner's credential, or an agent's own credential under its Grant."],
    )
}

/// MCP's filtered gate judges no channel caveat; the facade's lane guard
/// does. Both preview doors meet it here.
fn preview_lane(auth: &CoreAuth) -> MemoryResult<()> {
    auth.require_lane_record_scope().map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a channel-bound credential reaches no export preview door",
            &[],
        )
    })
}

/// The check a preview row's door runs before its pre chain
/// (`door_admits`): the lane guard, then a credential that binds a
/// principal. A host root alone binds none. Its Grant is the engine's.
pub(super) fn preview_admits(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
    preview_lane(auth)?;
    super::owner_binding::facade_caller_or(server, auth, || not_a_previewer(verb)).map(drop)
}

/// One preview door: the caller bound from its own credential, the
/// owner's proof when it carries one, and `act` run on that credential's
/// own lane.
async fn as_previewer<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    invocation: Option<InvocationId>,
    act: impl FnOnce(&Memory<'_>, &CodeExportPreviewProof) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let bound = || {
        preview_lane(auth)?;
        let caller =
            super::owner_binding::facade_caller_or(server, auth, || not_a_previewer(verb))?;
        let proof = match super::owner_binding::facade_owner(server, auth, verb) {
            Ok(owner) => CodeExportPreviewProof::Owner(owner),
            Err(_) => CodeExportPreviewProof::Grant,
        };
        Ok::<_, MemoryError>((caller, proof))
    };
    let (caller, proof) = match bound() {
        Ok(bound) => bound,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        let memory = match invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        };
        act(&memory, &proof)
    })
    .await
}

pub(crate) async fn vault_code_export_preview(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: CodeExportPreviewRequest,
) -> Listed<CodeExportPreviewAnswer> {
    as_previewer(
        server,
        auth,
        "vault.code.export.preview",
        invocation,
        move |memory, proof| memory.code_export_preview_as(proof, input),
    )
    .await
}

pub(crate) async fn vault_code_export_preview_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: CodeExportFileReadRequest,
) -> Listed<CodeExportFileReadAnswer> {
    as_previewer(
        server,
        auth,
        "vault.code.export.preview.read",
        invocation,
        move |memory, proof| memory.code_export_preview_read_as(proof, input),
    )
    .await
}

/// The holder door binds its actual credential, never an owner or a run.
pub(super) fn checkout_holder_admits(server: &SyncServer, auth: &CoreAuth) -> MemoryResult<()> {
    checkout_holder_caller(server, auth).map(drop)
}

fn checkout_holder_caller(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    auth.require_lane_record_scope().map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a channel-bound credential reaches no checkout holder door",
            &[],
        )
    })?;
    super::owner_binding::facade_caller_or(server, auth, || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "checkout materialization needs the lease holder's own credential",
            &[],
        )
    })
}

pub(crate) async fn vault_code_checkout_holder_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: oneiron::memory::repo_doors::RepoCheckoutBindInput,
) -> Listed<oneiron::memory::repo_doors::RepoCheckoutBindOutput> {
    let caller = match checkout_holder_caller(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.code.checkout.holder.bind",
        move |_, _, memory| {
            let memory = match invocation {
                Some(invocation) => memory.with_invocation(invocation),
                None => memory,
            };
            memory.repo_checkout_bind_for_holder(input)
        },
    )
    .await
}
