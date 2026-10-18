//! Credential-bound host projections of the typed origin and checkout doors
//! (DOOR-139). HTTP, SDK, MCP and code mode all take the owner's proof here;
//! export and binding then take the owner's own live checkout lease inside
//! the engine door.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::origin_doors::*;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn owner_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })
}

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let admitted = || {
        let owner = owner_proof(server, auth, verb)?;
        let caller = super::facade_actor(auth).map_err(FacadeApiError::into_memory_error)?;
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
