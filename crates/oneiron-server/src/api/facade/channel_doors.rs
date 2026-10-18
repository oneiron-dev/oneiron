//! Credential-bound host projections of the typed channel setup verbs.
//! HTTP, SDK, MCP and code mode all use these same owner/agent admissions.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{Memory, MemoryError, MemoryResult, MEMORY_CODE_FORBIDDEN};
use oneiron::memory::channel_doors::*;
use oneiron::channel_identity_selection::ChannelIdentitySelectionRuleSet;

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn owner_proof(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<AuthenticatedOwner> {
    crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(MEMORY_CODE_FORBIDDEN, format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."])
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
    credential_listing(server, auth, caller, verb, move |_, _, memory| act(&memory, &owner)).await
}

pub(crate) async fn vault_channel_identities_provision(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelIdentityProvisionRequest,
) -> Listed<ChannelIdentityLifecycleReceipt> {
    as_owner(server, auth, "vault.channel_identities.provision", move |memory, owner| {
        memory.channel_identity_provision_as(owner, input)
    }).await
}

pub(crate) async fn vault_channel_identities_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelIdentityBindRequest,
) -> Listed<ChannelIdentityLifecycleReceipt> {
    as_owner(server, auth, "vault.channel_identities.bind", move |memory, owner| {
        memory.channel_identity_bind_as(owner, input)
    }).await
}

pub(crate) async fn vault_channel_identities_fulfill(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelIdentityRequest,
) -> Listed<ChannelIdentityLifecycleReceipt> {
    as_owner(server, auth, "vault.channel_identities.fulfill", move |memory, owner| {
        memory.channel_identity_fulfill_as(owner, input)
    }).await
}

pub(crate) async fn vault_channel_identities_rotate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelIdentityRequest,
) -> Listed<ChannelIdentityLifecycleReceipt> {
    as_owner(server, auth, "vault.channel_identities.rotate", move |memory, owner| {
        memory.channel_identity_rotate_as(owner, input)
    }).await
}

pub(crate) async fn vault_channel_identities_release(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelIdentityReleaseRequest,
) -> Listed<ChannelIdentityLifecycleReceipt> {
    as_owner(server, auth, "vault.channel_identities.release", move |memory, owner| {
        memory.channel_identity_release_as(owner, input)
    }).await
}

pub(crate) async fn vault_channel_identities_route_inbound(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelIdentityRequest,
) -> Listed<ChannelIdentityLifecycleReceipt> {
    as_owner(server, auth, "vault.channel_identities.route_inbound", move |memory, owner| {
        memory.channel_identity_route_inbound_as(owner, input)
    }).await
}

pub(crate) async fn vault_delivery_window_policy_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DeliveryWindowPolicyPutRequest,
) -> Listed<oneiron::memory::CommitReceipt> {
    as_owner(server, auth, "vault.delivery_window.policy.put", move |memory, owner| {
        memory.delivery_window_put_as(owner, input)
    }).await
}

pub(crate) async fn vault_delivery_window_policy_retract(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DeliveryWindowPolicyRetractRequest,
) -> Listed<oneiron::memory::CommitReceipt> {
    as_owner(server, auth, "vault.delivery_window.policy.retract", move |memory, owner| {
        memory.delivery_window_retract_as(owner, input)
    }).await
}

/// Only a human authenticated as the owner receives an owner's stamp.
/// An agent uses its own write actor and the engine's amendability checks.
pub(crate) async fn vault_channel_identities_selection_update(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSelectionUpdateRequest,
) -> Listed<ChannelIdentitySelectionRuleSet> {
    const VERB: &str = "vault.channel_identities.selection.update";
    let caller = match super::facade_actor(auth).map_err(FacadeApiError::into_memory_error) {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    if caller.1 == oneiron::EdgeActorClass::Human {
        return as_owner(server, auth, VERB, move |memory, owner| {
            memory.channel_selection_update_as(Some(owner), input)
        }).await;
    }
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.channel_selection_update_as(None, input)
    }).await
}
