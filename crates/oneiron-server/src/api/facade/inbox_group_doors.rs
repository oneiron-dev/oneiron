//! The owner inbox's group doors over both group kinds (FIX 3024, 3026): the
//! owner's answer to one group, dispatched by its kind, and the vault
//! shape's apply groups with their answer (ARCH-0070 `shape:plan-apply`).
//! Each runs under the owner's proof, as `vault.inbox.groups` does; a shape
//! answer carries the host's slip issuer when it has one, as
//! `vault.shape.apply` does. The generated HTTP facade handler and the MCP
//! dispatcher both call these through `host_doors`.
use std::sync::Arc;

use oneiron::inbox::{InboxGroupResolution, InboxGroupResolveRequest};
use oneiron::memory::ShapeGroupResolveRequest;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::vault_shape::{ShapeApplyReceipt, ShapeInboxGroup};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.inbox.groups.resolve`: the owner's answer to one inbox group of
/// either kind.
pub(crate) async fn vault_inbox_groups_resolve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: InboxGroupResolveRequest,
) -> Listed<InboxGroupResolution> {
    const VERB: &str = "vault.inbox.groups.resolve";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |server, _, memory| {
        crate::api::pairing::with_host_issuer(server, |slips| {
            memory.resolve_inbox_group_of_kind(&owner, slips, &input)
        })
    })
    .await
}

/// `vault.shape.groups`: every apply with an item waiting for the owner's
/// word, one group each.
pub(crate) async fn vault_shape_groups(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    _input: EmptyRequest,
) -> Listed<Vec<ShapeInboxGroup>> {
    const VERB: &str = "vault.shape.groups";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.shape_inbox_groups(&owner)
    })
    .await
}

/// `vault.shape.groups.resolve`: the owner's answer to one apply's group.
pub(crate) async fn vault_shape_groups_resolve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ShapeGroupResolveRequest,
) -> Listed<ShapeApplyReceipt> {
    const VERB: &str = "vault.shape.groups.resolve";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |server, _, memory| {
        crate::api::pairing::with_host_issuer(server, |slips| {
            memory.resolve_shape_inbox_group(&owner, slips, &input)
        })
    })
    .await
}
