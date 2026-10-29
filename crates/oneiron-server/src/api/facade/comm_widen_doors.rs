//! The owner's revoke of a recorded stop-asking choice (FIX 11104):
//! `vault.tasks.comm_widen.revoke`, over the one engine door
//! `Memory::revoke_comm_widen_standing` (FIX 10695). It takes the vault
//! owner's proof (`owner_proof`, after the host preflight every owner door
//! takes) on the caller's own handle, which the engine door rechecks in the
//! writer that ends the standing, and no gate of its own. `host_doors`
//! re-exports it, so the generated HTTP facade handler and the MCP
//! dispatcher call it by the name every host door has. It carries out the
//! owner's own revoke and nothing else: no standing ends on its own.
use std::sync::Arc;

use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::CommWidenRevokeReceipt;
use oneiron::task_verb::sdk::{self, CommWidenRevokeRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.tasks.comm_widen.revoke`: ends the standing of one run's
/// stop-asking choice, answering the existing receipt; a second revoke
/// answers the first. It lists the rows its handle read.
pub(crate) async fn vault_tasks_comm_widen_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: CommWidenRevokeRequest,
) -> Listed<CommWidenRevokeReceipt> {
    const VERB: &str = "vault.tasks.comm_widen.revoke";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        sdk::revoke_comm_widen_as(&memory, &owner, input)
    })
    .await
}
