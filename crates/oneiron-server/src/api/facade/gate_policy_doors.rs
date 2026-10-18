//! Owner policy and checker host doors. HTTP, SDK and MCP use the same
//! unattenuated owner credential as the neighboring setting doors.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::policy_manifest_doors::{
    self, GateCheckerReceipt, GateCheckerSet, GateCheckerView, PolicyManifestPut,
    PolicyManifestRead, PolicyManifestReceipt, PolicyManifestsView,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::EntityId;

use super::host_doors::{Listed, internal};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> oneiron::Result<T> + Send + 'static,
) -> MemoryResult<T> {
    let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || act(&server, &owner).map_err(MemoryError::from))
        .await
        .map_err(|_| internal(verb))?
}

pub(crate) async fn vault_gate_policy_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PolicyManifestRead,
) -> Listed<PolicyManifestsView> {
    let answer = as_owner(server, auth, "vault.gate.policy.get", move |server, owner| {
        policy_manifest_doors::policy_manifests_as_owner(server.vault(), owner, &input)
    }).await;
    let rows = answer.as_ref().map_or_else(|_| Vec::new(), |view| {
        view.manifests.iter().filter_map(|row| EntityId::from_hex(&row.manifest_ref).ok()).collect()
    });
    (answer, rows)
}

pub(crate) async fn vault_gate_policy_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PolicyManifestPut,
) -> Listed<PolicyManifestReceipt> {
    let answer = as_owner(server, auth, "vault.gate.policy.put", move |server, owner| {
        policy_manifest_doors::put_policy_manifest_as_owner(server.vault(), owner, input)
    }).await;
    let rows = answer.as_ref().ok().and_then(|receipt| {
        EntityId::from_hex(&receipt.manifest.manifest_ref).ok()
    }).into_iter().collect();
    (answer, rows)
}

pub(crate) async fn vault_gate_checker_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<GateCheckerView> {
    (as_owner(server, auth, "vault.gate.checker.get", move |server, owner| {
        policy_manifest_doors::gate_checker_as_owner(server.vault(), owner)
    }).await, Vec::new())
}

pub(crate) async fn vault_gate_checker_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GateCheckerSet,
) -> Listed<GateCheckerReceipt> {
    (as_owner(server, auth, "vault.gate.checker.set", move |server, owner| {
        policy_manifest_doors::set_gate_checker_as_owner(server.vault(), owner, input)
    }).await, Vec::new())
}
