//! `vault.machines.status` (design pass 34 section 5, row Q2): every machine of the owner's with
//! what the vault keeps about it (the built list and its latest capacity claim, each with its
//! age) and, on `refresh`, what its execution node answers now. The owner's own read, as
//! `vault.machines.list` is. The engine reads the vault half (`oneiron::machine_status`); the
//! issuer asks the nodes (`gpu_execution_node::issuer::node_status`). The door writes nothing.

use std::sync::Arc;

use oneiron::machine_status::{
    MACHINE_STATUS_VERB, MachineStatusReply, MachineStatusRequest, machine_status_from_vault,
};

use super::support::Listed;
use super::support::owner_action::as_owner;
use crate::auth::CoreAuth;
use crate::gpu_execution_node::issuer::{JobNodeClient, VAULT_MACHINE_BACKEND, not_the_issuer};
use crate::server::SyncServer;

/// `vault.machines.status`: every machine, and on `refresh` each node's answer now.
pub(crate) async fn vault_machines_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MachineStatusRequest,
) -> Listed<MachineStatusReply> {
    let vault = Arc::clone(server.vault());
    let asker = input.refresh.then(|| node_client(server));
    as_owner(server, auth, MACHINE_STATUS_VERB, move |_memory, owner| {
        let now = crate::gpu_host::now_ms();
        let why = match &asker {
            None => "not_refreshed",
            Some(Err(why)) => *why,
            Some(Ok(_)) => "not_reached",
        };
        let mut reply = machine_status_from_vault(&vault, owner, now, why)?;
        if let Some(Ok(client)) = &asker {
            crate::gpu_execution_node::issuer::node_status::ask_nodes(
                &mut reply,
                client.as_ref(),
                now,
            );
        }
        Ok(reply)
    })
    .await
}

/// The issuer's client of the nodes, or why this server asks none: only the vault's issuer of
/// vault machine jobs asks them (pass 33, 8.7), over its mesh listener, each call within its
/// call timeout.
fn node_client(server: &Arc<SyncServer>) -> Result<Arc<dyn JobNodeClient>, &'static str> {
    if not_the_issuer(server, VAULT_MACHINE_BACKEND).is_err() {
        return Err("not_the_issuer");
    }
    mesh_client(server)
}

#[cfg(feature = "mesh")]
fn mesh_client(server: &Arc<SyncServer>) -> Result<Arc<dyn JobNodeClient>, &'static str> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| "no_runtime")?;
    let timeout =
        std::time::Duration::from_secs(server.config.gpu_jobs.vault_machine.call_timeout_secs);
    Ok(Arc::new(
        crate::gpu_execution_node::issuer::MeshJobNodeClient::new(
            Arc::downgrade(server),
            runtime,
            timeout,
        ),
    ))
}

#[cfg(not(feature = "mesh"))]
fn mesh_client(_server: &Arc<SyncServer>) -> Result<Arc<dyn JobNodeClient>, &'static str> {
    Err("no_mesh")
}
