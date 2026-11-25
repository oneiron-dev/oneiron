//! `vault.machines.status` (design pass 34 section 5, row Q2): every machine of the owner's with
//! what the vault keeps about it (the built list and its latest capacity claim, each with its
//! age) and, on `refresh`, what its execution node answers now. The owner's own read, as
//! `vault.machines.list` is. The engine reads the vault half
//! (`oneiron::task_verb::sdk::machine_status_from_vault`); the issuer asks the nodes
//! (`gpu_execution_node::issuer::node_status`). The door writes nothing.

use std::sync::{Arc, Weak};

use oneiron::EntityId;
use oneiron::task_verb::sdk::{
    MACHINE_STATUS_VERB, MachineStatusReply, MachineStatusRequest, machine_status_from_vault,
};

use super::support::Listed;
use super::support::owner_action::as_owner;
use crate::auth::CoreAuth;
use crate::gpu_execution_node::issuer::issuer_machine;
use crate::server::SyncServer;

/// `vault.machines.status`: every machine, and on `refresh` each node's answer now.
pub(crate) async fn vault_machines_status(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MachineStatusRequest,
) -> Listed<MachineStatusReply> {
    // What a refresh needs, read on the caller's side without touching the vault: the issuer
    // the settings name, the serving runtime and the call timeout.
    let asker = input.refresh.then(|| NodeAsker {
        server: Arc::downgrade(server),
        issuer: issuer_machine(server),
        runtime: tokio::runtime::Handle::try_current().ok(),
        timeout: std::time::Duration::from_secs(
            server.config.gpu_jobs.vault_machine.call_timeout_secs,
        ),
    });
    as_owner(server, auth, MACHINE_STATUS_VERB, move |memory, owner| {
        let now = crate::gpu_host::now_ms();
        let Some(asker) = asker else {
            return machine_status_from_vault(memory, owner, now, "not_refreshed");
        };
        let mut reply = machine_status_from_vault(memory, owner, now, "not_reached")?;
        // Only the vault's issuer of vault machine jobs asks the nodes (pass 33, 8.7). This
        // install is the list's own row, so the check reads no key.
        let local = reply
            .machines
            .iter()
            .find(|item| item.machine.this_install)
            .and_then(|item| EntityId::from_hex(&item.machine.machine).ok());
        match asker.client(local) {
            Ok(client) => crate::gpu_execution_node::issuer::node_status::ask_nodes(
                &mut reply,
                client.as_ref(),
                now,
            ),
            Err(why) => {
                for item in &mut reply.machines {
                    item.node = oneiron::task_verb::sdk::MachineNodeView::not_asked(why);
                }
            }
        }
        Ok(reply)
    })
    .await
}

/// What the door needs to ask the nodes.
struct NodeAsker {
    server: Weak<SyncServer>,
    issuer: Option<EntityId>,
    runtime: Option<tokio::runtime::Handle>,
    timeout: std::time::Duration,
}

impl NodeAsker {
    /// The issuer's client of the nodes, or why this server asks none.
    fn client(
        self,
        local: Option<EntityId>,
    ) -> Result<Arc<dyn crate::gpu_execution_node::issuer::JobNodeClient>, &'static str> {
        if self.issuer.is_none() || self.issuer != local {
            return Err("not_the_issuer");
        }
        let runtime = self.runtime.ok_or("no_runtime")?;
        mesh_client(self.server, runtime, self.timeout)
    }
}

#[cfg(feature = "mesh")]
fn mesh_client(
    server: Weak<SyncServer>,
    runtime: tokio::runtime::Handle,
    timeout: std::time::Duration,
) -> Result<Arc<dyn crate::gpu_execution_node::issuer::JobNodeClient>, &'static str> {
    Ok(Arc::new(
        crate::gpu_execution_node::issuer::MeshJobNodeClient::new(server, runtime, timeout),
    ))
}

#[cfg(not(feature = "mesh"))]
fn mesh_client(
    _server: Weak<SyncServer>,
    _runtime: tokio::runtime::Handle,
    _timeout: std::time::Duration,
) -> Result<Arc<dyn crate::gpu_execution_node::issuer::JobNodeClient>, &'static str> {
    Err("no_mesh")
}
