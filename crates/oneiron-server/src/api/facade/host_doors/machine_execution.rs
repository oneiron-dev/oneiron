//! `vault.machines.execution.get` (pass 33 door 11): what each machine the vault holds a job
//! grant for offers its GPU jobs now, asked of the machine itself by the vault's issuer. Its row
//! proves `verb_grant_caller`: the owner under their own proof, or an agent whose own live Grant
//! lists the verb, judged again by the engine's read. It writes nothing; it lists no row; its
//! reply is never kept for a same-id retry (`invocations::UNKEPT_REPLY_VERBS`).

use std::sync::Arc;

use oneiron::task_verb::sdk::{
    MACHINES_EXECUTION_GET_VERB, MachineExecutionReply, MachineExecutionRequest,
    machine_execution_targets_as,
};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::gpu_execution_node::issuer::node_status::NodeAsker;
use crate::gpu_execution_node::issuer::{SystemIssuerClock, read_machine_execution};
use crate::server::SyncServer;

/// `vault.machines.execution.get`: the engine names the machines the caller may be shown and
/// the grants this vault holds for each; the issuer then asks each one, off the runtime. On any
/// other install every ask is `not_asked`, `not_the_issuer` (pass 33, 8.7).
pub(crate) async fn vault_machines_execution_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MachineExecutionRequest,
) -> Listed<MachineExecutionReply> {
    let asker = NodeAsker::of(server);
    verb_grant_door(
        server,
        auth,
        MACHINES_EXECUTION_GET_VERB,
        move |_, memory, owner| {
            let targets = machine_execution_targets_as(memory, owner, &input)?;
            let client = asker.client(targets.serving_machine);
            Ok(read_machine_execution(
                client,
                &SystemIssuerClock,
                targets.targets,
            ))
        },
    )
    .await
}
