//! The owner's machine list and his name for each machine, as facade rows
//! (FIX [DEVICE-DISPLAY-NAME]): `vault.machines.list` and
//! `vault.machines.name.set`, under the owner's proof. Display only.

use std::sync::Arc;

use oneiron::task_verb::sdk::{
    EmptyRequest, MachineListReply, MachineNameSetReply, MachineNameSetRequest,
};

use super::host_doors::support::Listed;
use super::host_doors::support::owner_action::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.machines.list`: every machine the vault's authority names, with
/// the name each is shown by.
pub(crate) async fn vault_machines_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<MachineListReply> {
    as_owner(server, auth, "vault.machines.list", |memory, owner| {
        oneiron::task_verb::sdk::list_machines_as(memory.vault(), owner)
    })
    .await
}

/// `vault.machines.name.set`: the owner's own name for one of his machines,
/// set or cleared.
pub(crate) async fn vault_machines_name_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MachineNameSetRequest,
) -> Listed<MachineNameSetReply> {
    as_owner(
        server,
        auth,
        "vault.machines.name.set",
        move |memory, owner| {
            oneiron::task_verb::sdk::set_machine_name_as(memory.vault(), owner, input)
        },
    )
    .await
}
