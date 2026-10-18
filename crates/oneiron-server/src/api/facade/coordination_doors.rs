//! The owner's task-type tree doors (DOOR-111), with the owner's own proof:
//! store an authored tree on an open team-shape fork as a candidate, and
//! read the tree in force or one kept version. `host_doors` re-exports them,
//! so the generated HTTP facade handler and the MCP dispatcher call them by
//! the name every host door has.
use std::sync::Arc;

use oneiron::team::doors::{
    TaskTypeTreePin, TaskTypeTreePinReceipt, TaskTypeTreeRead, TaskTypeTreeReadReply,
};

use super::host_doors::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// A pin names the fork it stored the tree on.
pub(crate) async fn vault_task_types_pin(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TaskTypeTreePin,
) -> MaybeListed<TaskTypeTreePinReceipt> {
    const VERB: &str = "vault.task_types.pin";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| oneiron::team::doors::pin_tree_as(server.vault(), &owner, input),
        |stored| Some(vec![stored.fork_ref]),
    )
    .await
}

/// A read names the team-shape skill in force, when one is.
pub(crate) async fn vault_task_types_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TaskTypeTreeRead,
) -> MaybeListed<TaskTypeTreeReadReply> {
    const VERB: &str = "vault.task_types.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| oneiron::team::doors::read_tree_as(server.vault(), &owner, input),
        |read| Some(read.in_force_skill_ref.into_iter().collect()),
    )
    .await
}
