//! The owner's task-type tree doors (DOOR-111), with the owner's own proof:
//! store an authored tree on an open team-shape fork as a candidate, and
//! read the tree in force or one kept version; and the owner's read of one
//! spawned agent by its attempt; and the owner's run doors over one TASK's
//! branches (DOOR-100): the unrefusable force-stop of every live branch,
//! and the read of every branch. `host_doors` re-exports them, so the
//! generated HTTP facade handler and the MCP dispatcher call them by the
//! name every host door has.
use std::sync::Arc;

use oneiron::task_verb::run_doors::{
    CancelForceReceipt, CancelForceRequest, RunBranchesRequest, RunBranchesView,
};
use oneiron::team::doors::{
    CriticAssociation, PlannedSpawnObservation, PlannedSpawnRead, TaskTypeTreePin,
    TaskTypeTreePinReceipt, TaskTypeTreeRead, TaskTypeTreeReadReply,
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

/// A spawn read names the attempt, every attempt that launched with it and
/// the team start's leader and members, and each critique's lens and, for
/// one keyed under a launched attempt, that attempt.
pub(crate) async fn vault_agents_spawn_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PlannedSpawnRead,
) -> MaybeListed<PlannedSpawnObservation> {
    const VERB: &str = "vault.agents.spawn.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| oneiron::team::doors::observe_spawn_as(server.vault(), &owner, input),
        spawn_rows,
    )
    .await
}

/// A force names the TASK whose branches it stopped.
pub(crate) async fn vault_tasks_cancel_force(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CancelForceRequest,
) -> MaybeListed<CancelForceReceipt> {
    const VERB: &str = "vault.tasks.cancel_force";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            oneiron::task_verb::run_doors::cancel_force_as(server.vault(), &owner, input)
        },
        |receipt| Some(vec![receipt.task_ref]),
    )
    .await
}

/// A branch read names the TASK whose branches it read.
pub(crate) async fn vault_runs_branches_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RunBranchesRequest,
) -> MaybeListed<RunBranchesView> {
    const VERB: &str = "vault.runs.branches.get";
    as_person_naming(
        server,
        VERB,
        owner_proof(auth, server, VERB),
        move |server, owner| {
            oneiron::task_verb::run_doors::read_branches_as(server.vault(), &owner, input)
        },
        |read| Some(vec![read.task_ref]),
    )
    .await
}

fn spawn_rows(read: &PlannedSpawnObservation) -> Option<Vec<oneiron::EntityId>> {
    let mut rows = vec![read.spawn_ref];
    rows.extend(read.launched.iter().map(|member| member.attempt_ref));
    if let Some(binding) = &read.binding {
        rows.push(binding.leader);
        rows.extend(binding.member_attempt_refs.iter().copied());
    }
    for critic in &read.critics {
        rows.push(critic.lens_ref);
        if critic.association == CriticAssociation::BranchAttempt {
            rows.push(critic.branch_attempt_ref);
        }
    }
    rows.sort_unstable();
    rows.dedup();
    Some(rows)
}
