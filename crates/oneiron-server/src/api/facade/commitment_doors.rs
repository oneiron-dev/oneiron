//! The commitment reminder-route doors written by hand: the owner's
//! `vault.commitments.reminder_route.get` and `.set`, setting doors that keep
//! their hand door until Setting stages 1 to 3 have landed (UC-01 plan,
//! U1-A2). The other commitment doors are generated from their rows (UC-01
//! PR 1). The generated HTTP, SDK and MCP doors all use the caller's
//! credential and existing gate.
use super::host_doors::support::Listed;
use super::host_doors::support::owner_listing::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::memory::commitment_doors::{
    CommitmentReminderRouteReply, CommitmentReminderRouteSetRequest,
};
use oneiron::task_verb::sdk::EmptyRequest;
use std::sync::Arc;

pub(crate) async fn vault_commitments_reminder_route_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<CommitmentReminderRouteReply> {
    as_owner(
        server,
        auth,
        "vault.commitments.reminder_route.get",
        move |memory, owner| memory.commitments_reminder_route_get_as(owner),
    )
    .await
}

pub(crate) async fn vault_commitments_reminder_route_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CommitmentReminderRouteSetRequest,
) -> Listed<CommitmentReminderRouteReply> {
    as_owner(
        server,
        auth,
        "vault.commitments.reminder_route.set",
        move |memory, owner| memory.commitments_reminder_route_set_as(owner, input),
    )
    .await
}
