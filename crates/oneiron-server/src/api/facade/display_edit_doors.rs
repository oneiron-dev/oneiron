//! The owner's answers to his agents' display-edit proposals, as facade rows
//! (FIX [SECRETS-LABEL-PURPOSE-VERBS], [DEVICE-DISPLAY-NAME]; Engine RULING
//! DISPLAY-EDIT-PROPOSAL-SCOPE = A): `vault.display_edits.list`, `.accept`
//! and `.decline`, under the owner's proof. An accept runs his own door.
//! Each reads the server's vault, the one the owner door's memory handle
//! wraps (`Memory::vault` is crate-private to oneiron).

use std::sync::Arc;

use oneiron::task_verb::sdk::{
    DisplayEditAcceptReply, DisplayEditAnswerRequest, DisplayEditDeclineReply,
    DisplayEditListReply, EmptyRequest,
};

use super::host_doors::support::Listed;
use super::host_doors::support::owner_action::as_owner;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.display_edits.list`: every open proposal, newest first.
pub(crate) async fn vault_display_edits_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<DisplayEditListReply> {
    let vault = Arc::clone(server.vault());
    as_owner(
        server,
        auth,
        "vault.display_edits.list",
        move |_memory, owner| oneiron::task_verb::sdk::list_display_edits_as(&vault, owner),
    )
    .await
}

/// `vault.display_edits.accept`: the owner's door makes the proposed edit as
/// his act, and the proposal closes.
pub(crate) async fn vault_display_edits_accept(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DisplayEditAnswerRequest,
) -> Listed<DisplayEditAcceptReply> {
    let vault = Arc::clone(server.vault());
    as_owner(
        server,
        auth,
        "vault.display_edits.accept",
        move |_memory, owner| oneiron::task_verb::sdk::accept_display_edit_as(&vault, owner, input),
    )
    .await
}

/// `vault.display_edits.decline`: the proposal closes, and nothing it names
/// changes.
pub(crate) async fn vault_display_edits_decline(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DisplayEditAnswerRequest,
) -> Listed<DisplayEditDeclineReply> {
    let vault = Arc::clone(server.vault());
    as_owner(
        server,
        auth,
        "vault.display_edits.decline",
        move |_memory, owner| {
            oneiron::task_verb::sdk::decline_display_edit_as(&vault, owner, input)
        },
    )
    .await
}
