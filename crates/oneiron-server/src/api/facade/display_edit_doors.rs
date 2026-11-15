//! The owner's answers to his agents' display-edit proposals, as facade rows
//! (FIX [SECRETS-LABEL-PURPOSE-VERBS], [DEVICE-DISPLAY-NAME]; Engine RULING
//! DISPLAY-EDIT-PROPOSAL-SCOPE = A): `vault.display_edits.list`, `.accept`
//! and `.decline`, under the owner's proof. An accept runs his own door.

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
    as_owner(server, auth, "vault.display_edits.list", |memory, owner| {
        oneiron::task_verb::sdk::list_display_edits_as(memory.vault(), owner)
    })
    .await
}

/// `vault.display_edits.accept`: the owner's door makes the proposed edit as
/// his act, and the proposal closes.
pub(crate) async fn vault_display_edits_accept(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DisplayEditAnswerRequest,
) -> Listed<DisplayEditAcceptReply> {
    as_owner(
        server,
        auth,
        "vault.display_edits.accept",
        move |memory, owner| {
            oneiron::task_verb::sdk::accept_display_edit_as(memory.vault(), owner, input)
        },
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
    as_owner(
        server,
        auth,
        "vault.display_edits.decline",
        move |memory, owner| {
            oneiron::task_verb::sdk::decline_display_edit_as(memory.vault(), owner, input)
        },
    )
    .await
}
