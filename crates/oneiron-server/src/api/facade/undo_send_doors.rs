//! The host doors of the owner's undo-send window (DEC-0006 #undo-send; REV-8
//! = B): the setting's read and set, the list of agent sends in a window, and
//! the undo. `host_doors` re-exports them, so the generated HTTP facade
//! handler and the MCP dispatcher call each by the name every host door has,
//! and a tool call, a code-mode call and an SDK call meet one admission: the
//! vault owner's proof, as `/v1/owner` takes it, never a person's or an
//! agent's. Each engine door rechecks that proof. The set records the owner's
//! act with where it was said (the surface the call itself carried, through
//! `host_door_surface`). The list and the undo list the TASKs they name
//! (`host_door_lists`).
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::outbound::{
    UndoSendHeldSends, UndoSendRequest, UndoSendUndone, undo_send_as, undo_send_held_as,
};
use oneiron::settings::undo_send::{UndoSendSetting, UndoSendSettings};
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.consent.undo_send`: the owner reads the window and the first agent
/// send through each channel.
pub(crate) async fn vault_consent_undo_send(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<UndoSendSettings> {
    as_owner_naming(
        server,
        auth,
        "vault.consent.undo_send",
        |server, owner| Ok(server.vault().undo_send_settings_as_owner(owner)?),
        |_| Vec::new(),
    )
    .await
}

/// `vault.consent.undo_send.set`: the owner sets the window.
pub(crate) async fn vault_consent_undo_send_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: UndoSendSetting,
) -> Listed<UndoSendSetting> {
    as_owner_naming(
        server,
        auth,
        "vault.consent.undo_send.set",
        move |server, owner| Ok(server.vault().set_undo_send(owner, Some(surface), &input)?),
        |_| Vec::new(),
    )
    .await
}

/// `vault.outbound.undo_send.held`: the owner lists the agent sends in a
/// window, listing their TASKs.
pub(crate) async fn vault_outbound_undo_send_held(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<UndoSendHeldSends> {
    as_owner_naming(
        server,
        auth,
        "vault.outbound.undo_send.held",
        |server, owner| undo_send_held_as(server.vault(), owner),
        |held| held.sends.iter().map(|send| send.task_ref).collect(),
    )
    .await
}

/// `vault.outbound.undo_send`: the owner takes a held send back, listing its
/// TASK.
pub(crate) async fn vault_outbound_undo_send(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: UndoSendRequest,
) -> Listed<UndoSendUndone> {
    as_owner_naming(
        server,
        auth,
        "vault.outbound.undo_send",
        move |server, owner| undo_send_as(server.vault(), owner, input),
        |undone| vec![undone.task_ref],
    )
    .await
}
