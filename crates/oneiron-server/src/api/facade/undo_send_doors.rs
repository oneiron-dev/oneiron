//! The host doors of the undo-send window (DEC-0006 #undo-send; REV-8 = B):
//! the setting's read and set, the list of sends in a window, and the undo.
//! `host_doors` re-exports them, so the generated HTTP facade handler and the
//! MCP dispatcher call each by the name every host door has, and a tool call,
//! a code-mode call and an SDK call meet one admission. The setting is the
//! vault owner's, under the owner's proof as `/v1/owner` takes it; the set
//! records the owner's act with where it was said (the surface the call itself
//! carried, through `host_door_surface`). The list and the undo take a live
//! person's proof (`shared_act_doors::person`): the owner's, or a person's own
//! on their verified human slip, and the engine door lists or takes back only
//! the sends that person may (Engine RULING 02:57, 13 Nov: the owner, or the
//! person who made the send). An agent is refused. Each engine door rechecks
//! its proof. The list and the undo list the TASKs they name
//! (`host_door_lists`).
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::outbound::{
    UndoSendHeldSends, UndoSendRequest, UndoSendUndone, undo_send_as, undo_send_held_as,
};
use oneiron::settings::undo_send::{UndoSendSetting, UndoSendSettings};
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::{Listed, MaybeListed};
use super::legal_hold_doors::as_owner_naming;
use super::shared_act_doors::{as_person_naming, person};
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

/// `vault.outbound.undo_send.held`: the owner lists every send in a window,
/// and a person their own, listing their TASKs.
pub(crate) async fn vault_outbound_undo_send_held(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MaybeListed<UndoSendHeldSends> {
    const VERB: &str = "vault.outbound.undo_send.held";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        |server, caller| undo_send_held_as(server.vault(), &caller),
        |held| Some(held.sends.iter().map(|send| send.task_ref).collect()),
    )
    .await
}

/// `vault.outbound.undo_send`: the owner takes any held send back, and a
/// person their own, listing its TASK.
pub(crate) async fn vault_outbound_undo_send(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: UndoSendRequest,
) -> MaybeListed<UndoSendUndone> {
    const VERB: &str = "vault.outbound.undo_send";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, caller| undo_send_as(server.vault(), &caller, input),
        |undone| Some(vec![undone.task_ref]),
    )
    .await
}
