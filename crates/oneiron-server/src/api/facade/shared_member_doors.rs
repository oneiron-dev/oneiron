//! The host doors of the shared-vault invitation rows (OF-531 / OF-158),
//! beside `shared_act_doors`: an invitee lists, accepts or declines their own
//! invitation, and an `add_member` holder withdraws one. With them, the
//! veto-window rows (OF-163): objecting and withdrawing an objection, the
//! started and matured notices, and the erase asks. `host_doors` re-exports
//! them. Each takes the person's own proof (`shared_act_doors::person`); the
//! engine's roster, role, expiry and power checks decide.
use std::sync::Arc;

use oneiron::federation::{
    PendingActMatured, PendingActStarted, PendingAuthorityAct, SharedActExecutionReceipt,
    SharedEraseAsk, SharedInvitation,
};
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    self, SharedActRequest, SharedEraseAskCloseRequest, SharedEraseAskRequest,
    SharedInvitationRequest, SharedInvitationWithdrawRequest, SharedVaultRequest,
};

use super::host_doors::internal;
use super::shared_act_doors::person;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `act` off the runtime: every engine door here reads or writes LMDB.
async fn off_runtime<T: Send + 'static>(
    server: &Arc<SyncServer>,
    verb: &'static str,
    act: impl FnOnce(&Arc<SyncServer>) -> MemoryResult<T> + Send + 'static,
) -> MemoryResult<T> {
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || act(&server))
        .await
        .map_err(|_| internal(verb))?
}

/// `vault.members.invitations`: the caller's own pending invitations.
pub(crate) async fn vault_members_invitations(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<SharedInvitation>> {
    const VERB: &str = "vault.members.invitations";
    let reader = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::read_shared_invitations(server.vault(), &reader, input)
    })
    .await
}

/// `vault.members.accept`: the invitee's own acceptance.
pub(crate) async fn vault_members_accept(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedInvitationRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.accept";
    let invitee = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::accept_shared_invitation_as(server.vault(), &invitee, input)
    })
    .await
}

/// `vault.members.decline`: the invitee's own refusal.
pub(crate) async fn vault_members_decline(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedInvitationRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.decline";
    let invitee = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::decline_shared_invitation_as(server.vault(), &invitee, input)
    })
    .await
}

/// `vault.members.withdraw_invitation`: an `add_member` holder's withdrawal,
/// checked by the engine against the live roster.
pub(crate) async fn vault_members_withdraw_invitation(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedInvitationWithdrawRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.withdraw_invitation";
    let admin = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::withdraw_shared_invitation_as(server.vault(), &admin, input)
    })
    .await
}

/// `vault.shared.object`: an objector-role holder's objection.
pub(crate) async fn vault_shared_object(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedActRequest,
) -> MemoryResult<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.object";
    let holder = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::object_to_shared_act(server.vault(), &holder, input)
    })
    .await
}

/// `vault.shared.withdraw_objection`: the holder withdraws their objection.
pub(crate) async fn vault_shared_withdraw_objection(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedActRequest,
) -> MemoryResult<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.withdraw_objection";
    let holder = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::withdraw_shared_act_objection(server.vault(), &holder, input)
    })
    .await
}

/// `vault.shared.started`: the caller's own started-act notices.
pub(crate) async fn vault_shared_started(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<PendingActStarted>> {
    const VERB: &str = "vault.shared.started";
    let holder = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::read_shared_act_started(server.vault(), &holder, input)
    })
    .await
}

/// `vault.shared.matured`: the caller's own matured-act notices.
pub(crate) async fn vault_shared_matured(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<PendingActMatured>> {
    const VERB: &str = "vault.shared.matured";
    let holder = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::read_shared_act_matured(server.vault(), &holder, input)
    })
    .await
}

/// `vault.shared.erase_ask`: a Member's request or an Admin's proposal to erase a record.
pub(crate) async fn vault_shared_erase_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedEraseAskRequest,
) -> MemoryResult<SharedEraseAsk> {
    const VERB: &str = "vault.shared.erase_ask";
    let holder = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::ask_shared_erase_as(server.vault(), &holder, input)
    })
    .await
}

/// `vault.shared.erase_asks`: the erase asks the caller may see.
pub(crate) async fn vault_shared_erase_asks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<SharedEraseAsk>> {
    const VERB: &str = "vault.shared.erase_asks";
    let holder = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::read_shared_erase_asks(server.vault(), &holder, input)
    })
    .await
}

/// `vault.shared.close_erase_ask`: an Owner closes an open erase ask.
pub(crate) async fn vault_shared_close_erase_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedEraseAskCloseRequest,
) -> MemoryResult<SharedEraseAsk> {
    const VERB: &str = "vault.shared.close_erase_ask";
    let holder = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        sdk::close_shared_erase_ask_as(server.vault(), &holder, input)
    })
    .await
}
