//! The host doors of the shared-vault invitation rows (OF-531 / OF-158),
//! beside `shared_act_doors`: an invitee lists, accepts or declines their own
//! invitation, and an `add_member` holder withdraws one. `host_doors`
//! re-exports them. Each takes the person's own proof
//! (`shared_act_doors::person`); the engine's invitee, expiry and power
//! checks decide.
use std::sync::Arc;

use oneiron::federation::{SharedActExecutionReceipt, SharedInvitation};
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    self, SharedInvitationRequest, SharedInvitationWithdrawRequest, SharedVaultRequest,
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
