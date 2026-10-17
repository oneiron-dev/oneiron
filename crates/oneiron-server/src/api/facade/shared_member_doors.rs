//! The host doors of the shared-vault invitation rows (OF-531 / OF-158),
//! beside `shared_act_doors`: an invitee lists, accepts or declines their own
//! invitation, and an `add_member` holder withdraws one. `host_doors`
//! re-exports them. Each takes the person's own proof
//! (`shared_act_doors::person`); the engine's invitee, expiry and power
//! checks decide. Beside them, the owner's guest slip mint (OF-232), under
//! the owner's proof and the host's slip issuer.
use std::sync::Arc;

use oneiron::federation::{SharedActExecutionReceipt, SharedInvitation};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, GuestSlipMintRequest, GuestSlipMinted, SharedInvitationRequest,
    SharedInvitationWithdrawRequest, SharedVaultRequest,
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

/// `vault.guests.mint_slip`: the owner mints an ask guest's slip, bound to
/// its grant, for the key the guest generated on their own device.
pub(crate) async fn vault_guests_mint_slip(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GuestSlipMintRequest,
) -> MemoryResult<GuestSlipMinted> {
    const VERB: &str = "vault.guests.mint_slip";
    let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    off_runtime(server, VERB, move |server| {
        crate::api::pairing::with_issuer(server, |issuer| {
            Ok(sdk::mint_guest_slip_as(
                server.vault(),
                &owner,
                issuer,
                input,
            ))
        })
        .map_err(|_| internal(VERB))?
    })
    .await
}
