//! The host doors of the shared-vault invitation rows (OF-531 / OF-158),
//! beside `shared_act_doors`: an invitee lists, accepts or declines their own
//! invitation, and an `add_member` holder withdraws one. With them, the
//! veto-window rows (OF-163): objecting and withdrawing an objection, the
//! started and matured notices, and the erase asks. `host_doors` re-exports
//! them. Each takes the person's own proof (`shared_act_doors::person`); the
//! engine's roster, role, expiry and power checks decide. Beside them, the
//! owner's guest slip mint (OF-232), under the owner's proof and the host's
//! slip issuer. An invitee's own slip (FIX 1925) lists, accepts or declines
//! only the invitation it names.
use std::sync::Arc;

use oneiron::federation::{
    PendingActMatured, PendingActStarted, PendingAuthorityAct, SharedActExecutionReceipt,
    SharedEraseAsk, SharedInvitation,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, GuestSlipMintRequest, GuestSlipMinted, InvitationSlip, InvitationSlipRequest,
    SharedActRequest, SharedEraseAskCloseRequest, SharedEraseAskRequest, SharedInvitationRequest,
    SharedInvitationWithdrawRequest, SharedVaultRequest,
};

use super::host_doors::internal;
use super::shared_act_doors::person;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The invitation an invitee's own slip (FIX 1925) names, when the request
/// came on one.
fn slip_invitation(auth: &CoreAuth) -> Option<&str> {
    auth.verified_slip()
        .and_then(|slip| slip.claims().invitation_ref.as_deref())
}

/// Refuses an invitee's slip at an invitation other than its own.
fn require_slip_invitation(auth: &CoreAuth, verb: &str, invitation: &str) -> MemoryResult<()> {
    match slip_invitation(auth) {
        Some(own) if !own.eq_ignore_ascii_case(invitation) => Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} names another invitation than this credential's"),
            &["Present the credential minted with this invitation."],
        )),
        _ => Ok(()),
    }
}

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
    let own = slip_invitation(auth).map(str::to_owned);
    let mut invitations = off_runtime(server, VERB, move |server| {
        sdk::read_shared_invitations(server.vault(), &reader, input)
    })
    .await?;
    if let Some(own) = own {
        invitations.retain(|invitation| invitation.id.eq_ignore_ascii_case(&own));
    }
    Ok(invitations)
}

/// `vault.members.accept`: the invitee's own acceptance.
pub(crate) async fn vault_members_accept(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedInvitationRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.accept";
    let invitee = person(server, auth, VERB)?;
    require_slip_invitation(auth, VERB, &input.invitation)?;
    off_runtime(server, VERB, move |server| {
        sdk::accept_shared_invitation_as(server.vault(), &invitee, input)
    })
    .await
}

/// `vault.members.invitation_slip`: an `add_member` holder's mint of a
/// pending invitation's slip (a founding invitation's, or a lost one), under
/// the host's slip issuer.
pub(crate) async fn vault_members_invitation_slip(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InvitationSlipRequest,
) -> MemoryResult<InvitationSlip> {
    const VERB: &str = "vault.members.invitation_slip";
    let admin = person(server, auth, VERB)?;
    off_runtime(server, VERB, move |server| {
        crate::api::pairing::with_issuer(server, |issuer| {
            Ok(sdk::mint_invitation_slip_as(
                server.vault(),
                &admin,
                issuer,
                input,
            ))
        })
        .map_err(|_| internal(VERB))?
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
    require_slip_invitation(auth, VERB, &input.invitation)?;
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
