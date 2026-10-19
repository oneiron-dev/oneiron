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
//!
//! Every row here but the erase pair lists its rows (`host_door_lists`), as
//! `shared_act_doors` says: invitations, objections, notices and erase asks
//! live in the authority log and the shared-act tables, which hold no row,
//! so each lists the records its answer names (an erase ask's record), and
//! a guest's slip lists the grant it binds.
use std::sync::Arc;

use oneiron::EdgeActorClass;
use oneiron::federation::{
    PendingActMatured, PendingActStarted, PendingAuthorityAct, SharedActExecutionReceipt,
    SharedEraseAsk, SharedInvitation,
};
use oneiron::memory::erase_sweep::{RecordEraseSweep, RecordEraseSweepRequest};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, ActAnswer, GuestSlipMintRequest, GuestSlipMinted, InvitationSlip, InvitationSlipRequest,
    RecordEraseConfirmRequest, RecordEraseOutcome, RecordErasePreview, RecordEraseRequest,
    SharedActRequest, SharedEraseAskCloseRequest, SharedEraseAskRequest, SharedInvitationRequest,
    SharedInvitationWithdrawRequest, SharedVaultRequest,
};

use super::host_doors::{
    Listed, MaybeListed, credential_listing, internal, off_runtime_listing, owner_proof, refused,
};
use super::shared_act_doors::{as_person_naming, person, receipt_rows};
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

/// `vault.records.erase_preview`: what erasing one record takes, read under
/// the caller's own person proof; the engine's deletion authority decides.
/// Beside it, the rows the preview was derived from.
pub(crate) async fn vault_records_erase_preview(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RecordEraseRequest,
) -> Listed<RecordErasePreview> {
    const VERB: &str = "vault.records.erase_preview";
    let caller = match person(server, auth, VERB) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    let locality = auth.locality();
    off_runtime_listing(VERB, move |producers| {
        let memory = server
            .vault()
            .memory(
                caller.revalidate_person(server.vault())?,
                EdgeActorClass::Human,
            )
            .at(locality)
            .listing_producers(producers);
        sdk::preview_record_erase(&memory, input)
    })
    .await
}

/// `vault.records.erase_confirm`: the caller's own erase of the record they
/// previewed. Their proof starts a held record's `erase` act, which
/// `vault.shared.execute` carries out after its veto window, from whatever
/// surface the proof came from. Beside it, the rows the preview it confirms
/// was derived from; a caller off this device whose answer would carry a row
/// that stays here hears only that it ran (FIX 3414).
pub(crate) async fn vault_records_erase_confirm(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RecordEraseConfirmRequest,
) -> Listed<ActAnswer<RecordEraseOutcome>> {
    const VERB: &str = "vault.records.erase_confirm";
    let caller = match person(server, auth, VERB) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let held = Arc::clone(server);
    let answer = off_runtime_listing(VERB, move |producers| {
        let memory = held
            .vault()
            .memory(
                caller.revalidate_person(held.vault())?,
                EdgeActorClass::Human,
            )
            .listing_producers(producers);
        sdk::confirm_record_erase(&memory, &caller, input)
    })
    .await;
    crate::device_local::act_answer(server.vault(), &auth.destination(), answer)
}

/// The owner's historical erasure timing, without starting or polling a sweep.
pub(crate) async fn vault_records_erase_sweep(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RecordEraseSweepRequest,
) -> Listed<Option<RecordEraseSweep>> {
    const VERB: &str = "vault.records.erase_sweep";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let actor = match owner.revalidate(server.vault()) {
        Ok(actor) => actor,
        Err(error) => return refused(error.into()),
    };
    credential_listing(
        server,
        auth,
        (actor, EdgeActorClass::Human),
        VERB,
        move |_, _, memory| memory.record_erase_sweep_as(&owner, input),
    )
    .await
}

/// The record each erase ask names.
fn ask_records(asks: &[SharedEraseAsk]) -> Vec<oneiron::EntityId> {
    asks.iter()
        .filter_map(|ask| oneiron::EntityId::from_hex(&ask.record).ok())
        .collect()
}

/// `vault.members.invitations`: the caller's own pending invitations.
pub(crate) async fn vault_members_invitations(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<Vec<SharedInvitation>> {
    const VERB: &str = "vault.members.invitations";
    let own = slip_invitation(auth).map(str::to_owned);
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, reader| {
            let mut invitations = sdk::read_shared_invitations(server.vault(), &reader, input)?;
            if let Some(own) = own {
                invitations.retain(|invitation| invitation.id.eq_ignore_ascii_case(&own));
            }
            Ok(invitations)
        },
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.members.accept`: the invitee's own acceptance.
pub(crate) async fn vault_members_accept(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedInvitationRequest,
) -> MaybeListed<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.accept";
    let invitee = person(server, auth, VERB).and_then(|invitee| {
        require_slip_invitation(auth, VERB, &input.invitation).map(|()| invitee)
    });
    as_person_naming(
        server,
        VERB,
        invitee,
        move |server, invitee| sdk::accept_shared_invitation_as(server.vault(), &invitee, input),
        receipt_rows,
    )
    .await
}

/// `vault.members.invitation_slip`: an `add_member` holder's mint of a
/// pending invitation's slip (a founding invitation's, or a lost one), under
/// the host's slip issuer.
pub(crate) async fn vault_members_invitation_slip(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InvitationSlipRequest,
) -> MaybeListed<InvitationSlip> {
    const VERB: &str = "vault.members.invitation_slip";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, admin| {
            crate::api::pairing::with_issuer(server, |issuer| {
                Ok(sdk::mint_invitation_slip_as(
                    server.vault(),
                    &admin,
                    issuer,
                    input,
                ))
            })
            .map_err(|_| internal(VERB))?
        },
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.members.decline`: the invitee's own refusal.
pub(crate) async fn vault_members_decline(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedInvitationRequest,
) -> MaybeListed<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.decline";
    let invitee = person(server, auth, VERB).and_then(|invitee| {
        require_slip_invitation(auth, VERB, &input.invitation).map(|()| invitee)
    });
    as_person_naming(
        server,
        VERB,
        invitee,
        move |server, invitee| sdk::decline_shared_invitation_as(server.vault(), &invitee, input),
        receipt_rows,
    )
    .await
}

/// `vault.members.withdraw_invitation`: an `add_member` holder's withdrawal,
/// checked by the engine against the live roster.
pub(crate) async fn vault_members_withdraw_invitation(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedInvitationWithdrawRequest,
) -> MaybeListed<SharedActExecutionReceipt> {
    const VERB: &str = "vault.members.withdraw_invitation";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, admin| sdk::withdraw_shared_invitation_as(server.vault(), &admin, input),
        receipt_rows,
    )
    .await
}

/// `vault.shared.object`: an objector-role holder's objection.
pub(crate) async fn vault_shared_object(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedActRequest,
) -> MaybeListed<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.object";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::object_to_shared_act(server.vault(), &holder, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.withdraw_objection`: the holder withdraws their objection.
pub(crate) async fn vault_shared_withdraw_objection(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedActRequest,
) -> MaybeListed<PendingAuthorityAct> {
    const VERB: &str = "vault.shared.withdraw_objection";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::withdraw_shared_act_objection(server.vault(), &holder, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.started`: the caller's own started-act notices.
pub(crate) async fn vault_shared_started(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<Vec<PendingActStarted>> {
    const VERB: &str = "vault.shared.started";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::read_shared_act_started(server.vault(), &holder, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.matured`: the caller's own matured-act notices.
pub(crate) async fn vault_shared_matured(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<Vec<PendingActMatured>> {
    const VERB: &str = "vault.shared.matured";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::read_shared_act_matured(server.vault(), &holder, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.shared.erase_ask`: a Member's request or an Admin's proposal to erase a record.
pub(crate) async fn vault_shared_erase_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedEraseAskRequest,
) -> MaybeListed<SharedEraseAsk> {
    const VERB: &str = "vault.shared.erase_ask";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::ask_shared_erase_as(server.vault(), &holder, input),
        |ask| Some(ask_records(std::slice::from_ref(ask))),
    )
    .await
}

/// `vault.shared.erase_asks`: the erase asks the caller may see.
pub(crate) async fn vault_shared_erase_asks(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<Vec<SharedEraseAsk>> {
    const VERB: &str = "vault.shared.erase_asks";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::read_shared_erase_asks(server.vault(), &holder, input),
        |asks| Some(ask_records(asks)),
    )
    .await
}

/// `vault.shared.close_erase_ask`: an Owner closes an open erase ask.
pub(crate) async fn vault_shared_close_erase_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedEraseAskCloseRequest,
) -> MaybeListed<SharedEraseAsk> {
    const VERB: &str = "vault.shared.close_erase_ask";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, holder| sdk::close_shared_erase_ask_as(server.vault(), &holder, input),
        |ask| Some(ask_records(std::slice::from_ref(ask))),
    )
    .await
}

/// `vault.guests.mint_slip`: the owner mints an ask guest's slip, bound to
/// its grant, for the key the guest generated on their own device.
pub(crate) async fn vault_guests_mint_slip(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: GuestSlipMintRequest,
) -> MaybeListed<GuestSlipMinted> {
    const VERB: &str = "vault.guests.mint_slip";
    let owner = super::owner_binding::facade_owner(server, auth, VERB);
    let grant = input.grant_ref;
    as_person_naming(
        server,
        VERB,
        owner,
        move |server, owner| {
            crate::api::pairing::with_issuer(server, |issuer| {
                Ok(sdk::mint_guest_slip_as(
                    server.vault(),
                    &owner,
                    issuer,
                    input,
                ))
            })
            .map_err(|_| internal(VERB))?
        },
        move |_| Some(vec![grant]),
    )
    .await
}
