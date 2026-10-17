//! The invitation rows of a shared vault (OF-531 / OF-158): `vault.members.add`
//! invites, and the invitee lists, accepts or declines their own invitation
//! under their own proof while an `add_member` holder may withdraw it. Beside
//! them, the veto-window rows a holder works a pending act with (OF-163): an
//! Owner's objection and its withdrawal, the started and matured notices, and
//! a Member's or Admin's ask that the Owners erase a record. Each fn passes
//! the engine exactly what it asks for.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::federation::{
    PendingActMatured, PendingActStarted, PendingAuthorityAct, SharedActExecutionReceipt,
    SharedEraseAsk, SharedInvitation,
};
use crate::memory::{MemoryError, MemoryResult};
use crate::task_verb::sdk::{SharedActRequest, SharedVaultRequest};
use crate::{EntityId, Vault};

/// One of the caller's own invitations, by the id its `MemberInvited`
/// receipt named.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedInvitationRequest {
    pub vault_id: u64,
    pub invitation: String,
}

/// `vault.members.withdraw_invitation`'s input: the invitee's PERSON id, hex,
/// and the invitation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedInvitationWithdrawRequest {
    pub vault_id: u64,
    pub member: String,
    pub invitation: String,
}

/// `vault.shared.erase_ask`'s input: the record the asker wants erased,
/// entity id hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedEraseAskRequest {
    pub vault_id: u64,
    pub record: String,
}

/// `vault.shared.close_erase_ask`'s input: `erased` when the Owner erased the
/// record, naming with `act_id` the `erase` act they started where the veto
/// window applied; else declined.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedEraseAskCloseRequest {
    pub ask_id: String,
    pub erased: bool,
    #[serde(default)]
    pub act_id: Option<String>,
}

/// `vault.members.invitations`: the caller's own pending invitations.
pub fn read_shared_invitations(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<SharedInvitation>> {
    Ok(vault.shared_invitations(reader, input.vault_id)?)
}

/// `vault.members.accept`: the invitee joins at the invited role.
pub fn accept_shared_invitation_as(
    vault: &Vault,
    invitee: &AuthenticatedOwner,
    input: SharedInvitationRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    Ok(vault.accept_shared_invitation(invitee, input.vault_id, &input.invitation)?)
}

/// `vault.members.decline`: the invitee declines; nothing is granted.
pub fn decline_shared_invitation_as(
    vault: &Vault,
    invitee: &AuthenticatedOwner,
    input: SharedInvitationRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    Ok(vault.decline_shared_invitation(invitee, input.vault_id, &input.invitation)?)
}

/// `vault.members.withdraw_invitation`: an `add_member` holder takes a
/// pending invitation back.
pub fn withdraw_shared_invitation_as(
    vault: &Vault,
    admin: &AuthenticatedOwner,
    input: SharedInvitationWithdrawRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    let member = EntityId::from_hex(&input.member)
        .map_err(|_| MemoryError::bad_request("member is not an entity id"))?;
    Ok(vault.withdraw_shared_invitation(admin, input.vault_id, member, &input.invitation)?)
}

/// `vault.shared.object`: a holder of the act's objector role objects inside
/// its window.
pub fn object_to_shared_act(
    vault: &Vault,
    holder: &AuthenticatedOwner,
    input: SharedActRequest,
) -> MemoryResult<PendingAuthorityAct> {
    Ok(vault.change_authority_objection(holder, &input.act_id, true)?)
}

/// `vault.shared.withdraw_objection`: the holder takes their objection back;
/// past the deadline, the last withdrawal releases the act.
pub fn withdraw_shared_act_objection(
    vault: &Vault,
    holder: &AuthenticatedOwner,
    input: SharedActRequest,
) -> MemoryResult<PendingAuthorityAct> {
    Ok(vault.change_authority_objection(holder, &input.act_id, false)?)
}

/// `vault.shared.started`: the caller's own notices of acts started in the
/// vault.
pub fn read_shared_act_started(
    vault: &Vault,
    holder: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<PendingActStarted>> {
    // The engine reads the roster at its own store clock; no earlier time
    // can widen it.
    Ok(vault.pending_act_started_events(holder, input.vault_id, 0)?)
}

/// `vault.shared.matured`: the caller's own notices of acts whose window has
/// passed.
pub fn read_shared_act_matured(
    vault: &Vault,
    holder: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<PendingActMatured>> {
    Ok(vault.pending_act_matured_events(holder, input.vault_id)?)
}

/// `vault.shared.erase_ask`: a Member requests, or an Admin proposes, that
/// the Owners erase a record.
pub fn ask_shared_erase_as(
    vault: &Vault,
    asker: &AuthenticatedOwner,
    input: SharedEraseAskRequest,
) -> MemoryResult<SharedEraseAsk> {
    let record = EntityId::from_hex(&input.record)
        .map_err(|_| MemoryError::bad_request("record is not an entity id"))?;
    Ok(vault.ask_shared_erase(asker, input.vault_id, record)?)
}

/// `vault.shared.erase_asks`: every ask for an Owner, the caller's own for
/// anyone else.
pub fn read_shared_erase_asks(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<SharedEraseAsk>> {
    Ok(vault.shared_erase_asks(reader, input.vault_id)?)
}

/// `vault.shared.close_erase_ask`: an Owner closes an open ask.
pub fn close_shared_erase_ask_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SharedEraseAskCloseRequest,
) -> MemoryResult<SharedEraseAsk> {
    Ok(
        vault.close_shared_erase_ask(
            owner,
            &input.ask_id,
            input.erased,
            input.act_id.as_deref(),
        )?,
    )
}
