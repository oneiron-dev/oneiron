//! The inputs and answers of the shared-vault rows a host door answers
//! (OF-158): the acts the shared preset waits on (`vault.shared.*`), the
//! membership changes that never wait (`vault.members.*`) and the owner's
//! fork alarms (`vault.authority.handoff_alarms*`). Each fn passes the engine
//! exactly what it asks for. A server mints the proof from the request and
//! hands in its slip issuer; an embedded handle acts as the vault's embedded
//! owner, with no issuer.
use serde::{Deserialize, Serialize};

use crate::authority::{AuthorityHandoffAlarm, HostSlipIssuer};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::federation::{
    FederationGrantRole as Role, PendingAuthorityAct, RemovalExportDelivery, SharedActExecution,
    SharedActExecutionReceipt, SharedActKind, SharedActOutcome, SharedVaultDeletion,
};
use crate::memory::{MemoryError, MemoryResult, ProducerRows};
use crate::{EntityId, Vault};

/// A shared vault, by the id its creation named.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedVaultRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
}

/// `vault.shared.propose_transfer`'s input: the starter, a live Owner, hands
/// the vault to `to`, then keeps `from_keeps` or leaves when it is absent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedTransferRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// The new Owner's PERSON id, hex: a live person not yet an Owner.
    pub to: String,
    /// `admin`, `member` or `viewer`.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    pub from_keeps: Option<Role>,
}

/// `vault.shared.propose_remove_owner`'s input. `target` keeps
/// `target_keeps` or leaves when it is absent; removing the last Owner names
/// a `successor`. `export_first` is the removal flow's "export first?".
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedRemoveOwnerRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// The Owner removed, PERSON id hex.
    pub target: String,
    /// The Owner that takes the target's place, PERSON id hex.
    #[serde(default)]
    pub successor: Option<String>,
    /// `admin`, `member` or `viewer`.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    pub target_keeps: Option<Role>,
    pub export_first: bool,
}

/// A started shared act, by the id its proposal answered.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedActRequest {
    pub act_id: String,
}

/// A shared-act or membership receipt, by id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedReceiptRequest {
    pub receipt_id: String,
}

/// `vault.members.add`'s input: a live person with no membership here, at a
/// non-root role, or the creation preset's default member role when absent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedMemberAddRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// PERSON id, hex.
    pub member: String,
    /// `admin`, `member` or `viewer`.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    pub role: Option<Role>,
    /// The public key (64 hex) the invitee generated on their own device:
    /// the host then mints their own slip for this invitation (FIX 1925).
    #[serde(default)]
    pub holder_key: Option<String>,
}

/// `vault.members.add`'s answer: the invitation's receipt and, when the call
/// named the invitee's device key on a host that signs slips, the invitee's
/// own slip for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedMemberInvited {
    pub receipt: SharedActExecutionReceipt,
    pub credential: Option<InvitationSlip>,
}

impl InvitationSlip {
    pub(super) fn from_slip(slip: crate::authority::CapabilitySlip) -> MemoryResult<Self> {
        Ok(Self {
            slip_id: crate::entity_id::bytes_to_hex_lower(&slip.claims.slip_id),
            slip: slip.to_token()?,
            expires_at: slip.claims.expires_at,
        })
    }
}

/// An invitee's own slip (FIX 1925): it lists, accepts or declines its one
/// invitation while that is pending, and nothing else. The invitee proves
/// each request with their own key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationSlip {
    /// The slip id, hex.
    pub slip_id: String,
    /// The `v2.slip.` credential.
    pub slip: String,
    /// When the invitation, and with it the slip, expires.
    pub expires_at: u64,
}

/// `vault.members.change`'s input: another non-root role for a member who
/// is not an Owner.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedMemberRoleRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// PERSON id, hex.
    pub member: String,
    /// `admin`, `member` or `viewer`.
    #[schemars(with = "String")]
    pub role: Role,
}

/// One member of a shared vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedMemberRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// PERSON id, hex.
    pub member: String,
}

/// A saved handoff alarm, by its retired key (`suite:hex`, as the alarm
/// names it).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffAlarmRequest {
    pub signer: String,
}

/// `vault.shared.execute`'s answer: the act's receipt and, for an
/// export-first removal, where its archive went: to the removed Owner alone,
/// retrievable by them until the delivery's deadline (FIX 1300). The Owner
/// who runs the act never receives the archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedActExecuted {
    pub receipt: SharedActExecutionReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<RemovalExportDelivery>,
}

impl From<SharedActExecution> for SharedActExecuted {
    fn from(execution: SharedActExecution) -> Self {
        Self {
            receipt: execution.receipt,
            delivery: execution.delivery,
        }
    }
}

fn person_id(field: &str, hex: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(hex)
        .map_err(|_| MemoryError::bad_request(format!("{field} is not an entity id")))
}

/// `vault.shared.propose_delete`: start the vault's `delete_vault` act.
pub fn propose_shared_delete(
    vault: &Vault,
    starter: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<PendingAuthorityAct> {
    Ok(vault.propose_delete_vault(starter, input.vault_id)?)
}

/// `vault.shared.propose_transfer`: start a `transfer_ownership` act.
pub fn propose_shared_transfer(
    vault: &Vault,
    starter: &AuthenticatedOwner,
    input: SharedTransferRequest,
) -> MemoryResult<PendingAuthorityAct> {
    let to = person_id("to", &input.to)?;
    Ok(vault.propose_transfer_ownership(starter, input.vault_id, to, input.from_keeps)?)
}

/// `vault.shared.propose_remove_owner`: start a `remove_owner` act.
pub fn propose_shared_remove_owner(
    vault: &Vault,
    starter: &AuthenticatedOwner,
    input: SharedRemoveOwnerRequest,
) -> MemoryResult<PendingAuthorityAct> {
    let target = person_id("target", &input.target)?;
    let successor = input
        .successor
        .as_deref()
        .map(|id| person_id("successor", id))
        .transpose()?;
    Ok(vault.propose_remove_owner(
        starter,
        input.vault_id,
        target,
        successor,
        input.target_keeps,
        input.export_first,
    )?)
}

/// `vault.shared.execute`: run a matured act once; running it again answers
/// the same receipt, and a remaining Owner's re-run of an export-first
/// removal delivers its archive to the removed Owner again (FIX 1300). A held
/// `erase` act runs its own executor, then its receipt tells the Owners.
pub fn execute_shared_act(
    vault: &Vault,
    executor: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedActRequest,
) -> MemoryResult<SharedActExecuted> {
    execute_shared_act_listing(vault, executor, slips, input).0
}

/// [`execute_shared_act`], beside the rows its answer was derived from, the
/// rows its receipt names by ref aside (DEC-0005): those a held erase's
/// handle listed, and none past the receipt's for any other act, whose
/// effect reads the act, the roster and the grants its receipt names.
/// An export-first removal's first execution lists every record its
/// export counted and digested (FIX 3412); `None` for its re-delivery,
/// whose archive the first execution built.
pub fn execute_shared_act_listing(
    vault: &Vault,
    executor: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedActRequest,
) -> (MemoryResult<SharedActExecuted>, Option<Vec<EntityId>>) {
    let producers = ProducerRows::default();
    let mut export_listed = false;
    let answer = execute_shared_act_into(
        vault,
        executor,
        slips,
        input,
        &producers,
        &mut export_listed,
    );
    // A first execution lists the records its export counted (FIX 3412);
    // a re-delivery's archive was built before, and no list names it.
    let listed = match &answer {
        Ok(executed) if executed.receipt.export.is_some() && !export_listed => None,
        _ => Some(producers.take()),
    };
    (answer, listed)
}

fn execute_shared_act_into(
    vault: &Vault,
    executor: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedActRequest,
    producers: &ProducerRows,
    export_listed: &mut bool,
) -> MemoryResult<SharedActExecuted> {
    let erase = vault
        .pending_authority_act(&input.act_id)?
        .is_some_and(|act| SharedActKind::parse(&act.act) == Some(SharedActKind::Erase));
    if erase {
        // A held erase runs through its own executor, which binds the
        // record; its receipt then tells the Owners (OF-150).
        vault
            .memory(executor.revalidate_person(vault)?, EdgeActorClass::Human)
            .listing_producers(producers)
            .execute_completed_entity_erase(executor, &input.act_id)?;
        return Ok(SharedActExecuted {
            receipt: vault.record_erase_completion(executor, &input.act_id)?,
            delivery: None,
        });
    }
    let execution = vault.execute_completed_shared_act(executor, &input.act_id, slips)?;
    if let Some(records) = &execution.export_records {
        producers.list(records.iter().copied());
        *export_listed = true;
    }
    Ok(execution.into())
}

/// `vault.shared.receipt`: a receipt its reader was told about.
pub fn read_shared_receipt(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    input: SharedReceiptRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    Ok(vault.shared_act_receipt(reader, &input.receipt_id)?)
}

/// `vault.shared.outcomes`: the reader's own outcome notices for the vault.
pub fn read_shared_outcomes(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<SharedActOutcome>> {
    Ok(vault.shared_act_outcomes(reader, input.vault_id)?)
}

/// `vault.shared.deletion`: the executed delete-the-vault act, if any.
pub fn read_shared_deletion(vault: &Vault) -> MemoryResult<Option<SharedVaultDeletion>> {
    Ok(vault.shared_vault_deletion()?)
}

/// `vault.members.add`: an Admin's `add_member` power invites a member, who
/// joins on `vault.members.accept`. With the invitee's `holder_key` and the
/// host's `slips` issuer, the answer carries the invitee's own slip for the
/// invitation; an embedded handle holds no issuer and invites without one.
pub fn add_shared_member_as(
    vault: &Vault,
    admin: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedMemberAddRequest,
) -> MemoryResult<SharedMemberInvited> {
    let member = person_id("member", &input.member)?;
    let key = input
        .holder_key
        .as_deref()
        .map(super::sdk_shared_members::holder_key)
        .transpose()?;
    let (receipt, slip) =
        vault.invite_shared_member(admin, input.vault_id, member, input.role, slips.zip(key))?;
    let credential = slip.map(InvitationSlip::from_slip).transpose()?;
    Ok(SharedMemberInvited {
        receipt,
        credential,
    })
}

/// `vault.members.change`: an Admin's `assign_role` power moves a member.
pub fn change_shared_member_as(
    vault: &Vault,
    admin: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedMemberRoleRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    let member = person_id("member", &input.member)?;
    Ok(vault.change_shared_member_role(admin, input.vault_id, member, input.role, slips)?)
}

/// `vault.members.remove`: an Admin's `remove_member` power removes a member
/// who is not an Owner.
pub fn remove_shared_member_as(
    vault: &Vault,
    admin: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedMemberRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    let member = person_id("member", &input.member)?;
    Ok(vault.remove_shared_member(admin, input.vault_id, member, slips)?)
}

/// `vault.members.leave`: a member who is not an Owner leaves.
pub fn leave_shared_vault_as(
    vault: &Vault,
    member: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedVaultRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    Ok(vault.leave_shared_vault(member, input.vault_id, slips)?)
}

/// `vault.authority.handoff_alarms`: every saved fork alarm. The engine read
/// takes no proof; the owner's is the door's admission, as
/// `/v1/owner/authority/handoff-alarms` takes it.
pub fn read_handoff_alarms(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<AuthorityHandoffAlarm>> {
    Ok(vault.authority_handoff_alarms()?)
}

/// `vault.authority.handoff_alarms.acknowledge`: the owner has seen one alarm.
pub fn acknowledge_handoff_alarm(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: HandoffAlarmRequest,
) -> MemoryResult<AuthorityHandoffAlarm> {
    Ok(vault.acknowledge_authority_handoff_alarm(owner, &input.signer)?)
}
