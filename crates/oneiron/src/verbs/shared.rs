//! The inputs and answers of the shared-vault rows a host door answers
//! (OF-158): the acts the shared preset waits on (`vault.shared.*`), the
//! membership changes that never wait (`vault.members.*`) and the owner's
//! fork alarms (`vault.authority.handoff_alarms*`). Each fn passes the engine
//! exactly what it asks for. A server mints the proof from the request and
//! hands in its slip issuer; an embedded handle acts as the vault's embedded
//! owner, with no issuer.
use serde::{Deserialize, Serialize};

use super::owner_confirm;
use crate::authority::{
    ActAuthority, ActSurface, AuthorityHandoffAlarm, AuthorityKey, HostSlipIssuer,
    OWNER_KEY_MOVE_NOT_PLANNED, OwnerKeyMovePlan, OwnerKeyMoveSigner,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, RecordError};
use crate::federation::{
    FederationGrantRole as Role, MemberAskChange, OwnerRemoval, PendingAuthorityAct,
    RemovalExportDelivery, SharedActExecution, SharedActExecutionReceipt, SharedActKind,
    SharedActOutcome, SharedMemberAsk, SharedVaultDeletion,
};
use crate::memory::{MemoryError, MemoryResult, ProducerRows};
use crate::{EntityId, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::shared::{
    HandoffAlarmRequest, SharedActExecuteRequest, SharedActRequest, SharedAddOwnerRequest,
    SharedMemberAskIdRequest, SharedMemberAskKind, SharedMemberRequest,
    SharedOwnerChangeWaitSetRequest, SharedOwnerKeyMoveConfirm, SharedOwnerKeyMovePlan,
    SharedOwnerKeyMoveSignRequest, SharedOwnerKeyMoveSigner, SharedReceiptRequest,
    SharedVaultRequest,
};

/// `vault.shared.propose_delete`'s input: the shared vault, the approved
/// check-in of another asker the starting Owner applies, when one is named,
/// and the confirm the shared preview returned for this call.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedDeleteProposeRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// An asker's approved check-in for this vault's delete, 32 hex: the
    /// Owner applies it on their own proof, and the act names its asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
    /// The confirm `vault.owner_confirm.preview` returned for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
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
    /// An asker's approved check-in for this transfer, 32 hex: the starting
    /// Owner applies it on their own proof, and the act names its asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
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
    /// An asker's approved check-in for this removal, 32 hex: the starting
    /// Owner applies it on their own proof, and the act names its asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

/// `vault.members.add`'s input: a live person with no membership here, at a
/// non-root role, or the creation preset's default member role when absent.
/// It names no key: the invitee binds their own (FIX 8745).
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
    /// The check-in an earlier call's `CHECK_IN_PENDING` named, 32 hex: once
    /// a holder approved it, this call spends it and the add runs.
    #[serde(default)]
    pub check_in_ref: Option<String>,
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
/// invitation while that is pending and its key is the one the invitee bound
/// (FIX 8745), and nothing else. The invitee proves each request with that
/// key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationSlip {
    /// The slip id, hex.
    pub slip_id: String,
    /// The `v2.slip.` credential.
    pub slip: String,
    /// When the invitation, and with it the slip, expires.
    pub expires_at: u64,
}

/// `vault.members.accept_with_credential`'s answer: the acceptance receipt and
/// the regular member credential minted in that same writer. The credential is
/// always present; plain acceptance keeps its original receipt-only answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedInvitationAcceptedWithCredential {
    pub receipt: SharedActExecutionReceipt,
    pub credential: MemberSlip,
}

impl MemberSlip {
    pub(super) fn from_slip(slip: crate::authority::CapabilitySlip) -> MemoryResult<Self> {
        Ok(Self {
            slip_id: crate::entity_id::bytes_to_hex_lower(&slip.claims.slip_id),
            slip: slip.to_token()?,
            expires_at: slip.claims.expires_at,
        })
    }
}

/// An accepted member's regular credential, bound to the accepted grant and
/// the same device key that proved the invitation request. The private key
/// stays on the invitee's device and proves each subsequent request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberSlip {
    /// The slip id, hex.
    pub slip_id: String,
    /// The `v2.slip.` credential.
    pub slip: String,
    /// The caller-chosen expiry admitted by the normal mint validator.
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
    /// The check-in an earlier call's `CHECK_IN_PENDING` named, 32 hex: once
    /// a holder approved it, this call spends it and the move runs.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

/// The member of a shared vault `vault.members.remove` removes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedMemberRemoveRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// PERSON id, hex.
    pub member: String,
    /// The check-in an earlier call's `CHECK_IN_PENDING` named, 32 hex: once
    /// a holder approved it, this call spends it and the removal runs.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

/// A Steward's ask for one member change in a shared vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedMemberAskRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub kind: SharedMemberAskKind,
    /// PERSON id, hex.
    pub member: String,
    /// `admin`, `member` or `viewer`: optional for `add`, required for
    /// `assign_role`, none for `remove`.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    pub role: Option<Role>,
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

/// The settled check-in a call names, when it names one.
pub(super) fn check_in_ref(hex: Option<&str>) -> MemoryResult<Option<EntityId>> {
    hex.map(|hex| {
        EntityId::from_hex(hex)
            .map_err(|_| MemoryError::bad_request("check_in_ref is not a check-in id"))
    })
    .transpose()
}

/// `vault.shared.propose_delete`: start the vault's `delete_vault` act,
/// once the shared confirm of this proposal is admitted. The act records
/// the Owner's check-in decision; with `check_in_ref` the Owner applies an
/// asker's approved check-in for this delete (2j).
pub fn propose_shared_delete(
    vault: &Vault,
    starter: &AuthenticatedOwner,
    input: SharedDeleteProposeRequest,
) -> MemoryResult<PendingAuthorityAct> {
    let check_in = check_in_ref(input.check_in_ref.as_deref())?;
    let ask = owner_confirm::asked("vault.shared.propose_delete", &input)?;
    owner_confirm::admit(vault, starter, ask, &())?;
    Ok(vault.propose_delete_vault_with_check_in(starter, input.vault_id, check_in)?)
}

/// `vault.shared.propose_transfer`: start a `transfer_ownership` act. The
/// act records the Owner's check-in decision; with `check_in_ref` the Owner
/// applies an asker's approved check-in for this transfer (2k1).
pub fn propose_shared_transfer(
    vault: &Vault,
    starter: &AuthenticatedOwner,
    input: SharedTransferRequest,
) -> MemoryResult<PendingAuthorityAct> {
    let to = person_id("to", &input.to)?;
    let check_in = check_in_ref(input.check_in_ref.as_deref())?;
    Ok(vault.propose_transfer_ownership_with_check_in(
        starter,
        input.vault_id,
        to,
        input.from_keeps,
        check_in,
    )?)
}

/// `vault.shared.propose_remove_owner`: start a `remove_owner` act. The act
/// records the Owner's check-in decision; with `check_in_ref` the Owner
/// applies an asker's approved check-in for this removal (2k1).
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
    let check_in = check_in_ref(input.check_in_ref.as_deref())?;
    Ok(vault.propose_remove_owner_with_check_in(
        starter,
        input.vault_id,
        OwnerRemoval {
            target,
            successor,
            target_keeps: input.target_keeps,
            export_first: input.export_first,
        },
        check_in,
    )?)
}

/// `vault.shared.propose_add_owner`: start an `add_owner` act. The act
/// records the Owner's check-in decision; with `check_in_ref` the Owner
/// applies an asker's approved check-in for this add (2k1).
pub fn propose_shared_add_owner(
    vault: &Vault,
    starter: &AuthenticatedOwner,
    input: SharedAddOwnerRequest,
) -> MemoryResult<PendingAuthorityAct> {
    let owner = person_id("owner", &input.owner)?;
    let check_in = check_in_ref(input.check_in_ref.as_deref())?;
    Ok(vault.propose_add_owner_with_check_in(starter, input.vault_id, owner, check_in)?)
}

/// `vault.shared.owner_change_wait.set`: one live Owner sets the common
/// owner-change wait, and receives the effective wait in seconds.
pub fn set_shared_owner_change_wait(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SharedOwnerChangeWaitSetRequest,
) -> MemoryResult<Option<u64>> {
    vault.set_owner_change_wait_days(owner, input.vault_id, input.days)?;
    Ok(vault.owner_change_wait_secs()?)
}

/// `vault.shared.owner_change_wait.get`: the common wait in seconds, if set.
pub fn read_shared_owner_change_wait(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
) -> MemoryResult<Option<u64>> {
    Ok(vault.owner_change_wait_secs()?)
}

/// `vault.shared.execute`: run a matured act once; running it again answers
/// the same receipt, and a remaining Owner's re-run of an export-first
/// removal delivers its archive to the removed Owner again (FIX 1300). A held
/// `erase` act runs its own executor, then its receipt tells the Owners.
/// The rows a device of `executor` signed for the act's owner-key move
/// ([`sign_shared_owner_key_move`]) land in the act's writer before its move
/// (row HOSTED-OWNER-MOVE-TWO-PHASE); an erase ends no Owner standing, so
/// rows given for one are refused.
pub fn execute_shared_act(
    vault: &Vault,
    executor: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedActExecuteRequest,
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
    input: SharedActExecuteRequest,
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
    input: SharedActExecuteRequest,
    producers: &ProducerRows,
    export_listed: &mut bool,
) -> MemoryResult<SharedActExecuted> {
    let owner_key_revokes = input
        .owner_key_revokes
        .iter()
        .map(|row| {
            oneiron_hex::decode_vec(row).ok_or_else(|| {
                MemoryError::bad_request("owner_key_revokes holds a row that is not lowercase hex")
            })
        })
        .collect::<MemoryResult<Vec<_>>>()?;
    let erase = vault
        .pending_authority_act(&input.act_id)?
        .is_some_and(|act| SharedActKind::parse(&act.act) == Some(SharedActKind::Erase));
    if erase {
        if !owner_key_revokes.is_empty() {
            return Err(Error::Record(RecordError::InvalidAuthorityLogBody(
                OWNER_KEY_MOVE_NOT_PLANNED,
            ))
            .into());
        }
        // A held erase runs through its own executor, which binds the
        // record; its receipt then tells the Owners (OF-150).
        let memory = vault
            .memory(executor.revalidate_person(vault)?, EdgeActorClass::Human)
            .listing_producers(producers);
        // The vault owner carrying out the erase of a Connect guest's PERSON
        // withdraws its grants, signed by the host's key, as his direct
        // delete does (FIX 3875, 5317). Another Owner erases as before.
        let memory = match slips {
            Some(issuer) if vault.is_live_vault_owner(executor)? => memory
                .with_owner_authorship(executor)
                .with_host_slip_issuer(issuer),
            _ => memory,
        };
        memory.execute_completed_entity_erase(executor, &input.act_id)?;
        return Ok(SharedActExecuted {
            receipt: vault.record_erase_completion(executor, &input.act_id)?,
            delivery: None,
        });
    }
    let execution = vault.execute_completed_shared_act_with_owner_key_revokes(
        executor,
        &input.act_id,
        slips,
        &owner_key_revokes,
    )?;
    if let Some(records) = &execution.export_records {
        producers.list(records.iter().copied());
        *export_listed = true;
    }
    Ok(execution.into())
}

/// `vault.shared.owner_key_move_plan`: the plan a device of `executor`, a
/// live Owner who may run the act now, confirms the act's owner-key move
/// with (row HOSTED-OWNER-MOVE-TWO-PHASE): its answer is the input of
/// `vault.shared.owner_key_move_sign` on that device. A frontier join the
/// plan needs is signed by `slips` (or this install's live host issuer) and
/// kept; nothing else is written.
pub fn plan_shared_owner_key_move(
    vault: &Vault,
    executor: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedActRequest,
) -> MemoryResult<SharedOwnerKeyMovePlan> {
    let plan = vault.owner_key_move_plan(executor, &input.act_id, slips)?;
    Ok(owner_key_move_plan_wire(plan))
}

/// `vault.shared.owner_key_move_sign`: the owner key this install holds for
/// `owner` signs the plan's revokes, after the plan is checked against this
/// install's copy of the vault (row HOSTED-OWNER-MOVE-TWO-PHASE). It runs on
/// the Owner's own device: a host holds none of an Owner's keys, so there it
/// answers the refusal. `input.member` is the member the Owner confirmed on
/// the device, from its own copy; a plan of another member signs nothing.
/// It writes nothing; the answer goes to `vault.shared.execute` as it is.
pub fn sign_shared_owner_key_move(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SharedOwnerKeyMoveSignRequest,
) -> MemoryResult<SharedOwnerKeyMoveConfirm> {
    let member = person_id("member", &input.member)?;
    let plan = owner_key_move_plan_from_wire(input.plan)?;
    let authority = ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall);
    let rows = vault.sign_owner_key_move_as(&authority, &plan, member)?;
    Ok(SharedOwnerKeyMoveConfirm {
        owner_key_revokes: rows.iter().map(|row| oneiron_hex::encode(row)).collect(),
    })
}

/// `plan` as the wire carries it: byte fields in lowercase hex.
fn owner_key_move_plan_wire(plan: OwnerKeyMovePlan) -> SharedOwnerKeyMovePlan {
    fn hex_all(values: &[[u8; 32]]) -> Vec<String> {
        values
            .iter()
            .map(|value| oneiron_hex::encode(value))
            .collect()
    }
    SharedOwnerKeyMovePlan {
        authority_vault_id: oneiron_hex::encode(&plan.vault_id),
        member: plan.member.to_hex(),
        parents: hex_all(&plan.parents),
        revoked: plan.revoked.iter().map(owner_key_hex).collect(),
        signers: plan
            .signers
            .iter()
            .map(|signer| SharedOwnerKeyMoveSigner {
                public_key: oneiron_hex::encode(&signer.public_key),
                seq: signer.seq,
            })
            .collect(),
        at: plan.at,
        act_id: plan.act_id,
    }
}

/// An owner key as a plan's wire names it: its key bytes in lowercase hex,
/// 64 digits for an Ed25519 key, 66 for a passkey's compressed P-256 key
/// (row WEB-PASSKEY-OWNER-KEY).
fn owner_key_hex(key: &AuthorityKey) -> String {
    match key {
        AuthorityKey::Ed25519(bytes) => oneiron_hex::encode(bytes),
        AuthorityKey::P256(bytes) => oneiron_hex::encode(bytes),
    }
}

/// The plan the wire `plan` carries; a field that is not its hex is a bad
/// request.
fn owner_key_move_plan_from_wire(plan: SharedOwnerKeyMovePlan) -> MemoryResult<OwnerKeyMovePlan> {
    fn bytes32(field: &str, text: &str) -> MemoryResult<[u8; 32]> {
        oneiron_hex::decode(text)
            .ok_or_else(|| MemoryError::bad_request(format!("{field} is not 64 lowercase hex")))
    }
    fn bytes32_all(field: &str, texts: &[String]) -> MemoryResult<Vec<[u8; 32]>> {
        texts.iter().map(|text| bytes32(field, text)).collect()
    }
    fn owner_key(field: &str, text: &str) -> MemoryResult<AuthorityKey> {
        if let Some(bytes) = oneiron_hex::decode::<32>(text) {
            return Ok(AuthorityKey::Ed25519(bytes));
        }
        oneiron_hex::decode::<33>(text)
            .map(|bytes| AuthorityKey::P256(bytes.to_vec()))
            .ok_or_else(|| {
                MemoryError::bad_request(format!("{field} is not 64 or 66 lowercase hex"))
            })
    }
    Ok(OwnerKeyMovePlan {
        vault_id: bytes32("plan.authority_vault_id", &plan.authority_vault_id)?,
        member: person_id("plan.member", &plan.member)?,
        parents: bytes32_all("plan.parents", &plan.parents)?,
        revoked: plan
            .revoked
            .iter()
            .map(|text| owner_key("plan.revoked", text))
            .collect::<MemoryResult<_>>()?,
        signers: plan
            .signers
            .iter()
            .map(|signer| {
                Ok(OwnerKeyMoveSigner {
                    public_key: bytes32("plan.signers.public_key", &signer.public_key)?,
                    seq: signer.seq,
                })
            })
            .collect::<MemoryResult<_>>()?,
        at: plan.at,
        act_id: plan.act_id,
    })
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
/// joins on `vault.members.accept`. It only creates the invitation: the
/// invitee binds a key of their own to it (`vault.members.invitation_slip`,
/// or an owner's invitation pairing code; FIX 8745). The act checks in
/// first (2i): an Owner's or an Admin's add goes, and a Deputy's goes on
/// their own judgment; the receipt records the decision.
pub fn add_shared_member_as(
    vault: &Vault,
    admin: &AuthenticatedOwner,
    input: SharedMemberAddRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    let call = super::HeldVerbCall::new("vault.members.add", &input)?;
    let answer = (|| -> MemoryResult<_> {
        let member = person_id("member", &input.member)?;
        let check_in = check_in_ref(input.check_in_ref.as_deref())?;
        Ok(vault.add_shared_member_with_check_in(
            admin,
            input.vault_id,
            member,
            input.role,
            check_in,
        )?)
    })();
    call.answer(vault, admin, answer)
}

/// `vault.members.change`: an Admin's `assign_role` power moves a member.
/// The act checks in first (2i): a Deputy's move that is not a Member's
/// raise to Admin waits on an Owner's answer (`CHECK_IN_PENDING`), and the
/// call that names the approved check-in as `check_in_ref` runs it.
pub fn change_shared_member_as(
    vault: &Vault,
    admin: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedMemberRoleRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    let call = super::HeldVerbCall::new("vault.members.change", &input)?;
    let answer = (|| -> MemoryResult<_> {
        let member = person_id("member", &input.member)?;
        let check_in = check_in_ref(input.check_in_ref.as_deref())?;
        Ok(vault.change_shared_member_role_with_check_in(
            admin,
            input.vault_id,
            member,
            input.role,
            slips,
            check_in,
        )?)
    })();
    call.answer(vault, admin, answer)
}

/// `vault.members.remove`: an Admin's `remove_member` power removes a member
/// who is not an Owner. The act checks in first (2i): a Deputy's removal
/// waits on an Owner's answer (`CHECK_IN_PENDING`), and the call that names
/// the approved check-in as `check_in_ref` runs it.
pub fn remove_shared_member_as(
    vault: &Vault,
    admin: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedMemberRemoveRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    let call = super::HeldVerbCall::new("vault.members.remove", &input)?;
    let answer = (|| -> MemoryResult<_> {
        let member = person_id("member", &input.member)?;
        let check_in = check_in_ref(input.check_in_ref.as_deref())?;
        Ok(vault.remove_shared_member_with_check_in(
            admin,
            input.vault_id,
            member,
            slips,
            check_in,
        )?)
    })();
    call.answer(vault, admin, answer)
}

/// `vault.members.ask`: a Steward suggests one member change. It writes one
/// ask, which every live Owner and Admin gets in the inbox, and changes no
/// membership (ARCH-0043 Steward, propose-only).
pub fn ask_shared_member_as(
    vault: &Vault,
    steward: &AuthenticatedOwner,
    input: SharedMemberAskRequest,
) -> MemoryResult<SharedMemberAsk> {
    person_id("member", &input.member)?;
    let change = match (input.kind, input.role) {
        (SharedMemberAskKind::Add, role) => MemberAskChange::Add {
            member: input.member,
            role,
        },
        (SharedMemberAskKind::Remove, None) => MemberAskChange::Remove {
            member: input.member,
        },
        (SharedMemberAskKind::AssignRole, Some(role)) => MemberAskChange::AssignRole {
            member: input.member,
            role,
        },
        (SharedMemberAskKind::Remove, Some(_)) => {
            return Err(MemoryError::bad_request("a remove ask names no role"));
        }
        (SharedMemberAskKind::AssignRole, None) => {
            return Err(MemoryError::bad_request(
                "an assign_role ask names its role",
            ));
        }
    };
    Ok(vault.ask_shared_member_change(steward, input.vault_id, change)?)
}

/// `vault.members.asks`: the member asks the caller may see in a shared
/// vault: every ask for a live Owner or Admin, a Steward's own asks.
pub fn read_shared_member_asks(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<SharedMemberAsk>> {
    Ok(vault.shared_member_asks(reader, input.vault_id)?)
}

/// Refuses an ask id the caller cannot see in the named shared vault, so a
/// request answers for the vault it names.
fn ask_in_vault(
    vault: &Vault,
    caller: &AuthenticatedOwner,
    input: &SharedMemberAskIdRequest,
) -> MemoryResult<()> {
    if vault
        .shared_member_asks(caller, input.vault_id)?
        .iter()
        .any(|ask| ask.id.eq_ignore_ascii_case(&input.ask))
    {
        Ok(())
    } else {
        Err(MemoryError::bad_request(
            "no such member ask in this shared vault",
        ))
    }
}

/// `vault.members.asks.apply`: a live Admin or Owner applies an open ask
/// through the membership door its change names; the receipt names the
/// Steward as its proposer.
pub fn apply_shared_member_ask_as(
    vault: &Vault,
    applier: &AuthenticatedOwner,
    slips: Option<&HostSlipIssuer>,
    input: SharedMemberAskIdRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    let call = super::HeldVerbCall::new("vault.members.asks.apply", &input)?;
    let answer = (|| -> MemoryResult<_> {
        ask_in_vault(vault, applier, &input)?;
        Ok(vault.apply_shared_member_ask(applier, &input.ask, slips)?)
    })();
    call.answer(vault, applier, answer)
}

/// `vault.members.asks.decline`: a live Admin or Owner declines an open
/// ask; no membership changes.
pub fn decline_shared_member_ask_as(
    vault: &Vault,
    applier: &AuthenticatedOwner,
    input: SharedMemberAskIdRequest,
) -> MemoryResult<SharedMemberAsk> {
    ask_in_vault(vault, applier, &input)?;
    Ok(vault.decline_shared_member_ask(applier, &input.ask)?)
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
