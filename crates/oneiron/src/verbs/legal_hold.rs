//! The inputs and answers of the owner's legal-hold rows (OF-470):
//! `vault.legal_holds.place`, `.widen`, `.list`, `.log`, `.lift_and_erase`
//! and `.withdraw_erase`, each a host door. Each fn passes the engine exactly
//! what it asks for, under the vault owner's proof: a server mints it from
//! the request, as `/v1/owner` does; an embedded handle acts as the vault's
//! embedded owner. Oneiron's host-order doors have no row here, since no
//! owner, member or agent surface may route to them.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    ErasePendingReason, EraseWithdrawal, LegalHold, LegalHoldEvent, LegalHoldTarget,
    LiftAndEraseOutcome, LiftAndEraseShownState, LiftAndEraseStatus,
};
use crate::error::LegalHoldBound;
use crate::memory::MemoryResult;
use crate::{EntityId, Vault};

/// `vault.legal_holds.place`'s input: what the owner's customer hold names,
/// and an optional opaque matter reference.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldPlaceRequest {
    /// Each `{"record": "<hex>"}`, `{"gate_partition": "<hex>"}` (a claim's
    /// gate-decision key partition), or `{"gate_partition": null}` (the
    /// claim-free partition).
    pub targets: Vec<LegalHoldTarget>,
    /// An opaque id, never free text: 1 to 128 of A-Z a-z 0-9 . _ : - /.
    #[serde(default)]
    pub matter_ref: Option<String>,
}

/// `vault.legal_holds.widen`'s input: more targets for one of the owner's
/// standing customer holds. A hold narrows only through the one confirm.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldWidenRequest {
    pub hold_id: EntityId,
    /// As [`LegalHoldPlaceRequest::targets`].
    pub targets: Vec<LegalHoldTarget>,
}

/// `vault.legal_holds.lift_and_erase`'s input: the records the owner's one
/// "Lift the hold and erase?" confirm names, whether it releases the
/// claim-free gate-decision partition too (FIX 9782), and what it showed
/// the owner (FIX 1462).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldLiftAndEraseRequest {
    pub records: Vec<EntityId>,
    /// Also release every customer hold on the claim-free partition, the
    /// one the retention-horizon sweep ages. A host order on it stays.
    #[serde(default)]
    pub claim_free_partition: bool,
    /// What the confirm showed: its title and prompt, these targets, and
    /// every standing customer hold on them, whole, as the hold list reads
    /// them. The engine acts only when it reads the same.
    pub shown_state: LiftAndEraseShownState,
}

/// What the owner's one confirm did to one record, by one rule wherever the
/// bytes live (WILL-PLAN L01 row 04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LegalHoldEraseState {
    /// The hold is lifted and the record erased: its deletion receipt's
    /// signed final row is appended, its hard purge, historical sweep and
    /// every custody retirement it bound finished (C4, FIX 5844). No receipt
    /// when nothing was there.
    Erased { receipt_ref: Option<String> },
    /// "erase confirmed; completion pending"
    /// ([`crate::deletion::ERASE_COMPLETION_PENDING`]): the erase ran and
    /// `reason` is still outstanding on `receipt_ref`, or, with neither, an
    /// order the owner may not be told of keeps the bytes. Not erased yet.
    CompletionPending {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt_ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<ErasePendingReason>,
    },
    /// A legal order binding Oneiron's hosting keeps the bytes: `bound`
    /// names its law, and the note says what self-hosting changes. The erase
    /// runs when the order lifts. Not erased.
    RetainedForLaw {
        bound: LegalHoldBound,
        works_self_hosted: bool,
        self_hosted_note: String,
    },
    /// The hold was lifted, then the erase failed; a plain delete retries it.
    Failed { message: String },
}

impl From<LiftAndEraseStatus> for LegalHoldEraseState {
    fn from(status: LiftAndEraseStatus) -> Self {
        match status {
            LiftAndEraseStatus::Erased { receipt_ref } => Self::Erased { receipt_ref },
            LiftAndEraseStatus::CompletionPending {
                receipt_ref,
                reason,
            } => Self::CompletionPending {
                receipt_ref,
                reason,
            },
            LiftAndEraseStatus::RetainedForLaw(notice) => Self::RetainedForLaw {
                bound: notice.bound,
                works_self_hosted: notice.works_self_hosted,
                self_hosted_note: notice.self_hosted_note,
            },
            LiftAndEraseStatus::Failed { message } => Self::Failed { message },
        }
    }
}

/// One record the confirm named, with what it did to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldErasedRecord {
    pub record: EntityId,
    pub status: LegalHoldEraseState,
}

/// `vault.legal_holds.lift_and_erase`'s answer: the customer holds lifted or
/// narrowed to what is left, and each named record's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldLiftAndErased {
    pub holds: Vec<EntityId>,
    pub records: Vec<LegalHoldErasedRecord>,
    /// What the confirm shows now, when it is not what the owner was shown:
    /// nothing was lifted or erased; confirm again with this (FIX 1462).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<LiftAndEraseShownState>,
}

impl From<LiftAndEraseOutcome> for LegalHoldLiftAndErased {
    fn from(outcome: LiftAndEraseOutcome) -> Self {
        Self {
            holds: outcome.holds,
            records: outcome
                .records
                .into_iter()
                .map(|(record, status)| LegalHoldErasedRecord {
                    record,
                    status: status.into(),
                })
                .collect(),
            changed: outcome.changed,
        }
    }
}

/// `vault.legal_holds.withdraw_erase`'s input: the records whose waiting
/// erase the owner withdraws (FIX 10401).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldWithdrawEraseRequest {
    pub records: Vec<EntityId>,
}

/// One record the withdrawal named, with what it did to the erase that
/// waited on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldWithdrawnErase {
    pub record: EntityId,
    pub status: EraseWithdrawal,
}

/// `vault.legal_holds.withdraw_erase`'s answer: each named record's state,
/// in id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldErasesWithdrawn {
    pub records: Vec<LegalHoldWithdrawnErase>,
}

/// `vault.legal_holds.place`: the owner's customer hold on `targets`.
pub fn place_legal_hold_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LegalHoldPlaceRequest,
) -> MemoryResult<LegalHold> {
    Ok(vault.place_legal_hold(owner, input.targets, input.matter_ref)?)
}

/// `vault.legal_holds.widen`: adds targets to the owner's standing hold.
pub fn widen_legal_hold_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LegalHoldWidenRequest,
) -> MemoryResult<LegalHold> {
    Ok(vault.widen_legal_hold(owner, input.hold_id, input.targets)?)
}

/// `vault.legal_holds.list`: every hold the owner may see.
pub fn read_legal_holds(vault: &Vault, owner: &AuthenticatedOwner) -> MemoryResult<Vec<LegalHold>> {
    Ok(vault.legal_holds(owner)?)
}

/// `vault.legal_holds.log`: the owner-visible hold log, oldest first.
pub fn read_legal_hold_log(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<LegalHoldEvent>> {
    Ok(vault.legal_hold_log(owner)?)
}

/// `vault.legal_holds.lift_and_erase`: the owner's one "Lift the hold and
/// erase?" confirm over `input.records`, and the claim-free partition with
/// `input.claim_free_partition`. The engine takes the owner's proof, the
/// targets and the state the confirm showed, unchanged, and checks that
/// state itself: there is no second press, token or expiry, and nothing
/// here prepares a state the owner was not shown (FIX 1462).
pub fn lift_legal_hold_and_erase_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LegalHoldLiftAndEraseRequest,
) -> MemoryResult<LegalHoldLiftAndErased> {
    Ok(vault
        .confirm_lift_legal_hold_and_erase(
            owner,
            &input.records,
            input.claim_free_partition,
            &input.shown_state,
        )?
        .into())
}

/// `vault.legal_holds.withdraw_erase`: the owner withdraws the erase that
/// waits on each of `input.records`, under the owner proof the confirm
/// takes (FIX 10401). A hold the confirm lifted stays lifted.
pub fn withdraw_legal_hold_erase_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LegalHoldWithdrawEraseRequest,
) -> MemoryResult<LegalHoldErasesWithdrawn> {
    let records = vault
        .withdraw_waiting_erases(owner, &input.records)?
        .into_iter()
        .map(|(record, status)| LegalHoldWithdrawnErase { record, status })
        .collect();
    Ok(LegalHoldErasesWithdrawn { records })
}
