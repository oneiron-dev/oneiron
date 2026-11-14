//! The inputs and answers of the owner's legal-hold rows (OF-470):
//! `vault.legal_holds.place`, `.widen`, `.list`, `.log`, `.lift_and_erase`
//! and `.withdraw_erase`, each a host door. Each fn passes the engine exactly
//! what it asks for, under the vault owner's proof: a server mints it from
//! the request, as `/v1/owner` does; an embedded handle acts as the vault's
//! embedded owner. Oneiron's host-order doors have no row here, since no
//! owner, member or agent surface may route to them.
use serde::{Deserialize, Serialize};

use super::owner_confirm;
use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    LegalHold, LegalHoldEvent, LiftAndEraseOutcome, LiftAndEraseShownState, LiftAndEraseStatus,
};
use crate::memory::MemoryResult;
use crate::{EntityId, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::legal_hold::{
    LegalHoldEraseState, LegalHoldErasedRecord, LegalHoldErasesWithdrawn, LegalHoldPlaceRequest,
    LegalHoldWidenRequest, LegalHoldWithdrawEraseRequest, LegalHoldWithdrawnErase,
};

/// `vault.legal_holds.lift_and_erase`'s input: the records the owner's one
/// "Lift the hold and erase?" confirm names, whether it releases the
/// claim-free gate-decision partition too (FIX 9782), and the confirm the
/// shared preview returned for this call (FIX 1462).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldLiftAndEraseRequest {
    pub records: Vec<EntityId>,
    /// Also release every customer hold on the claim-free partition, the
    /// one the retention-horizon sweep ages. A host order on it stays.
    #[serde(default)]
    pub claim_free_partition: bool,
    /// The confirm `vault.owner_confirm.preview` returned for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
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
            LiftAndEraseStatus::Failed { message } => Self::Failed { message },
        }
    }
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
/// `input.claim_free_partition`. The engine reads what the confirm shows
/// now, admits the call only on the shared confirm of that same state, and
/// checks the state again inside its own txn: one press, no expiry
/// (`PreviewKeep::UntilUsed`), and nothing here prepares a state the owner
/// was not shown (FIX 1462).
pub fn lift_legal_hold_and_erase_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LegalHoldLiftAndEraseRequest,
) -> MemoryResult<LegalHoldLiftAndErased> {
    let ask = owner_confirm::asked("vault.legal_holds.lift_and_erase", &input)?;
    let shown =
        vault.lift_and_erase_shown_state(owner, &input.records, input.claim_free_partition)?;
    owner_confirm::admit(vault, owner, ask, &shown)?;
    Ok(vault
        .confirm_lift_legal_hold_and_erase(
            owner,
            &input.records,
            input.claim_free_partition,
            &shown,
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
