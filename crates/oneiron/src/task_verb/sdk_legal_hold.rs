//! The inputs and answers of the owner's legal-hold rows (OF-470):
//! `vault.legal_holds.place`, `.widen`, `.list`, `.log` and
//! `.lift_and_erase`, each a host door. Each fn passes the engine exactly
//! what it asks for, under the vault owner's proof: a server mints it from
//! the request, as `/v1/owner` does; an embedded handle acts as the vault's
//! embedded owner. Oneiron's host-order doors have no row here, since no
//! owner, member or agent surface may route to them.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    LegalHold, LegalHoldEvent, LegalHoldTarget, LiftAndEraseOutcome, LiftAndEraseStatus,
};
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
    #[schemars(with = "Vec<serde_json::Value>")]
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
    #[schemars(with = "Vec<serde_json::Value>")]
    pub targets: Vec<LegalHoldTarget>,
}

/// `vault.legal_holds.lift_and_erase`'s input: the records the owner's one
/// "Lift the hold and erase?" confirm names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldLiftAndEraseRequest {
    pub records: Vec<EntityId>,
}

/// What the owner's one confirm did to one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LegalHoldEraseState {
    /// Self-hosted: the hold is lifted and the record erased.
    Erased { receipt_ref: Option<String> },
    /// "erase confirmed; completion pending"
    /// ([`crate::deletion::ERASE_COMPLETION_PENDING`]): where Oneiron hosts
    /// the bytes, until the deletion receipt completes. Not erased yet.
    CompletionPending,
    /// A legal order Oneiron must obey keeps the bytes; the erase runs when
    /// the order lifts. Not erased.
    KeptByLegalOrder,
    /// The hold was lifted, then the erase failed; a plain delete retries it.
    Failed { message: String },
}

impl From<LiftAndEraseStatus> for LegalHoldEraseState {
    fn from(status: LiftAndEraseStatus) -> Self {
        match status {
            LiftAndEraseStatus::Erased { receipt_ref } => Self::Erased { receipt_ref },
            LiftAndEraseStatus::CompletionPending => Self::CompletionPending,
            LiftAndEraseStatus::KeptByLegalOrder => Self::KeptByLegalOrder,
            LiftAndEraseStatus::Failed { message } => Self::Failed { message },
        }
    }
}

/// One record the confirm named, with what it did to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldErasedRecord {
    pub record: EntityId,
    pub status: LegalHoldEraseState,
}

/// `vault.legal_holds.lift_and_erase`'s answer: the customer holds lifted or
/// narrowed to what is left, and each named record's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldLiftAndErased {
    pub holds: Vec<EntityId>,
    pub records: Vec<LegalHoldErasedRecord>,
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
/// erase?" confirm over `input.records`. The engine takes the owner's proof
/// and the records, and no other token.
pub fn lift_legal_hold_and_erase_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LegalHoldLiftAndEraseRequest,
) -> MemoryResult<LegalHoldLiftAndErased> {
    Ok(vault
        .confirm_lift_legal_hold_and_erase(owner, &input.records)?
        .into())
}
