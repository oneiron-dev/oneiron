//! The inputs and answers of the owner's legal-hold rows (OF-470):
//! `vault.legal_holds.place`, `.widen`, `.list`, `.log`, `.lift`, `.produce`,
//! `.lift_and_erase` and `.withdraw_erase`, each a host door. Each fn passes
//! the engine exactly what it asks for, under the vault owner's proof: a
//! server mints it from the request, as `/v1/owner` does; an embedded handle
//! acts as the vault's embedded owner. Oneiron's host-order doors have no row
//! here, since no owner, member or agent surface may route to them.
use base64::Engine as _;
use oneiron_crypto::HybridPublicKey;
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    LegalHold, LegalHoldEvent, LegalHoldProduction, LiftAndEraseOutcome, LiftAndEraseShownState,
    LiftAndEraseStatus,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::legal_hold::{
    LegalHoldEraseState, LegalHoldErasedRecord, LegalHoldErasesWithdrawn, LegalHoldPlaceRequest,
    LegalHoldWidenRequest, LegalHoldWithdrawEraseRequest, LegalHoldWithdrawnErase,
};

/// `vault.legal_holds.lift`'s input: the owner's customer hold to lift. The
/// lift destroys its sealed copy; nothing in the vault is erased by it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldLiftRequest {
    pub hold_id: EntityId,
}

/// `vault.legal_holds.produce`'s input: the standing customer hold to
/// re-seal, and the recipient public key the owner names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldProduceRequest {
    pub hold_id: EntityId,
    /// The recipient's `HybridPublicKey::to_bytes`, as STANDARD base64.
    pub recipient_public_key: String,
}

/// One produced capture: its sealed frames, as STANDARD base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldProducedCapture {
    pub capture: EntityId,
    /// The capture's fingerprint, as 64 hex.
    pub fingerprint: String,
    /// The capture file's bytes.
    pub frames: String,
}

/// `vault.legal_holds.produce`'s answer: the hold's seed sealed to the named
/// recipient, and each capture's sealed frames byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldProduced {
    pub hold_id: EntityId,
    pub production_id: EntityId,
    /// The blake3 of the recipient public key's bytes, as 64 hex.
    pub recipient_fingerprint: String,
    /// The hold's seed sealed to the recipient, as STANDARD base64.
    pub sealed_hold_key: String,
    /// The hold's captures, oldest first.
    pub captures: Vec<LegalHoldProducedCapture>,
}

impl From<LegalHoldProduction> for LegalHoldProduced {
    fn from(production: LegalHoldProduction) -> Self {
        Self {
            hold_id: production.hold_id,
            production_id: production.production_id,
            recipient_fingerprint: bytes_to_hex_lower(&production.recipient_fingerprint),
            sealed_hold_key: base64::engine::general_purpose::STANDARD
                .encode(&production.sealed_hold_key),
            captures: production
                .captures
                .into_iter()
                .map(|capture| LegalHoldProducedCapture {
                    capture: capture.capture,
                    fingerprint: bytes_to_hex_lower(&capture.fingerprint),
                    frames: base64::engine::general_purpose::STANDARD.encode(&capture.frames),
                })
                .collect(),
        }
    }
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

/// `vault.legal_holds.lift`: lifts the owner's customer hold and destroys
/// its sealed copy. Nothing in the vault is erased by it.
pub fn lift_legal_hold_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LegalHoldLiftRequest,
) -> MemoryResult<LegalHold> {
    Ok(vault.lift_legal_hold(owner, input.hold_id)?)
}

/// `vault.legal_holds.produce`: re-seals the standing customer hold's sealed
/// copy to the recipient public key the owner names, and logs the access. A
/// key that does not decode or parse is the caller's error.
pub fn produce_legal_hold_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LegalHoldProduceRequest,
) -> MemoryResult<LegalHoldProduced> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(input.recipient_public_key.as_bytes())
        .map_err(|_| MemoryError::bad_request("recipient_public_key must be standard base64"))?;
    let recipient = HybridPublicKey::from_bytes(&decoded).map_err(|_| {
        MemoryError::bad_request("recipient_public_key is not a recipient public key")
    })?;
    Ok(vault
        .produce_legal_hold(owner, input.hold_id, &recipient)?
        .into())
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
