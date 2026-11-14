//! The inputs and answers of the owner's legal-hold rows (OF-470):
//! `vault.legal_holds.place`, `.widen`, `.list`, `.log`, `.lift` and `.produce`,
//! each a host door. Each fn passes
//! the engine exactly what it asks for, under the vault owner's proof: a
//! server mints it from the request, as `/v1/owner` does; an embedded handle
//! acts as the vault's embedded owner. Oneiron's host-order doors have no row
//! here, since no owner, member or agent surface may route to them.
use base64::Engine as _;
use oneiron_crypto::HybridPublicKey;
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    LegalHold, LegalHoldEvent, LegalHoldFutureMessages, LegalHoldProduction, LegalHoldTarget,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Vault};

/// `vault.legal_holds.place`'s input: what the owner's customer hold names,
/// an optional opaque matter reference, and the future messages it names.
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
    /// The future messages the hold names: each matching new MESSAGE joins
    /// its copy until `until` or the lift (Ruling
    /// L10-21-OWNER-FUTURE-MESSAGES = A, ARCH-0038 :321). None captures
    /// nothing new.
    #[serde(default)]
    pub future_messages: Option<LegalHoldFutureMessages>,
}

/// `vault.legal_holds.widen`'s input: more targets for one of the owner's
/// standing customer holds. A hold never narrows; `lift` ends it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldWidenRequest {
    pub hold_id: EntityId,
    /// As [`LegalHoldPlaceRequest::targets`].
    pub targets: Vec<LegalHoldTarget>,
}

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

/// `vault.legal_holds.place`: the owner's customer hold on `targets`.
pub fn place_legal_hold_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LegalHoldPlaceRequest,
) -> MemoryResult<LegalHold> {
    Ok(vault.place_legal_hold(
        owner,
        input.targets,
        input.matter_ref,
        input.future_messages,
    )?)
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
