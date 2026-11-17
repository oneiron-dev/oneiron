//! Moved from `crates/oneiron/src/verbs/coreference.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The link whose owner confirms or removes it. Endpoint order is immaterial.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoreferencePairRequest {
    pub local_person: EntityId,
    pub other_person: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreferenceShareConsentReceipt {
    pub local_person: EntityId,
    pub other_person: EntityId,
    pub pact: String,
    pub consent_claim: EntityId,
}

/// Only link metadata is retracted. Neither person's original claims change.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreferenceUnlinkReceipt {
    pub local_person: EntityId,
    pub other_person: EntityId,
    pub unlinked: bool,
    pub retracted_claims: Vec<EntityId>,
    pub original_claims_retained: bool,
}
