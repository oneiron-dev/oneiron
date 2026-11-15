//! Moved from `crates/oneiron/src/skill_hub/refinement_custody.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_hub::claim_refinement::ClaimRefinementMergeReceipt;
use crate::skill_hub::shared_gate::SharedSkillMergeReceipt;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub(crate) use oneiron_store::refinement_carrier::refinement_carrier_payload;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "receipt",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RefinementReceipt {
    Skill(SharedSkillMergeReceipt),
    Claim(ClaimRefinementMergeReceipt),
}

impl RefinementReceipt {
    fn identity(&self) -> Result<(EntityId, EntityId)> {
        let (candidate, ruling) = match self {
            Self::Skill(row) => (&row.delta.candidate, &row.receipt_id),
            Self::Claim(row) => (&row.candidate, &row.receipt_id),
        };
        Ok((EntityId::from_hex(candidate)?, EntityId::from_hex(ruling)?))
    }
}
