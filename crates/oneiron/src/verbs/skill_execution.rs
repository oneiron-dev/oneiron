//! Typed owner observations and reads over the existing pack attribution projector.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::learning::Anchor;
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use crate::receipt::{PackAttributionFields, ReceiptRecord};
use crate::skill_attribution::{AnchoredPackOutcome, LateCreditReceipt};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPackReceiptRequest {
    pub attempt_receipt: String,
}

/// The frozen loaded versions and actual-use evidence, not a transport receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillPackReceipt {
    pub receipt: ReceiptRecord,
    pub loaded_skills: Vec<String>,
    pub attribution: PackAttributionFields,
}

/// An owner's external verdict. Neither the executor nor the judge, actor,
/// loaded versions or contribution checks can be supplied by this request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPackOutcomeRequest {
    pub attempt_receipt: String,
    pub outcome_receipt: String,
    pub succeeded: bool,
    pub axis: String,
    pub at: u64,
    #[serde(default)]
    pub goal_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillPackCreditRequest {
    pub receipt_id: String,
}

pub fn skill_pack_receipt_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillPackReceiptRequest,
) -> MemoryResult<SkillPackReceipt> {
    owner.revalidate(vault)?;
    let receipt = crate::receipt::attempt_pack_receipt(vault, &input.attempt_receipt)?
        .ok_or_else(|| MemoryError::new(MEMORY_CODE_NOT_FOUND, "no stamped pack receipt", &[]))?;
    let loaded_skills = receipt.pack_manifest_skills().unwrap_or_default();
    let attribution = receipt.pack_attribution_fields()?;
    Ok(SkillPackReceipt {
        receipt,
        loaded_skills,
        attribution,
    })
}

/// `persisted` is false while attribution facts are unavailable. The caller
/// must wait for attribution and project the same observation again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillPackOutcomeProjection {
    pub receipt: LateCreditReceipt,
    pub persisted: bool,
}

pub fn skill_pack_outcome_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillPackOutcomeRequest,
) -> MemoryResult<SkillPackOutcomeProjection> {
    let receipt = crate::skill_attribution::project_anchored_pack_outcome_as_owner(
        vault,
        owner,
        &input.attempt_receipt,
        &AnchoredPackOutcome {
            receipt: input.outcome_receipt.clone(),
            anchor: Anchor::OwnerVerdict,
            succeeded: input.succeeded,
            axis: input.axis.clone(),
            at: input.at,
            goal_revision: input.goal_revision.clone(),
        },
        crate::unix_seconds_now(),
    )?;
    let persisted =
        crate::skill_attribution::late_credit_receipt(vault, &receipt.receipt_id)?.is_some();
    Ok(SkillPackOutcomeProjection { receipt, persisted })
}

pub fn skill_pack_credit_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillPackCreditRequest,
) -> MemoryResult<Option<LateCreditReceipt>> {
    owner.revalidate(vault)?;
    Ok(crate::skill_attribution::late_credit_receipt(
        vault,
        &input.receipt_id,
    )?)
}
