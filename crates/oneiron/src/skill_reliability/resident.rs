//! Per-resident version bandit over independently attributed fork receipts.

use crate::Vault;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::Estimate;
use crate::learning::ranking::rank_by_estimate;
use crate::skill::{SkillLifecycle, resident_of};

use super::posterior::SELECTION_EXPLORATION;
use super::{SkillReliabilityQuery, read_skill_reliability};

/// Rank active versions owned by ONE resident. Every candidate must be from
/// the same skill family; a foreign/unowned candidate is a refusal rather
/// than an arm whose foreign outcomes silently influence the ranking.
/// Scores use the shared ranking over each version's estimate. Ties break
/// by entity id for replay-stable selection.
pub fn rank_resident_skill_versions(
    vault: &Vault,
    resident: &EntityId,
    versions: &[EntityId],
    executor_model: &str,
    query: &SkillReliabilityQuery,
) -> Result<Vec<(EntityId, f32)>> {
    let mut family = None;
    let mut seen = std::collections::HashSet::new();
    let mut arms: Vec<(EntityId, Estimate)> = Vec::new();
    for skill in versions {
        if !seen.insert(*skill) {
            return Err(Error::InvalidConfig(
                "duplicate resident skill version".into(),
            ));
        }
        let record = vault
            .get_skill_record(skill)?
            .ok_or(Error::EntityNotFound)?;
        if record.lifecycle_status != SkillLifecycle::Active
            || !matches!(
                record.approval_status,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            || resident_of(&record)? != Some(*resident)
            || family.as_ref().is_some_and(|name| name != &record.skill_id)
        {
            return Err(Error::InvalidConfig(
                "version is not an active fork of this resident and family".into(),
            ));
        }
        family = Some(record.skill_id);
        let estimate = read_skill_reliability(vault, skill, executor_model, query)?.estimate;
        arms.push((*skill, estimate));
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "shared f64 ranking scores narrow to the f32 the signature keeps"
    )]
    let ranked: Vec<(EntityId, f32)> =
        rank_by_estimate(arms, SELECTION_EXPLORATION, |arm| &arm.1, |arm| arm.0)
            .into_iter()
            .map(|((id, _), score)| (id, score as f32))
            .collect();
    Ok(ranked)
}
