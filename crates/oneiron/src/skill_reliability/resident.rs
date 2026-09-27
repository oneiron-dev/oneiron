//! Per-resident version bandit over independently attributed fork receipts.

use crate::Vault;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::{SkillLifecycle, resident_of};

use super::{
    SkillReliabilityPosterior, skill_reliability_posterior_for_executor, skill_reliability_prior,
};

/// Rank active versions owned by ONE resident. Every candidate must be from
/// the same skill family; a foreign/unowned candidate is a refusal rather
/// than an arm whose foreign outcomes silently influence the ranking.
/// Scores use each version's own posterior and the shared UCB exploration
/// horizon. Ties break by entity id for replay-stable selection.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "positive, bounded posterior pull counts feed the UCB horizon as u32"
)]
pub fn rank_resident_skill_versions(
    vault: &Vault,
    resident: &EntityId,
    versions: &[EntityId],
    executor_model: &str,
) -> Result<Vec<(EntityId, f32)>> {
    let mut family = None;
    let mut seen = std::collections::HashSet::new();
    let mut arms: Vec<(EntityId, SkillReliabilityPosterior)> = Vec::new();
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
        let posterior = skill_reliability_posterior_for_executor(vault, skill, executor_model)?
            .unwrap_or(skill_reliability_prior(vault, skill)?);
        arms.push((*skill, posterior));
    }
    let total = arms.iter().fold(0_u32, |count, (_, posterior)| {
        count.saturating_add(posterior.observations().max(0.0) as u32)
    });
    let mut ranked: Vec<_> = arms
        .into_iter()
        .map(|(id, posterior)| (id, posterior.ucb(total)))
        .collect();
    ranked.sort_by(|(a_id, a), (b_id, b)| {
        b.total_cmp(a)
            .then_with(|| a_id.as_bytes().cmp(b_id.as_bytes()))
    });
    Ok(ranked)
}
