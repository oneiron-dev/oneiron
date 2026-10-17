//! Skill reliability reads use learning cells, never SkillRecord confidence.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{ConsolidationReader, claim_consolidation_eligible_in_txn};
use crate::learning::project::StoredEstimateClaim;
use crate::learning::{
    Estimate, EstimateValue, LearningCell, LearningPredicate, LearningRead, PriorOrigin, TypeRef,
};
use crate::ports::EntityStoreRead;
use crate::skill::SkillRecord;
use crate::temporal::TimeRange;

use super::codec::invalid;
use super::posterior::SkillReliabilityPosterior;
use super::priors::read_cell_in_txn;
use super::projector::PREDICATE_SKILL_RELIABILITY;
use super::provenance::{skill_reliability_prior, skill_reliability_prior_in_txn};

/// The task placement and axis the caller will execute. The judge is not a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillReliabilityQuery {
    pub type_ref: TypeRef,
    pub axis: String,
    /// The type tree's parent chain, nearest parent first.
    pub type_parents: Vec<TypeRef>,
}

impl SkillReliabilityQuery {
    pub fn validate(&self) -> Result<()> {
        self.type_ref.validate()?;
        if self.axis.is_empty() || self.axis.len() > 256 || self.axis.chars().any(char::is_control)
        {
            return Err(invalid("invalid skill reliability axis"));
        }
        for parent in &self.type_parents {
            parent.validate()?;
            if parent.tree_version != self.type_ref.tree_version {
                return Err(invalid(
                    "skill type parents must use the placement's tree version",
                ));
            }
        }
        Ok(())
    }

    /// The query for `type_ref` on `tree`, its parents read off that tree;
    /// `axis` omitted reads the skill-outcome axis. `None` when `tree` does
    /// not hold `type_ref` at its version. Pure: the caller loads the tree.
    pub fn on_tree(
        tree: &crate::task_type::TypeTree,
        type_ref: TypeRef,
        axis: Option<String>,
    ) -> Result<Option<Self>> {
        if !tree.contains(&type_ref) {
            return Ok(None);
        }
        let query = Self {
            type_parents: tree.ancestors(&type_ref),
            type_ref,
            axis: axis.unwrap_or_else(|| super::SKILL_OUTCOME_AXIS.to_owned()),
        };
        query.validate()?;
        Ok(Some(query))
    }

    pub(super) fn cell(&self, skill: EntityId, executor: &str) -> Result<LearningCell> {
        self.validate()?;
        validate_executor(executor)?;
        let cell = LearningCell::new(LearningPredicate::Reliability, skill)
            .executor(executor)
            .type_ref(self.type_ref.clone())
            .axis(self.axis.clone());
        cell.validate()?;
        Ok(cell)
    }
}

/// Full metadata, including fractional own runs, prior origin and UNTESTED.
pub fn read_skill_reliability(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
    query: &SkillReliabilityQuery,
) -> Result<LearningRead> {
    let txn = vault.store.env.read_txn()?;
    let cell = query.cell(*skill, executor)?;
    read_cell_in_txn(vault, &txn, &cell, &query.type_parents)
}

/// Diagnostic unqualified read: the richest cell, never a pooled posterior.
/// Selection for a task uses read_skill_reliability instead.
pub fn skill_reliability_posterior(
    vault: &Vault,
    skill: &EntityId,
) -> Result<Option<SkillReliabilityPosterior>> {
    let txn = vault.store.env.read_txn()?;
    resolved_reliability_posterior_in_txn(vault, &txn, skill, None)
}

/// Diagnostic executor read. Different task types and axes never add together.
pub fn skill_reliability_posterior_for_executor(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
) -> Result<Option<SkillReliabilityPosterior>> {
    validate_executor(executor)?;
    let txn = vault.store.env.read_txn()?;
    resolved_reliability_posterior_in_txn(vault, &txn, skill, Some(executor))
}

pub(crate) fn validate_executor(executor: &str) -> Result<()> {
    if executor.len() > 256
        || executor.chars().any(char::is_control)
        || !executor
            .rsplit_once('@')
            .is_some_and(|(id, revision)| !id.is_empty() && !revision.is_empty())
    {
        return Err(invalid("invalid skill reliability executor"));
    }
    Ok(())
}

pub(super) fn posterior_from_estimate(estimate: &Estimate) -> Result<SkillReliabilityPosterior> {
    let EstimateValue::Beta { alpha, beta } = &estimate.value else {
        return Err(invalid("skill reliability requires a Beta estimate"));
    };
    #[allow(clippy::cast_possible_truncation)]
    let posterior = SkillReliabilityPosterior {
        alpha: *alpha as f32,
        beta: *beta as f32,
    };
    if !posterior.alpha.is_finite()
        || !posterior.beta.is_finite()
        || posterior.alpha <= 0.0
        || posterior.beta <= 0.0
    {
        return Err(invalid(
            "skill reliability Beta parameters are finite and positive",
        ));
    }
    Ok(posterior)
}

pub(super) fn resolved_estimate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<Option<Estimate>> {
    let mut resolved: Option<Estimate> = None;
    for (id, body, _) in active_reliability_heads_in_txn(vault, txn, skill, executor)? {
        if !claim_consolidation_eligible_in_txn(
            &vault.store,
            txn,
            &id,
            ConsolidationReader::SkillReliabilityPosterior,
        )? {
            continue;
        }
        let estimate = StoredEstimateClaim::from_value(&body.value)?.estimate;
        if estimate.ver != crate::learning::ESTIMATOR_VERSION {
            continue;
        }
        if resolved
            .as_ref()
            .is_none_or(|held| estimate.runs > held.runs)
        {
            resolved = Some(estimate);
        }
    }
    Ok(resolved)
}

pub(super) fn resolved_reliability_posterior_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<Option<SkillReliabilityPosterior>> {
    resolved_estimate_in_txn(vault, txn, skill, executor)?
        .as_ref()
        .map(posterior_from_estimate)
        .transpose()
}

/// EVERY active claim for `predicate` on `skill`, with the `occurred_start` a
/// supersession has to clamp against.
pub(super) fn active_claims_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    predicate: &str,
) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(rtxn, skill)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate != predicate || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let raw = vault
            .store
            .port_entity_record(rtxn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::CorruptedIndex("claim_of edge"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        rows.push((id, body, header.occurred_start));
    }
    Ok(rows)
}

pub(super) fn active_reliability_heads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
    Ok(
        active_claims_in_txn(vault, txn, skill, PREDICATE_SKILL_RELIABILITY)?
            .into_iter()
            .filter(|(_, body, _)| {
                body.source == Some(crate::claim::ClaimSource::Observed)
                    && body.approval == crate::claim::ClaimApprovalStatus::Auto
                    && StoredEstimateClaim::from_value(&body.value).is_ok_and(|stored| {
                        executor.is_none_or(|executor| {
                            stored.cell.executor.as_deref() == Some(executor)
                        })
                    })
            })
            .collect(),
    )
}

/// Rebuild the scalar diagnostic cache from the richest measured cell.
/// No selector reads this cache.
pub fn rebuild_skill_confidence_cache(vault: &Vault, skill: &EntityId, at: u64) -> Result<f32> {
    let prior = skill_reliability_prior(vault, skill)?;
    vault.with_write_txn_grouped(|txn| {
        let posterior =
            resolved_reliability_posterior_in_txn(vault, txn, skill, None)?.unwrap_or(prior);
        let mean = posterior.mean();
        vault.refresh_skill_confidence_cache_in_txn(
            txn,
            skill,
            mean,
            TimeRange { start: at, end: at },
            at,
        )?;
        Ok(mean)
    })
}

/// Untyped discovery has only a provenance prior. A task's measured history
/// requires the same placement and axis that will appear on its receipt.
pub fn skill_selection_score(vault: &Vault, skill: &EntityId, total_pulls: u32) -> Result<f32> {
    let txn = vault.store.env.read_txn()?;
    Ok(selection_posterior_in_txn(vault, &txn, skill, None)?.ucb(total_pulls))
}

pub(crate) fn skill_selection_score_from_posterior(
    posterior: SkillReliabilityPosterior,
    total_pulls: u32,
) -> f32 {
    posterior.ucb(total_pulls)
}

pub(crate) fn selection_posterior_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<SkillReliabilityPosterior> {
    if let Some(executor) = executor {
        validate_executor(executor)?;
    }
    skill_reliability_prior_in_txn(vault, txn, skill)
}

pub(crate) fn selection_posterior_for_query_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
    query: Option<&SkillReliabilityQuery>,
) -> Result<SkillReliabilityPosterior> {
    match (executor, query) {
        (Some(executor), Some(query)) => {
            let cell = query.cell(*skill, executor)?;
            posterior_from_estimate(
                &read_cell_in_txn(vault, txn, &cell, &query.type_parents)?.estimate,
            )
        }
        _ => selection_posterior_in_txn(vault, txn, skill, executor),
    }
}

/// Typed skill arms pick by UCB through the existing shared Posterior.
pub fn skill_selection_score_for_executor(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
    query: &SkillReliabilityQuery,
    total_pulls: u32,
) -> Result<f32> {
    let read = read_skill_reliability(vault, skill, executor, query)?;
    Ok(posterior_from_estimate(&read.estimate)?.ucb(total_pulls))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExecutorReliability {
    pub posterior: SkillReliabilityPosterior,
    pub runs: f64,
    pub new_model: bool,
    pub untested: bool,
    pub prior_origin: PriorOrigin,
    pub prior_weight_runs: f64,
}

/// This exact cell's own-run dominance and carried/provenance presentation.
pub fn skill_executor_reliability(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
    query: &SkillReliabilityQuery,
) -> Result<ExecutorReliability> {
    let estimate = read_skill_reliability(vault, skill, executor, query)?.estimate;
    Ok(ExecutorReliability {
        posterior: posterior_from_estimate(&estimate)?,
        runs: estimate.runs,
        new_model: estimate.runs == 0.0,
        untested: estimate.untested(),
        prior_origin: estimate.prior.origin,
        prior_weight_runs: estimate.prior.weight_runs,
    })
}

pub(super) fn read_skill(vault: &Vault, skill: &EntityId) -> Result<SkillRecord> {
    vault
        .get_skill_record(skill)?
        .ok_or(invalid("skill reliability names an unknown skill"))
}
