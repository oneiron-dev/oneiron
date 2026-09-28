//! Reading reliability truth back: the resolved posterior, the selection score, and the confidence-cache rebuild.

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::skill::SkillRecord;
use crate::temporal::TimeRange;

use super::codec::{invalid, map_entry};
use super::posterior::SkillReliabilityPosterior;
use super::projector::PREDICATE_SKILL_RELIABILITY;
use super::provenance::{skill_reliability_prior, skill_reliability_prior_in_txn};
use rmpv::Value;

/// Reads the legacy unknown-executor arm, or `None` when it has never been
/// projected. Named-model selection must use [`skill_reliability_posterior_for_executor`].
pub fn skill_reliability_posterior(
    vault: &Vault,
    skill: &EntityId,
) -> Result<Option<SkillReliabilityPosterior>> {
    let rtxn = vault.store.env.read_txn()?;
    resolved_reliability_posterior_in_txn(vault, &rtxn, skill, None)
}

/// Reads a named (skill, executor model@revision) pair. A new model has no
/// projected claim even when another model has many runs.
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

pub(super) fn claim_executor(body: &ClaimBody) -> Option<&str> {
    map_entry(&body.value, "executor").and_then(Value::as_str)
}

/// The posterior the active heads settle on: the richest one.
///
/// A fork is transient — the next projection supersedes every head — but a read
/// that lands mid-fork must not answer with whichever row the edge index
/// happened to yield first.
pub(super) fn resolved_reliability_posterior_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<Option<SkillReliabilityPosterior>> {
    let mut resolved: Option<SkillReliabilityPosterior> = None;
    for (_, body, _) in active_reliability_heads_in_txn(vault, rtxn, skill, executor)? {
        let candidate = SkillReliabilityPosterior::from_value(&body.value)?;
        if resolved.is_none_or(|held| candidate.observations() > held.observations()) {
            resolved = Some(candidate);
        }
    }
    Ok(resolved)
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
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
    Ok(
        active_claims_in_txn(vault, rtxn, skill, PREDICATE_SKILL_RELIABILITY)?
            .into_iter()
            .filter(|(_, body, _)| {
                body.source == Some(crate::claim::ClaimSource::Observed)
                    && body.approval == crate::claim::ClaimApprovalStatus::Auto
                    && claim_executor(body) == executor
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Cache rebuild (CID-7 demotion door)
// ---------------------------------------------------------------------------

/// Rebuilds the record's `confidence` CACHE from the reliability claim and
/// returns the value written.
///
/// The REPAIR law in one call (doc 13 §3, CID-7's shape): clobber or drop the
/// record field, run this, get the claim's posterior mean back. Claims are
/// truth — this reads them and never writes them, which is the direction proof.
/// A skill with no reliability claim rebuilds to its provenance prior's mean,
/// so the cache is defined before the first attributed outcome too.
///
/// A SUPERSEDED revision is frozen history and keeps the cache it was frozen
/// with (see `Vault::refresh_skill_confidence_cache_in_txn`); the value returned
/// is still the claim's, so a caller reading it reads truth either way.
pub fn rebuild_skill_confidence_cache(vault: &Vault, skill: &EntityId, at: u64) -> Result<f32> {
    let prior = skill_reliability_prior(vault, skill)?;
    vault.with_write_txn(|wtxn| {
        let posterior =
            resolved_reliability_posterior_in_txn(vault, wtxn, skill, None)?.unwrap_or(prior);
        let mean = posterior.mean();
        vault.refresh_skill_confidence_cache_in_txn(
            wtxn,
            skill,
            mean,
            TimeRange { start: at, end: at },
            at,
        )?;
        Ok(mean)
    })
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// The legacy unknown-executor arm's score: posterior mean plus the exploration bonus
/// ([`SkillReliabilityPosterior::ucb`]).
///
/// Reads the CLAIM, never the record's cache field — a stale or clobbered cache
/// must never be able to change which skills load. A skill with no claim scores
/// off its provenance prior.
///
/// `total_pulls` is the observation total across the candidate set the caller is
/// ranking (sum of [`SkillReliabilityPosterior::observations`]); it is an
/// argument rather than a hidden scan so ranking N skills costs N reads, not N².
pub fn skill_selection_score(vault: &Vault, skill: &EntityId, total_pulls: u32) -> Result<f32> {
    let rtxn = vault.store.env.read_txn()?;
    skill_selection_score_in_txn(vault, &rtxn, skill, total_pulls)
}

/// Same score as the public door, on the retrieval candidate's read snapshot.
fn skill_selection_score_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    total_pulls: u32,
) -> Result<f32> {
    Ok(skill_selection_score_from_posterior(
        selection_posterior_in_txn(vault, rtxn, skill, None)?,
        total_pulls,
    ))
}

/// The shared score computation after a candidate set has fixed its pull horizon.
/// Lets retrieval reuse the posterior it already resolved for that horizon.
pub(crate) fn skill_selection_score_from_posterior(
    posterior: SkillReliabilityPosterior,
    total_pulls: u32,
) -> f32 {
    posterior.ucb(total_pulls)
}

pub(crate) fn selection_posterior_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
) -> Result<SkillReliabilityPosterior> {
    match resolved_reliability_posterior_in_txn(vault, rtxn, skill, executor)? {
        Some(posterior) => Ok(posterior),
        None => skill_reliability_prior_in_txn(vault, rtxn, skill),
    }
}

/// Pair-specific UCB ranking, seeded from provenance until measured. Never
/// borrows another executor's claim or the skill-wide confidence cache.
pub fn skill_selection_score_for_executor(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
    total_pulls: u32,
) -> Result<f32> {
    let posterior = skill_reliability_posterior_for_executor(vault, skill, executor)?
        .unwrap_or(skill_reliability_prior(vault, skill)?);
    Ok(posterior.ucb(total_pulls))
}

/// Read-ready metadata for the faint "new model, n runs" presentation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExecutorReliability {
    pub posterior: SkillReliabilityPosterior,
    pub runs: u32,
    pub new_model: bool,
}

pub fn skill_executor_reliability(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
) -> Result<ExecutorReliability> {
    let prior = skill_reliability_prior(vault, skill)?;
    let posterior =
        skill_reliability_posterior_for_executor(vault, skill, executor)?.unwrap_or(prior);
    let runs = super::projector::attributed_outcomes(prior, posterior);
    Ok(ExecutorReliability {
        posterior,
        runs,
        new_model: runs == 0,
    })
}

pub(super) fn read_skill(vault: &Vault, skill: &EntityId) -> Result<SkillRecord> {
    vault
        .get_skill_record(skill)?
        .ok_or(invalid("skill reliability names an unknown skill"))
}
