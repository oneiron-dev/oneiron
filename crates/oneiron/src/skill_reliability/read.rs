//! Reading reliability truth back: the resolved posterior, the selection score, and the confidence-cache rebuild.

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::SkillRecord;
use crate::temporal::TimeRange;

use super::codec::invalid;
use super::posterior::SkillReliabilityPosterior;
use super::projector::PREDICATE_SKILL_RELIABILITY;
use super::provenance::skill_reliability_prior;

/// Reads the active `skill.reliability` posterior, or `None` when the skill has
/// never been projected.
pub fn skill_reliability_posterior(
    vault: &Vault,
    skill: &EntityId,
) -> Result<Option<SkillReliabilityPosterior>> {
    let rtxn = vault.store.env.read_txn()?;
    resolved_reliability_posterior_in_txn(vault, &rtxn, skill)
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
) -> Result<Option<SkillReliabilityPosterior>> {
    let mut resolved: Option<SkillReliabilityPosterior> = None;
    for (_, body, _) in active_reliability_heads_in_txn(vault, rtxn, skill)? {
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
            .entities
            .get(rtxn, id.as_bytes())?
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
) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
    active_claims_in_txn(vault, rtxn, skill, PREDICATE_SKILL_RELIABILITY)
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
        let posterior = resolved_reliability_posterior_in_txn(vault, wtxn, skill)?.unwrap_or(prior);
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

/// The skill's selection score: posterior mean plus the exploration bonus
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
    let posterior = match skill_reliability_posterior(vault, skill)? {
        Some(posterior) => posterior,
        None => skill_reliability_prior(vault, skill)?,
    };
    Ok(posterior.ucb(total_pulls))
}

pub(super) fn read_skill(vault: &Vault, skill: &EntityId) -> Result<SkillRecord> {
    vault
        .get_skill_record(skill)?
        .ok_or(invalid("skill reliability names an unknown skill"))
}
