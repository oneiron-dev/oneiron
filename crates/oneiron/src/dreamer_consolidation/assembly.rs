//! Store-backed mechanical inputs for the consolidation executor.
use super::conflict::candidate_facts;
use super::resources::BranchResources;
use super::routing::{attach_duplicate_evidence, judge_queue};
use super::selection::{SelectionCandidate, SelectionConfig, StrengthSignals, select_candidates};
use super::{ConflictSet, PromotionCandidate};
use crate::{EntityId, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct AssembledCandidates {
    pub(super) candidates: Vec<PromotionCandidate>,
    pub(super) conflicts: Vec<ConflictSet>,
    pub(super) held: bool,
}

pub(super) fn assemble(
    vault: &Vault,
    resources: &BranchResources<'_>,
    candidates: Vec<PromotionCandidate>,
    now: u64,
) -> Result<AssembledCandidates> {
    resources.validate_candidates(resources.scope(), &candidates)?;
    let config = vault.consolidation_selection()?;
    let rules = resources.key_rules();
    let candidates = attach_duplicate_evidence(candidates, rules)?;
    let mut inputs = Vec::new();
    let mut embeddings = BTreeMap::new();
    for candidate in &candidates {
        let (fan_in, new_refs, vector) =
            resources.candidate_signals(resources.scope(), candidate)?;
        inputs.push(selection_input(
            resources, candidate, now, &config, fan_in, new_refs,
        )?);
        if let Some(vector) = vector {
            embeddings.insert(candidate.claim_id, vector);
        }
    }
    let plan = select_candidates(&inputs, now, &config)?;
    let mut by_id: BTreeMap<EntityId, PromotionCandidate> =
        candidates.into_iter().map(|c| (c.claim_id, c)).collect();
    let ready: Vec<_> = plan
        .ready
        .iter()
        .filter_map(|id| by_id.remove(id))
        .collect();
    let conflicts = judge_queue(&ready, &embeddings, rules, config.cosine_threshold)?;
    let conflicts = resources.route_priors(&ready, conflicts, rules)?;
    Ok(AssembledCandidates {
        candidates: ready,
        conflicts,
        held: !plan.held.is_empty(),
    })
}

fn selection_input(
    resources: &BranchResources<'_>,
    candidate: &PromotionCandidate,
    now: u64,
    config: &SelectionConfig,
    fan_in: u64,
    new_refs: u64,
) -> Result<SelectionCandidate> {
    let facts = candidate_facts(&candidate.candidate)?;
    let refs: BTreeSet<_> = candidate.evidence_turn_refs.iter().copied().collect();
    let mut earliest = None;
    let mut latest = 0;
    let mut count = 0;
    let mut sessions = BTreeSet::new();
    for id in refs {
        let learned_at = resources.evidence_time(resources.scope(), &id)?;
        earliest = Some(earliest.map_or(learned_at, |at: u64| at.min(learned_at)));
        latest = latest.max(learned_at);
        count += 1;
        sessions.insert(resources.conversation());
    }
    let signals = StrengthSignals {
        type_prior: config
            .type_priors
            .get(&facts.predicate)
            .copied()
            .unwrap_or(config.default_type_prior),
        frequency: (count as f64 / config.frequency_scale as f64).min(1.0),
        recency: 1.0
            - (now.saturating_sub(latest) as f64 / config.recency_window_ms as f64).min(1.0),
        diversity: (sessions.len() as f64 / config.diversity_scale as f64).min(1.0),
    };
    Ok(SelectionCandidate {
        claim_id: candidate.claim_id,
        first_seen_ms: earliest.unwrap_or(candidate.learned_at),
        evidence_count: count,
        fan_in,
        new_refs,
        signals,
    })
}
