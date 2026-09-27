//! Store-backed mechanical inputs for the consolidation executor.
use super::conflict::{
    SwarmChildReturn, SwarmEvidenceRef, VerifiedSwarmEvidence, candidate_facts,
    collapse_sibling_evidence, evidence_trust_meet,
};
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
    pub(super) retry_at_ms: u64,
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
    let mut candidates = attach_duplicate_evidence(candidates, rules)?;
    // The returned ids are citations, not evidence facts. Hydrate ALL sibling
    // citations at one actor-scoped ledger revision before selection counts
    // independent signals or the write can inherit a trust class.
    let children: Vec<_> = candidates
        .iter()
        .map(|candidate| SwarmChildReturn {
            evidence: candidate
                .evidence_turn_refs
                .iter()
                .copied()
                .map(SwarmEvidenceRef::whole_turn)
                .collect(),
            candidates: Vec::new(),
        })
        .collect();
    let collapsed = collapse_sibling_evidence(resources, &children)?;
    let verified: BTreeMap<_, _> = collapsed
        .independent
        .iter()
        .map(|entry| (entry.source_id, *entry))
        .collect();
    for candidate in &mut candidates {
        candidate.evidence_turn_refs.sort_unstable();
        candidate.evidence_turn_refs.dedup();
        candidate.evidence_meet = super::provenance::source_meet(
            candidate.evidence_meet,
            evidence_trust_meet(
                candidate
                    .evidence_turn_refs
                    .iter()
                    .filter_map(|id| verified.get(id)),
            ),
        );
    }
    let mut inputs = Vec::new();
    let mut embeddings = BTreeMap::new();
    for candidate in &candidates {
        let (fan_in, new_refs, vector) =
            resources.candidate_signals(resources.scope(), candidate)?;
        inputs.push(selection_input(
            resources, candidate, &verified, now, &config, fan_in, new_refs,
        )?);
        if let Some(vector) = vector {
            embeddings.insert(candidate.claim_id, vector);
        }
    }
    let plan = select_candidates(&inputs, now, &config)?;
    let retry_at_ms = plan
        .held
        .iter()
        .filter_map(|(id, hold)| {
            inputs
                .iter()
                .find(|input| input.claim_id == *id)
                .map(|input| match hold {
                    super::selection::SelectionHold::Soak => {
                        input.first_seen_ms.saturating_add(config.soak_ms)
                    }
                    super::selection::SelectionHold::EvidenceCount => now.saturating_add(60_000),
                })
        })
        .min()
        .unwrap_or(now)
        .max(now.saturating_add(1));
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
        retry_at_ms,
    })
}

fn selection_input(
    resources: &BranchResources<'_>,
    candidate: &PromotionCandidate,
    verified: &BTreeMap<EntityId, VerifiedSwarmEvidence>,
    now: u64,
    config: &SelectionConfig,
    fan_in: u64,
    new_refs: u64,
) -> Result<SelectionCandidate> {
    let facts = candidate_facts(&candidate.candidate)?;
    let mut seen = BTreeSet::new();
    let mut earliest = None;
    let mut latest = 0;
    let mut count = 0;
    let mut sessions = BTreeSet::new();
    for &id in &candidate.evidence_turn_refs {
        let entry = verified
            .get(&id)
            .ok_or_else(|| super::support::invalid_consolidation("unverified evidence signal"))?;
        if !seen.insert((entry.source_id, entry.content_hash)) {
            continue;
        }
        let learned_at = resources
            .evidence_time(resources.scope(), &id)?
            .saturating_mul(1_000);
        earliest = Some(earliest.map_or(learned_at, |at: u64| at.min(learned_at)));
        latest = latest.max(learned_at);
        count += 1;
        // A partition has one conversation, but its evidence can come from
        // distinct speakers. Count those store-backed sources, not the partition.
        if let Some(speaker) = resources.turn(resources.scope(), &id)?.speaker {
            sessions.insert(speaker.trim().to_lowercase());
        }
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
