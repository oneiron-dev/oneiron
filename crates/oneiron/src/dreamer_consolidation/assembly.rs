//! Store-backed mechanical inputs for the consolidation executor.
use super::ConflictSet;
#[cfg(test)]
use super::PromotionCandidate;
use super::conflict::candidate_facts;
#[cfg(test)]
use super::evidence::EvidenceLocator;
use super::evidence::{ExtractedCandidate, VerifiedCandidate};
use super::resources::BranchResources;
use super::routing::{candidate_keys, judge_queue};
use super::selection::{SelectionCandidate, SelectionConfig, StrengthSignals, select_candidates};
use crate::{EntityId, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct AssembledCandidates {
    pub(super) candidates: Vec<VerifiedCandidate>,
    pub(super) conflicts: Vec<ConflictSet>,
    pub(super) held: bool,
    pub(super) retry_at_ms: u64,
}

#[cfg(test)]
pub(super) fn assemble(
    vault: &Vault,
    resources: &BranchResources<'_>,
    candidates: Vec<PromotionCandidate>,
    now: u64,
) -> Result<AssembledCandidates> {
    let raw = candidates
        .into_iter()
        .map(|candidate| {
            let refs = candidate
                .evidence_turn_refs
                .iter()
                .copied()
                .map(EvidenceLocator::whole_turn)
                .collect();
            ExtractedCandidate::new(candidate, refs)
        })
        .collect::<Result<Vec<_>>>()?;
    assemble_extracted(vault, resources, raw, now)
}

/// Raw judgements enter once, with typed refs. The parent verifies and owns
/// the evidence set BEFORE selecting or routing any candidate.
pub(super) fn assemble_extracted(
    vault: &Vault,
    resources: &BranchResources<'_>,
    candidates: Vec<ExtractedCandidate>,
    now: u64,
) -> Result<AssembledCandidates> {
    let config = vault.consolidation_selection()?;
    let rules = resources.key_rules();
    let mut grouped = BTreeMap::new();
    for extracted in candidates {
        let key = (
            candidate_keys(extracted.proposal(), rules)?,
            extracted.proposal().supersedes,
        );
        match grouped.entry(key) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(extracted);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let (incoming, refs) = extracted.into_parts();
                let (mut kept, mut old_refs) = slot.get().clone().into_parts();
                old_refs.extend(refs);
                kept.evidence_turn_refs.extend(incoming.evidence_turn_refs);
                kept.evidence_turn_refs.sort_unstable();
                kept.evidence_turn_refs.dedup();
                for hop in incoming.provenance_chain {
                    if !kept.provenance_chain.contains(&hop) {
                        kept.provenance_chain.push(hop);
                    }
                }
                kept.evidence_meet =
                    super::provenance::source_meet(kept.evidence_meet, incoming.evidence_meet);
                kept.learned_at = kept.learned_at.min(incoming.learned_at);
                *slot.get_mut() = ExtractedCandidate::new(kept, old_refs)?;
            }
        }
    }
    let candidates: Vec<VerifiedCandidate> = grouped
        .into_values()
        .map(|raw| VerifiedCandidate::from_extracted(resources, raw))
        .collect::<Result<_>>()?;
    for candidate in &candidates {
        resources
            .validate_candidates(resources.scope(), std::slice::from_ref(&candidate.proposal))?;
    }
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
    let mut by_id: BTreeMap<EntityId, VerifiedCandidate> =
        candidates.into_iter().map(|c| (c.claim_id, c)).collect();
    let ready: Vec<_> = plan
        .ready
        .iter()
        .filter_map(|id| by_id.remove(id))
        .collect();
    let ready_data: Vec<_> = ready.iter().map(|row| row.proposal.clone()).collect();
    let conflicts = judge_queue(&ready_data, &embeddings, rules, config.cosine_threshold)?;
    let conflicts = resources.route_priors(&ready_data, conflicts, rules)?;
    Ok(AssembledCandidates {
        candidates: ready,
        conflicts,
        held: !plan.held.is_empty(),
        retry_at_ms,
    })
}

fn selection_input(
    resources: &BranchResources<'_>,
    candidate: &VerifiedCandidate,
    now: u64,
    config: &SelectionConfig,
    fan_in: u64,
    new_refs: u64,
) -> Result<SelectionCandidate> {
    let facts = candidate_facts(&candidate.proposal.candidate)?;
    let mut earliest = None;
    let mut latest = 0;
    let mut sessions = BTreeSet::new();
    for (id, _hash, claim) in candidate.evidence.signal_sources() {
        let learned_at = resources
            .evidence_time(resources.scope(), &id)?
            .saturating_mul(1_000);
        earliest = Some(earliest.map_or(learned_at, |at: u64| at.min(learned_at)));
        latest = latest.max(learned_at);
        if claim {
            sessions.insert(id.to_hex());
        } else if let Some(speaker) = resources.turn(resources.scope(), &id)?.speaker {
            sessions.insert(speaker.trim().to_lowercase());
        }
    }
    let count = candidate.evidence.count();
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
