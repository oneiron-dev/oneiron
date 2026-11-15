//! Native candidate, admitted prior, replay cohort and stored-vector observations.

use super::tokens::observation_key_tokens;
use super::types::{
    CandidateObservation, ExtractionObservationsPageRequest, ObservationFacts, PriorObservation,
    ReplayObservation, SimilarityScore,
};
use crate::EntityId;
use crate::claim::{ClaimBody, ClaimSource, ScopedRead};
use crate::dreamer_consolidation::extraction_pack::BoundBranchRead;
use crate::dreamer_consolidation::routing::{candidate_keys, cosine};
use crate::dreamer_consolidation::{PromotionCandidate, candidate_probe_body};
use crate::dreamer_promotion::scope_with_taint;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::snapshot_read::{SourceVersion, source_version_in_txn};

/// Reads the complete fact set without selecting, grouping or routing any operand.
pub(super) fn extraction_observation_facts(
    memory: &Memory<'_>,
    (read, turn_read): (&ScopedRead<'_>, &ScopedRead<'_>),
    txn: &heed::RoTxn<'_>,
    bound: &BoundBranchRead,
    input: &ExtractionObservationsPageRequest,
    proposals: Vec<PromotionCandidate>,
) -> MemoryResult<ObservationFacts> {
    let vault = memory.vault();
    let mut facts = ObservationFacts {
        candidates: Vec::with_capacity(proposals.len()),
        priors: Vec::new(),
        replay: Vec::new(),
        scores: Vec::new(),
    };
    let mut scopes = Vec::with_capacity(proposals.len());
    let mut vectors = Vec::with_capacity(proposals.len());
    for (index, (operand, proposal)) in input.candidates.iter().zip(proposals).enumerate() {
        let candidate = bound.verify_observation_candidate_in_txn(
            memory,
            turn_read,
            txn,
            operand,
            &proposal,
            input.now_ms,
        )?;
        let selection = bound.selection_facts_in_txn(read, txn, &candidate)?;
        let (fan_in, new_refs, vector) = bound.candidate_signals_in_txn(read, txn, &candidate)?;
        let keys = candidate_keys(&candidate, bound.key_rules())?;
        let tokens = observation_key_tokens(&keys)?;
        let fresh = candidate_probe_body(&candidate.candidate)?;
        let named_facet = BoundBranchRead::observation_named_facet(fresh.scope.as_ref())
            .ok()
            .flatten();
        let replay_facet = match named_facet {
            Some(facet) => facet,
            None => vault.default_facet_in_txn(txn)?,
        };
        let (meet, observed) =
            BoundBranchRead::observation_qualification_in_txn(vault, txn, &candidate)?;
        facts.candidates.push(CandidateObservation {
            index,
            claim: candidate.claim_id.to_hex(),
            identity_token: tokens.identity,
            topic_token: tokens.topic,
            value_token: tokens.value,
            slice_token: tokens.slice,
            predicate: fresh.predicate.clone(),
            corrects: operand.corrects.clone(),
            meet,
            observed,
            evidence_count: selection.evidence_count,
            first_seen_ms: selection.first_seen_ms,
            latest_ms: selection.latest_ms,
            diversity: selection.diversity,
            fan_in,
            new_refs,
            has_vector: vector.is_some(),
            named_facet: named_facet.map(|facet| facet.to_hex()),
            scope_facet: fresh.scope_facet.to_hex(),
            scope_project: fresh.scope_project.to_hex(),
            replay_facet: replay_facet.to_hex(),
        });
        for head in bound.replay_heads_in_txn(read, txn, &candidate)? {
            let tokens = observation_key_tokens(&bound.observation_prior_keys(&head)?)?;
            facts.replay.push(ReplayObservation {
                index,
                claim: head.claim_id.to_hex(),
                version: observation_source_version(read, txn, head.claim_id)?,
                identity_token: tokens.identity,
                topic_token: tokens.topic,
                value_token: tokens.value,
                scope_facet: head.body.scope_facet.to_hex(),
                scope_project: head.body.scope_project.to_hex(),
                scope_equal: scope_with_taint(fresh.scope.clone(), meet)
                    == scope_with_taint(head.body.scope.clone(), meet),
            });
        }
        scopes.push((fresh, meet));
        vectors.push(vector);
    }
    facts.priors = prior_observations(read, txn, bound, &scopes)?;
    facts.scores = similarity_scores(&vectors);
    Ok(facts)
}

/// Reads every admitted prior's equality, version, standing and full-scope facts.
fn prior_observations(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    bound: &BoundBranchRead,
    scopes: &[(ClaimBody, ClaimSource)],
) -> MemoryResult<Vec<PriorObservation>> {
    let mut priors = Vec::with_capacity(bound.priors().len());
    for head in bound.priors().values() {
        let tokens = observation_key_tokens(&bound.observation_prior_keys(head)?)?;
        let provisional = bound.observation_prior_provisional(head)?;
        let scope_equal_candidates = scopes
            .iter()
            .enumerate()
            .filter_map(|(index, (fresh, meet))| {
                (scope_with_taint(fresh.scope.clone(), *meet)
                    == scope_with_taint(head.body.scope.clone(), *meet))
                .then_some(index)
            })
            .collect();
        priors.push(PriorObservation {
            claim: head.claim_id.to_hex(),
            version: observation_source_version(read, txn, head.claim_id)?,
            identity_token: tokens.identity,
            topic_token: tokens.topic,
            value_token: tokens.value,
            source: head.body.source.unwrap_or(ClaimSource::Imported),
            standing: if provisional { "provisional" } else { "prior" }.to_owned(),
            writable: bound.require_prior_write(head.claim_id).is_ok(),
            scope_facet: head.body.scope_facet.to_hex(),
            scope_project: head.body.scope_project.to_hex(),
            scope_equal_candidates,
        });
    }
    Ok(priors)
}

/// Computes every available unordered operand pair without applying a threshold.
/// A pair the native cosine refuses serves no score, never a page refusal.
fn similarity_scores(vectors: &[Option<Vec<f32>>]) -> Vec<SimilarityScore> {
    let mut scores = Vec::new();
    for (i, first) in vectors.iter().enumerate() {
        let Some(first) = first else {
            continue;
        };
        for (j, second) in vectors.iter().enumerate().skip(i + 1) {
            if let Some(second) = second {
                scores.push(SimilarityScore {
                    i,
                    j,
                    cosine: cosine(first, second).ok(),
                });
            }
        }
    }
    scores
}

/// Requires an observed head's version under the same live read as its facts.
fn observation_source_version(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
) -> MemoryResult<SourceVersion> {
    source_version_in_txn(read, txn, &claim)?
        .map(|(version, _)| version)
        .ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "an extraction observation head is not readable",
                &[],
            )
        })
}
