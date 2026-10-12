//! RET-010 rerank hook: the post-sort score-ladder reassignment over the top-N block.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::trace::retrieval_trace_top_scores;
use crate::pipeline::types::{ClaimStatusGateCache, ScoredEntity};
use crate::rerank::RerankCandidate;
use crate::store::{RetrievalScoreComponent, RetrievalSignal};
use std::collections::HashMap;

/// The read-only faces the rerank ladder draws on.
#[derive(Clone, Copy)]
pub(super) struct RerankLadderInputs<'a> {
    /// Each candidate's post-boost, pre-decay score; `None` when no
    /// reranker is configured.
    pub(super) ladder_scores: Option<&'a HashMap<EntityId, f32>>,
    pub(super) blend_access_factors: &'a HashMap<EntityId, f32>,
    pub(super) blend_components: &'a HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    pub(super) claim_gate: &'a ClaimStatusGateCache,
    pub(super) rerank_query: Option<&'a str>,
    pub(super) capture_retrieval_trace: bool,
    pub(super) trace_candidate_limit: usize,
}

/// What the rerank hook produced; both options are `None`, and the map
/// empty, when it did not run.
pub(super) struct RerankApplied {
    pub(super) merged_components: Option<HashMap<EntityId, Vec<RetrievalScoreComponent>>>,
    pub(super) reranked_trace_scores: Option<Vec<ScoredEntity>>,
    /// The revision of the words each block candidate was scored at. The
    /// block is served at these, so a TURN shows the words its score is
    /// for, not those its messages hold by the time its item is read.
    pub(super) words_revisions: HashMap<EntityId, crate::vault::RevisionRef>,
}

impl PipelineBuilder<'_> {
    // RET-010 rerank hook: post-sort, pre-budget/pre-truncate, so the
    // reranker sees the blended+filtered ordering over more than
    // `result_limit` candidates and the budget/truncate operate on
    // the final relevance order. Score-ladder reassignment: the block
    // is permuted by (rerank score desc, id bytes asc) but position i
    // keeps the i-th highest POST-BOOST, PRE-DECAY score of the block,
    // multiplied by the RECEIVING entity's own access factor; raw
    // reranker scores survive in the Rerank components.
    //
    // The factor is entity-bound on purpose. A ladder built from
    // already-decayed scores hands position i whatever decay the
    // entity that used to sit there carried: a zero-factor claim
    // promoted to the top would be RESURRECTED with a live
    // neighbor's score, and a live entity demoted into its slot
    // would be punished for someone else's age. The shadow ladder
    // starts from the pre-decay blend and receives the same contiguity
    // and facet-Prefer multipliers as the live scores. Re-multiplying
    // each rung by its receiving entity's factor keeps both those
    // boosts and a single factor application. When every block factor
    // is 1.0 this is the legacy ladder.
    pub(super) fn apply_rerank_ladder(
        &self,
        rtxn: &heed::RoTxn<'_>,
        scores: &mut [ScoredEntity],
        inputs: RerankLadderInputs<'_>,
    ) -> Result<RerankApplied> {
        let mut rerank_merged_components = None;
        let mut reranked_trace_scores = None;
        let mut words_revisions = HashMap::new();
        // Empty block: reranking zero candidates is a semantic no-op —
        // never invoke the host impl, so an otherwise-empty retrieval
        // cannot fail on reranker behavior and no needless work happens
        // under the held read txn. (The fail-closed top_n/query
        // validation at the top of run_for_pack still applies.)
        if let Some((reranker, options)) = self.rerank.as_ref()
            && options.top_n.min(scores.len()) > 0
            && !self.deadline_reached()
        {
            let query = inputs.rerank_query.unwrap_or_default();
            let block_len = options.top_n.min(scores.len());
            let block_ids: Vec<EntityId> =
                scores[..block_len].iter().map(|scored| scored.id).collect();
            let mut ladder = Vec::with_capacity(block_len);
            for id in &block_ids {
                let Some(base) = inputs
                    .ladder_scores
                    .and_then(|ladder_scores| ladder_scores.get(id))
                    .copied()
                else {
                    return Err(Error::InvariantViolation(
                        "rerank block entity missing its blended base score",
                    ));
                };
                ladder.push(base);
            }
            ladder.sort_unstable_by(|left, right| right.total_cmp(left));
            let mut candidates: Vec<RerankCandidate<'_>> = Vec::with_capacity(block_len);
            for (index, scored) in scores[..block_len].iter().enumerate() {
                let revision = self.words_revision(rtxn, &scored.id)?;
                candidates.push(RerankCandidate {
                    id: scored.id,
                    score: scored.score,
                    rank: (index + 1).min(u32::MAX as usize) as u32,
                    claim: inputs
                        .claim_gate
                        .decisions
                        .get(&scored.id)
                        .and_then(|decision| decision.as_ref()),
                    revision,
                });
            }
            let rerank_scores = reranker.rerank(query, &candidates)?;
            words_revisions = candidates
                .iter()
                .filter_map(|candidate| Some((candidate.id, candidate.revision?)))
                .collect();
            drop(candidates);
            if rerank_scores.len() != block_len {
                return Err(Error::InvariantViolation(
                    "reranker returned mismatched score count",
                ));
            }
            if rerank_scores.iter().any(|score| !score.is_finite()) {
                return Err(Error::InvariantViolation(
                    "reranker returned non-finite score",
                ));
            }

            let mut order: Vec<usize> = (0..block_len).collect();
            order.sort_by(|&left, &right| {
                rerank_scores[right]
                    .partial_cmp(&rerank_scores[left])
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| block_ids[left].as_bytes().cmp(block_ids[right].as_bytes()))
            });
            let mut rerank_components = HashMap::<EntityId, Vec<RetrievalScoreComponent>>::new();
            for (new_pos, &old_pos) in order.iter().enumerate() {
                let Some(access_factor) = inputs
                    .blend_access_factors
                    .get(&block_ids[old_pos])
                    .copied()
                else {
                    return Err(Error::InvariantViolation(
                        "rerank block entity missing its applied access factor",
                    ));
                };
                scores[new_pos] = ScoredEntity {
                    id: block_ids[old_pos],
                    score: ladder[new_pos] * access_factor,
                };
                rerank_components
                    .entry(block_ids[old_pos])
                    .or_default()
                    .push(RetrievalScoreComponent {
                        signal: RetrievalSignal::Rerank,
                        rank: (new_pos + 1).min(u32::MAX as usize) as u32,
                        score: rerank_scores[old_pos],
                    });
            }

            // Rerank components append AFTER the blend components in each
            // entity's vector (pinned merge order; no dedup, no re-sort).
            let mut merged = inputs.blend_components.clone();
            for (id, components) in rerank_components {
                merged.entry(id).or_default().extend(components);
            }
            rerank_merged_components = Some(merged);

            if inputs.capture_retrieval_trace {
                reranked_trace_scores = Some(retrieval_trace_top_scores(
                    scores,
                    inputs.trace_candidate_limit,
                ));
            }
        }
        Ok(RerankApplied {
            merged_components: rerank_merged_components,
            reranked_trace_scores,
            words_revisions,
        })
    }

    /// The revision of the words `id` holds in this transaction (see
    /// [`RerankCandidate::revision`]).
    fn words_revision(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<crate::vault::RevisionRef>> {
        use crate::ports::EntityStoreRead;
        let kind = self
            .vault
            .store
            .port_entity_record(rtxn, id)?
            .map(|row| row.entity_type);
        if kind == Some(crate::registry::ENTITY_TYPE_TURN) {
            return Ok(crate::vault::entity_revision::served_turn_text_in_txn(
                self.vault,
                rtxn,
                id,
                crate::vault::ReadMode::Indexed,
            )?
            .map(|text| text.revision));
        }
        match self.vault.indexed_revision_in_txn(rtxn, id) {
            Ok(revision) => Ok(revision),
            Err(Error::EntityNotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
}
