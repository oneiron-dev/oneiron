//! RET-010 rerank hook: the post-sort score-ladder reassignment over the top-N block.

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::export::write_door_refuses_body;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::filters::pipeline_candidate_matches_filters_and_gate;
use crate::pipeline::trace::retrieval_trace_top_scores;
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, ScoredEntity, TurnFold,
};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::rerank::RerankCandidate;
use crate::store::{RetrievalScoreComponent, RetrievalSignal};
use crate::vault::entity_revision::TurnText;
use crate::vault::{ReadMode, RevisionRef};
use std::collections::{HashMap, HashSet};

/// The read-only faces the rerank ladder draws on.
#[derive(Clone, Copy)]
pub(super) struct RerankLadderInputs<'a> {
    /// Each candidate's post-boost, pre-decay score; `None` when no
    /// reranker is configured.
    pub(super) ladder_scores: Option<&'a HashMap<EntityId, f32>>,
    pub(super) blend_access_factors: &'a HashMap<EntityId, f32>,
    pub(super) blend_components: &'a HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    pub(super) filter_config: PipelineFilterConfig<'a>,
    pub(super) rerank_query: Option<&'a str>,
    pub(super) capture_retrieval_trace: bool,
    pub(super) trace_candidate_limit: usize,
}

/// What the rerank hook produced; both options are `None`, and the map
/// empty, when it did not run.
#[derive(Default)]
pub(super) struct RerankApplied {
    pub(super) merged_components: Option<HashMap<EntityId, Vec<RetrievalScoreComponent>>>,
    pub(super) reranked_trace_scores: Option<Vec<ScoredEntity>>,
    /// For a reranker that binds words, the revision of the words each block
    /// candidate was scored at, and each TURN a scored MESSAGE folds into.
    /// The run serves those rows at these, so a TURN shows the words its
    /// score is for, not those its messages hold by the time it is read.
    pub(super) words_revisions: HashMap<EntityId, RevisionRef>,
    /// For a reranker that binds words, each TURN of the block, or that a
    /// scored MESSAGE folds into, whose messages showed no words to pin: the
    /// run does not serve it under scores its later words were not given.
    pub(super) unpinned_turns: HashSet<EntityId>,
}

/// What a binding reranker's candidate is bound to (see [`RerankCandidate`]).
#[derive(Clone, Copy, Default)]
struct BoundWords {
    revision: Option<RevisionRef>,
    turn: Option<(EntityId, RevisionRef)>,
    /// The TURN the candidate is served as, when it holds no words to pin.
    unpinned: Option<EntityId>,
    /// A MESSAGE whose row does not hold the words it is served with (its
    /// text moved into its entity document, or the row has no revision to
    /// read), or a row with words the write door refuses (stored while the
    /// owner's secret scan was off), which no model is sent. The run does
    /// not rerank it.
    unscored: bool,
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
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
        inputs: RerankLadderInputs<'_>,
    ) -> Result<RerankApplied> {
        let mut rerank_merged_components = None;
        let mut reranked_trace_scores = None;
        let mut words_revisions = HashMap::new();
        let mut unpinned_turns = HashSet::new();
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
            let mut block_len = options.top_n.min(scores.len());
            // Only a reranker whose scores are for the words reads them, and
            // a deadline that comes meanwhile skips the stage.
            let mut bound = Vec::new();
            let mut tail_len = 0;
            if reranker.binds_words() {
                bound.reserve(block_len);
                for scored in &scores[..block_len] {
                    if self.deadline_reached() {
                        return Ok(RerankApplied::default());
                    }
                    bound.push(self.bound_words(
                        rtxn,
                        &scored.id,
                        inputs.filter_config,
                        metadata_cache,
                        claim_gate,
                    )?);
                }
                (bound, tail_len) = set_aside_unscored(&mut scores[..block_len], bound);
                block_len -= tail_len;
                if block_len == 0 {
                    return Ok(RerankApplied::default());
                }
            }
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
                let words = bound.get(index).copied().unwrap_or_default();
                unpinned_turns.extend(words.unpinned);
                candidates.push(RerankCandidate {
                    id: scored.id,
                    score: scored.score,
                    rank: (index + 1).min(u32::MAX as usize) as u32,
                    claim: claim_gate
                        .decisions
                        .get(&scored.id)
                        .and_then(|decision| decision.as_ref()),
                    revision: words.revision,
                    turn: words.turn,
                });
            }
            let rerank_scores = reranker.rerank(query, &candidates)?;
            words_revisions = candidates
                .iter()
                .flat_map(|candidate| {
                    candidate
                        .revision
                        .map(|revision| (candidate.id, revision))
                        .into_iter()
                        .chain(candidate.turn)
                })
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
            let (reranked, rest) = scores.split_at_mut(block_len);
            cap_set_aside(reranked, &mut rest[..tail_len]);

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
            unpinned_turns,
        })
    }

    /// The revision of the words `id` holds in this transaction (see
    /// [`RerankCandidate::revision`]) and, for a MESSAGE the run folds into a
    /// TURN it admits, that TURN's (see [`RerankCandidate::turn`]). A TURN
    /// whose messages show no words has no text revision to pin them by. A
    /// MESSAGE whose row does not hold its words is not reranked, nor is a
    /// row with words the write door refuses.
    fn bound_words(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        filter_config: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<BoundWords> {
        let kind = metadata_cache
            .get(&self.read, rtxn, id)?
            .map(|meta| meta.entity_type);
        if kind == Some(ENTITY_TYPE_TURN) {
            let text = self.turn_text(rtxn, id)?;
            // Words the write door refuses are sent to no model.
            if text.as_ref().is_some_and(|text| {
                text.messages
                    .iter()
                    .any(|(_, words, _)| write_door_refuses_body(words.as_bytes()))
            }) {
                return Ok(BoundWords {
                    unscored: true,
                    ..BoundWords::default()
                });
            }
            let revision = text.map(|text| text.revision);
            return Ok(BoundWords {
                revision,
                turn: None,
                unpinned: revision.is_none().then_some(*id),
                unscored: false,
            });
        }
        let revision = match self
            .vault
            .indexed_revision_from_in_txn(&self.read, rtxn, id)
        {
            Ok(revision) => revision,
            Err(Error::EntityNotFound) => None,
            Err(error) => return Err(error),
        };
        // A streamed or edited MESSAGE holds its words in its entity
        // document, which its row revision does not pin; a build without
        // `sync` reads no document, but still sees that it has one. A row the
        // write door refuses is sent to no model.
        let message_without_words = kind == Some(ENTITY_TYPE_MESSAGE)
            && (revision.is_none()
                || crate::vault::entity_revision::message_has_document_in_txn(
                    self.vault, rtxn, id,
                )?);
        if message_without_words
            || crate::vault::entity_revision::read_entity_revision_from_store_in_txn(
                self.vault,
                &self.read,
                rtxn,
                id,
                ReadMode::Indexed,
            )?
            .is_some_and(|raw| write_door_refuses_body(&raw[ENTITY_METADATA_HEADER_LEN..]))
        {
            return Ok(BoundWords {
                unscored: true,
                ..BoundWords::default()
            });
        }
        let mut words = BoundWords {
            revision,
            ..BoundWords::default()
        };
        if kind != Some(ENTITY_TYPE_MESSAGE) || self.turn_fold == TurnFold::Off {
            return Ok(words);
        }
        // The fold's own rule: a MESSAGE stands as its TURN when the run
        // admits that TURN.
        let Some(turn) = super::turn_fold::turn_of(&self.read, rtxn, id, metadata_cache)? else {
            return Ok(words);
        };
        if !pipeline_candidate_matches_filters_and_gate(
            &self.read,
            rtxn,
            &turn,
            filter_config,
            metadata_cache,
            claim_gate,
        )? {
            return Ok(words);
        }
        match self.turn_text(rtxn, &turn)?.map(|text| text.revision) {
            Some(revision) => words.turn = Some((turn, revision)),
            None => words.unpinned = Some(turn),
        }
        Ok(words)
    }

    /// The words `turn` holds in this transaction, under the text revision
    /// that commits to the state of every message they come from; `None`
    /// when its messages show none.
    fn turn_text(&self, rtxn: &heed::RoTxn<'_>, turn: &EntityId) -> Result<Option<TurnText>> {
        Ok(crate::vault::entity_revision::served_turn_text_in_txn(
            self.vault,
            &self.read,
            rtxn,
            turn,
            ReadMode::Indexed,
            false,
        )?
        .filter(|text| !text.messages.is_empty()))
    }
}

/// Sets aside the block's rows that do not hold their words (see
/// [`BoundWords::unscored`]): they are not reranked, and their words bind
/// nothing. They move after the rows that are reranked, each group in its
/// first-stage order. Returns the kept rows' words and how many were set
/// aside.
fn set_aside_unscored(
    block: &mut [ScoredEntity],
    bound: Vec<BoundWords>,
) -> (Vec<BoundWords>, usize) {
    if !bound.iter().any(|words| words.unscored) {
        return (bound, 0);
    }
    let (kept, unscored): (Vec<_>, Vec<_>) = block
        .iter()
        .copied()
        .zip(bound)
        .partition(|(_, words)| !words.unscored);
    for (slot, (scored, _)) in block.iter_mut().zip(kept.iter().chain(&unscored)) {
        *slot = *scored;
    }
    (
        kept.into_iter().map(|(_, words)| words).collect(),
        unscored.len(),
    )
}

/// The rows set aside step down from the weakest reranked score, keeping
/// their order, so a later sort keeps them below every reranked row.
fn cap_set_aside(reranked: &[ScoredEntity], set_aside: &mut [ScoredEntity]) {
    let mut cap = reranked
        .iter()
        .map(|scored| scored.score)
        .fold(f32::INFINITY, f32::min);
    for scored in set_aside {
        if cap > 0.0 {
            cap = cap.next_down();
        }
        cap = cap.min(scored.score);
        scored.score = cap;
    }
}

#[cfg(test)]
mod tests;
