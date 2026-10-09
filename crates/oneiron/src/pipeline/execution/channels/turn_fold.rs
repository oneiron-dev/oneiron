//! A MESSAGE hit folds into its TURN, so one result never holds both.

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::filters::pipeline_candidate_matches_filters_and_gate;
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, ScoredEntity, TurnFold,
};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::{RetrievalScoreComponent, Store};
use heed::RoTxn;
use std::collections::{HashMap, HashSet};

/// Puts each MESSAGE row's TURN in its place and keeps one row per TURN, at
/// the best place any of them held, then returns the messages each TURN took
/// in, best first, so its item can quote the words that matched.
///
/// ARCH-0004 makes the turn the unit recall returns: its vector carries the
/// meaning, and a lexical hit on one of its messages is a hit on it. A turn
/// stands in for its message only when the run would admit the turn itself
/// (`filter_config`, the run's own filters and gate); a message with no such
/// turn stays as it is, or under [`TurnFold::TurnsOnly`] leaves the run.
///
/// The turn also takes in each message's channel evidence
/// (`signal_components`), so the RET-01 check and the trace see the words
/// that matched on the row that now holds them.
#[expect(
    clippy::too_many_arguments,
    reason = "the fold reads the run's filters and caches and rewrites both its rows and their evidence"
)]
pub(super) fn fold_messages_into_turns(
    scores: &mut Vec<ScoredEntity>,
    signal_components: &mut HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    fold: TurnFold,
    store: &Store,
    rtxn: &RoTxn<'_>,
    filter_config: PipelineFilterConfig<'_>,
    metadata_cache: &mut EntityMetadataCache,
    claim_gate: &mut ClaimStatusGateCache,
) -> Result<HashMap<EntityId, Vec<EntityId>>> {
    let mut cited = HashMap::<EntityId, Vec<EntityId>>::new();
    let mut admitted = HashMap::<EntityId, bool>::new();
    let mut placed = HashSet::new();
    let mut folded = Vec::with_capacity(scores.len());
    for hit in scores.drain(..) {
        let is_message = metadata_cache
            .get(store, rtxn, &hit.id)?
            .is_some_and(|meta| meta.entity_type == ENTITY_TYPE_MESSAGE);
        let mut id = hit.id;
        if is_message && let Some(turn) = turn_of(store, rtxn, &hit.id, metadata_cache)? {
            let admits = match admitted.get(&turn) {
                Some(admits) => *admits,
                None => {
                    let admits = pipeline_candidate_matches_filters_and_gate(
                        store,
                        rtxn,
                        &turn,
                        filter_config,
                        metadata_cache,
                        claim_gate,
                    )?;
                    admitted.insert(turn, admits);
                    admits
                }
            };
            if admits {
                cited.entry(turn).or_default().push(hit.id);
                if let Some(evidence) = signal_components.get(&hit.id).cloned() {
                    carry_evidence(signal_components.entry(turn).or_default(), &evidence);
                }
                id = turn;
            }
        }
        if is_message && id == hit.id && fold == TurnFold::TurnsOnly {
            continue;
        }
        if placed.insert(id) {
            folded.push(ScoredEntity { id, ..hit });
        }
    }
    *scores = folded;
    Ok(cited)
}

/// Adds a message's channel evidence to its turn's, keeping the better score
/// on a channel both carry.
fn carry_evidence(turn: &mut Vec<RetrievalScoreComponent>, message: &[RetrievalScoreComponent]) {
    for part in message {
        match turn.iter_mut().find(|held| held.signal == part.signal) {
            Some(held) if part.score > held.score => *held = part.clone(),
            Some(_) => {}
            None => turn.push(part.clone()),
        }
    }
}

/// The TURN a witnessed MESSAGE is `PartOf`.
fn turn_of(
    store: &Store,
    rtxn: &RoTxn<'_>,
    message: &EntityId,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<Option<EntityId>> {
    for edge in store.port_edges(
        rtxn,
        message,
        EdgeDirection::Out,
        Some(EdgeKind::PartOf),
        None,
    )? {
        let target = edge?.target;
        if metadata_cache
            .get(store, rtxn, &target)?
            .is_some_and(|meta| meta.entity_type == ENTITY_TYPE_TURN)
        {
            return Ok(Some(target));
        }
    }
    Ok(None)
}
