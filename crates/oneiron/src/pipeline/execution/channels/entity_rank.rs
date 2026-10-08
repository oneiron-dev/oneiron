//! Named entities below the content a query matched.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::types::{EntityMetadataCache, ScoredEntity};
use crate::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use crate::store::{RetrievalScoreComponent, RetrievalSignal, Store};
use heed::RoTxn;
use std::collections::HashMap;

/// Moves each PERSON, ORG and RELATIONSHIP the query did not match itself
/// to just after the last row it did match, keeping their order, and caps
/// their scores below the weakest match so a later sort keeps them there.
///
/// Every message a principal writes is `AuthoredBy` that principal, so PPR
/// pools all its seeds' mass into the author, and a person's slower decay
/// keeps it fresh beside older content: left alone, the owner outranks the
/// messages that matched. A person the query names matches on its own text
/// and keeps its rank. Every other row keeps its place, so a reranked order
/// stands; with no direct match at all (a pure graph or time query) nothing
/// moves.
pub(super) fn rank_unmatched_entities_below_matches(
    scores: &mut Vec<ScoredEntity>,
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<()> {
    let direct = |id: &EntityId| {
        components.get(id).is_some_and(|parts| {
            parts.iter().any(|part| {
                part.score > 0.0
                    && matches!(
                        part.signal,
                        RetrievalSignal::Text
                            | RetrievalSignal::Vector
                            | RetrievalSignal::Phonetic
                            | RetrievalSignal::Hyde
                            | RetrievalSignal::HydeRetry
                    )
            })
        })
    };
    let Some(last_match) = scores.iter().rposition(|hit| direct(&hit.id)) else {
        return Ok(());
    };
    // Every direct match sits at or before `last_match`, so the floor is
    // whole by the time the rows after it are read. A row after it can still
    // outscore the floor when a reranker set the order, so it is capped too.
    let mut floor = f32::INFINITY;
    let mut demote = vec![false; scores.len()];
    for (index, hit) in scores.iter().enumerate() {
        if direct(&hit.id) {
            floor = floor.min(hit.score);
        } else if index < last_match || hit.score >= floor {
            let kind = metadata_cache
                .get(store, rtxn, &hit.id)?
                .map(|meta| meta.entity_type);
            demote[index] = matches!(
                kind,
                Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_ORG | ENTITY_TYPE_RELATIONSHIP)
            );
        }
    }
    if !demote.contains(&true) {
        return Ok(());
    }
    let mut moved = Vec::new();
    let mut index = 0;
    scores.retain(|hit| {
        let keep = index >= last_match || !demote[index];
        if !keep {
            moved.push(*hit);
        }
        index += 1;
        keep
    });
    // Each capped score steps down from the one before it, so a later sort
    // keeps their order. A direct hit may score zero (a zero access factor);
    // scores stay at or above it, where community selection expects them.
    let mut cap = floor;
    let mut below = |score: f32| {
        if cap > 0.0 {
            cap = cap.next_down();
        }
        cap = cap.min(score);
        cap
    };
    for hit in &mut moved {
        hit.score = below(hit.score);
    }
    // Rows after `last_match` keep their indices: as many rows leave before
    // it as come back in right after it.
    let at = last_match + 1 - moved.len();
    scores.splice(at..at, moved);
    for (hit, _) in scores
        .iter_mut()
        .zip(&demote)
        .skip(last_match + 1)
        .filter(|(_, demoted)| **demoted)
    {
        hit.score = below(hit.score);
    }
    Ok(())
}
