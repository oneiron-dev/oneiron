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
    let mut floor = f32::INFINITY;
    let mut demote = vec![false; last_match];
    for (index, hit) in scores[..=last_match].iter().enumerate() {
        if direct(&hit.id) {
            floor = floor.min(hit.score);
            continue;
        }
        let kind = metadata_cache
            .get(store, rtxn, &hit.id)?
            .map(|meta| meta.entity_type);
        demote[index] = matches!(
            kind,
            Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_ORG | ENTITY_TYPE_RELATIONSHIP)
        );
    }
    let mut moved = Vec::new();
    let mut index = 0;
    scores.retain(|hit| {
        let keep = !demote.get(index).copied().unwrap_or(false);
        if !keep {
            moved.push(*hit);
        }
        index += 1;
        keep
    });
    if moved.is_empty() {
        return Ok(());
    }
    // A direct hit may score zero (a zero access factor); scores stay at or
    // above it, where community selection expects them.
    let mut cap = floor;
    for hit in &mut moved {
        if cap > 0.0 {
            cap = cap.next_down();
        }
        hit.score = hit.score.min(cap);
    }
    let at = last_match + 1 - moved.len();
    scores.splice(at..at, moved);
    Ok(())
}
