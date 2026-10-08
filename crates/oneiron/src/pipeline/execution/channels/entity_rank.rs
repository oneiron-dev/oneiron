//! Named entities below the content a query matched.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::fusion;
use crate::pipeline::types::{EntityMetadataCache, ScoredEntity};
use crate::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use crate::store::{RetrievalScoreComponent, RetrievalSignal, Store};
use heed::RoTxn;
use std::collections::HashMap;

/// Ranks each PERSON, ORG and RELATIONSHIP the query did not match itself
/// just below the weakest row it did match, keeping their order.
///
/// Every message a principal writes is `AuthoredBy` that principal, so PPR
/// pools all its seeds' mass into the author, and a person's slower decay
/// keeps it fresh beside older content: left alone, the owner outranks the
/// messages that matched. A person the query names matches on its own text
/// and keeps its rank. With no direct match at all (a pure graph or time
/// query) the order stands.
pub(super) fn rank_unmatched_entities_below_matches(
    scores: &mut [ScoredEntity],
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
    let Some(floor) = scores
        .iter()
        .filter(|hit| direct(&hit.id))
        .map(|hit| hit.score)
        .min_by(f32::total_cmp)
    else {
        return Ok(());
    };
    let mut cap = floor;
    for hit in scores.iter_mut() {
        if hit.score < floor || direct(&hit.id) {
            continue;
        }
        let kind = metadata_cache
            .get(store, rtxn, &hit.id)?
            .map(|meta| meta.entity_type);
        if matches!(
            kind,
            Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_ORG | ENTITY_TYPE_RELATIONSHIP)
        ) {
            cap = cap.next_down();
            hit.score = cap;
        }
    }
    if cap < floor {
        fusion::sort_scored_entities_desc(scores);
    }
    Ok(())
}
