//! Rows the query did not match, below the content it did match.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::types::{EntityMetadataCache, ScoredEntity};
use crate::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use crate::store::{RetrievalScoreComponent, RetrievalSignal, StoreRead};
use heed::RoTxn;
use std::collections::HashMap;

/// How one run reads the query's own matches.
#[derive(Clone, Copy)]
pub(super) struct MatchReading {
    /// The temporal channel scans a window the query or the host named. The
    /// effort dial's default now anchor names none: it scores how fresh a
    /// row is, which the query did not ask for.
    pub(super) temporal_is_query: bool,
    /// Every row the query did not match moves, not only a PERSON, ORG or
    /// RELATIONSHIP: the order is still the blend's.
    pub(super) every_kind: bool,
}

/// Moves each row the query did not match itself to just after the last row
/// it did match, keeping their order, and caps their scores below the
/// weakest match so a later sort keeps them there. The query matched a row
/// that a text, vector, phonetic, HyDE or media channel scored, or that the
/// temporal channel scored on a window the query or the host named.
///
/// A PERSON, ORG or RELATIONSHIP moves in every run. Every message a
/// principal writes is `AuthoredBy` that principal, so PPR pools all its
/// seeds' mass into the author, and a person's slower decay keeps it fresh
/// beside older content: left alone, the owner outranks the messages that
/// matched. A person the query names matches on its own text and keeps its
/// rank.
///
/// Any other row moves only while the order is the blend's (FIX 22182): the
/// pipeline runs this before it takes the rerank block, and again after the
/// rerank for the named entities alone. In the blend, graph mass and the
/// effort's now anchor alone rank fresh rows the query never named above the
/// rows it did: ten fresh skill records outranked the two claims the query's
/// one word matched, and the limit cut those claims. Moved first, they can
/// neither fill the rerank block nor push a match past the limit. A reranked
/// order stands. With no direct match at all (a pure graph or time query)
/// nothing moves.
pub(super) fn rank_unmatched_below_matches(
    scores: &mut Vec<ScoredEntity>,
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    reading: MatchReading,
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<()> {
    let direct = |id: &EntityId| {
        components.get(id).is_some_and(|parts| {
            parts.iter().any(|part| {
                part.score > 0.0
                    && match part.signal {
                        RetrievalSignal::Text
                        | RetrievalSignal::Vector
                        | RetrievalSignal::Phonetic
                        | RetrievalSignal::Hyde
                        | RetrievalSignal::HydeRetry
                        | RetrievalSignal::MediaVector => true,
                        RetrievalSignal::Temporal => reading.temporal_is_query,
                        _ => false,
                    }
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
            demote[index] =
                reading.every_kind || named_entity(store, rtxn, metadata_cache, &hit.id)?;
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

/// Whether `id` is a PERSON, ORG or RELATIONSHIP, the rows PPR pools a
/// principal's mass into.
fn named_entity(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    id: &EntityId,
) -> Result<bool> {
    let kind = metadata_cache
        .get(store, rtxn, id)?
        .map(|meta| meta.entity_type);
    Ok(matches!(
        kind,
        Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_ORG | ENTITY_TYPE_RELATIONSHIP)
    ))
}
