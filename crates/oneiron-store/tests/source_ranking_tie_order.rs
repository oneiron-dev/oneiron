//! RERANK-GROUP-ORDER = A, at a weakest reranked score of zero (review round
//! 2 of #8383): the rerank ladder gives a reranked row its access factor, so
//! a factor of zero scores it zero, and a row past the block is capped there
//! too, since no score is below zero. The pipeline serves the reranked row
//! first; the pack's source ranking then sorts by score, and before the fix
//! it broke that tie by id, so the unscored row with the lower id came
//! first.
//!
//! The pack's results now keep the pipeline's order among equal scores;
//! its neighbors, which all come in at one score, still sort by id.
//!
//! Public crate surface only: `claim_source_ranking::apply` with the shipped
//! policy, on rows that are not claims (no claim body, one world section).
//!
//! Fleet: `cargo test --locked -p oneiron-store --all-features --test source_ranking_tie_order`

use std::collections::HashMap;

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::claim_source_ranking::{SourceRankingPolicy, apply};
use oneiron_store::serialize::context_entity::ContextEntity;

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn row(id: EntityId, score: f32) -> ContextEntity {
    ContextEntity {
        id,
        short_id: id.to_hex()[..8].to_owned(),
        content_hash: 0,
        source_revision_ref: None,
        entity_type: 0,
        score,
        critical: false,
        fields: None,
        edges: None,
        vector: None,
    }
}

fn ids(rows: &[ContextEntity]) -> Vec<EntityId> {
    rows.iter().map(|row| row.id).collect()
}

/// A reranked row at zero comes in ahead of an unscored row capped to zero
/// with a lower id; the pack serves them in that order.
#[test]
fn results_of_equal_score_keep_the_pipeline_order() {
    let lead = id(0x51);
    let reranked_at_zero = id(0x53);
    let capped_at_zero = id(0x52);
    let mut results = vec![
        row(lead, 0.9),
        row(reranked_at_zero, 0.0),
        row(capped_at_zero, 0.0),
    ];
    let mut neighbors = Vec::new();
    apply(
        &mut results,
        &mut neighbors,
        &HashMap::new(),
        &SourceRankingPolicy::default(),
    )
    .expect("source ranking");
    assert_eq!(
        ids(&results),
        vec![lead, reranked_at_zero, capped_at_zero],
        "the tie at zero keeps the pipeline's order, not the id order: {:?}",
        results
            .iter()
            .map(|row| (row.id.to_hex(), row.score))
            .collect::<Vec<_>>(),
    );
}

/// A score still decides over the order rows come in, and neighbors of one
/// score sort by id.
#[test]
fn scores_order_the_results_and_ids_order_tied_neighbors() {
    let weaker = id(0x61);
    let stronger = id(0x62);
    let mut results = vec![row(weaker, 0.2), row(stronger, 0.7)];
    let mut neighbors = vec![row(id(0x73), 0.0), row(id(0x71), 0.0), row(id(0x72), 0.0)];
    apply(
        &mut results,
        &mut neighbors,
        &HashMap::new(),
        &SourceRankingPolicy::default(),
    )
    .expect("source ranking");
    assert_eq!(ids(&results), vec![stronger, weaker]);
    assert_eq!(ids(&neighbors), vec![id(0x71), id(0x72), id(0x73)]);
}
