//! Done-means (the Engine lane's ruling on Sol round 6, R6-1): a block row
//! whose words no revision pins (a MESSAGE whose words live in its entity
//! document) is found but not reranked. It follows the reranked rows in its
//! first-stage order, under the weakest reranked score, and its words bind
//! nothing.

use super::*;

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

fn scored(id: EntityId, score: f32) -> ScoredEntity {
    ScoredEntity { id, score }
}

fn pinned(byte: u8) -> BoundWords {
    BoundWords {
        revision: Some(RevisionRef([byte; 16])),
        ..BoundWords::default()
    }
}

#[test]
fn a_row_set_aside_follows_the_reranked_rows_below_their_weakest_score() {
    let (streamed, earlier) = (id(0x31), id(0x34));
    let (turn, message, other) = (id(0x32), id(0x33), id(0x35));
    // First-stage order: both document-backed messages outrank a reranked row.
    let mut block = vec![
        scored(streamed, 0.9),
        scored(turn, 0.8),
        scored(message, 0.7),
        scored(earlier, 0.6),
        scored(other, 0.5),
    ];
    // Had the streamed message been reranked, it would have pinned its TURN.
    let lent = (id(0x36), RevisionRef([0x36; 16]));
    let bound = vec![
        BoundWords {
            turn: Some(lent),
            unscored: true,
            ..BoundWords::default()
        },
        pinned(0x32),
        pinned(0x33),
        BoundWords {
            unscored: true,
            ..BoundWords::default()
        },
        pinned(0x35),
    ];

    let (kept, set_aside) = set_aside_unscored(&mut block, bound);
    let order: Vec<EntityId> = block.iter().map(|scored| scored.id).collect();
    assert_eq!(order, [turn, message, other, streamed, earlier]);
    assert_eq!(set_aside, 2);
    let revisions: Vec<_> = kept.iter().map(|words| words.revision).collect();
    assert_eq!(
        revisions,
        [0x32, 0x33, 0x35].map(|byte| Some(RevisionRef([byte; 16])))
    );
    assert!(kept.iter().all(|words| words.turn != Some(lent)));

    // The reranker reorders the three it was given over their ladder.
    block[..3].copy_from_slice(&[scored(other, 0.8), scored(turn, 0.7), scored(message, 0.5)]);
    let (reranked, rest) = block.split_at_mut(3);
    cap_set_aside(reranked, rest);
    assert!(block[3].score < 0.5, "{:?}", block[3]);
    assert!(block[4].score < block[3].score, "{:?}", block[4]);
    // A later sort keeps them after every reranked row, in their own order.
    block.sort_by(|left, right| right.score.total_cmp(&left.score));
    let order: Vec<EntityId> = block.iter().map(|scored| scored.id).collect();
    assert_eq!(order, [other, turn, message, streamed, earlier]);
}
