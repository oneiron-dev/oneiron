use super::*;

fn scored(id: [u8; 16], score: f32) -> ScoredEntity {
    ScoredEntity {
        id: EntityId::from_bytes_unchecked(id),
        score,
    }
}

#[test]
fn channel_relevance_orders_candidates_the_four_signals_tie() {
    let strong = [7; 16];
    let middle = [1; 16];
    let weak = [3; 16];
    let inputs = retrieval_candidates_from_ranked_lists(&[vec![
        scored(strong, 47.3),
        scored(middle, 6.6),
        scored(weak, 5.5),
    ]]);
    let ranked = linear_log_blend(&inputs);
    assert_eq!(
        ranked
            .iter()
            .map(|row| *row.id.as_bytes())
            .collect::<Vec<_>>(),
        vec![strong, middle, weak],
        "relevance, not the id, orders tied modulators"
    );
    assert!(ranked[0].score > ranked[1].score && ranked[1].score > ranked[2].score);
}
