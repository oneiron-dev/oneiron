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
    let inputs = retrieval_candidates_from_ranked_lists(
        &[vec![
            scored(strong, 47.3),
            scored(middle, 6.6),
            scored(weak, 5.5),
        ]],
        &[],
    );
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

fn relevance_of(inputs: &[RetrievalBlendInput], id: [u8; 16]) -> f64 {
    inputs
        .iter()
        .find(|input| *input.id.as_bytes() == id)
        .expect("a candidate")
        .relevance
}

/// Guard, the owner's kept rule (EMBED-PACK, DESIGN arm 7): a candidate a
/// channel did not return takes that list's lowest z, the same charge
/// whether it was ineligible there or ranked low. It ties the weakest row
/// the channel returned.
#[test]
fn a_candidate_a_channel_missed_takes_its_lowest_z() {
    let (top, middle, weakest, missed) = ([1; 16], [2; 16], [3; 16], [4; 16]);
    let inputs = retrieval_candidates_from_ranked_lists(
        &[
            vec![scored(top, 9.0), scored(middle, 5.0), scored(weakest, 1.0)],
            // Flat: every row here scores z 0, as does a row it missed.
            vec![scored(weakest, 2.0), scored(missed, 2.0)],
        ],
        &[],
    );
    assert_eq!(
        relevance_of(&inputs, missed),
        relevance_of(&inputs, weakest)
    );
    assert!(relevance_of(&inputs, missed) < relevance_of(&inputs, middle));
}

/// Done-means (DESIGN §1.5 item 4): a list is z-scored against its own top
/// [`FUSION_LIST_LENGTH`] rows, so its best rows score the same however many
/// rows a caller fetched past them. Before, the scale was every row the
/// channel returned, and a longer fetch moved every z.
#[test]
fn a_list_is_scaled_by_its_top_rows_however_many_follow() {
    let rows: Vec<ScoredEntity> = (1..=200_u8)
        .map(|rank| scored([rank; 16], 1.0 / f32::from(rank)))
        .collect();
    let long = retrieval_candidates_from_ranked_lists(&[rows.clone()], &[]);
    let short = retrieval_candidates_from_ranked_lists(&[rows[..FUSION_LIST_LENGTH].to_vec()], &[]);
    for rank in 1..=10_u8 {
        assert_eq!(
            relevance_of(&long, [rank; 16]),
            relevance_of(&short, [rank; 16]),
            "rank {rank}"
        );
    }
}
