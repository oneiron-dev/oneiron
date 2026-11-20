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
    let long = retrieval_candidates_from_ranked_lists(std::slice::from_ref(&rows), &[]);
    let short = retrieval_candidates_from_ranked_lists(&[rows[..FUSION_LIST_LENGTH].to_vec()], &[]);
    for rank in 1..=10_u8 {
        assert_eq!(
            relevance_of(&long, [rank; 16]),
            relevance_of(&short, [rank; 16]),
            "rank {rank}"
        );
    }
}

/// Sol R1 on this branch: a window whose top rows all score the same has no
/// spread, and every row, the weaker ones past it too, took z 0; a weaker
/// row then tied the window and could win the id order. The window's rows
/// keep z 0 and a weaker row past it falls below them.
#[test]
fn a_flat_window_keeps_weaker_rows_past_it_below() {
    let weaker = [0; 16];
    let mut rows: Vec<ScoredEntity> = (1..=FUSION_LIST_LENGTH)
        .map(|rank| scored([u8::try_from(rank).unwrap(); 16], 1.0))
        .collect();
    rows.push(scored(weaker, 0.0));
    let inputs = retrieval_candidates_from_ranked_lists(&[rows], &[]);

    assert_eq!(relevance_of(&inputs, [1; 16]), 0.0);
    assert!(relevance_of(&inputs, weaker) < 0.0, "{inputs:?}");
}

/// Sol R2 on this branch (DESIGN §1.5 item 5): a sparse list was z-scored
/// over the candidates the channels returned, so its scale moved with the
/// other lists' coverage, and a single-code hit no other list returned lost
/// to a row two lists ranked first. It is scored as a list of the fusion
/// length whose other places are non-hits, RESEARCH-1216's z over 80 clips.
#[test]
fn a_sparse_list_scores_as_a_full_list_whatever_the_others_return() {
    let (hit, both, neither) = ([1; 16], [2; 16], [3; 16]);
    let others = vec![scored(both, 1.0), scored(neither, 0.0)];
    let inputs = retrieval_candidates_from_ranked_lists(
        &[vec![scored(hit, 1.0)], others.clone(), others],
        &[0],
    );

    assert!(
        relevance_of(&inputs, hit) > relevance_of(&inputs, both),
        "{inputs:?}"
    );
}

/// Sol R3 on this branch: a sparse pool of 80 equal hits had no non-hit
/// place left to give it a spread, so its hits scored z 0, as a candidate
/// it missed did, and the non-hit won the id order. The non-hit stays below.
#[test]
fn a_full_sparse_list_of_equal_hits_keeps_a_non_hit_below() {
    let non_hit = [0; 16];
    let hits: Vec<ScoredEntity> = (1..=FUSION_LIST_LENGTH)
        .map(|rank| scored([u8::try_from(rank).unwrap(); 16], 1.0))
        .collect();
    let mut text = hits.clone();
    text.push(scored(non_hit, 1.0));
    let inputs = retrieval_candidates_from_ranked_lists(&[hits, text], &[0]);

    assert!(
        relevance_of(&inputs, non_hit) < relevance_of(&inputs, [1; 16]),
        "{inputs:?}"
    );
}

/// Sol R3 on this branch: a sparse list longer than the fusion length was
/// scaled over every hit, so a hit's z grew as matching rows accumulated. It
/// is scaled by its best hits, as a dense list is.
#[test]
fn a_sparse_list_is_scaled_by_its_best_hits_however_many_follow() {
    let best = [0xF0; 16];
    let list = |hits: u8| {
        let mut list = vec![scored(best, 2.4)];
        list.extend((1..=hits).map(|hit| scored([hit; 16], 1.0)));
        list
    };
    let short = retrieval_candidates_from_ranked_lists(&[list(79)], &[0]);
    let long = retrieval_candidates_from_ranked_lists(&[list(159)], &[0]);

    assert_eq!(relevance_of(&short, best), relevance_of(&long, best));
}

/// A msgpack map of `entries`, in order.
fn msgpack_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(entries)).expect("encode map");
    body
}

/// A named body, and the salience and confidence main's lone reader reads from it.
type BodyCase = (&'static str, Vec<u8>, [Option<f32>; 2]);

/// One parse reads salience and confidence by the rule each lone read keeps:
/// the first entry of a field counts, a key that is no string ends the search
/// of each field not yet read, and an empty, truncated or non-map body reads
/// nothing.
#[test]
fn one_parse_reads_each_field_by_the_lone_read_rule() {
    let sal = || Value::from("sal");
    let conf = || Value::from("conf");
    let mut array = Vec::new();
    rmpv::encode::write_value(&mut array, &Value::Array(vec![sal(), Value::F32(0.5)]))
        .expect("encode array");
    let mut truncated = msgpack_map(vec![(sal(), Value::F32(0.5)), (conf(), Value::F32(0.5))]);
    truncated.truncate(truncated.len() - 2);
    let mut trailing = msgpack_map(vec![(sal(), Value::F32(0.5)), (conf(), Value::F32(0.25))]);
    trailing.push(0xC1);
    // {<2 bytes that are no UTF-8>: 0, "sal": 0.5}
    let invalid_key = vec![
        0x82, 0xA2, 0xFF, 0xFE, 0x00, 0xA3, b's', b'a', b'l', 0xCA, 0x3F, 0x00, 0x00, 0x00,
    ];
    let cases: Vec<BodyCase> = vec![
        (
            "both fields",
            msgpack_map(vec![(sal(), Value::F32(0.25)), (conf(), Value::F64(0.75))]),
            [Some(0.25), Some(0.75)],
        ),
        (
            "one field absent",
            msgpack_map(vec![(conf(), Value::F32(0.5))]),
            [None, Some(0.5)],
        ),
        (
            "integers clamped",
            msgpack_map(vec![(sal(), Value::from(7)), (conf(), Value::from(-3))]),
            [Some(1.0), Some(0.0)],
        ),
        (
            "not finite, not numeric",
            msgpack_map(vec![
                (sal(), Value::F32(f32::NAN)),
                (conf(), Value::from("x")),
            ]),
            [None, None],
        ),
        (
            "the first entry counts",
            msgpack_map(vec![
                (sal(), Value::from("x")),
                (sal(), Value::F32(0.5)),
                (conf(), Value::F32(0.5)),
                (conf(), Value::F32(0.9)),
            ]),
            [None, Some(0.5)],
        ),
        (
            "a key that is no string between the fields",
            msgpack_map(vec![
                (sal(), Value::F32(0.5)),
                (Value::from(1), Value::Nil),
                (conf(), Value::F32(0.5)),
            ]),
            [Some(0.5), None],
        ),
        (
            "a key that is no string first",
            msgpack_map(vec![(Value::from(1), Value::Nil), (sal(), Value::F32(0.5))]),
            [None, None],
        ),
        ("a key that is no UTF-8 first", invalid_key, [None, None]),
        ("no map", array, [None, None]),
        ("empty body", Vec::new(), [None, None]),
        ("truncated map", truncated, [None, None]),
        (
            "trailing bytes after the map",
            trailing,
            [Some(0.5), Some(0.25)],
        ),
    ];
    for (case, body, expected) in cases {
        assert_eq!(
            decode_msgpack_body_floats(&body, ["sal", "conf"]),
            expected,
            "{case}: both fields from one parse"
        );
        let row = [&[0_u8; ENTITY_METADATA_HEADER_LEN][..], &body].concat();
        assert_eq!(
            [
                decode_msgpack_float(&row, "sal"),
                decode_msgpack_float(&row, "conf")
            ],
            expected,
            "{case}: each field read alone"
        );
    }
}
