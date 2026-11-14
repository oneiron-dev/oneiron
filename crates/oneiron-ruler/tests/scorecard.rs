use std::path::PathBuf;

use oneiron_ruler::pack::{PackSlice, Slice, load_slice, sha256_hex};
use oneiron_ruler::scorecard::{
    Hit, QueryRun, RepeatRun, RunHeader, ScorecardError, build_scorecard, load_scorecard,
    write_scorecard,
};

const SCORES: [f32; 5] = [0.9, 0.8, 0.7, 0.6, 0.5];

fn fixture_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/retrieval_pack_tiny"
    ))
}

fn score_bits(rank: usize) -> u32 {
    SCORES[rank].to_bits()
}

fn standard_header(budget_rows: u32) -> RunHeader {
    RunHeader {
        engine_commit: "abc123".to_owned(),
        params_digest: "a".repeat(64),
        budget_rows,
    }
}

fn repeat_run(ids: &[&str], search_us: u64) -> RepeatRun {
    let mut hits = Vec::with_capacity(ids.len());
    for (rank, id) in ids.iter().enumerate() {
        hits.push(Hit {
            record_id: (*id).to_owned(),
            score_bits: score_bits(rank),
        });
    }
    RepeatRun { hits, search_us }
}

fn standard_runs() -> Vec<QueryRun> {
    let q1_ids = ["tiny-r03", "tiny-r02", "tiny-r01", "tiny-r04"];
    let q2_ids = ["tiny-r11", "tiny-r07", "tiny-r09", "tiny-r12", "tiny-r10"];
    let q1_first = repeat_run(&q1_ids, 100);
    let q1_second = repeat_run(&q1_ids, 120);
    let q2_first = repeat_run(&q2_ids, 300);
    let q2_second = repeat_run(&q2_ids, 200);
    let q3_first = repeat_run(&[], 50);
    let q3_second = repeat_run(&[], 60);
    vec![
        QueryRun {
            query_id: "tiny-q1".to_owned(),
            repeats: vec![q1_first, q1_second],
        },
        QueryRun {
            query_id: "tiny-q2".to_owned(),
            repeats: vec![q2_first, q2_second],
        },
        QueryRun {
            query_id: "tiny-q3".to_owned(),
            repeats: vec![q3_first, q3_second],
        },
    ]
}

fn load_tiny() -> (PackSlice, String) {
    let loaded = load_slice(&fixture_dir(), Slice::Search).expect("tiny fixture loads");
    let pack = loaded.slice;
    let digest = loaded.pack_digest;
    (pack, digest)
}

fn assert_close(left: f64, right: f64) {
    assert!((left - right).abs() < 1e-12, "left {left}, right {right}");
}

fn assert_opt_close(left: Option<f64>, right: Option<f64>) {
    match (left, right) {
        (Some(a), Some(b)) => assert_close(a, b),
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => panic!("option mismatch: {left:?} vs {right:?}"),
    }
}

#[test]
fn ranked_metrics_match_hand_computed_values() {
    let (pack, pack_digest) = load_tiny();
    let header = standard_header(2);
    let runs = standard_runs();
    let card = build_scorecard(&pack, &pack_digest, &header, &runs).unwrap();
    let q1 = &card.per_query[0];
    assert_eq!(q1.query_id, "tiny-q1");
    let log2_3 = 3f64.log2();
    let q1_ndcg = (3.0 / log2_3 + 1.0 / 2.0) / (3.0 + 1.0 / log2_3);
    assert_opt_close(q1.ndcg_at_10, Some(q1_ndcg));
    assert_opt_close(q1.mrr, Some(1.0 / 2.0));
    assert_opt_close(q1.recall_at_5, Some(1.0));
    assert_opt_close(q1.recall_at_20, Some(1.0));
    let q2 = &card.per_query[1];
    assert_eq!(q2.query_id, "tiny-q2");
    let log2_6 = 6f64.log2();
    let q2_ndcg = (3.0 + 1.0 / log2_6) / (3.0 + 1.0 / log2_3 + 1.0 / 2.0);
    assert_opt_close(q2.ndcg_at_10, Some(q2_ndcg));
    assert_opt_close(q2.mrr, Some(1.0));
    assert_opt_close(q2.recall_at_5, Some(2.0 / 3.0));
    assert_opt_close(q2.recall_at_20, Some(2.0 / 3.0));
    assert_close(card.metrics.ndcg_at_10, (q1_ndcg + q2_ndcg) / 2.0);
}

#[test]
fn recall_at_budget_cuts_at_budget_rows() {
    let (pack, pack_digest) = load_tiny();
    let runs = standard_runs();
    let header2 = standard_header(2);
    let card2 = build_scorecard(&pack, &pack_digest, &header2, &runs).unwrap();
    assert_opt_close(card2.per_query[0].recall_at_budget, Some(1.0 / 2.0));
    assert_opt_close(card2.per_query[1].recall_at_budget, Some(1.0 / 3.0));
    let header5 = standard_header(5);
    let card5 = build_scorecard(&pack, &pack_digest, &header5, &runs).unwrap();
    assert_opt_close(card5.per_query[0].recall_at_budget, Some(1.0));
    assert_opt_close(card5.per_query[1].recall_at_budget, Some(2.0 / 3.0));
}

#[test]
fn abstention_f1_counts_empty_results() {
    let (pack, pack_digest) = load_tiny();
    let header = standard_header(2);
    let runs = standard_runs();
    let card = build_scorecard(&pack, &pack_digest, &header, &runs).unwrap();
    assert_close(card.metrics.abstention_f1, 1.0);
    let mut runs_fn = standard_runs();
    let q3_bad_first = repeat_run(&["tiny-r01"], 50);
    let q3_bad_second = repeat_run(&["tiny-r01"], 60);
    runs_fn[2].repeats = vec![q3_bad_first, q3_bad_second];
    let card_fn = build_scorecard(&pack, &pack_digest, &header, &runs_fn).unwrap();
    assert_close(card_fn.metrics.abstention_f1, 0.0);
    let mut runs_fp = standard_runs();
    runs_fp[0].repeats = vec![repeat_run(&[], 100), repeat_run(&[], 120)];
    let card_fp = build_scorecard(&pack, &pack_digest, &header, &runs_fp).unwrap();
    assert_close(card_fp.metrics.abstention_f1, 2.0 / 3.0);
}

#[test]
fn per_category_min_names_the_weakest_category() {
    let (pack, pack_digest) = load_tiny();
    let header = standard_header(2);
    let runs = standard_runs();
    let card = build_scorecard(&pack, &pack_digest, &header, &runs).unwrap();
    let min_ndcg = card.per_category_min.get("ndcg_at_10").unwrap();
    assert_eq!(min_ndcg.category, "single-session-user");
    let q1_ndcg = card.per_query[0].ndcg_at_10.unwrap();
    assert_close(min_ndcg.value, q1_ndcg);
    let min_mrr = card.per_category_min.get("mrr").unwrap();
    assert_eq!(min_mrr.category, "single-session-user");
    assert_close(min_mrr.value, 1.0 / 2.0);
    assert!(!card.per_category.contains_key("abstention"));
}

#[test]
fn latency_uses_nearest_rank() {
    let (pack, pack_digest) = load_tiny();
    let header = standard_header(2);
    let runs = standard_runs();
    let card = build_scorecard(&pack, &pack_digest, &header, &runs).unwrap();
    assert_eq!(card.latency.search_p50_us, 100);
    assert_eq!(card.latency.search_p95_us, 300);
    assert_eq!(card.latency.aa_p95_spread_us, Some(100));
    let mut one_runs = standard_runs();
    for run in &mut one_runs {
        run.repeats.truncate(1);
    }
    let one = build_scorecard(&pack, &pack_digest, &header, &one_runs).unwrap();
    assert_eq!(one.latency.aa_p95_spread_us, None);
}

#[test]
fn repeat_digest_equal_is_false_when_repeats_differ() {
    let (pack, pack_digest) = load_tiny();
    let header = standard_header(2);
    let runs = standard_runs();
    let card = build_scorecard(&pack, &pack_digest, &header, &runs).unwrap();
    assert!(card.repeat_digest_equal);
    let mut swapped = standard_runs();
    swapped[1].repeats[1].hits.swap(1, 2);
    let card_swapped = build_scorecard(&pack, &pack_digest, &header, &swapped).unwrap();
    assert!(!card_swapped.repeat_digest_equal);
    let mut bits_changed = standard_runs();
    bits_changed[1].repeats[1].hits[0].score_bits ^= 1;
    let card_bits = build_scorecard(&pack, &pack_digest, &header, &bits_changed).unwrap();
    assert!(!card_bits.repeat_digest_equal);
}

#[test]
fn ranked_digests_only_on_search_slice() {
    let (pack, pack_digest) = load_tiny();
    let header = standard_header(2);
    let runs = standard_runs();
    let card = build_scorecard(&pack, &pack_digest, &header, &runs).unwrap();
    assert_eq!(card.per_query.len(), 3);
    for entry in &card.per_query {
        let digest = entry.ranked_digest.as_ref().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
    }
    let b0 = score_bits(0);
    let b1 = score_bits(1);
    let b2 = score_bits(2);
    let b3 = score_bits(3);
    let value = serde_json::json!([
        ["tiny-r03", b0],
        ["tiny-r02", b1],
        ["tiny-r01", b2],
        ["tiny-r04", b3]
    ]);
    let canonical = serde_json_canonicalizer::to_vec(&value).unwrap();
    let expected = sha256_hex(&canonical);
    let q1_digest = card.per_query[0].ranked_digest.as_ref().unwrap();
    assert_eq!(expected, *q1_digest);
    let mut held_pack = pack.clone();
    held_pack.slice = Slice::HeldOut;
    for query in &mut held_pack.queries {
        query.slice = Slice::HeldOut;
    }
    let held = build_scorecard(&held_pack, &pack_digest, &header, &runs).unwrap();
    assert_eq!(held.per_query.len(), 3);
    for entry in &held.per_query {
        assert!(entry.ranked_digest.is_none());
    }
    let mut sealed_pack = pack;
    sealed_pack.slice = Slice::Sealed;
    for query in &mut sealed_pack.queries {
        query.slice = Slice::Sealed;
    }
    let sealed = build_scorecard(&sealed_pack, &pack_digest, &header, &runs).unwrap();
    assert!(sealed.per_query.is_empty());
    assert_close(sealed.metrics.ndcg_at_10, card.metrics.ndcg_at_10);
    assert_close(sealed.metrics.mrr, card.metrics.mrr);
    assert_close(sealed.metrics.recall_at_5, card.metrics.recall_at_5);
    assert_close(sealed.metrics.recall_at_20, card.metrics.recall_at_20);
    assert_close(
        sealed.metrics.recall_at_budget,
        card.metrics.recall_at_budget,
    );
    assert_close(sealed.metrics.abstention_f1, card.metrics.abstention_f1);
}

#[test]
fn scorecard_refuses_bad_runs() {
    let (pack, pack_digest) = load_tiny();
    let header = standard_header(2);
    let mut missing = standard_runs();
    missing.truncate(2);
    assert!(matches!(
        build_scorecard(&pack, &pack_digest, &header, &missing),
        Err(ScorecardError::MissingQueryRun { .. })
    ));
    let mut outside = standard_runs();
    outside[0].repeats[0].hits[0].record_id = "tiny-r07".to_owned();
    assert!(matches!(
        build_scorecard(&pack, &pack_digest, &header, &outside),
        Err(ScorecardError::HitOutsideCorpus { .. })
    ));
    let mut dup = standard_runs();
    dup[0].repeats[0].hits = vec![
        Hit {
            record_id: "tiny-r02".to_owned(),
            score_bits: score_bits(0),
        },
        Hit {
            record_id: "tiny-r02".to_owned(),
            score_bits: score_bits(1),
        },
    ];
    assert!(matches!(
        build_scorecard(&pack, &pack_digest, &header, &dup),
        Err(ScorecardError::DuplicateHit { .. })
    ));
    let mut mismatch = standard_runs();
    mismatch[1].repeats.truncate(1);
    assert!(matches!(
        build_scorecard(&pack, &pack_digest, &header, &mismatch),
        Err(ScorecardError::RepeatCountMismatch { .. })
    ));
}

#[test]
fn scorecard_round_trips_through_write_and_load() {
    let (pack, pack_digest) = load_tiny();
    let header = standard_header(2);
    let runs = standard_runs();
    let card = build_scorecard(&pack, &pack_digest, &header, &runs).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("scorecard.json");
    write_scorecard(&path, &card).unwrap();
    let loaded = load_scorecard(&path).unwrap();
    assert_eq!(loaded.contract, card.contract);
    assert_eq!(loaded.engine_commit, card.engine_commit);
    assert_eq!(loaded.params_digest, card.params_digest);
    assert_eq!(loaded.pack_id, card.pack_id);
    assert_eq!(loaded.revision, card.revision);
    assert_eq!(loaded.pack_digest, card.pack_digest);
    assert_eq!(loaded.slice, card.slice);
    assert_eq!(loaded.model_id, card.model_id);
    assert_eq!(loaded.budget_rows, card.budget_rows);
    assert_eq!(loaded.repeats, card.repeats);
    assert_eq!(loaded.query_count, card.query_count);
    assert_eq!(loaded.latency, card.latency);
    assert_eq!(loaded.repeat_digest_equal, card.repeat_digest_equal);
    assert_eq!(loaded.per_category.len(), card.per_category.len());
    for (key, value) in &card.per_category {
        let other = loaded.per_category.get(key).unwrap();
        assert_eq!(other.queries, value.queries);
    }
    assert_eq!(loaded.per_category_min.len(), card.per_category_min.len());
    for (key, value) in &card.per_category_min {
        let other = loaded.per_category_min.get(key).unwrap();
        assert_eq!(other.category, value.category);
    }
    assert_eq!(loaded.per_query.len(), card.per_query.len());
    for (a, b) in loaded.per_query.iter().zip(card.per_query.iter()) {
        assert_eq!(a.query_id, b.query_id);
        assert_eq!(a.category, b.category);
        assert_eq!(a.expect_empty, b.expect_empty);
        assert_eq!(a.returned, b.returned);
        assert_eq!(a.ranked_digest, b.ranked_digest);
    }
    assert_close(loaded.metrics.ndcg_at_10, card.metrics.ndcg_at_10);
    assert_close(loaded.metrics.mrr, card.metrics.mrr);
    assert_close(loaded.metrics.recall_at_5, card.metrics.recall_at_5);
    assert_close(loaded.metrics.recall_at_20, card.metrics.recall_at_20);
    assert_close(
        loaded.metrics.recall_at_budget,
        card.metrics.recall_at_budget,
    );
    assert_close(loaded.metrics.abstention_f1, card.metrics.abstention_f1);
    for (key, value) in &card.per_category {
        let other = loaded.per_category.get(key).unwrap();
        assert_close(other.ndcg_at_10, value.ndcg_at_10);
        assert_close(other.mrr, value.mrr);
        assert_close(other.recall_at_5, value.recall_at_5);
        assert_close(other.recall_at_20, value.recall_at_20);
        assert_close(other.recall_at_budget, value.recall_at_budget);
    }
    for (key, value) in &card.per_category_min {
        let other = loaded.per_category_min.get(key).unwrap();
        assert_close(other.value, value.value);
    }
    for (a, b) in loaded.per_query.iter().zip(card.per_query.iter()) {
        assert_opt_close(a.ndcg_at_10, b.ndcg_at_10);
        assert_opt_close(a.mrr, b.mrr);
        assert_opt_close(a.recall_at_5, b.recall_at_5);
        assert_opt_close(a.recall_at_20, b.recall_at_20);
        assert_opt_close(a.recall_at_budget, b.recall_at_budget);
    }
}
