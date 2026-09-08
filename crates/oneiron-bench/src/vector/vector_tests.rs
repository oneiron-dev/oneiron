//! Vector bench contract and end-to-end tests.

// ─── Tests ───────────────────────────────────────────────────────────────

use super::*;

use oneiron::HnswConfig;

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// The bench pins the LITERAL ARCH-0019 values. A plausible-but-wrong
/// edit (e.g. ef_search 100, target 10ms) must fail here.
#[test]
fn contract_literals_pinned() {
    assert_eq!(TARGET_SEARCH_TOP10_P50_MS, 5.0);
    assert_eq!(TARGET_INSERT_P50_MS, 1.0);
    assert_eq!(TARGET_RECALL_AT_10, 0.90);
    assert_eq!(CONTRACT_EF_SEARCH, 128);
    assert_eq!(CONTRACT_EF_CONSTRUCTION, 200);
    assert_eq!(CONTRACT_M_MAX_0, 64);
    assert_eq!(SEARCH_LIMIT, 10);
    assert_eq!(MENTIONS_EDGE_WEIGHT, 0.6);
}

/// The harness config must match the contract table, and the engine's
/// own default must agree with ARCH-0019 — if either drifts, this fails.
#[test]
fn bench_config_matches_contract_and_engine_default() {
    let cfg = bench_config(10_000, 1024);
    assert_eq!(cfg.hnsw.ef_search, 128);
    assert_eq!(cfg.hnsw.ef_construction, 200);
    assert_eq!(cfg.hnsw.m_max_0, 64);
    assert_eq!(cfg.dimensions, 1024);
    assert!(cfg.embedding_model.is_some());

    let engine_default = HnswConfig::default();
    assert_eq!(
        engine_default.ef_search, 128,
        "engine default drifted from ARCH-0019"
    );
    assert_eq!(
        engine_default.ef_construction, 200,
        "engine default drifted from ARCH-0019"
    );
    assert_eq!(
        engine_default.m_max_0, 64,
        "engine default drifted from ARCH-0019"
    );
}

#[test]
fn parse_args_defaults_to_contract_operating_point() {
    let settings = parse_args(&[]).expect("defaults parse");
    assert_eq!(settings.n, 10_000);
    assert_eq!(settings.dim, 1024);
    assert_eq!(settings.seed, 42);
    assert_eq!(settings.queries, 100);
    assert_eq!(settings.churn, ChurnMode::Both);
    assert_eq!(settings.churn_pct, 10);
    assert_eq!(settings.churn_ops, None);
    assert!(settings.assert_recall);
}

#[test]
fn parse_args_accepts_presets() {
    let settings = parse_args(&args(&[
        "--n",
        "1k",
        "--dim",
        "4096",
        "--seed",
        "7",
        "--queries",
        "25",
        "--churn",
        "refresh",
        "--churn-pct",
        "25",
        "--no-recall-assert",
    ]))
    .expect("flags parse");
    assert_eq!(settings.n, 1_000);
    assert_eq!(settings.dim, 4096);
    assert_eq!(settings.seed, 7);
    assert_eq!(settings.queries, 25);
    assert_eq!(settings.churn, ChurnMode::Refresh);
    assert_eq!(settings.churn_pct, 25);
    assert!(!settings.assert_recall);
}

/// Fail closed: only the ticket's presets are accepted.
#[test]
fn parse_args_rejects_off_contract_values() {
    assert!(parse_args(&args(&["--n", "5k"])).is_err());
    assert!(parse_args(&args(&["--n", "100"])).is_err());
    assert!(parse_args(&args(&["--dim", "512"])).is_err());
    assert!(parse_args(&args(&["--dim", "1536"])).is_err());
    assert!(parse_args(&args(&["--churn", "bogus"])).is_err());
    assert!(parse_args(&args(&["--churn-pct", "0"])).is_err());
    assert!(parse_args(&args(&["--churn-pct", "100"])).is_err());
    assert!(parse_args(&args(&["--churn-ops", "0"])).is_err());
    assert!(parse_args(&args(&["--churn-ops", "-3"])).is_err());
    assert!(parse_args(&args(&["--queries", "0"])).is_err());
    assert!(parse_args(&args(&["--seed"])).is_err());
    assert!(parse_args(&args(&["--frobnicate"])).is_err());
}

#[test]
fn parse_args_accepts_churn_ops_cap() {
    let settings = parse_args(&args(&["--churn-ops", "8"])).expect("churn-ops parse");
    assert_eq!(settings.churn_ops, Some(8));
    // pct stays at its default; the ops cap overrides it at runtime.
    assert_eq!(settings.churn_pct, 10);
}

/// `churn_count` literals: pct-derived, min-1 floor, absolute override,
/// clamped to the live set.
#[test]
fn churn_count_literals() {
    assert_eq!(churn_count(10_000, 10, None), 1_000);
    assert_eq!(churn_count(100, 10, None), 10);
    assert_eq!(churn_count(10, 1, None), 1); // min-1 floor
    assert_eq!(churn_count(10_000, 10, Some(8)), 8); // ops cap wins
    assert_eq!(churn_count(100, 10, Some(1_000)), 100); // clamped to live
}

#[test]
fn corpus_and_queries_are_seed_deterministic() {
    let mut rng_a = StdRng::seed_from_u64(42);
    let corpus_a = gen_corpus(&mut rng_a, 32, 8);
    let queries_a = gen_queries(&mut rng_a, &corpus_a, 5);

    let mut rng_b = StdRng::seed_from_u64(42);
    let corpus_b = gen_corpus(&mut rng_b, 32, 8);
    let queries_b = gen_queries(&mut rng_b, &corpus_b, 5);

    assert_eq!(corpus_a, corpus_b);
    assert_eq!(queries_a, queries_b);

    let mut rng_c = StdRng::seed_from_u64(43);
    let corpus_c = gen_corpus(&mut rng_c, 32, 8);
    assert_ne!(corpus_a, corpus_c, "different seed must change the corpus");
}

#[test]
fn percentile_is_nearest_rank() {
    let sorted: Vec<f64> = (1..=10).map(|v| f64::from(v) * 10.0).collect();
    assert_eq!(percentile(&sorted, 50.0), 50.0);
    assert_eq!(percentile(&sorted, 90.0), 90.0);
    assert_eq!(percentile(&sorted, 99.0), 100.0);
    assert_eq!(percentile(&[7.5], 50.0), 7.5);
    assert_eq!(percentile(&[7.5], 99.0), 7.5);
}

#[test]
fn brute_force_top_k_known_answer() {
    let ids: Vec<EntityId> = (1_u8..=4)
        .map(|b| EntityId::from_bytes([b; 16]).expect("id"))
        .collect();
    let mut live = BTreeMap::new();
    live.insert(ids[0], vec![1.0_f32, 0.0]); // dist 0.0 to query
    live.insert(ids[1], vec![0.9_f32, 0.1]); // dist ~0.0062
    live.insert(ids[2], vec![0.0_f32, 1.0]); // dist 1.0
    live.insert(ids[3], vec![-1.0_f32, 0.0]); // dist 2.0

    let top2 = brute_force_top_k(&live, &[1.0, 0.0], 2);
    assert_eq!(top2, vec![ids[0], ids[1]]);

    let top3 = brute_force_top_k(&live, &[1.0, 0.0], 3);
    assert_eq!(top3, vec![ids[0], ids[1], ids[2]]);
}

#[test]
fn cosine_distance_literal_values() {
    assert_eq!(cosine_distance_f32(&[1.0, 0.0], &[1.0, 0.0]), 0.0);
    assert_eq!(cosine_distance_f32(&[1.0, 0.0], &[0.0, 1.0]), 1.0);
    assert_eq!(cosine_distance_f32(&[1.0, 0.0], &[-1.0, 0.0]), 2.0);
    // Zero vector fails closed to max distance, never NaN.
    assert_eq!(cosine_distance_f32(&[0.0, 0.0], &[1.0, 0.0]), 1.0);
}

#[test]
fn churn_selection_is_deterministic_and_sized() {
    let mut live = BTreeMap::new();
    for b in 1_u8..=100 {
        live.insert(EntityId::from_bytes([b; 16]).expect("id"), vec![0.0_f32; 4]);
    }
    let mut rng_a = StdRng::seed_from_u64(9);
    let mut rng_b = StdRng::seed_from_u64(9);
    let picked_a = select_churn_ids(&mut rng_a, &live, 10);
    let picked_b = select_churn_ids(&mut rng_b, &live, 10);
    assert_eq!(picked_a, picked_b);
    assert_eq!(picked_a.len(), 10);
    assert_eq!(select_churn_ids(&mut rng_a, &live, 1).len(), 1);
    // min-1 floor: 1% of 10 entities rounds to 0 but must churn 1.
    let mut small = BTreeMap::new();
    for b in 1_u8..=10 {
        small.insert(EntityId::from_bytes([b; 16]).expect("id"), vec![0.0_f32; 4]);
    }
    assert_eq!(select_churn_ids(&mut rng_a, &small, 1).len(), 1);
}

/// End-to-end at a tiny operating point (n=100 < ef_search=128, so the
/// search beam covers the whole graph): recall must be exactly 1.0 in
/// every phase, churn counts must match, and the post-delete phase must
/// produce zero structural violations (no tombstone leaks).
#[test]
fn run_bench_tiny_end_to_end() {
    let settings = BenchSettings {
        n: 100,
        dim: 16,
        seed: 42,
        queries: 20,
        churn: ChurnMode::Both,
        churn_pct: 10,
        churn_ops: None,
        assert_recall: true,
    };
    let report = run_bench(&settings).expect("tiny bench run");

    assert_eq!(report.insert_new.count, 100);
    assert_eq!(report.baseline.recall_k, 10);
    assert!(report.baseline.violations.is_empty());
    assert_eq!(report.baseline.recall, 1.0);

    let refresh = report.refresh.as_ref().expect("refresh phase ran");
    assert_eq!(refresh.churned, 10);
    assert_eq!(refresh.live_after, 100);
    assert!(refresh.search.violations.is_empty());
    assert_eq!(refresh.search.recall, 1.0);

    let delete = report.delete.as_ref().expect("delete phase ran");
    assert_eq!(delete.churned, 10);
    assert_eq!(delete.live_after, 90);
    assert!(delete.search.violations.is_empty());
    assert_eq!(delete.search.recall, 1.0);

    assert_eq!(report.ram.vectors_raw_bytes, 100 * 16 * 4);
    assert!(report.ram.data_mdb_disk_bytes.is_some_and(|b| b > 0));
}

/// Same seed ⇒ identical recall in every phase across two full runs
/// (fresh vault each time) — the determinism contract of AC4.
#[test]
fn run_bench_is_deterministic_across_runs() {
    let settings = BenchSettings {
        n: 100,
        dim: 16,
        seed: 7,
        queries: 10,
        churn: ChurnMode::Both,
        churn_pct: 20,
        churn_ops: None,
        assert_recall: true,
    };
    let a = run_bench(&settings).expect("run a");
    let b = run_bench(&settings).expect("run b");

    assert_eq!(a.baseline.recall, b.baseline.recall);
    assert_eq!(
        a.refresh.as_ref().map(|c| c.search.recall),
        b.refresh.as_ref().map(|c| c.search.recall)
    );
    assert_eq!(
        a.delete.as_ref().map(|c| c.search.recall),
        b.delete.as_ref().map(|c| c.search.recall)
    );
    assert_eq!(
        a.delete.as_ref().map(|c| c.live_after),
        b.delete.as_ref().map(|c| c.live_after)
    );
}

#[test]
fn run_bench_rejects_n_below_search_limit() {
    let settings = BenchSettings {
        n: 5,
        dim: 8,
        seed: 1,
        queries: 1,
        churn: ChurnMode::None,
        churn_pct: 10,
        churn_ops: None,
        assert_recall: true,
    };
    assert!(run_bench(&settings).is_err());
}
