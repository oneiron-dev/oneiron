//! The retrieval matrix CLI end to end: the mini pack converts, the keyword arm grades it to hand-counted values, the tuner leaves a bad start on the search slice only, and compare reports each language against the Lucene reference.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

/// A 40-hex engine commit for the fixtures.
const ENGINE_COMMIT: &str = "0123456789012345678901234567890123456789";

/// The mini manifest, in the `convert-trec` format.
const MINI_MANIFEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/retrieval_matrix/mini/manifest.json"
);

/// The tuner start: the default numbers with `cjk_ngram.weight` 0.0.
const START_PROFILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/retrieval_matrix/cjk-ngram-weight-0.profile.json"
);

/// The compare candidate: the default numbers with `stem.weight` 0.5.
const CANDIDATE_PROFILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/retrieval_matrix/candidate-stem-0.5.profile.json"
);

/// The hand-written TREC run in the baseline's output shape.
const LUCENE_RUN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/retrieval_matrix/mini/lucene.held_out.run"
);

/// Run `oneiron-bench scorecard` with the given arguments.
fn scorecard(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron-bench"))
        .arg("scorecard")
        .args(args)
        .output()
        .expect("scorecard CLI fixture")
}

/// Read a JSON file into a value.
fn read_json(path: &Path) -> Value {
    let bytes = std::fs::read(path).expect("fixture file reads");
    serde_json::from_slice(&bytes).expect("fixture file is JSON")
}

/// Assert two floats agree within the 1e-9 the brief allows.
fn assert_close(left: f64, right: f64) {
    assert!((left - right).abs() < 1e-9, "left {left}, right {right}");
}

/// One held_out category's hand-counted reference gap, as `[ndcg_at_10, recall_at_budget]` pairs.
struct CategoryGap {
    /// The query category.
    category: &'static str,
    /// The candidate's means.
    ours: [f64; 2],
    /// The reference's means.
    reference: [f64; 2],
    /// ours / reference, or None where the reference is 0.
    ratio: [Option<f64>; 2],
}

impl CategoryGap {
    /// One category's expected gap.
    fn new(
        category: &'static str,
        ours: [f64; 2],
        reference: [f64; 2],
        ratio: [Option<f64>; 2],
    ) -> Self {
        Self {
            category,
            ours,
            reference,
            ratio,
        }
    }
}

/// Convert the mini manifest into a fresh tempdir; return the dir, the pack dir and the summary.
fn convert_mini() -> (tempfile::TempDir, String, Value) {
    let dir = tempfile::tempdir().expect("mini fixture dir");
    let pack_dir = dir.path().join("packs");
    let pack_arg = pack_dir.to_str().expect("pack dir").to_owned();
    let result = scorecard(&[
        "convert-trec",
        "--manifest",
        MINI_MANIFEST,
        "--out-dir",
        &pack_arg,
    ]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "convert-trec failed: {stderr}");
    let summary: Value = serde_json::from_slice(&result.stdout).expect("convert prints JSON");
    (dir, pack_arg, summary)
}

/// The pack digest of one `convert-trec` slice row.
fn slice_digest(summary: &Value, slice: &str) -> String {
    let rows = summary["slices"].as_array().expect("slices");
    let row = rows
        .iter()
        .find(|row| row["slice"].as_str() == Some(slice))
        .expect("slice row");
    row["pack_digest"].as_str().expect("digest").to_owned()
}

/// Write a dominance campaign over the standard axes, pinning the held_out digest.
fn write_campaign(dir: &Path, held_out: &str) -> PathBuf {
    let body = json!({
        "campaign_id": "retrieval-matrix-mini",
        "search_axes": [{"name": "fanout", "values": ["4", "8"]}],
        "metric_set": {"set_id": "retrieval-scorecard", "revision": "r1", "axes": [
            {"name": "ndcg_at_10", "direction": "higher", "role": "primary"},
            {"name": "recall_at_5", "direction": "higher", "role": "floor", "tolerance": 0.001},
            {"name": "search_p95_us", "direction": "lower", "role": "cost", "tolerance": 50.0},
        ]},
        "splits": {
            "search": {"dataset_id": "retrieval-matrix-mini", "revision": "search-1"},
            "held_out": {"dataset_id": "retrieval-matrix-mini", "revision": held_out},
            "sealed": {"dataset_id": "retrieval-matrix-mini", "revision": "sealed-1"},
        },
        "budget": {"budget_id": "lease-1", "max_units": 10, "exploration_units": 2},
        "decide": {"kind": "dominance"},
    });
    let path = dir.join("campaign.json");
    std::fs::write(&path, serde_json::to_vec(&body).expect("campaign JSON"))
        .expect("campaign write");
    path
}

/// Run the keyword arm on one slice; return the scorecard path.
fn keyword_run(
    dir: &Path,
    pack_dir: &str,
    slice: &str,
    name: &str,
    profile: Option<&str>,
) -> String {
    let out = dir.join(name);
    let out_arg = out.to_str().expect("scorecard path").to_owned();
    let mut args = vec![
        "run",
        "--arm",
        "keyword",
        "--pack-dir",
        pack_dir,
        "--slice",
        slice,
        "--budget-rows",
        "100",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        out_arg.as_str(),
    ];
    if let Some(profile) = profile {
        args.push("--rank-profile");
        args.push(profile);
    }
    let result = scorecard(&args);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "keyword run failed: {stderr}");
    out_arg
}

#[test]
fn keyword_arm_grades_the_mini_pack_to_the_hand_counted_values() {
    let (dir, pack_dir, _convert) = convert_mini();
    let out = dir.path().join("keyword-search.json");
    let out_arg = out.to_str().expect("scorecard path").to_owned();
    let result = scorecard(&[
        "run",
        "--arm",
        "keyword",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "search",
        "--budget-rows",
        "100",
        "--repeats",
        "2",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &out_arg,
    ]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "keyword run failed: {stderr}");
    let summary: Value = serde_json::from_slice(&result.stdout).expect("run prints JSON");
    assert_eq!(summary["arm"], json!("keyword"));
    assert_eq!(summary["retriever"], json!("bm25f"));
    assert_eq!(summary["repeat_digest_equal"], json!(true));
    let card = read_json(&out);
    assert_eq!(card["model_id"], json!("bm25f"));
    // Every search category ranks its relevant passage first; see mini/README.md.
    for category in [
        "miracl-ja",
        "miracl-ko",
        "miracl-zh",
        "miracl-th",
        "miracl-en",
    ] {
        let entry = &card["per_category"][category];
        assert_close(entry["ndcg_at_10"].as_f64().expect("ndcg"), 1.0);
        assert_close(entry["recall_at_budget"].as_f64().expect("recall"), 1.0);
    }
    let params = scorecard(&[
        "run",
        "--arm",
        "keyword",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "search",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &out_arg,
        "--params",
        "whatever",
    ]);
    assert_eq!(params.status.code(), Some(2));
    let profile = scorecard(&[
        "run",
        "--arm",
        "pipeline",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "search",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &out_arg,
        "--rank-profile",
        "whatever",
    ]);
    assert_eq!(profile.status.code(), Some(2));
}

#[test]
fn tune_bm25f_leaves_a_bad_start_and_reads_only_the_search_slice() {
    let (dir, pack_dir, convert) = convert_mini();
    let search_digest = slice_digest(&convert, "search");
    let held_digest = slice_digest(&convert, "held_out");
    let sealed_digest = slice_digest(&convert, "sealed");
    let out = dir.path().join("tuned.json");
    let out_arg = out.to_str().expect("tuned path").to_owned();
    let steps = dir.path().join("steps.json");
    let steps_arg = steps.to_str().expect("steps path").to_owned();
    let result = scorecard(&[
        "tune-bm25f",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "search",
        "--start",
        START_PROFILE,
        "--out",
        &out_arg,
        "--steps-out",
        &steps_arg,
        "--engine-commit",
        ENGINE_COMMIT,
    ]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "tune failed: {stderr}");
    let summary: Value = serde_json::from_slice(&result.stdout).expect("tune prints JSON");
    assert_eq!(summary["slice"], json!("search"));
    assert_eq!(summary["pack_digest"], json!(search_digest));
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(!stdout.contains(held_digest.as_str()));
    assert!(!stdout.contains(sealed_digest.as_str()));
    let start_ndcg = summary["start"]["macro_ndcg_at_10"]
        .as_f64()
        .expect("start ndcg");
    let best_ndcg = summary["best"]["macro_ndcg_at_10"]
        .as_f64()
        .expect("best ndcg");
    assert!(best_ndcg >= start_ndcg);
    assert!(best_ndcg > start_ndcg);
    let tuned = read_json(&out);
    assert!(
        tuned["channels"]["cjk_ngram"]["weight"]
            .as_f64()
            .expect("weight")
            > 0.0
    );
    let steps_value = read_json(&steps);
    assert!(!steps_value.as_array().expect("steps").is_empty());
    let reload = dir.path().join("reload.json");
    let reload_arg = reload.to_str().expect("reload path").to_owned();
    let again = scorecard(&[
        "run",
        "--arm",
        "keyword",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "search",
        "--rank-profile",
        &out_arg,
        "--budget-rows",
        "100",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &reload_arg,
    ]);
    let again_stderr = String::from_utf8_lossy(&again.stderr);
    assert!(
        again.status.success(),
        "tuned profile loads back: {again_stderr}"
    );
    for slice in ["held_out", "sealed"] {
        let bad_out = dir.path().join(format!("bad-{slice}.json"));
        let bad_steps = dir.path().join(format!("bad-{slice}-steps.json"));
        let bad_out_arg = bad_out.to_str().expect("bad path").to_owned();
        let bad_steps_arg = bad_steps.to_str().expect("bad steps path").to_owned();
        let refused = scorecard(&[
            "tune-bm25f",
            "--pack-dir",
            &pack_dir,
            "--slice",
            slice,
            "--start",
            START_PROFILE,
            "--out",
            &bad_out_arg,
            "--steps-out",
            &bad_steps_arg,
            "--engine-commit",
            ENGINE_COMMIT,
        ]);
        assert_eq!(refused.status.code(), Some(2));
        assert!(!bad_out.exists());
        assert!(!bad_steps.exists());
    }
}

#[test]
fn compare_reports_each_language_against_the_lucene_scorecard() {
    let (dir, pack_dir, convert) = convert_mini();
    let held_digest = slice_digest(&convert, "held_out");
    let incumbent = keyword_run(dir.path(), &pack_dir, "held_out", "inc.json", None);
    let candidate = keyword_run(
        dir.path(),
        &pack_dir,
        "held_out",
        "cand.json",
        Some(CANDIDATE_PROFILE),
    );
    let reference_path = dir.path().join("lucene.json");
    let reference_arg = reference_path.to_str().expect("reference path").to_owned();
    let graded = scorecard(&[
        "grade-run",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "held_out",
        "--run",
        LUCENE_RUN,
        "--retriever",
        "pyserini-bm25-mini",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &reference_arg,
        "--budget-rows",
        "100",
    ]);
    let graded_stderr = String::from_utf8_lossy(&graded.stderr);
    assert!(graded.status.success(), "grade-run failed: {graded_stderr}");
    let campaign = write_campaign(dir.path(), &held_digest);
    let campaign_arg = campaign.to_str().expect("campaign path").to_owned();
    let judged = scorecard(&[
        "compare",
        "--campaign",
        &campaign_arg,
        "--reference",
        &reference_arg,
        &incumbent,
        &candidate,
    ]);
    assert!(judged.status.code() == Some(0) || judged.status.code() == Some(1));
    let summary: Value = serde_json::from_slice(&judged.stdout).expect("compare prints JSON");
    assert!(summary.get("error").is_none());
    assert_eq!(
        summary["reference"]["retriever"],
        json!("pyserini-bm25-mini")
    );
    let categories = summary["reference"]["per_category"]
        .as_object()
        .expect("per_category");
    assert_eq!(categories.len(), 5);
    // Each hand count below is derived in mini/README.md.
    let expected = [
        CategoryGap::new("miracl-ja", [1.0, 1.0], [1.0, 1.0], [Some(1.0), Some(1.0)]),
        CategoryGap::new("miracl-ko", [0.0, 0.0], [1.0, 1.0], [Some(0.0), Some(0.0)]),
        CategoryGap::new("miracl-zh", [1.0, 1.0], [1.0, 1.0], [Some(1.0), Some(1.0)]),
        CategoryGap::new("miracl-th", [1.0, 1.0], [0.0, 0.0], [None, None]),
        CategoryGap::new(
            "miracl-en",
            [0.6131471927654584, 0.5],
            [1.0, 1.0],
            [Some(0.6131471927654584), Some(0.5)],
        ),
    ];
    for want in &expected {
        let entry = categories.get(want.category).expect("category");
        for (index, metric) in ["ndcg_at_10", "recall_at_budget"].into_iter().enumerate() {
            let gap = &entry[metric];
            let ours = want.ours[index];
            let reference = want.reference[index];
            assert_close(gap["ours"].as_f64().expect("ours"), ours);
            assert_close(gap["reference"].as_f64().expect("reference"), reference);
            match want.ratio[index] {
                Some(ratio) => assert_close(gap["ratio"].as_f64().expect("ratio"), ratio),
                None => assert!(gap["ratio"].is_null()),
            }
            let difference = gap["mean_difference"].as_f64().expect("difference");
            assert_close(difference, ours - reference);
            let bound = gap["lower_bound"].as_f64().expect("bound");
            assert_close(bound, ours - reference);
        }
    }
    let overall = &summary["reference"]["overall"];
    assert_close(
        overall["ndcg_at_10"]["ours"].as_f64().expect("ours"),
        0.7226294385530917,
    );
    assert_close(
        overall["ndcg_at_10"]["reference"]
            .as_f64()
            .expect("reference"),
        0.8,
    );
    assert_close(
        overall["ndcg_at_10"]["ratio"].as_f64().expect("ratio"),
        0.9032867981913646,
    );
    assert_close(
        overall["ndcg_at_10"]["mean_difference"]
            .as_f64()
            .expect("difference"),
        -0.07737056144690832,
    );
    assert_close(
        overall["recall_at_budget"]["ours"].as_f64().expect("ours"),
        0.7,
    );
    assert_close(
        overall["recall_at_budget"]["reference"]
            .as_f64()
            .expect("reference"),
        0.8,
    );
    assert_close(
        overall["recall_at_budget"]["ratio"]
            .as_f64()
            .expect("ratio"),
        0.8749999999999999,
    );
    assert_close(
        overall["recall_at_budget"]["mean_difference"]
            .as_f64()
            .expect("difference"),
        -0.1,
    );
    assert!(
        overall["ndcg_at_10"]["lower_bound"]
            .as_f64()
            .expect("bound")
            .is_finite()
    );
    let plain = scorecard(&[
        "compare",
        "--campaign",
        &campaign_arg,
        &incumbent,
        &candidate,
    ]);
    let same: Value = serde_json::from_slice(&plain.stdout).expect("compare prints JSON");
    assert_eq!(same["verdict"], summary["verdict"]);
    assert_eq!(same["decided_by"], summary["decided_by"]);
    assert_eq!(same["axes"], summary["axes"]);
    assert_eq!(same["bootstrap"], summary["bootstrap"]);
    let sealed = scorecard(&[
        "grade-run",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "sealed",
        "--run",
        LUCENE_RUN,
        "--retriever",
        "pyserini-bm25-mini",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &reference_arg,
    ]);
    assert_eq!(sealed.status.code(), Some(2));
}
