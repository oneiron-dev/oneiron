//! Drive `scorecard compare`, `proposals` and `stamp` end to end: fixtures in, JSON out.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use oneiron_ruler::pack::{Slice, sha256_hex};
use oneiron_ruler::proposal::proposal_id;
use oneiron_ruler::ruler_paths::SHIPPED_RULER_PATHS;
use oneiron_ruler::scorecard::{
    Latency, Metrics, QueryScore, SCORECARD_CONTRACT, Scorecard, write_scorecard,
};
use oneiron_ruler::sealed::ExperimentIdentity;
use serde_json::{Value, json};

/// A 40-hex engine commit for the fixtures.
const ENGINE_COMMIT: &str = "0123456789012345678901234567890123456789";

/// A second 40-hex engine commit for the fixtures.
const ENGINE_OTHER: &str = "1111111111111111111111111111111111111111";

/// The pack id every fixture scorecard and campaign names.
const PACK_ID: &str = "fixture-pack";

/// The campaign id every fixture campaign names.
const CAMPAIGN_ID: &str = "fixture-campaign";

/// The metric set the fixture campaigns pin.
const SET_ID: &str = "retrieval-scorecard";

/// The metric set revision the fixture campaigns pin.
const SET_REVISION: &str = "r1";

/// The held_out pack digest: 64 lowercase hex, so the bootstrap can seed from it.
const HELD_OUT_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The sealed pack digest.
const SEALED_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The five blend signals in pin order.
const PIN_SIGNALS: [&str; 5] = ["recency", "salience", "confidence", "gravity", "relevance"];

/// The candidate's pinned blend weights.
fn candidate_weights() -> Value {
    json!({
        "recency": 0.2,
        "salience": 0.1,
        "confidence": 0.1,
        "gravity": 0.1,
        "relevance": 0.5,
    })
}

/// Other pinned blend weights, for a params file that does not match.
fn other_weights() -> Value {
    json!({
        "recency": 0.5,
        "salience": 0.5,
        "confidence": 0.5,
        "gravity": 0.5,
        "relevance": 0.5,
    })
}

/// One fixture scorecard: the aggregate `metrics` and the `per_query` rows are set independently.
fn card(
    slice: Slice,
    engine_commit: &str,
    params_digest: &str,
    pack_digest: &str,
    per_query: Vec<QueryScore>,
) -> Scorecard {
    let query_count = u32::try_from(per_query.len()).expect("few fixture queries");
    Scorecard {
        contract: SCORECARD_CONTRACT.to_owned(),
        engine_commit: engine_commit.to_owned(),
        params_digest: params_digest.to_owned(),
        pack_id: PACK_ID.to_owned(),
        revision: "r1".to_owned(),
        pack_digest: pack_digest.to_owned(),
        slice,
        model_id: "model".to_owned(),
        budget_rows: 10,
        repeats: 1,
        query_count,
        metrics: Metrics {
            ndcg_at_10: 0.5,
            mrr: 0.5,
            recall_at_5: 0.5,
            recall_at_20: 0.5,
            recall_at_budget: 0.5,
            abstention_f1: 0.5,
        },
        per_category: BTreeMap::new(),
        per_category_min: BTreeMap::new(),
        latency: Latency {
            search_p50_us: 100,
            search_p95_us: 200,
            aa_p95_spread_us: None,
        },
        repeat_digest_equal: true,
        per_query,
    }
}

/// One fixture query score at the given ranked value.
fn qs(id: &str, ndcg: Option<f64>) -> QueryScore {
    QueryScore {
        query_id: id.to_owned(),
        category: "cat".to_owned(),
        expect_empty: ndcg.is_none(),
        returned: 3,
        ndcg_at_10: ndcg,
        mrr: ndcg,
        recall_at_5: ndcg,
        recall_at_20: ndcg,
        recall_at_budget: ndcg,
        ranked_digest: None,
    }
}

/// Thirty fixture queries at one ndcg.
fn flat_queries(prefix: &str, ndcg: f64) -> Vec<QueryScore> {
    (0..30)
        .map(|index| qs(&format!("{prefix}-{index:02}"), Some(ndcg)))
        .collect()
}

/// Clear-win held_out cards: 30 queries at 0.4 vs 0.6, the floor tied, p95 within tolerance.
fn clear_win_cards(
    engine_inc: &str,
    engine_cand: &str,
    params_inc: &str,
    params_cand: &str,
) -> (Scorecard, Scorecard) {
    let mut incumbent = card(
        Slice::HeldOut,
        engine_inc,
        params_inc,
        HELD_OUT_DIGEST,
        flat_queries("q", 0.4),
    );
    incumbent.metrics.ndcg_at_10 = 0.4;
    incumbent.metrics.recall_at_5 = 0.5;
    incumbent.latency.search_p95_us = 100;
    let mut candidate = card(
        Slice::HeldOut,
        engine_cand,
        params_cand,
        HELD_OUT_DIGEST,
        flat_queries("q", 0.6),
    );
    candidate.metrics.ndcg_at_10 = 0.6;
    candidate.metrics.recall_at_5 = 0.5;
    candidate.latency.search_p95_us = 110;
    (incumbent, candidate)
}

/// One campaign axis.
fn axis(name: &str, direction: &str, role: &str, tolerance: Option<f64>) -> Value {
    match tolerance {
        Some(tolerance) => json!({
            "name": name,
            "direction": direction,
            "role": role,
            "tolerance": tolerance,
        }),
        None => json!({
            "name": name,
            "direction": direction,
            "role": role,
        }),
    }
}

/// The standard fixture axes: ndcg primary, recall floor, p95 cost.
fn standard_axes() -> Vec<Value> {
    vec![
        axis("ndcg_at_10", "higher", "primary", None),
        axis("recall_at_5", "higher", "floor", Some(0.001)),
        axis("search_p95_us", "lower", "cost", Some(50.0)),
    ]
}

/// Write a dominance campaign over the given axes.
fn write_campaign(dir: &Path, name: &str, axes: Vec<Value>) -> PathBuf {
    let body = json!({
        "campaign_id": CAMPAIGN_ID,
        "search_axes": [{"name": "fanout", "values": ["4", "8"]}],
        "metric_set": {"set_id": SET_ID, "revision": SET_REVISION, "axes": axes},
        "splits": {
            "search": {"dataset_id": PACK_ID, "revision": "search-1"},
            "held_out": {"dataset_id": PACK_ID, "revision": HELD_OUT_DIGEST},
            "sealed": {"dataset_id": PACK_ID, "revision": SEALED_DIGEST},
        },
        "budget": {"budget_id": "lease-1", "max_units": 10, "exploration_units": 2},
        "decide": {"kind": "dominance"},
    });
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec(&body).expect("campaign JSON"))
        .expect("campaign write");
    path
}

/// `resolve`'s digest for pinned weights: sha256 over the canonical resolved object.
fn params_digest_of(weights: &Value) -> String {
    let resolved = json!({
        "contract": "oneiron.retrieval_eval_params.v1",
        "blend_weights": weights,
    });
    let canonical = serde_json_canonicalizer::to_vec(&resolved).expect("canonical params");
    sha256_hex(&canonical)
}

/// Write a pinned params file; return its path and `resolve`'s digest for it.
fn write_params(dir: &Path, name: &str, weights: Value) -> (PathBuf, String) {
    let digest = params_digest_of(&weights);
    let body = json!({
        "contract": "oneiron.retrieval_eval_params.v1",
        "blend_weights": weights,
    });
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec(&body).expect("params JSON")).expect("params write");
    (path, digest)
}

/// `resolve`'s digest for the learned table.
fn learned_digest() -> String {
    let resolved = json!({
        "contract": "oneiron.retrieval_eval_params.v1",
        "blend_weights": "learned_table",
    });
    let canonical = serde_json_canonicalizer::to_vec(&resolved).expect("canonical learned");
    sha256_hex(&canonical)
}

/// Write one fixture scorecard.
fn write_card(path: &Path, card: &Scorecard) {
    write_scorecard(path, card).expect("scorecard write");
}

/// Run `oneiron-bench scorecard` with the given arguments.
fn scorecard(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron-bench"))
        .arg("scorecard")
        .args(args)
        .output()
        .expect("scorecard CLI fixture")
}

/// True when no held_out record sits under `dir` (a missing dir counts as unwritten).
fn nothing_written(dir: &Path) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return true,
    };
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        if entry.path().join("held_out.json").is_file() {
            return false;
        }
    }
    true
}

/// Assert exit 2 with an error string, and no held_out record under `proposals`.
fn assert_input_error(result: &std::process::Output, proposals: &Path) {
    assert_eq!(result.status.code(), Some(2));
    let body: Value = serde_json::from_slice(&result.stdout).expect("error prints JSON");
    assert!(
        body.get("error").is_some_and(Value::is_string),
        "refusal names its error: {body}"
    );
    assert!(nothing_written(proposals), "writes nothing");
}

/// A promoted held_out proposal, with everything the sealed tests need.
struct Promotion {
    /// The held_out summary.
    summary: Value,
    /// The campaign file.
    campaign: PathBuf,
    /// The proposals dir.
    proposals: PathBuf,
    /// The proposal id.
    proposal_id: String,
    /// The candidate's pinned weights.
    weights: Value,
    /// The incumbent's engine commit.
    inc_engine: String,
    /// The incumbent's params digest.
    inc_params: String,
    /// The candidate's engine commit.
    cand_engine: String,
    /// The candidate's params digest.
    cand_params: String,
}

/// Promote a clear win through the CLI: campaign, cards, params, and the store dir.
fn promote(dir: &Path) -> Promotion {
    let campaign = write_campaign(dir, "campaign.json", standard_axes());
    let weights = candidate_weights();
    let (params_path, cand_digest) = write_params(dir, "params.json", weights.clone());
    let inc_digest = learned_digest();
    let (incumbent, candidate) =
        clear_win_cards(ENGINE_COMMIT, ENGINE_COMMIT, &inc_digest, &cand_digest);
    let base = dir.join("base.json");
    let cand = dir.join("cand.json");
    write_card(&base, &incumbent);
    write_card(&cand, &candidate);
    let proposals = dir.join("proposals");
    let result = scorecard(&[
        "compare",
        "--campaign",
        campaign.to_str().expect("campaign path"),
        "--candidate-params",
        params_path.to_str().expect("params path"),
        "--proposals",
        proposals.to_str().expect("proposals path"),
        "--at",
        "1700000000",
        base.to_str().expect("base path"),
        cand.to_str().expect("cand path"),
    ]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "promote failed: {stderr}");
    let summary: Value = serde_json::from_slice(&result.stdout).expect("promote prints JSON");
    let proposal_id = summary["proposal_id"]
        .as_str()
        .expect("proposal id")
        .to_owned();
    Promotion {
        summary,
        campaign,
        proposals,
        proposal_id,
        weights,
        inc_engine: ENGINE_COMMIT.to_owned(),
        inc_params: inc_digest,
        cand_engine: ENGINE_COMMIT.to_owned(),
        cand_params: cand_digest,
    }
}

/// Run git with the given arguments in `dir`, succeeding.
fn git(dir: &Path, args: &[&str]) {
    let result = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git fixture");
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "git {args:?} failed: {stderr}");
}

/// Run git with the given arguments in `dir`, returning its trimmed stdout.
fn git_stdout(dir: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git fixture");
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "git {args:?} failed: {stderr}");
    String::from_utf8_lossy(&result.stdout).trim().to_owned()
}

#[test]
fn compare_promotes_a_clear_held_out_win_and_writes_the_proposal() {
    let dir = tempfile::tempdir().expect("compare fixture dir");
    let promotion = promote(dir.path());
    let summary = &promotion.summary;
    assert_eq!(summary["verdict"], json!("promote"));
    assert_eq!(summary["decided_by"], json!("dominance"));
    assert_eq!(summary["ruler_paths"]["touched"], json!([]));
    assert_eq!(summary["ruler_paths"]["source"], json!("same_commit"));
    let bounds = summary["bootstrap"].as_array().expect("bounds");
    assert_eq!(bounds.len(), 1);
    for bound in bounds {
        assert!(bound["lower_bound"].as_f64().expect("bound") > 0.0);
    }
    let record = promotion
        .proposals
        .join(&promotion.proposal_id)
        .join("held_out.json");
    assert!(record.is_file());
    assert_eq!(
        summary["proposal_record"],
        json!(record.to_str().expect("record path"))
    );
    let bytes = std::fs::read(&record).expect("record reads");
    let held: Value = serde_json::from_slice(&bytes).expect("record is JSON");
    assert_eq!(held["decided_at"], json!(1_700_000_000));
    let weights = &promotion.weights;
    assert_eq!(
        held["candidate_params"],
        json!({
            "contract": "oneiron.retrieval_eval_params.v1",
            "blend_weights": weights,
        })
    );
    let incumbent = ExperimentIdentity {
        engine_commit: promotion.inc_engine.clone(),
        params_digest: promotion.inc_params.clone(),
        pack_digest: HELD_OUT_DIGEST.to_owned(),
    };
    let candidate = ExperimentIdentity {
        engine_commit: promotion.cand_engine.clone(),
        params_digest: promotion.cand_params.clone(),
        pack_digest: HELD_OUT_DIGEST.to_owned(),
    };
    let computed = proposal_id(CAMPAIGN_ID, &incumbent, &candidate).expect("proposal id");
    let wanted = json!(computed);
    assert_eq!(held["proposal_id"], wanted);
    assert_eq!(summary["proposal_id"], wanted);
}

#[test]
fn compare_rejects_a_dominance_win_the_bootstrap_does_not_back() {
    let dir = tempfile::tempdir().expect("bootstrap fixture dir");
    let campaign = write_campaign(dir.path(), "campaign.json", standard_axes());
    let weights = candidate_weights();
    let (params_path, cand_digest) = write_params(dir.path(), "params.json", weights);
    let inc_digest = learned_digest();
    let mut incumbent = card(
        Slice::HeldOut,
        ENGINE_COMMIT,
        &inc_digest,
        HELD_OUT_DIGEST,
        flat_queries("q", 0.4),
    );
    incumbent.metrics.ndcg_at_10 = 0.4;
    let mut candidate = card(
        Slice::HeldOut,
        ENGINE_COMMIT,
        &cand_digest,
        HELD_OUT_DIGEST,
        flat_queries("q", 0.4),
    );
    candidate.metrics.ndcg_at_10 = 0.5;
    candidate.per_query[0] = qs("q-00", Some(1.0));
    incumbent.per_query[0] = qs("q-00", Some(0.1));
    let base = dir.path().join("base.json");
    let cand = dir.path().join("cand.json");
    write_card(&base, &incumbent);
    write_card(&cand, &candidate);
    let proposals = dir.path().join("proposals");
    let result = scorecard(&[
        "compare",
        "--campaign",
        campaign.to_str().expect("campaign path"),
        "--candidate-params",
        params_path.to_str().expect("params path"),
        "--proposals",
        proposals.to_str().expect("proposals path"),
        "--at",
        "1700000000",
        base.to_str().expect("base path"),
        cand.to_str().expect("cand path"),
    ]);
    assert_eq!(result.status.code(), Some(1));
    let summary: Value = serde_json::from_slice(&result.stdout).expect("reject prints JSON");
    assert_eq!(summary["verdict"], json!("reject"));
    assert_eq!(summary["decided_by"], json!("bootstrap"));
    assert!(summary.get("error").is_none(), "no error key");
    assert_eq!(summary["proposal_record"], Value::Null);
    assert!(nothing_written(&proposals), "writes nothing");
}

#[test]
fn compare_rejects_a_candidate_whose_commit_changes_a_ruler_path() {
    let dir = tempfile::tempdir().expect("ruler paths fixture dir");
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).expect("repo dir");
    git(&repo, &["init"]);
    let ruler_dir = repo.join("crates").join("oneiron-ruler");
    std::fs::create_dir_all(ruler_dir.join("src")).expect("ruler dir");
    std::fs::create_dir_all(repo.join("docs")).expect("docs dir");
    std::fs::write(ruler_dir.join("RULER-PATHS.txt"), SHIPPED_RULER_PATHS).expect("ruler paths");
    let listed = ruler_dir.join("src").join("pack.rs");
    std::fs::write(&listed, "v1\n").expect("listed file");
    let unlisted = repo.join("docs").join("notes.txt");
    std::fs::write(&unlisted, "hello\n").expect("unlisted file");
    git(&repo, &["add", "-A"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "base",
        ],
    );
    let commit_a = git_stdout(&repo, &["rev-parse", "HEAD"]);
    std::fs::write(&unlisted, "hello again\n").expect("unlisted change");
    git(&repo, &["add", "-A"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "unlisted",
        ],
    );
    let commit_b = git_stdout(&repo, &["rev-parse", "HEAD"]);
    std::fs::write(&listed, "v2\n").expect("listed change");
    git(&repo, &["add", "-A"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "listed",
        ],
    );
    let commit_c = git_stdout(&repo, &["rev-parse", "HEAD"]);
    let campaign = write_campaign(dir.path(), "campaign.json", standard_axes());
    let campaign_arg = campaign.to_str().expect("campaign path").to_owned();
    let repo_arg = repo.to_str().expect("repo path").to_owned();
    let params_inc = "c".repeat(64);
    let params_cand = "d".repeat(64);
    let (incumbent, unlisted_cand) =
        clear_win_cards(&commit_a, &commit_b, &params_inc, &params_cand);
    let base = dir.path().join("base.json");
    write_card(&base, &incumbent);
    let cand_b = dir.path().join("cand-b.json");
    write_card(&cand_b, &unlisted_cand);
    let (_, listed_cand) = clear_win_cards(&commit_a, &commit_c, &params_inc, &params_cand);
    let cand_c = dir.path().join("cand-c.json");
    write_card(&cand_c, &listed_cand);
    let base_arg = base.to_str().expect("base path").to_owned();
    let cand_b_arg = cand_b.to_str().expect("cand b path").to_owned();
    let cand_c_arg = cand_c.to_str().expect("cand c path").to_owned();
    let clean = scorecard(&[
        "compare",
        "--campaign",
        campaign_arg.as_str(),
        "--repo",
        repo_arg.as_str(),
        base_arg.as_str(),
        cand_b_arg.as_str(),
    ]);
    let clean_stderr = String::from_utf8_lossy(&clean.stderr);
    assert!(
        clean.status.success(),
        "clean compare failed: {clean_stderr}"
    );
    let summary: Value = serde_json::from_slice(&clean.stdout).expect("clean prints JSON");
    assert_eq!(summary["verdict"], json!("promote"));
    assert_eq!(summary["ruler_paths"]["touched"], json!([]));
    assert_eq!(summary["ruler_paths"]["source"], json!("base_commit"));
    let dirty = scorecard(&[
        "compare",
        "--campaign",
        campaign_arg.as_str(),
        "--repo",
        repo_arg.as_str(),
        base_arg.as_str(),
        cand_c_arg.as_str(),
    ]);
    assert_eq!(dirty.status.code(), Some(1));
    let judged: Value = serde_json::from_slice(&dirty.stdout).expect("dirty prints JSON");
    assert_eq!(judged["verdict"], json!("reject"));
    assert_eq!(judged["decided_by"], json!("ruler_paths"));
    assert_eq!(
        judged["ruler_paths"]["touched"],
        json!(["crates/oneiron-ruler/src/pack.rs"])
    );
}

#[test]
fn compare_refuses_bad_input_before_writing() {
    let dir = tempfile::tempdir().expect("bad input fixture dir");
    // A card whose pack digest is not the campaign's held_out revision.
    {
        let case = dir.path().join("digest");
        std::fs::create_dir(&case).expect("case dir");
        let campaign = write_campaign(&case, "campaign.json", standard_axes());
        let (params_path, cand_digest) = write_params(&case, "params.json", candidate_weights());
        let (incumbent, mut candidate) = clear_win_cards(
            ENGINE_COMMIT,
            ENGINE_COMMIT,
            &learned_digest(),
            &cand_digest,
        );
        candidate.pack_digest = SEALED_DIGEST.to_owned();
        let base = case.join("base.json");
        let cand = case.join("cand.json");
        write_card(&base, &incumbent);
        write_card(&cand, &candidate);
        let proposals = case.join("proposals");
        let result = scorecard(&[
            "compare",
            "--campaign",
            campaign.to_str().expect("campaign path"),
            "--candidate-params",
            params_path.to_str().expect("params path"),
            "--proposals",
            proposals.to_str().expect("proposals path"),
            "--at",
            "1700000000",
            base.to_str().expect("base path"),
            cand.to_str().expect("cand path"),
        ]);
        assert_input_error(&result, &proposals);
    }
    // A campaign naming an unknown axis.
    {
        let case = dir.path().join("axis");
        std::fs::create_dir(&case).expect("case dir");
        let axes = vec![
            axis("ndcg_at_11", "higher", "primary", None),
            axis("recall_at_5", "higher", "floor", Some(0.001)),
            axis("search_p95_us", "lower", "cost", Some(50.0)),
        ];
        let campaign = write_campaign(&case, "campaign.json", axes);
        let (params_path, cand_digest) = write_params(&case, "params.json", candidate_weights());
        let (incumbent, candidate) = clear_win_cards(
            ENGINE_COMMIT,
            ENGINE_COMMIT,
            &learned_digest(),
            &cand_digest,
        );
        let base = case.join("base.json");
        let cand = case.join("cand.json");
        write_card(&base, &incumbent);
        write_card(&cand, &candidate);
        let proposals = case.join("proposals");
        let result = scorecard(&[
            "compare",
            "--campaign",
            campaign.to_str().expect("campaign path"),
            "--candidate-params",
            params_path.to_str().expect("params path"),
            "--proposals",
            proposals.to_str().expect("proposals path"),
            "--at",
            "1700000000",
            base.to_str().expect("base path"),
            cand.to_str().expect("cand path"),
        ]);
        assert_input_error(&result, &proposals);
    }
    // A primary axis with no per-query values.
    {
        let case = dir.path().join("per-query");
        std::fs::create_dir(&case).expect("case dir");
        let axes = vec![
            axis("abstention_f1", "higher", "primary", None),
            axis("recall_at_5", "higher", "floor", Some(0.001)),
            axis("search_p95_us", "lower", "cost", Some(50.0)),
        ];
        let campaign = write_campaign(&case, "campaign.json", axes);
        let (params_path, cand_digest) = write_params(&case, "params.json", candidate_weights());
        let (incumbent, candidate) = clear_win_cards(
            ENGINE_COMMIT,
            ENGINE_COMMIT,
            &learned_digest(),
            &cand_digest,
        );
        let base = case.join("base.json");
        let cand = case.join("cand.json");
        write_card(&base, &incumbent);
        write_card(&cand, &candidate);
        let proposals = case.join("proposals");
        let result = scorecard(&[
            "compare",
            "--campaign",
            campaign.to_str().expect("campaign path"),
            "--candidate-params",
            params_path.to_str().expect("params path"),
            "--proposals",
            proposals.to_str().expect("proposals path"),
            "--at",
            "1700000000",
            base.to_str().expect("base path"),
            cand.to_str().expect("cand path"),
        ]);
        assert_input_error(&result, &proposals);
    }
    // Differing engine commits without --repo.
    {
        let case = dir.path().join("repo");
        std::fs::create_dir(&case).expect("case dir");
        let campaign = write_campaign(&case, "campaign.json", standard_axes());
        let (params_path, cand_digest) = write_params(&case, "params.json", candidate_weights());
        let (incumbent, candidate) =
            clear_win_cards(ENGINE_COMMIT, ENGINE_OTHER, &learned_digest(), &cand_digest);
        let base = case.join("base.json");
        let cand = case.join("cand.json");
        write_card(&base, &incumbent);
        write_card(&cand, &candidate);
        let proposals = case.join("proposals");
        let result = scorecard(&[
            "compare",
            "--campaign",
            campaign.to_str().expect("campaign path"),
            "--candidate-params",
            params_path.to_str().expect("params path"),
            "--proposals",
            proposals.to_str().expect("proposals path"),
            "--at",
            "1700000000",
            base.to_str().expect("base path"),
            cand.to_str().expect("cand path"),
        ]);
        assert_input_error(&result, &proposals);
    }
    // --proposals without --at.
    {
        let case = dir.path().join("at");
        std::fs::create_dir(&case).expect("case dir");
        let campaign = write_campaign(&case, "campaign.json", standard_axes());
        let (params_path, cand_digest) = write_params(&case, "params.json", candidate_weights());
        let (incumbent, candidate) = clear_win_cards(
            ENGINE_COMMIT,
            ENGINE_COMMIT,
            &learned_digest(),
            &cand_digest,
        );
        let base = case.join("base.json");
        let cand = case.join("cand.json");
        write_card(&base, &incumbent);
        write_card(&cand, &candidate);
        let proposals = case.join("proposals");
        let result = scorecard(&[
            "compare",
            "--campaign",
            campaign.to_str().expect("campaign path"),
            "--candidate-params",
            params_path.to_str().expect("params path"),
            "--proposals",
            proposals.to_str().expect("proposals path"),
            base.to_str().expect("base path"),
            cand.to_str().expect("cand path"),
        ]);
        assert_input_error(&result, &proposals);
    }
    // A params file whose digest is not the candidate's.
    {
        let case = dir.path().join("params");
        std::fs::create_dir(&case).expect("case dir");
        let campaign = write_campaign(&case, "campaign.json", standard_axes());
        let (params_path, _) = write_params(&case, "params.json", other_weights());
        let cand_digest = params_digest_of(&candidate_weights());
        let (incumbent, candidate) = clear_win_cards(
            ENGINE_COMMIT,
            ENGINE_COMMIT,
            &learned_digest(),
            &cand_digest,
        );
        let base = case.join("base.json");
        let cand = case.join("cand.json");
        write_card(&base, &incumbent);
        write_card(&cand, &candidate);
        let proposals = case.join("proposals");
        let result = scorecard(&[
            "compare",
            "--campaign",
            campaign.to_str().expect("campaign path"),
            "--candidate-params",
            params_path.to_str().expect("params path"),
            "--proposals",
            proposals.to_str().expect("proposals path"),
            "--at",
            "1700000000",
            base.to_str().expect("base path"),
            cand.to_str().expect("cand path"),
        ]);
        assert_input_error(&result, &proposals);
    }
}

#[test]
fn sealed_compare_withdraws_on_a_floor_loss_and_the_owner_can_still_stamp() {
    let dir = tempfile::tempdir().expect("withdraw fixture dir");
    let promotion = promote(dir.path());
    let campaign_arg = promotion
        .campaign
        .to_str()
        .expect("campaign path")
        .to_owned();
    let proposals_arg = promotion
        .proposals
        .to_str()
        .expect("proposals path")
        .to_owned();
    let mut incumbent = card(
        Slice::Sealed,
        &promotion.inc_engine,
        &promotion.inc_params,
        SEALED_DIGEST,
        Vec::new(),
    );
    incumbent.query_count = 30;
    incumbent.metrics.ndcg_at_10 = 0.5;
    incumbent.metrics.recall_at_5 = 0.5;
    let mut candidate = card(
        Slice::Sealed,
        &promotion.cand_engine,
        &promotion.cand_params,
        SEALED_DIGEST,
        Vec::new(),
    );
    candidate.query_count = 30;
    candidate.metrics.ndcg_at_10 = 0.5;
    candidate.metrics.recall_at_5 = 0.49;
    let base = dir.path().join("sealed-base.json");
    let cand = dir.path().join("sealed-cand.json");
    write_card(&base, &incumbent);
    write_card(&cand, &candidate);
    let base_arg = base.to_str().expect("base path").to_owned();
    let cand_arg = cand.to_str().expect("cand path").to_owned();
    let judged = scorecard(&[
        "compare",
        "--sealed",
        "--campaign",
        campaign_arg.as_str(),
        "--proposals",
        proposals_arg.as_str(),
        "--proposal",
        promotion.proposal_id.as_str(),
        "--at",
        "1700000001",
        base_arg.as_str(),
        cand_arg.as_str(),
    ]);
    assert_eq!(judged.status.code(), Some(1));
    let summary: Value = serde_json::from_slice(&judged.stdout).expect("sealed prints JSON");
    assert_eq!(summary["verdict"], json!("withdrawn"));
    let reason = summary["reason"].as_str().expect("reason");
    assert!(
        reason.contains("recall_at_5"),
        "reason names the axis: {reason}"
    );
    let listed = scorecard(&["proposals", "--proposals", proposals_arg.as_str()]);
    let listed_stderr = String::from_utf8_lossy(&listed.stderr);
    assert!(listed.status.success(), "proposals failed: {listed_stderr}");
    let body: Value = serde_json::from_slice(&listed.stdout).expect("proposals prints JSON");
    let proposals = body["proposals"].as_array().expect("proposals");
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0]["status"], json!("withdrawn"));
    let listed_reason = proposals[0]["reason"].as_str().expect("listed reason");
    assert!(
        listed_reason.contains("recall_at_5"),
        "listed reason names the axis: {listed_reason}"
    );
    assert_eq!(
        proposals[0]["sealed"]["incumbent_sealed"]["engine_commit"],
        json!(&promotion.inc_engine)
    );
    assert_eq!(
        proposals[0]["sealed"]["candidate_sealed"]["engine_commit"],
        json!(&promotion.cand_engine)
    );
    let stamped = scorecard(&[
        "stamp",
        "--proposals",
        proposals_arg.as_str(),
        "--proposal",
        promotion.proposal_id.as_str(),
        "--at",
        "1700000002",
        "--note",
        "owen overrides the sealed check",
    ]);
    let stamped_stderr = String::from_utf8_lossy(&stamped.stderr);
    assert!(stamped.status.success(), "stamp failed: {stamped_stderr}");
    let stamp_body: Value = serde_json::from_slice(&stamped.stdout).expect("stamp prints JSON");
    assert_eq!(stamp_body["stamp"]["sealed_check"], json!("overridden"));
    let calls = stamp_body["pin_calls"].as_array().expect("pin calls");
    assert_eq!(calls.len(), PIN_SIGNALS.len());
    for (call, signal) in std::iter::zip(calls, PIN_SIGNALS) {
        assert_eq!(call["verb"], json!("vault.retrieval.policy.pin"));
        assert_eq!(call["input"]["signal"], json!(signal));
        assert_eq!(call["input"]["value"], promotion.weights[signal]);
    }
    let again = scorecard(&[
        "stamp",
        "--proposals",
        proposals_arg.as_str(),
        "--proposal",
        promotion.proposal_id.as_str(),
        "--at",
        "1700000003",
    ]);
    assert_eq!(again.status.code(), Some(2));
}

#[test]
fn sealed_compare_passes_within_tolerance_judges_no_cost_axis_and_runs_once() {
    let dir = tempfile::tempdir().expect("pass fixture dir");
    let promotion = promote(dir.path());
    let campaign_arg = promotion
        .campaign
        .to_str()
        .expect("campaign path")
        .to_owned();
    let proposals_arg = promotion
        .proposals
        .to_str()
        .expect("proposals path")
        .to_owned();
    let mut incumbent = card(
        Slice::Sealed,
        &promotion.inc_engine,
        &promotion.inc_params,
        SEALED_DIGEST,
        Vec::new(),
    );
    incumbent.query_count = 30;
    incumbent.metrics.ndcg_at_10 = 0.5;
    incumbent.metrics.recall_at_5 = 0.5;
    incumbent.latency.search_p95_us = 100;
    let mut candidate = card(
        Slice::Sealed,
        &promotion.cand_engine,
        &promotion.cand_params,
        SEALED_DIGEST,
        Vec::new(),
    );
    candidate.query_count = 30;
    candidate.metrics.ndcg_at_10 = 0.5;
    candidate.metrics.recall_at_5 = 0.4995;
    candidate.latency.search_p95_us = 5100;
    let base = dir.path().join("sealed-base.json");
    let cand = dir.path().join("sealed-cand.json");
    write_card(&base, &incumbent);
    write_card(&cand, &candidate);
    let base_arg = base.to_str().expect("base path").to_owned();
    let cand_arg = cand.to_str().expect("cand path").to_owned();
    let passed = scorecard(&[
        "compare",
        "--sealed",
        "--campaign",
        campaign_arg.as_str(),
        "--proposals",
        proposals_arg.as_str(),
        "--proposal",
        promotion.proposal_id.as_str(),
        "--at",
        "1700000001",
        base_arg.as_str(),
        cand_arg.as_str(),
    ]);
    let passed_stderr = String::from_utf8_lossy(&passed.stderr);
    assert!(
        passed.status.success(),
        "sealed compare failed: {passed_stderr}"
    );
    let summary: Value = serde_json::from_slice(&passed.stdout).expect("sealed prints JSON");
    assert_eq!(summary["verdict"], json!("passed"));
    assert!(summary["reason"].is_null());
    assert_eq!(summary["losses"], json!([]));
    let repeat = scorecard(&[
        "compare",
        "--sealed",
        "--campaign",
        campaign_arg.as_str(),
        "--proposals",
        proposals_arg.as_str(),
        "--proposal",
        promotion.proposal_id.as_str(),
        "--at",
        "1700000002",
        base_arg.as_str(),
        cand_arg.as_str(),
    ]);
    assert_eq!(repeat.status.code(), Some(2));
    let stamped = scorecard(&[
        "stamp",
        "--proposals",
        proposals_arg.as_str(),
        "--proposal",
        promotion.proposal_id.as_str(),
        "--at",
        "1700000003",
    ]);
    let stamped_stderr = String::from_utf8_lossy(&stamped.stderr);
    assert!(stamped.status.success(), "stamp failed: {stamped_stderr}");
    let stamp_body: Value = serde_json::from_slice(&stamped.stdout).expect("stamp prints JSON");
    assert_eq!(stamp_body["stamp"]["sealed_check"], json!("passed"));
    let calls = stamp_body["pin_calls"].as_array().expect("pin calls");
    assert_eq!(calls.len(), PIN_SIGNALS.len());
}
