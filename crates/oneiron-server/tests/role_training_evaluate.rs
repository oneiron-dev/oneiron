//! A returned role run scored by its role trainer's scorer process
//! (ROLE-TRAINING-RUN, RULING TRAIN-ROLE-EVALUATOR = A), served over the
//! real facade route through `vault.coach.training_runs.execute`:
//! - on a role trainer that names a scorer, the owner's execute trains the
//!   authorized run and then scores it: the tiny pinned scorer reads the
//!   exported checkpoint and the staged splits and writes one margin per
//!   pair, and the host computes preference accuracy, mean margin and, for
//!   the Decision seat, calibration from those margins, keeps its log and
//!   the scorer's receipt in custody, and removes the staged inputs;
//! - a scorer receipt that leaves a held-out pair without a margin scores
//!   nothing, and the run stays returned and unscored.
//!
//! Reads JSON and the vault's own run record, so on a head without the role
//! evaluator every case fails at its first execute, whose run holds with
//! `training.no_evaluator`.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! role_training_evaluate`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;
#[path = "support/role_training_fixture.rs"]
mod role_training_fixture;

use axum::http::StatusCode;
use engine_stack::run_on_engine_stack;
use oneiron::EntityId;
use oneiron::training_pack::{TrainingRun, TrainingState};
use role_training_fixture::{
    EXECUTE_VERB, Fixture, PREPARE_VERB, SCORED_ROLE_TRAINER, role_jobs_root, seed_role_run,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A wait long enough for the tiny worker and scorer to start and return.
const WAIT_MS: u64 = 20_000;

/// The owner prepares `draft` on the scored role trainer and authorizes it;
/// returns the run and its spec.
async fn prepare_and_authorize(fixture: &Fixture, draft: &Value) -> (String, String) {
    let (status, prepared) = fixture
        .as_owner(
            PREPARE_VERB,
            json!({"draft": draft, "connector": SCORED_ROLE_TRAINER}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "owner prepare: {prepared}");
    let run = prepared["run"].as_str().expect("run id").to_owned();
    let spec = prepared["spec"].as_str().expect("spec").to_owned();
    let (status, handoff) = fixture.authorize(&run, &spec).await;
    assert_eq!(status, StatusCode::OK, "owner authorize: {handoff}");
    (run, spec)
}

fn stored(fixture: &Fixture, run: &str) -> TrainingRun {
    fixture
        .vault
        .training_run(&EntityId::from_hex(run).expect("run hex"))
        .expect("read the run")
        .expect("the run is stored")
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Every file under `dir`, recursively.
fn files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read a directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else {
            files.push(path);
        }
    }
    files
}

/// The run's score directories under the role jobs root.
fn score_dirs(fixture: &Fixture, run: &str, spec: &str) -> Vec<std::path::PathBuf> {
    let prefix = format!("{run}-{spec}.score-");
    std::fs::read_dir(role_jobs_root(fixture.dir.path()))
        .expect("read the role jobs root")
        .map(|entry| entry.expect("jobs root entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&prefix))
        })
        .collect()
}

/// What a score directory holds, for an assert message.
fn score_evidence(dirs: &[std::path::PathBuf]) -> String {
    dirs.iter()
        .map(|dir| {
            let read = |name: &str| {
                std::fs::read_to_string(dir.join(name)).unwrap_or_else(|error| format!("<{error}>"))
            };
            format!(
                "{}\nscorer.stderr: {}\nreceipt: {}",
                dir.display(),
                read("scorer.stderr"),
                read("output/receipt.json")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The one non-empty line of a split.
fn only_line(bytes: &[u8]) -> &[u8] {
    let mut lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let line = lines.next().expect("one row");
    assert!(lines.next().is_none(), "the fixture split holds one row");
    line
}

/// The tiny scorer's margin for a pair line: (len(chosen) - len(rejected)) / 8.
fn fixture_margin(line: &[u8]) -> f64 {
    let pair: Value = serde_json::from_slice(line).expect("pair JSON");
    let length = |side: &str| {
        pair[side]
            .as_str()
            .expect("the fixture pair's texts are strings")
            .chars()
            .count() as f64
    };
    (length("chosen") - length("rejected")) / 8.0
}

/// Asserts no file under `dir` holds `line`.
fn assert_not_held(dir: &std::path::Path, line: &[u8]) {
    for file in files_under(dir) {
        let bytes = std::fs::read(&file).expect("read a score file");
        assert!(
            !bytes.windows(line.len()).any(|window| window == line),
            "a split row stayed in {}",
            file.display()
        );
    }
}

#[test]
fn owner_execute_scores_a_returned_role_run_through_its_trainers_scorer() {
    run_on_engine_stack("role-evaluate-owner", || async {
        let fixture = Fixture::new().await;
        let seeded = seed_role_run(&fixture.vault);
        let (run, spec) = prepare_and_authorize(&fixture, &seeded.draft).await;

        let (status, read) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": WAIT_MS}))
            .await;
        let dirs = score_dirs(&fixture, &run, &spec);
        assert_eq!(status, StatusCode::OK, "owner execute: {read}");
        assert_eq!(read["state"], "scored", "{read}\n{}", score_evidence(&dirs));
        assert_eq!(read["progress"], json!({"status": "done"}), "{read}");
        assert_eq!(dirs.len(), 1, "one score directory: {dirs:?}");
        let dir = &dirs[0];

        let record = stored(&fixture, &run);
        let held_out = fixture
            .vault
            .read_training_artifact(&record.corpus.held_out)
            .expect("read the held-out split");
        let training = fixture
            .vault
            .read_training_artifact(&record.corpus.training)
            .expect("read the training split");
        let held_out_line = only_line(&held_out);
        let training_line = only_line(&training);
        let margin = fixture_margin(held_out_line);
        assert!(margin > 0.0, "the fixture's chosen text is the longer one");

        // The host's measurements, from the scorer's margins alone.
        let evaluation = record.evaluation.as_ref().expect("the stored evaluation");
        assert_eq!(evaluation.cases, 1, "{evaluation:?}");
        assert_eq!(evaluation.metrics["preference_accuracy"], 1.0);
        assert_eq!(evaluation.metrics["correct"], 1.0);
        assert_eq!(evaluation.metrics["incorrect"], 0.0);
        assert_eq!(evaluation.metrics["ties"], 0.0);
        assert_eq!(evaluation.metrics["mean_margin"], margin);
        assert!(
            evaluation.passed,
            "no criterion is authored: {evaluation:?}"
        );
        let calibration = evaluation
            .calibration
            .as_ref()
            .expect("the Decision seat reports calibration");
        assert!(
            calibration.temperature.is_finite() && calibration.temperature > 0.0,
            "{calibration:?}"
        );
        for name in [
            "preference_brier",
            "preference_ece",
            "uncalibrated_preference_brier",
            "uncalibrated_preference_ece",
        ] {
            assert!(
                evaluation.metrics.contains_key(name),
                "{name}: {evaluation:?}"
            );
        }
        assert_eq!(
            read["evaluation"]["metrics"]["preference_accuracy"], 1.0,
            "{read}"
        );

        // Two run-bound verifier logs: the host's measurement log and the
        // scorer's receipt as it wrote it.
        assert_eq!(evaluation.verifier_logs.len(), 2, "{evaluation:?}");
        let log: Value = serde_json::from_slice(
            &fixture
                .vault
                .read_training_artifact(&evaluation.verifier_logs[0])
                .expect("read the measurement log"),
        )
        .expect("log JSON");
        assert_eq!(log["format"], "oneiron.role-held-out/1", "{log}");
        assert_eq!(log["calibration_fitting_split"], "training", "{log}");
        assert_eq!(
            log["cases"][0]["row_sha256"],
            sha256_hex(held_out_line),
            "{log}"
        );
        assert_eq!(log["cases"][0]["margin"], margin, "{log}");
        assert_eq!(log["cases"][0]["chosen_first"], true, "{log}");
        let scorer = std::fs::read(fixture.dir.path().join("trainer/role_trainer_scorer.py"))
            .expect("read the scorer");
        assert_eq!(log["scorer_sha256"], sha256_hex(&scorer), "{log}");
        let receipt_bytes = fixture
            .vault
            .read_training_artifact(&evaluation.verifier_logs[1])
            .expect("read the scorer's receipt");
        assert_eq!(
            std::fs::read(dir.join("output/receipt.json")).expect("the receipt on disk"),
            receipt_bytes
        );

        // The scorer read the exported checkpoint and both splits.
        let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("receipt JSON");
        let weights = record
            .result
            .as_ref()
            .expect("the returned result")
            .exported_checkpoint
            .files
            .iter()
            .find(|file| file.name == "adapter.safetensors")
            .expect("the exported weights");
        let weights = fixture
            .vault
            .read_training_artifact(&weights.content)
            .expect("read the exported weights");
        assert_eq!(
            receipt["checkpoint"]["files"],
            json!([{"name": "adapter.safetensors", "sha256": sha256_hex(&weights)}]),
            "{receipt}"
        );
        assert_eq!(
            receipt["held_out"]["sha256"],
            sha256_hex(&held_out),
            "{receipt}"
        );
        assert_eq!(
            receipt["training"]["sha256"],
            sha256_hex(&training),
            "{receipt}"
        );
        assert_eq!(
            receipt["training"]["margins"][0]["margin"],
            fixture_margin(training_line),
            "{receipt}"
        );

        // The staged inputs are gone; the request, output and stderr stay.
        for name in ["held-out.jsonl", "training.jsonl", "checkpoint"] {
            assert!(
                !dir.join(name).exists(),
                "{name} stayed in {}",
                dir.display()
            );
        }
        for name in ["request.json", "output/receipt.json", "scorer.stderr"] {
            assert!(
                dir.join(name).is_file(),
                "{name} is kept in {}",
                dir.display()
            );
        }
        assert_not_held(dir, held_out_line);
        assert_not_held(dir, training_line);

        // A second execute finds the run scored: nothing runs again.
        let (status, again) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": 0}))
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["state"], "scored", "{again}");
        assert_eq!(score_dirs(&fixture, &run, &spec).len(), 1);
        fixture.finish().await;
    });
}

#[test]
fn a_scorer_receipt_without_a_margin_for_each_held_out_pair_scores_nothing() {
    run_on_engine_stack("role-evaluate-short-receipt", || async {
        let fixture = Fixture::new().await;
        let mut seeded = seed_role_run(&fixture.vault);
        seeded.draft["plan"]["settings"]["fixture_scorer_fault"] = json!("drop_held_out_margin");
        let (run, spec) = prepare_and_authorize(&fixture, &seeded.draft).await;

        let (status, body) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": WAIT_MS}))
            .await;
        let dirs = score_dirs(&fixture, &run, &spec);
        assert!(
            status.is_server_error(),
            "{status}: {body}\n{}",
            score_evidence(&dirs)
        );
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|text| text.contains(EXECUTE_VERB)),
            "the failure names the verb: {body}"
        );
        let record = stored(&fixture, &run);
        assert_eq!(record.state, TrainingState::Returned);
        assert!(record.evaluation.is_none(), "nothing scored the run");

        // The scorer ran once and its staged inputs are gone all the same.
        assert_eq!(dirs.len(), 1, "one score directory: {dirs:?}");
        let receipt: Value = serde_json::from_slice(
            &std::fs::read(dirs[0].join("output/receipt.json")).expect("the receipt on disk"),
        )
        .expect("receipt JSON");
        assert_eq!(receipt["status"], "scored", "{receipt}");
        assert_eq!(receipt["held_out"]["margins"], json!([]), "{receipt}");
        for name in ["held-out.jsonl", "training.jsonl", "checkpoint"] {
            assert!(!dirs[0].join(name).exists(), "{name} stayed");
        }
        fixture.finish().await;
    });
}
