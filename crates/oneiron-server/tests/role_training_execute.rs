//! `vault.coach.training_runs.execute` served over the real facade route,
//! on the role trainer (ROLE-TRAINING-RUN, LEARN-TRAIN Q2 and Q4):
//! - a prepared run is refused until the owner authorizes it; once
//!   authorized, the owner's execute dispatches it to the role trainer,
//!   whose tiny pinned worker reads the staged training split and nothing
//!   held out, and the run returns inside the bound with its checks passed,
//!   bound to nothing, and waits on the host for an evaluator;
//! - a run whose waiter is lost (a host restart) and whose receipt lands
//!   after the execute's first step still returns inside the bound: the
//!   execute polls the trainer again while it waits;
//! - an agent executes only with a Grant listing the verb;
//! - a role run on a question connector, or on a recipe the role trainer does
//!   not list, holds with `training.no_connector` and answers at once;
//! - an unknown run and a wait above the cap are refused;
//! - the export check judges the difference the probe's own logits give, not
//!   the worker's stated one, so a summary inside the wire's rounding slack
//!   does not pass a zero tolerance.
//!
//! Reads JSON and the vault's own run record, so on a main without the role
//! trainer every case fails at its first role-trainer prepare (404, no such
//! connector) or its first execute (unknown verb).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! role_training_execute`.
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
    CONNECTOR, EXECUTE_VERB, Fixture, PREPARE_VERB, ROLE_TRAINER, role_jobs_root, seed_role_run,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A wait long enough for the tiny worker to start, read and return.
const WAIT_MS: u64 = 20_000;

/// The owner prepares `draft` on `connector`; returns the run and its spec.
async fn prepare(fixture: &Fixture, draft: &Value, connector: &str) -> (String, String) {
    let (status, prepared) = fixture
        .as_owner(
            PREPARE_VERB,
            json!({"draft": draft, "connector": connector}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "owner prepare: {prepared}");
    (
        prepared["run"].as_str().expect("run id").to_owned(),
        prepared["spec"].as_str().expect("spec").to_owned(),
    )
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

/// What the role worker left in its job directory, for an assert message.
fn job_evidence(job: &std::path::Path) -> String {
    let read = |name: &str| {
        std::fs::read_to_string(job.join(name)).unwrap_or_else(|error| format!("<{error}>"))
    };
    format!(
        "worker.stderr: {}\nreceipt: {}",
        read("worker.stderr"),
        read("output/receipt.json")
    )
}

/// Every file under `dir`, recursively.
fn files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read a job directory") {
        let path = entry.expect("job directory entry").path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else {
            files.push(path);
        }
    }
    files
}

#[test]
fn owner_executes_an_authorized_role_run_on_the_role_trainer_that_reads_the_staged_split() {
    run_on_engine_stack("role-execute-owner", || async {
        let fixture = Fixture::new().await;
        let seeded = seed_role_run(&fixture.vault);
        let (run, spec) = prepare(&fixture, &seeded.draft, ROLE_TRAINER).await;

        // Execute never authorizes: a prepared run waits for the owner.
        let (status, body) = fixture.as_owner(EXECUTE_VERB, json!({"run": run})).await;
        assert_eq!(status, StatusCode::CONFLICT, "prepared run: {body}");
        assert_eq!(stored(&fixture, &run).state, TrainingState::Prepared);

        let (status, handoff) = fixture.authorize(&run, &spec).await;
        assert_eq!(status, StatusCode::OK, "owner authorize: {handoff}");
        let (status, read) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": WAIT_MS}))
            .await;
        let job = role_jobs_root(fixture.dir.path()).join(format!("{run}-{spec}"));
        assert_eq!(status, StatusCode::OK, "owner execute: {read}");
        assert_eq!(read["state"], "returned", "{read}\n{}", job_evidence(&job));
        // No role evaluator ships yet: the returned run waits on the host.
        assert_eq!(
            read["progress"],
            json!({"status": "outstanding", "needs": "host"}),
            "{read}"
        );
        assert_eq!(read["hold"]["code"], "training.no_evaluator", "{read}");
        assert!(read["waited_ms"].as_u64() < Some(WAIT_MS), "{read}");

        // The worker read the run's staged training split, and no held-out
        // byte was staged for it.
        let record = stored(&fixture, &run);
        let training = fixture
            .vault
            .read_training_artifact(&record.corpus.training)
            .expect("read the training split");
        let held_out = fixture
            .vault
            .read_training_artifact(&record.corpus.held_out)
            .expect("read the held-out split");
        assert_eq!(
            std::fs::read(job.join("training.jsonl")).expect("staged training rows"),
            training
        );
        let receipt: Value = serde_json::from_slice(
            &std::fs::read(job.join("output/receipt.json")).expect("the worker's receipt"),
        )
        .expect("receipt JSON");
        assert_eq!(
            receipt["training"]["sha256"],
            sha256_hex(&training),
            "{receipt}"
        );
        assert_eq!(receipt["training"]["rows"], 1, "{receipt}");
        let held_out_line = held_out
            .split(|byte| *byte == b'\n')
            .find(|line| !line.is_empty())
            .expect("one held-out row");
        for file in files_under(&job) {
            let bytes = std::fs::read(&file).expect("read a job file");
            assert!(
                !bytes
                    .windows(held_out_line.len())
                    .any(|window| window == held_out_line),
                "a held-out row was staged in {}",
                file.display()
            );
        }

        // The returned checkpoint is in custody, its checks pass, and it
        // records the rows the worker read; nothing is bound.
        let result = record.result.as_ref().expect("the returned result");
        let checks = &result.checks;
        assert!(checks.hash_mismatches.is_empty(), "{checks:?}");
        assert!(checks.probe_coverage_matches, "{checks:?}");
        assert!(checks.probe_checkpoints_match, "{checks:?}");
        assert!(
            checks.settings_match && checks.harness_matches,
            "{checks:?}"
        );
        assert_eq!(checks.argmax_flips, 0, "{checks:?}");
        assert!(checks.question_check.is_none() && checks.candle_parity.is_none());
        let weights = result
            .exported_checkpoint
            .files
            .iter()
            .find(|file| file.name == "adapter.safetensors")
            .expect("the exported weights");
        let weights = fixture
            .vault
            .read_training_artifact(&weights.content)
            .expect("read the exported weights");
        let marker = format!("training sha256 {}", sha256_hex(&training));
        assert!(
            String::from_utf8_lossy(&weights).contains(&marker),
            "the weights name the rows the worker read"
        );
        assert!(record.evaluation.is_none(), "nothing scored the run");

        // A second execute takes the returned run's step again: it stays
        // held, and the trainer does not run again.
        let (status, again) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": 0}))
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["state"], "returned", "{again}");
        assert_eq!(again["hold"]["code"], "training.no_evaluator", "{again}");
        assert_eq!(
            stored(&fixture, &run)
                .result
                .as_ref()
                .map(|r| &r.connector_receipt),
            Some(&result.connector_receipt)
        );
        fixture.finish().await;
    });
}

/// A run whose waiter is lost, as after a host restart, moves only when a
/// step recovers its trainer's receipt. The receipt lands after the
/// execute's first step, so only an execute that polls the trainer again
/// while it waits returns the run inside the bound; the waiter that rejoins
/// later records nothing new.
#[test]
fn execute_recovers_a_run_whose_waiter_is_lost_when_its_receipt_lands_inside_the_bound() {
    run_on_engine_stack("role-execute-lost-waiter", || async {
        let fixture = Fixture::new().await;
        let mut seeded = seed_role_run(&fixture.vault);
        seeded.draft["plan"]["settings"]["receipt_delay_seconds"] = json!(2);
        let (run, spec) = prepare(&fixture, &seeded.draft, ROLE_TRAINER).await;
        let (status, handoff) = fixture.authorize(&run, &spec).await;
        assert_eq!(status, StatusCode::OK, "owner authorize: {handoff}");
        let waiter = fixture.dispatch_with_lost_waiter(&run).await;
        let job = role_jobs_root(fixture.dir.path()).join(format!("{run}-{spec}"));
        assert_eq!(stored(&fixture, &run).state, TrainingState::Running);
        assert!(
            !job.join("output/receipt.json").exists(),
            "the receipt lands after the execute's first step"
        );

        let (status, read) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": WAIT_MS}))
            .await;
        assert_eq!(status, StatusCode::OK, "owner execute: {read}");
        assert_eq!(read["state"], "returned", "{read}\n{}", job_evidence(&job));
        assert_eq!(read["hold"]["code"], "training.no_evaluator", "{read}");
        assert!(read["waited_ms"].as_u64() < Some(WAIT_MS), "{read}");
        let recovered = stored(&fixture, &run)
            .result
            .expect("the recovered result")
            .connector_receipt;

        tokio::task::spawn_blocking(move || waiter.rejoin())
            .await
            .expect("the waiter rejoins");
        let record = stored(&fixture, &run);
        assert_eq!(record.state, TrainingState::Returned);
        assert_eq!(
            record.result.map(|result| result.connector_receipt),
            Some(recovered)
        );
        fixture.finish().await;
    });
}

#[test]
fn agent_executes_a_run_only_with_a_grant_listing_execute() {
    run_on_engine_stack("role-execute-agent", || async {
        let fixture = Fixture::new().await;
        let seeded = seed_role_run(&fixture.vault);
        let (run, spec) = prepare(&fixture, &seeded.draft, ROLE_TRAINER).await;
        let (status, handoff) = fixture.authorize(&run, &spec).await;
        assert_eq!(status, StatusCode::OK, "owner authorize: {handoff}");
        let agent = fixture.pair_agent("role-execute-agent", [0x57; 32]).await;

        let (status, body) = fixture
            .as_agent(&agent, EXECUTE_VERB, json!({"run": run}))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no Grant: {body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|text| text.contains(EXECUTE_VERB)),
            "the refusal names the verb: {body}"
        );
        assert_eq!(
            stored(&fixture, &run).state,
            TrainingState::Authorized,
            "a refused execute dispatches nothing"
        );

        fixture
            .mint_grant(&agent.principal.to_hex(), &[EXECUTE_VERB])
            .await;
        let (status, read) = fixture
            .as_agent(
                &agent,
                EXECUTE_VERB,
                json!({"run": run, "wait_ms": WAIT_MS}),
            )
            .await;
        let job = role_jobs_root(fixture.dir.path()).join(format!("{run}-{spec}"));
        assert_eq!(status, StatusCode::OK, "granted agent: {read}");
        assert_eq!(read["state"], "returned", "{read}\n{}", job_evidence(&job));
        assert_eq!(read["hold"]["code"], "training.no_evaluator", "{read}");
        fixture.finish().await;
    });
}

#[test]
fn execute_holds_a_role_run_on_a_question_connector_at_once() {
    run_on_engine_stack("role-execute-question-connector", || async {
        let fixture = Fixture::new().await;
        let seeded = seed_role_run(&fixture.vault);
        let (run, spec) = prepare(&fixture, &seeded.draft, CONNECTOR).await;
        let (status, handoff) = fixture.authorize(&run, &spec).await;
        assert_eq!(status, StatusCode::OK, "owner authorize: {handoff}");

        let (status, read) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": WAIT_MS}))
            .await;
        assert_eq!(status, StatusCode::OK, "{read}");
        assert_eq!(read["state"], "authorized", "{read}");
        assert_eq!(
            read["progress"],
            json!({"status": "outstanding", "needs": "host"}),
            "{read}"
        );
        assert_eq!(read["hold"]["code"], "training.no_connector", "{read}");
        // The hold is the step's answer: the execute does not wait it out.
        assert!(read["waited_ms"].as_u64() < Some(WAIT_MS / 2), "{read}");

        // An unknown run and a wait above the cap are refused.
        let (status, body) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": EntityId::now().to_hex()}))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let (status, body) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": 30_001}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        fixture.finish().await;
    });
}

#[test]
fn execute_holds_a_role_run_on_a_recipe_the_role_trainer_does_not_list() {
    run_on_engine_stack("role-execute-unlisted-recipe", || async {
        let fixture = Fixture::new().await;
        let mut seeded = seed_role_run(&fixture.vault);
        seeded.draft["plan"]["settings"]["recipe"] = json!("fixture.unlisted-recipe/1");
        let (run, spec) = prepare(&fixture, &seeded.draft, ROLE_TRAINER).await;
        let (status, handoff) = fixture.authorize(&run, &spec).await;
        assert_eq!(status, StatusCode::OK, "owner authorize: {handoff}");

        let (status, read) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": WAIT_MS}))
            .await;
        assert_eq!(status, StatusCode::OK, "{read}");
        assert_eq!(read["state"], "authorized", "{read}");
        assert_eq!(read["hold"]["code"], "training.no_connector", "{read}");
        assert!(
            !role_jobs_root(fixture.dir.path())
                .join(format!("{run}-{spec}"))
                .exists(),
            "no job directory for a run the trainer does not serve"
        );
        fixture.finish().await;
    });
}

/// The worker states a largest logit difference of 0 while its export logits
/// sit 5e-10 from its training ones: inside the wire's rounding slack, so the
/// receipt is accepted, but the engine keeps the 5e-10 its logits give, and
/// that fails the owner's zero tolerance.
#[test]
fn the_export_check_judges_the_logits_difference_not_the_workers_summary() {
    run_on_engine_stack("role-execute-logit-difference", || async {
        let fixture = Fixture::new().await;
        let mut seeded = seed_role_run(&fixture.vault);
        seeded.draft["plan"]["export_logit_tolerance"] = json!(0.0);
        seeded.draft["plan"]["settings"]["export_logit_skew"] = json!(5e-10);
        let (run, spec) = prepare(&fixture, &seeded.draft, ROLE_TRAINER).await;
        let (status, handoff) = fixture.authorize(&run, &spec).await;
        assert_eq!(status, StatusCode::OK, "owner authorize: {handoff}");

        let (status, read) = fixture
            .as_owner(EXECUTE_VERB, json!({"run": run, "wait_ms": WAIT_MS}))
            .await;
        let job = role_jobs_root(fixture.dir.path()).join(format!("{run}-{spec}"));
        assert_eq!(status, StatusCode::OK, "owner execute: {read}");
        assert_eq!(read["state"], "returned", "{read}\n{}", job_evidence(&job));
        let receipt: Value = serde_json::from_slice(
            &std::fs::read(job.join("output/receipt.json")).expect("the worker's receipt"),
        )
        .expect("receipt JSON");
        assert_eq!(
            receipt["probes"][0]["max_logit_difference"],
            json!(0.0),
            "{receipt}"
        );

        let record = stored(&fixture, &run);
        let checks = &record.result.as_ref().expect("the returned result").checks;
        assert_eq!(checks.argmax_flips, 0, "{checks:?}");
        assert!(
            checks.max_logit_difference > checks.tolerance,
            "the logits' difference is kept: {checks:?}"
        );
        assert!(!checks.passed(), "{checks:?}");
        fixture.finish().await;
    });
}
