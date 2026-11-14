//! ARCH-0053 `#eval-trace-task` (census L1-20): a trace is a task only if its
//! answer is not leaked in the workspace or the history. A repaired run's
//! task, compiled from an owner's AG-UI capture, is refused when its observed
//! answer sits in its own rebuilt state or its input.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test eval_repair_task_answer_leak`
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::{AgUiCustomMapping, AgUiFileImport, AgUiObservationKind};
use oneiron::skill_optimize::{EvalRepairTaskSource, EvalSeat};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The answer the app observed after the person's repair.
const ANSWER: &str = "Ship the parcel to Lyon on Tuesday.";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    proof: AuthenticatedOwner,
    project: EntityId,
}

fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    oneiron::test_support::provision_engine_machines(&vault);
    let (owner, proof) = embedded_owner(&vault)?;
    let project = vault.root_project()?;
    Ok(Fixture {
        vault,
        _dir: dir,
        owner,
        proof,
        project,
    })
}

fn mapping(name: &str, kind: AgUiObservationKind) -> AgUiCustomMapping {
    AgUiCustomMapping {
        name: name.to_owned(),
        kind,
        id: Some("/value/id".to_owned()),
        thread_id: Some("/value/threadId".to_owned()),
        run_id: Some("/value/runId".to_owned()),
        tool_call_id: None,
        failure_id: None,
        repair_id: None,
        outcome: None,
    }
}

fn mappings() -> Vec<AgUiCustomMapping> {
    let failure = mapping("desk.failure", AgUiObservationKind::Failure);
    let repair = AgUiCustomMapping {
        failure_id: Some("/value/failureId".to_owned()),
        ..mapping("desk.repair", AgUiObservationKind::Repair)
    };
    let outcome = AgUiCustomMapping {
        repair_id: Some("/value/repairId".to_owned()),
        outcome: Some("/value/result".to_owned()),
        ..mapping("desk.outcome", AgUiObservationKind::Outcome)
    };
    vec![failure, repair, outcome]
}

/// A text-response task contract over `initial_state` and `input`, graded by
/// the observed outcome's `response`.
fn task(initial_state: Value, input: Value) -> Value {
    json!({
        "world": "text_response",
        "initial_state": initial_state,
        "preconditions": [],
        "intent": "Answer the customer with the delivery plan.",
        "input": input,
        "tools": [],
        "allowed_actions": ["respond"],
        "grader": { "kind": "observed_response_equals", "pointer": "/response" },
    })
}

fn clean_state() -> Value {
    json!({ "orders": [{ "id": "A-1", "city": "Lyon", "status": "packed" }] })
}

fn clean_input() -> Value {
    json!({ "history": [{ "role": "user", "text": "Where does my parcel go?" }] })
}

/// Captures one failure, the person's repair and the app's observed outcome
/// (ordinals 0, 1 and 2), the failure carrying `task` at `/value/task`, and
/// names that task as the outcome's linked source.
fn capture(fixture: &Fixture, task: Value) -> TestResult<EvalRepairTaskSource> {
    let events = [
        json!({
            "type": "CUSTOM",
            "name": "desk.failure",
            "value": { "id": "f-1", "threadId": "t-1", "runId": "r-1", "task": task },
        }),
        json!({
            "type": "CUSTOM",
            "name": "desk.repair",
            "value": { "id": "p-1", "threadId": "t-1", "runId": "r-1", "failureId": "f-1" },
        }),
        json!({
            "type": "CUSTOM",
            "name": "desk.outcome",
            "value": {
                "id": "o-1",
                "threadId": "t-1",
                "runId": "r-1",
                "repairId": "p-1",
                "result": { "response": ANSWER },
            },
        }),
    ];
    let jsonl = events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let receipt = fixture.vault.ingest_ag_ui_file(
        &fixture.proof,
        &AgUiFileImport {
            claim_ref: None,
            project_ref: fixture.project.to_hex(),
            app_id: "support-desk".to_owned(),
            custom_mappings: mappings(),
            jsonl,
        },
    )?;
    assert_eq!(receipt.event_count, 3);
    Ok(EvalRepairTaskSource {
        claim_ref: receipt.claim_ref,
        source_hash: receipt.source_hash,
        outcome_ordinal: 2,
        task_pointer: "/value/task".to_owned(),
        seat: EvalSeat::Companion,
    })
}

/// Compiles the task as the owner: the input a response leg is shown, or the
/// refusal's text.
fn compile(fixture: &Fixture, source: &EvalRepairTaskSource) -> Result<Value, String> {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_eval_repair_task(source)
        .map(|read| {
            let task = read.task.expect("the owner reads their own capture");
            assert!(task.grade_response(ANSWER), "the observed answer grades");
            task.response_input().clone()
        })
        .map_err(|error| error.to_string())
}

#[test]
fn a_task_whose_answer_its_world_does_not_hold_compiles() -> TestResult {
    let fixture = fixture()?;
    // The state names the city, a part of the answer, but not the answer.
    let source = capture(&fixture, task(clean_state(), clean_input()))?;
    let input = compile(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    assert_eq!(input["initial_state"], clean_state());
    assert!(
        !input.to_string().contains(ANSWER),
        "a compiled task never shows its answer: {input}"
    );
    Ok(())
}

#[test]
fn a_task_whose_workspace_holds_the_answer_is_refused() -> TestResult {
    let fixture = fixture()?;
    let mut state = clean_state();
    state["drafts"] = json!({ "reply": format!("  {ANSWER}\n") });
    let source = capture(&fixture, task(state, clean_input()))?;
    let refusal = compile(&fixture, &source).expect_err("a leaked answer is no task");
    assert!(
        refusal.contains("answer is leaked in its workspace or history"),
        "{refusal}"
    );
    Ok(())
}

#[test]
fn a_task_whose_history_holds_the_answer_is_refused() -> TestResult {
    let fixture = fixture()?;
    let input = json!({
        "history": [
            { "role": "user", "text": "Where does my parcel go?" },
            { "role": "assistant", "text": format!("Draft for review: {ANSWER} Shall I send it?") },
        ],
    });
    let source = capture(&fixture, task(clean_state(), input))?;
    let refusal = compile(&fixture, &source).expect_err("a leaked answer is no task");
    assert!(
        refusal.contains("answer is leaked in its workspace or history"),
        "{refusal}"
    );
    Ok(())
}
