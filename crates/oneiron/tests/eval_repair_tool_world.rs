//! ARCH-0053 `#eval-trace-task` (census L1-20, Engine ruling L1-20-TOOLWORLD
//! = B): a task carries the world, an initial state that can be rebuilt, the
//! intent, the tools and a grader that tests the intent. A repaired run whose
//! fix used tools compiles as a `json_state_tools` task: the world declares
//! pure tools over the rebuilt state, and fixed code applies a candidate's
//! tool calls and compares the end state with the app's observed outcome.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test eval_repair_tool_world`
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::{AgUiCustomMapping, AgUiFileImport, AgUiObservationKind};
use oneiron::skill_optimize::{EvalRepairTask, EvalRepairTaskSource, EvalRepairToolCall, EvalSeat};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The note the person's repair added, in the end state the app observed.
const NOTE: &str = "Customer moved to Lyon.";

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

fn initial_state() -> Value {
    json!({
        "orders": [{ "id": "A-1", "city": "Paris", "status": "packed" }],
        "notes": [],
    })
}

/// The state the app observed after the person's repair.
fn end_state() -> Value {
    json!({
        "orders": [{ "id": "A-1", "city": "Lyon", "status": "packed" }],
        "notes": [NOTE],
    })
}

fn history() -> Value {
    json!({ "history": [{ "role": "user", "text": "I moved: please send my parcel to Lyon." }] })
}

/// The tools the world declares: two the task offers, and one it does not.
fn declared_tools() -> Value {
    json!([
        { "name": "set_city", "effect": { "kind": "set", "pointer": "/orders/0/city" } },
        { "name": "add_note", "effect": { "kind": "append", "pointer": "/notes" } },
        { "name": "drop_order", "effect": { "kind": "remove", "pointer": "/orders/0" } },
    ])
}

/// A tool-world task contract that offers `tools`, over `initial_state` and
/// `input`, graded by the observed outcome's `state`.
fn tool_task(initial_state: Value, input: Value, tools: Value) -> Value {
    json!({
        "world": { "json_state_tools": { "tools": declared_tools() } },
        "initial_state": initial_state,
        "preconditions": [{ "pointer": "/orders/0/status", "equals": "packed" }],
        "intent": "Send the order to the city the customer asked for, and note why.",
        "input": input,
        "tools": tools,
        "allowed_actions": ["call_tool"],
        "grader": { "kind": "observed_state_equals", "pointer": "/state" },
    })
}

fn offered() -> Value {
    json!(["set_city", "add_note"])
}

/// Captures one failure, the person's repair and the app's observed outcome
/// (ordinals 0, 1 and 2), the failure carrying `task` at `/value/task` and the
/// outcome carrying `result`, and names that task as the outcome's source.
fn capture(fixture: &Fixture, task: Value, result: Value) -> TestResult<EvalRepairTaskSource> {
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
                "result": result,
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

/// Compiles the task as the owner: the task, or the refusal's text.
fn compile(fixture: &Fixture, source: &EvalRepairTaskSource) -> Result<EvalRepairTask, String> {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_eval_repair_task(source)
        .map(|read| read.task.expect("the owner reads their own capture"))
        .map_err(|error| error.to_string())
}

fn call(tool: &str, argument: Value) -> EvalRepairToolCall {
    EvalRepairToolCall {
        tool: tool.to_owned(),
        argument,
    }
}

/// The calls that make the person's repair: the city, then the note.
fn repair_calls() -> Vec<EvalRepairToolCall> {
    vec![
        call("set_city", json!("Lyon")),
        call("add_note", json!(NOTE)),
    ]
}

fn observed() -> Value {
    json!({ "state": end_state() })
}

#[test]
fn a_tool_world_task_compiles_with_its_declared_tools() -> TestResult {
    let fixture = fixture()?;
    let source = capture(
        &fixture,
        tool_task(initial_state(), history(), offered()),
        observed(),
    )?;
    let task = compile(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let input = task.response_input();
    assert_eq!(input["initial_state"], initial_state());
    assert_eq!(input["tools"], offered(), "the task offers its tools");
    assert_eq!(
        input["world"]["json_state_tools"]["tools"],
        declared_tools(),
        "the leg is shown what each declared tool does"
    );
    assert_eq!(input["allowed_actions"], json!(["call_tool"]));
    assert!(
        !input.to_string().contains(NOTE),
        "a compiled task never shows its end state: {input}"
    );
    assert!(
        !task.grade_response(NOTE),
        "a tool world grades no text response"
    );
    Ok(())
}

#[test]
fn the_state_grader_tests_the_intent() -> TestResult {
    let fixture = fixture()?;
    let source = capture(
        &fixture,
        tool_task(initial_state(), history(), offered()),
        observed(),
    )?;
    let task = compile(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;

    // Fixed code applies the calls to the rebuilt state; the end state the
    // app observed grades true.
    assert_eq!(task.apply_tool_calls(&repair_calls()), Some(end_state()));
    assert!(task.grade_tool_calls(&repair_calls()));

    // Another end state grades false: a wrong city, or the note left out.
    let wrong_city = [
        call("set_city", json!("Lille")),
        call("add_note", json!(NOTE)),
    ];
    assert!(!task.grade_tool_calls(&wrong_city));
    assert!(!task.grade_tool_calls(&[call("set_city", json!("Lyon"))]));
    assert!(
        !task.grade_tool_calls(&[]),
        "the initial state is not the end state"
    );

    // A tool the world declares but the task does not offer, or one nobody
    // declared, does not apply, and the calls grade false.
    let mut not_offered = repair_calls();
    not_offered.push(call("drop_order", Value::Null));
    assert_eq!(task.apply_tool_calls(&not_offered), None);
    assert!(!task.grade_tool_calls(&not_offered));
    let mut undeclared = repair_calls();
    undeclared.push(call("send_email", json!("Your parcel goes to Lyon.")));
    assert!(!task.grade_tool_calls(&undeclared));

    // One grade applies at most 256 calls: 256 that make the repair grade
    // true, and one call more grades false.
    let mut at_cap = vec![call("set_city", json!("Lyon")); 255];
    at_cap.push(call("add_note", json!(NOTE)));
    assert_eq!(at_cap.len(), 256);
    assert!(task.grade_tool_calls(&at_cap), "256 calls are applied");
    let mut over_cap = vec![call("set_city", json!("Lyon")); 256];
    over_cap.push(call("add_note", json!(NOTE)));
    assert_eq!(task.apply_tool_calls(&over_cap), None, "257 calls are not");
    assert!(!task.grade_tool_calls(&over_cap));
    Ok(())
}

#[test]
fn a_tool_world_with_a_failing_precondition_is_refused_as_such() -> TestResult {
    let fixture = fixture()?;
    let mut state = initial_state();
    state["orders"][0]["status"] = json!("shipped");
    let mut end = end_state();
    end["orders"][0]["status"] = json!("shipped");
    let source = capture(
        &fixture,
        tool_task(state, history(), offered()),
        json!({ "state": end }),
    )?;
    let refusal = compile(&fixture, &source).expect_err("an unmet precondition is no task");
    assert!(
        refusal.contains("Repair initial precondition failed"),
        "{refusal}"
    );
    Ok(())
}

#[test]
fn a_tool_outside_the_declared_set_is_refused() -> TestResult {
    let fixture = fixture()?;
    let source = capture(
        &fixture,
        tool_task(
            initial_state(),
            history(),
            json!(["set_city", "send_email"]),
        ),
        observed(),
    )?;
    let refusal = compile(&fixture, &source).expect_err("an undeclared tool is no task");
    assert!(
        refusal.contains("offers a tool its world does not declare"),
        "{refusal}"
    );

    // A text-response world declares no tool, so its rule is unchanged.
    let fixture = self::fixture()?;
    let text_task = json!({
        "world": "text_response",
        "initial_state": initial_state(),
        "preconditions": [],
        "intent": "Answer the customer with the delivery plan.",
        "input": history(),
        "tools": ["set_city"],
        "allowed_actions": ["respond"],
        "grader": { "kind": "observed_response_equals", "pointer": "/response" },
    });
    let source = capture(
        &fixture,
        text_task,
        json!({ "response": "It goes to Lyon." }),
    )?;
    let refusal = compile(&fixture, &source).expect_err("a text world runs no tool");
    assert!(
        refusal.contains("a text-response Repair task needs an intent, no tools and only respond"),
        "{refusal}"
    );
    Ok(())
}

#[test]
fn a_tool_world_whose_world_holds_its_end_state_is_refused() -> TestResult {
    let fixture = fixture()?;
    // The workspace already is the end state: no call is needed.
    let source = capture(
        &fixture,
        tool_task(end_state(), history(), offered()),
        observed(),
    )?;
    let refusal = compile(&fixture, &source).expect_err("a leaked end state is no task");
    assert!(
        refusal.contains("answer is leaked in its workspace or history"),
        "{refusal}"
    );

    // The history holds the end state.
    let fixture = self::fixture()?;
    let input = json!({
        "history": [
            { "role": "user", "text": "I moved: please send my parcel to Lyon." },
            { "role": "assistant", "draft_state": end_state() },
        ],
    });
    let source = capture(
        &fixture,
        tool_task(initial_state(), input, offered()),
        observed(),
    )?;
    let refusal = compile(&fixture, &source).expect_err("a leaked end state is no task");
    assert!(
        refusal.contains("answer is leaked in its workspace or history"),
        "{refusal}"
    );
    Ok(())
}

#[test]
fn a_grader_that_does_not_fit_its_world_is_refused() -> TestResult {
    let fixture = fixture()?;
    let mut task = tool_task(initial_state(), history(), offered());
    task["grader"] = json!({ "kind": "observed_response_equals", "pointer": "/response" });
    let source = capture(&fixture, task, json!({ "response": NOTE }))?;
    let refusal = compile(&fixture, &source).expect_err("a tool world grades its end state");
    assert!(
        refusal.contains("grader does not fit its world"),
        "{refusal}"
    );
    Ok(())
}
