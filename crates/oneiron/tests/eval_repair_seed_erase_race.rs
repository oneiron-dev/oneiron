//! ARCH-0053 `#eval-repair-seed` (census L1-20): a seed door's write never
//! acts on what an erase or another write changed after the door compiled
//! the task. A proposal that compiled before its capture was erased records
//! no seed, and a gate that read a seed records nothing once that seed row
//! changed, so an erase and a new proposal cannot give one source a second
//! case. Nor does a gate settle a seed whose capture was deleted after it
//! read the seed: a delete keeps the seed until the erase, but never lets it
//! take a case. The doors' writes run alone through the test doors, as a
//! compile that the erase overtook reaches them.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test eval_repair_seed_erase_race`
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::ingest::{AgUiCustomMapping, AgUiFileImport, AgUiObservationKind};
use oneiron::skill_optimize::{
    EvalArmPin, EvalRepairLegAnswer, EvalRepairSeedLegs, EvalRepairSeedRefusal,
    EvalRepairSeedRequest, EvalRepairSeedState, EvalRepairTaskSource, EvalSeat,
    eval_authoring_inventory,
};
use oneiron::test_doors::eval_repair_seed::{commit_proposal, commit_settlement};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The answer the person's repair gave, which the app observed.
const ANSWER: &str = "fixed answer";
const PROPOSED_AT: u64 = 1_000;
const SETTLED_AT: u64 = 2_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    source: EvalRepairTaskSource,
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

/// A vault with one linked capture: a failure carrying a text-response task
/// contract, the person's repair and the app's observed outcome.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    oneiron::test_support::provision_engine_machines(&vault);
    let (owner, proof) = embedded_owner(&vault)?;
    let project = vault.root_project()?;
    let task = json!({
        "world": "text_response",
        "initial_state": { "orders": [{ "id": "A-1", "city": "Lyon", "status": "packed" }] },
        "preconditions": [],
        "intent": "Answer the customer with the delivery plan.",
        "input": { "history": [{ "role": "user", "text": "Where does my parcel go?" }] },
        "tools": [],
        "allowed_actions": ["respond"],
        "grader": { "kind": "observed_response_equals", "pointer": "/response" },
    });
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
    let receipt = vault.ingest_ag_ui_file(
        &proof,
        &AgUiFileImport {
            claim_ref: None,
            project_ref: project.to_hex(),
            app_id: "support-desk".to_owned(),
            custom_mappings: vec![
                mapping("desk.failure", AgUiObservationKind::Failure),
                AgUiCustomMapping {
                    failure_id: Some("/value/failureId".to_owned()),
                    ..mapping("desk.repair", AgUiObservationKind::Repair)
                },
                AgUiCustomMapping {
                    repair_id: Some("/value/repairId".to_owned()),
                    outcome: Some("/value/result".to_owned()),
                    ..mapping("desk.outcome", AgUiObservationKind::Outcome)
                },
            ],
            jsonl: events
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        },
    )?;
    let source = EvalRepairTaskSource {
        claim_ref: receipt.claim_ref,
        source_hash: receipt.source_hash,
        outcome_ordinal: 2,
        task_pointer: "/value/task".to_owned(),
        seat: EvalSeat::Companion,
    };
    Ok(Fixture {
        vault,
        _dir: dir,
        owner,
        source,
    })
}

fn request(source: &EvalRepairTaskSource) -> EvalRepairSeedRequest {
    let arm = |skill: &str| EvalArmPin {
        model: "local-model".to_owned(),
        revision: "r1".to_owned(),
        skill_digest: Some(skill.to_owned()),
    };
    EvalRepairSeedRequest {
        source: source.clone(),
        old: arm("old-skill-digest"),
        candidate: arm("candidate-skill-digest"),
    }
}

fn legs() -> EvalRepairSeedLegs {
    EvalRepairSeedLegs {
        old_receipt: "attempt:old-leg".to_owned(),
        candidate_receipt: "attempt:candidate-leg".to_owned(),
    }
}

fn response(text: &str) -> EvalRepairLegAnswer {
    EvalRepairLegAnswer::Response(text.to_owned())
}

/// The companion seat's cases in sealed families no cohort holds yet.
fn uncut_sealed_cases(fixture: &Fixture) -> TestResult<usize> {
    let inventory = eval_authoring_inventory(&fixture.vault, 3_000)?;
    Ok(inventory
        .seats
        .iter()
        .filter(|seat| seat.seat == EvalSeat::Companion)
        .flat_map(|seat| seat.uncut.iter())
        .map(|family| family.cases)
        .sum())
}

#[test]
fn an_erase_between_compile_and_write_records_no_second_case() -> TestResult {
    let fixture = fixture()?;
    let source = &fixture.source;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    memory.propose_eval_repair_seed(&request(source), PROPOSED_AT)?;
    let confirmed = memory
        .settle_eval_repair_seed(
            source,
            &response("wrong answer"),
            &response(ANSWER),
            &legs(),
            SETTLED_AT,
        )?
        .seed
        .expect("the owner reads their own capture");
    assert!(
        matches!(confirmed.state, EvalRepairSeedState::Confirmed { .. }),
        "{:?}",
        confirmed.state
    );
    assert_eq!(uncut_sealed_cases(&fixture)?, 1);
    // A replayed proposal and a replayed settle compile the task, then the
    // capture's erase overtakes both.
    let task = memory
        .read_eval_repair_task(source)?
        .task
        .expect("the owner reads their own capture");
    let claim = EntityId::from_hex(&source.claim_ref)?;
    assert!(
        fixture.vault.delete_entity(&claim)?,
        "the capture is erased"
    );
    oneiron::test_doors::inquiry::erase_actor_in_tables_in_order(
        &fixture.vault,
        &claim,
        &["SKILL_OPTIMIZE_EVAL_REPAIR_SEED"],
    )?;
    assert!(fixture.vault.eval_repair_seed(source)?.is_none());
    let proposal = commit_proposal(&fixture.vault, &task, &request(source), SETTLED_AT + 1);
    assert!(
        proposal.is_err(),
        "an erased capture takes no new seed: {proposal:?}"
    );
    assert!(fixture.vault.eval_repair_seed(source)?.is_none());
    let settlement = commit_settlement(
        &fixture.vault,
        &confirmed,
        &task,
        (&response("wrong answer"), &response(ANSWER)),
        &legs(),
        SETTLED_AT + 2,
    );
    assert!(
        settlement.is_err(),
        "a settle never grades a seed it did not read: {settlement:?}"
    );
    assert_eq!(
        uncut_sealed_cases(&fixture)?,
        1,
        "the source keeps one case"
    );
    Ok(())
}

#[test]
fn a_settle_writes_only_the_seed_it_read() -> TestResult {
    let fixture = fixture()?;
    let source = &fixture.source;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let pending = memory
        .propose_eval_repair_seed(&request(source), PROPOSED_AT)?
        .seed
        .expect("the owner reads their own capture");
    let task = memory
        .read_eval_repair_task(source)?
        .task
        .expect("the owner reads their own capture");
    // Another settle refuses the seed first.
    let refused = memory
        .settle_eval_repair_seed(
            source,
            &response(ANSWER),
            &response(ANSWER),
            &legs(),
            SETTLED_AT,
        )?
        .seed
        .expect("the owner reads their own capture");
    assert_eq!(
        refused.state,
        EvalRepairSeedState::Refused {
            reason: EvalRepairSeedRefusal::OldPassed,
            at: SETTLED_AT,
        }
    );
    // A settle that read the seed while it was pending writes nothing now.
    let late = commit_settlement(
        &fixture.vault,
        &pending,
        &task,
        (&response("wrong answer"), &response(ANSWER)),
        &legs(),
        SETTLED_AT + 1,
    );
    assert!(
        late.is_err(),
        "the seed changed since it was read: {late:?}"
    );
    assert_eq!(fixture.vault.eval_repair_seed(source)?, Some(refused));
    assert_eq!(uncut_sealed_cases(&fixture)?, 0);
    Ok(())
}

#[test]
fn a_capture_deleted_while_its_seed_is_graded_takes_no_case() -> TestResult {
    let fixture = fixture()?;
    let source = &fixture.source;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let pending = memory
        .propose_eval_repair_seed(&request(source), PROPOSED_AT)?
        .seed
        .expect("the owner reads their own capture");
    // A settle compiles the task and reads the pending seed; then the
    // capture is deleted. The delete keeps its shell, and the seed stays
    // until the erase scrubs it.
    let task = memory
        .read_eval_repair_task(source)?
        .task
        .expect("the owner reads their own capture");
    let claim = EntityId::from_hex(&source.claim_ref)?;
    assert!(
        fixture.vault.delete_entity(&claim)?,
        "the capture is deleted"
    );
    assert_eq!(
        fixture.vault.eval_repair_seed(source)?,
        Some(pending.clone())
    );
    let settlement = commit_settlement(
        &fixture.vault,
        &pending,
        &task,
        (&response("wrong answer"), &response(ANSWER)),
        &legs(),
        SETTLED_AT,
    );
    assert!(
        settlement.is_err(),
        "a deleted capture's seed is never settled: {settlement:?}"
    );
    assert_eq!(fixture.vault.eval_repair_seed(source)?, Some(pending));
    assert_eq!(uncut_sealed_cases(&fixture)?, 0, "no case after the delete");
    Ok(())
}
