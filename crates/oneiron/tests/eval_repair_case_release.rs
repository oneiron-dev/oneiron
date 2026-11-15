//! A confirmed repair seed's case releases to a claimed measurement as a
//! `repair_response` task: the recompiled task's input with no answer text,
//! the case's anchoring label, and the seed's task hash. Uses only the vault
//! doors that predate the repair-seed host job.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test eval_repair_case_release`
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::{AgUiCustomMapping, AgUiFileImport, AgUiObservationKind};
use oneiron::skill_optimize::{
    CutDecision, EvalArmPin, EvalAxisPin, EvalCohort, EvalCohortSetup, EvalLabelKind,
    EvalMeasurementRequest, EvalRepairLegAnswer, EvalRepairSeed, EvalRepairSeedLegs,
    EvalRepairSeedRequest, EvalRepairSeedState, EvalRepairTaskSource, EvalSeat, FloorSlicePolicy,
    MeasurementMethodPin, MeasurementState, ScoreDirection, eval_authoring_inventory,
    setup_eval_cohorts,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The answer the person's repair gave, which the app observed.
const ANSWER: &str = "fixed answer";
/// When each seed is proposed, then settled.
const PROPOSED_AT: u64 = 1_000;
const SETTLED_AT: u64 = 2_000;

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

/// A text-response task contract over `initial_state`, graded by the
/// observed outcome's `response`.
fn text_task(initial_state: Value) -> Value {
    json!({
        "world": "text_response",
        "initial_state": initial_state,
        "preconditions": [],
        "intent": "Answer the customer with the delivery plan.",
        "input": { "history": [{ "role": "user", "text": "Where does my parcel go?" }] },
        "tools": [],
        "allowed_actions": ["respond"],
        "grader": { "kind": "observed_response_equals", "pointer": "/response" },
    })
}

fn clean_state() -> Value {
    json!({ "orders": [{ "id": "A-1", "city": "Lyon", "status": "packed" }] })
}

/// Captures one failure carrying `task`, the person's repair and the app's
/// observed outcome `result` (ordinals 0, 1 and 2), and names that task as
/// the outcome's source on the companion seat.
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

fn text_capture(fixture: &Fixture) -> TestResult<EvalRepairTaskSource> {
    capture(
        fixture,
        text_task(clean_state()),
        json!({ "response": ANSWER }),
    )
}

fn arm(skill: &str) -> EvalArmPin {
    EvalArmPin {
        model: "local-model".to_owned(),
        revision: "r1".to_owned(),
        skill_digest: Some(skill.to_owned()),
    }
}

fn request(source: &EvalRepairTaskSource) -> EvalRepairSeedRequest {
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

/// Proposes the seed as the owner; the seed, or the refusal's text.
fn propose(fixture: &Fixture, source: &EvalRepairTaskSource) -> Result<EvalRepairSeed, String> {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .propose_eval_repair_seed(&request(source), PROPOSED_AT)
        .map(|read| read.seed.expect("the owner reads their own capture"))
        .map_err(|error| error.to_string())
}

/// Settles the seed as the owner with the two arms' answers.
fn settle(
    fixture: &Fixture,
    source: &EvalRepairTaskSource,
    old: &EvalRepairLegAnswer,
    candidate: &EvalRepairLegAnswer,
) -> TestResult<EvalRepairSeed> {
    let read = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .settle_eval_repair_seed(source, old, candidate, &legs(), SETTLED_AT)?;
    Ok(read.seed.expect("the owner reads their own capture"))
}

/// Cuts the companion seat's sealed families before `until`, and returns
/// the cut cohort.
fn cut_before(fixture: &Fixture, until: u64) -> TestResult<EvalCohort> {
    let inventory = eval_authoring_inventory(&fixture.vault, 3_000)?;
    let report = setup_eval_cohorts(
        &fixture.vault,
        &fixture.proof,
        EvalCohortSetup {
            inventory_at: 3_000,
            inventory_digest: inventory.inventory_digest,
            families: Vec::new(),
            cases: Vec::new(),
            cuts: vec![CutDecision {
                seat: EvalSeat::Companion,
                from: 0,
                until,
                rubric_revision: "fixture/rubric-v1".to_owned(),
                reference: false,
            }],
        },
        3_000,
    )?;
    assert_eq!(report.cohorts_cut.len(), 1);
    let id = report.cohorts_cut[0];
    let cohort = fixture
        .vault
        .eval_cohorts(&EvalSeat::Companion)?
        .into_iter()
        .find(|cohort| cohort.id == id)
        .expect("the cut cohort");
    Ok(cohort)
}

/// Requests and claims a paired measurement over `cohort`.
fn measure(fixture: &Fixture, cohort: &EvalCohort) -> TestResult<[u8; 32]> {
    let request = EvalMeasurementRequest {
        decision: "fixture-decision".to_owned(),
        seat: EvalSeat::Companion,
        incumbent: arm("old-skill-digest"),
        candidate: arm("candidate-skill-digest"),
        requested_offers: None,
        cohort: cohort.id,
        membership_digest: cohort.membership_digest.clone(),
        rubric_revision: cohort.rubric_revision.clone(),
        scorer: "fixture-scorer".to_owned(),
        axis: EvalAxisPin {
            axis: "helpfulness".to_owned(),
            direction: ScoreDirection::HigherIsBetter,
            units: "points".to_owned(),
        },
        floor_slices: FloorSlicePolicy::default(),
        canary: None,
        method: MeasurementMethodPin::current(),
        retry: 0,
    };
    let digest = fixture.vault.request_eval_measurement(&request, 4_000)?;
    let claimed = fixture.vault.claim_eval_measurement(&digest, 4_000)?;
    assert!(
        matches!(claimed.state, MeasurementState::Claimed),
        "{:?}",
        claimed.state
    );
    Ok(digest)
}

#[test]
fn a_confirmed_repair_case_releases_as_repair_response() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let seed = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response(ANSWER),
    )?;
    let case = match &seed.state {
        EvalRepairSeedState::Confirmed { case, .. } => *case,
        state => panic!("the gate confirms the seed: {state:?}"),
    };
    let cohort = cut_before(&fixture, 1_500)?;
    assert!(cohort.cases.contains(&case));
    let digest = measure(&fixture, &cohort)?;
    let released = fixture.vault.released_eval_task(&digest, &case)?;
    let input = released.expect("a confirmed repair case releases");
    assert_eq!(input.kind, "repair_response");
    assert_eq!(input.task_hash, seed.task_hash);
    assert_eq!(input.labels.len(), 1);
    assert_eq!(input.labels[0].kind, EvalLabelKind::WorldOutcome);
    let text = serde_json::to_string(&input.input)?;
    assert!(
        !text.contains(ANSWER),
        "the released input holds no answer: {text}"
    );
    Ok(())
}
