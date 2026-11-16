//! The repair seed's measuring host (census L1-20 PR D): a `Pending` seed
//! queues one `coach.eval_repair_seed` job and a replayed proposal none, its
//! release holds the leg input and never the answer, the settle runs through
//! the capture owner's gate and hands back only the seed's state, and a
//! released Repair case grades exactly in fixed code.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test eval_repair_seed_host_doors`
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, CompleteDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt,
    DreamerRunnerStore,
};
use oneiron::ingest::{AgUiCustomMapping, AgUiFileImport, AgUiObservationKind};
use oneiron::skill_optimize::{
    CutDecision, EvalArmPin, EvalAxisPin, EvalCohort, EvalCohortSetup, EvalLabel, EvalLabelKind,
    EvalMeasurementRequest, EvalRepairLegAnswer, EvalRepairSeed, EvalRepairSeedLegs,
    EvalRepairSeedRequest, EvalRepairSeedState, EvalRepairTaskSource, EvalRepairTool,
    EvalRepairToolCall, EvalRepairToolEffect, EvalSeat, FloorSlicePolicy, MeasurementMethodPin,
    MeasurementState, ScoreDirection, eval_authoring_inventory, setup_eval_cohorts,
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
/// When an adjudicated seed's audit label is given.
const LABELLED_AT: u64 = 1_500;
/// The Coach host's lease and budget, as the nightly worker admits it.
const COACH_HOST: &str = "coach.host";

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

/// A tool-world task contract: set the city, graded by the observed end
/// state.
fn tool_task() -> Value {
    json!({
        "world": { "json_state_tools": { "tools": [
            { "name": "set_city", "effect": { "kind": "set", "pointer": "/orders/0/city" } },
        ] } },
        "initial_state": { "orders": [{ "id": "A-1", "city": "Paris" }] },
        "preconditions": [],
        "intent": "Send the order to the city the customer asked for.",
        "input": { "history": [{ "role": "user", "text": "I moved: send it to my new city." }] },
        "tools": ["set_city"],
        "allowed_actions": ["call_tool"],
        "grader": { "kind": "observed_state_equals", "pointer": "/state" },
    })
}

fn adjudicated_task(initial_state: Value) -> Value {
    let mut task = text_task(initial_state);
    task["grader"] = json!({ "kind": "adjudicated_response" });
    task
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

fn adjudicated_capture(
    fixture: &Fixture,
    initial_state: Value,
) -> TestResult<EvalRepairTaskSource> {
    capture(
        fixture,
        adjudicated_task(initial_state),
        json!({ "status": "resolved" }),
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

fn audit(kind: EvalLabelKind, value: &str) -> EvalLabel {
    EvalLabel {
        kind,
        value: value.to_owned(),
        reference: "audit:desk-1".to_owned(),
        weight: 0.8,
        at: LABELLED_AT,
        source_rows: None,
    }
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

/// Lands `label` on the seed as the owner; the seed, or the refusal's text.
fn label_seed(
    fixture: &Fixture,
    source: &EvalRepairTaskSource,
    label: &EvalLabel,
) -> Result<EvalRepairSeed, String> {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .label_eval_repair_seed(source, label)
        .map(|read| read.seed.expect("the owner reads their own capture"))
        .map_err(|error| error.to_string())
}

/// Admits the next queued Coach host job, if one waits.
fn admit_host_job(fixture: &Fixture) -> TestResult<Option<Box<DreamerAdmittedAttempt>>> {
    let now = fixture.vault.now_recorded_at();
    let outcome =
        DreamerRunnerStore::new(&fixture.vault).admit_next_coach_host_job(AdmitDreamerAttempt {
            lease_owner: COACH_HOST.to_owned(),
            now,
            budget_id: COACH_HOST.to_owned(),
            budget_total_units: 1 << 20,
            reserve_units: 1,
            started_milestone: None,
        })?;
    match outcome {
        DreamerAdmissionOutcome::Admitted(attempt) => Ok(Some(attempt)),
        DreamerAdmissionOutcome::Empty => Ok(None),
        other => panic!("the host budget is not spent: {other:?}"),
    }
}

/// The queued host job's seed key: admit it and read its target.
fn queued_seed_key(fixture: &Fixture) -> TestResult<[u8; 32]> {
    let attempt = admit_host_job(fixture)?.expect("one host job is queued");
    Ok(fixture.vault.coach_eval_repair_seed_target(&attempt)?)
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
fn a_pending_seed_queues_one_host_job() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let seed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    assert_eq!(seed.state, EvalRepairSeedState::Pending);
    // A replay queues nothing: one job waits.
    let replayed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    assert_eq!(replayed, seed);
    let key = queued_seed_key(&fixture)?;
    // The target is the seed's key: only it releases the seed.
    let release = fixture
        .vault
        .eval_repair_seed_release(&key)?
        .expect("the job's target releases the seed");
    assert_eq!(release.key, key);
    assert_eq!(release.old, seed.old);
    assert_eq!(release.candidate, seed.candidate);
    assert!(admit_host_job(&fixture)?.is_none(), "one job was queued");
    Ok(())
}

#[test]
fn an_adjudicated_seed_queues_no_job_until_its_label() -> TestResult {
    let fixture = fixture()?;
    let source = adjudicated_capture(&fixture, clean_state())?;
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    assert_eq!(proposed.state, EvalRepairSeedState::AwaitingLabel);
    assert!(
        admit_host_job(&fixture)?.is_none(),
        "no job before the label"
    );
    let labelled = label_seed(
        &fixture,
        &source,
        &audit(EvalLabelKind::AdjudicatedAudit, ANSWER),
    )
    .map_err(|refusal| format!("refused: {refusal}"))?;
    assert_eq!(labelled.state, EvalRepairSeedState::Pending);
    let key = queued_seed_key(&fixture)?;
    assert!(
        fixture.vault.eval_repair_seed_release(&key)?.is_some(),
        "the label queues the seed's job"
    );
    Ok(())
}

#[test]
fn the_host_release_holds_no_answer() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let seed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let key = queued_seed_key(&fixture)?;
    let release = fixture
        .vault
        .eval_repair_seed_release(&key)?
        .expect("a pending seed releases");
    assert_eq!(release.key, key);
    assert!(!release.moved);
    assert_eq!(release.seat, seed.source.seat);
    assert_eq!(release.old, seed.old);
    assert_eq!(release.candidate, seed.candidate);
    assert_eq!(release.source_rows, seed.source_rows);
    assert!(release.tools.is_empty());
    let text = serde_json::to_string(&release.input)?;
    assert!(
        !text.contains(ANSWER),
        "the release holds no answer: {text}"
    );

    // A tool world releases its declared tools.
    let fixture = self::fixture()?;
    let end = json!({ "orders": [{ "id": "A-1", "city": "Lyon" }] });
    let source = capture(&fixture, tool_task(), json!({ "state": end }))?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let key = queued_seed_key(&fixture)?;
    let release = fixture
        .vault
        .eval_repair_seed_release(&key)?
        .expect("a tool seed releases");
    assert_eq!(
        release.tools,
        vec![EvalRepairTool {
            name: "set_city".to_owned(),
            effect: EvalRepairToolEffect::Set {
                pointer: "/orders/0/city".to_owned(),
            },
        }]
    );
    Ok(())
}

#[test]
fn the_host_release_settles_through_the_owner() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let key = queued_seed_key(&fixture)?;
    assert!(
        fixture.vault.eval_repair_seed_release(&key)?.is_some(),
        "a pending seed releases"
    );
    let settled = fixture.vault.settle_eval_repair_seed_release(
        &key,
        &response("wrong answer"),
        &response(ANSWER),
        &legs(),
        SETTLED_AT,
    )?;
    assert!(settled.is_some(), "the owner settles the seed");
    let seed = fixture
        .vault
        .eval_repair_seed(&source)?
        .expect("the seed stands");
    assert!(
        matches!(seed.state, EvalRepairSeedState::Confirmed { .. }),
        "{:?}",
        seed.state
    );
    assert!(
        fixture.vault.eval_repair_seed_release(&key)?.is_none(),
        "a settled seed releases nothing"
    );
    Ok(())
}

#[test]
fn the_host_settle_hands_back_no_answer_digest() -> TestResult {
    let fixture = fixture()?;
    let source = adjudicated_capture(&fixture, clean_state())?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    label_seed(
        &fixture,
        &source,
        &audit(EvalLabelKind::AdjudicatedAudit, ANSWER),
    )
    .map_err(|refusal| format!("refused: {refusal}"))?;
    let key = queued_seed_key(&fixture)?;
    let settled = fixture
        .vault
        .settle_eval_repair_seed_release(
            &key,
            &response("wrong answer"),
            &response(ANSWER),
            &legs(),
            SETTLED_AT,
        )?
        .expect("the owner settles the seed");
    // The host gets back the seed's state alone: the adjudication's digest
    // names a short answer, so it stays with the gate.
    let shown = format!("{settled:?}");
    assert!(
        shown.contains("Confirmed"),
        "the gate confirms the seed: {shown}"
    );
    assert!(
        !shown.contains("answer_digest"),
        "the settle hands back no answer digest: {shown}"
    );
    Ok(())
}

#[test]
fn a_replayed_proposal_queues_no_second_job() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    // The host's job ends without settling the seed (as when it cannot
    // serve an arm): the seed stays Pending and its job is spent.
    let attempt = admit_host_job(&fixture)?.expect("one host job is queued");
    let _completed = DreamerRunnerStore::new(&fixture.vault).complete(CompleteDreamerAttempt {
        id: attempt.status.attempt.id,
        lease_owner: COACH_HOST.to_owned(),
        attempt_count: attempt.status.attempt.attempt_count,
        now: fixture.vault.now_recorded_at(),
    })?;
    let replayed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    assert_eq!(replayed.state, EvalRepairSeedState::Pending);
    assert!(
        admit_host_job(&fixture)?.is_none(),
        "a replayed proposal queues no second job, so no replay pays for the legs again"
    );
    Ok(())
}

#[test]
fn a_deleted_capture_releases_nothing() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let key = queued_seed_key(&fixture)?;
    assert!(
        fixture.vault.eval_repair_seed_release(&key)?.is_some(),
        "a pending seed releases"
    );
    let claim = EntityId::from_hex(&source.claim_ref)?;
    assert!(
        fixture.vault.delete_entity(&claim)?,
        "the capture is deleted"
    );
    assert!(
        fixture.vault.eval_repair_seed_release(&key)?.is_none(),
        "a deleted capture releases nothing"
    );
    Ok(())
}

#[test]
fn a_released_repair_case_grades_exactly() -> TestResult {
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
    let digest = measure(&fixture, &cohort)?;
    assert_eq!(
        fixture
            .vault
            .grade_released_eval_repair_answer(&digest, &case, &response(ANSWER))?,
        Ok(true)
    );
    assert_eq!(
        fixture.vault.grade_released_eval_repair_answer(
            &digest,
            &case,
            &response("wrong answer")
        )?,
        Ok(false)
    );

    // A tool world grades its observed calls.
    let fixture = self::fixture()?;
    let end = json!({ "orders": [{ "id": "A-1", "city": "Lyon" }] });
    let source = capture(&fixture, tool_task(), json!({ "state": end }))?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let set_city = |city: &str| EvalRepairToolCall {
        tool: "set_city".to_owned(),
        argument: json!(city),
    };
    let seed = settle(
        &fixture,
        &source,
        &EvalRepairLegAnswer::ToolCalls(vec![set_city("Paris")]),
        &EvalRepairLegAnswer::ToolCalls(vec![set_city("Lyon")]),
    )?;
    let case = match &seed.state {
        EvalRepairSeedState::Confirmed { case, .. } => *case,
        state => panic!("the gate confirms the tool seed: {state:?}"),
    };
    let cohort = cut_before(&fixture, 1_500)?;
    let digest = measure(&fixture, &cohort)?;
    assert_eq!(
        fixture.vault.grade_released_eval_repair_answer(
            &digest,
            &case,
            &EvalRepairLegAnswer::ToolCalls(vec![set_city("Lyon")])
        )?,
        Ok(true)
    );
    Ok(())
}
