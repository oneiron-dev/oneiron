//! ARCH-0053 `#eval-repair-seed` (census L1-20, Engine ruling
//! L1-20-SEEDER = A): a linked repair becomes a held-out case. Its source
//! family gets its sealed split before anything derives from it, the old
//! skill must fail the case and the candidate must pass it, graded against the
//! app's observed outcome, or an adjudicated label, and never the candidate's
//! own text, and a held-out family never feeds training.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test eval_repair_seed_gate`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::{AgUiCustomMapping, AgUiFileImport, AgUiObservationKind};
use oneiron::skill_optimize::{
    CutDecision, EvalArmPin, EvalCohortSetup, EvalLabel, EvalLabelKind, EvalRepairLegAnswer,
    EvalRepairSeed, EvalRepairSeedLegs, EvalRepairSeedRefusal, EvalRepairSeedRequest,
    EvalRepairSeedState, EvalRepairTaskSource, EvalRepairToolCall, EvalSeat, FamilyPurpose,
    eval_authoring_inventory, setup_eval_cohorts,
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

fn root(source: &EvalRepairTaskSource) -> String {
    format!("entity:{}", source.claim_ref)
}

/// The companion seat's cases in sealed families no cohort holds yet, as the
/// eval-authoring inventory counts them.
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
fn repair_seed_assigns_sealed_family_before_any_case() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let seed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    assert_eq!(seed.state, EvalRepairSeedState::Pending);
    assert_eq!(seed.proposed_at, PROPOSED_AT);
    let family = fixture
        .vault
        .eval_family_of_root(&EvalSeat::Companion, &root(&source))?
        .expect("the proposal assigns the capture's root");
    assert_eq!(family.purpose, FamilyPurpose::SealedConfirmation);
    assert_eq!(family.id, seed.family);
    assert!(
        fixture
            .vault
            .eval_cases(&EvalSeat::Companion, FamilyPurpose::Development)?
            .is_empty(),
        "no development case derives from a sealed repair"
    );
    assert_eq!(
        uncut_sealed_cases(&fixture)?,
        0,
        "no case exists before the gate"
    );
    let pending = fixture.vault.pending_eval_repair_seeds()?;
    assert_eq!(pending, vec![seed.clone()]);
    // A replay returns the seed already proposed.
    assert_eq!(
        propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?,
        seed
    );
    Ok(())
}

#[test]
fn repair_seed_confirms_when_old_fails_and_candidate_passes() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let seed = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response(ANSWER),
    )?;
    let EvalRepairSeedState::Confirmed {
        old_receipt,
        candidate_receipt,
        at,
        ..
    } = &seed.state
    else {
        panic!("the gate confirms the seed: {:?}", seed.state);
    };
    assert_eq!(old_receipt, "attempt:old-leg");
    assert_eq!(candidate_receipt, "attempt:candidate-leg");
    assert_eq!(*at, SETTLED_AT);
    assert_eq!(seed.family, proposed.family);
    assert_eq!(uncut_sealed_cases(&fixture)?, 1, "one sealed Repair case");
    assert!(fixture.vault.pending_eval_repair_seeds()?.is_empty());
    let inventory = eval_authoring_inventory(&fixture.vault, 3_000)?;
    let uncut = inventory
        .seats
        .iter()
        .find(|seat| seat.seat == EvalSeat::Companion)
        .and_then(|seat| {
            seat.uncut
                .iter()
                .find(|family| family.family == seed.family)
        })
        .expect("the sealed family waits for its cut");
    assert_eq!(
        uncut.first_at, PROPOSED_AT,
        "the case is dated by its proposal"
    );
    // A second settle records no second case.
    let again = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response(ANSWER),
    )?;
    assert_eq!(again, seed);
    assert_eq!(uncut_sealed_cases(&fixture)?, 1);
    Ok(())
}

#[test]
fn repair_seed_label_names_the_outcome_never_its_text() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let settled = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response(ANSWER),
    )?;
    let EvalRepairSeedState::Confirmed { case, .. } = settled.state else {
        panic!("the gate confirms the seed: {:?}", settled.state);
    };
    let seed = fixture
        .vault
        .eval_repair_seed(&source)?
        .expect("the seed is stored");
    let stored = format!("{seed:?}");
    assert!(
        !stored.contains(ANSWER),
        "a seed row never holds the answer: {stored}"
    );
    let expected = blake3::hash(ANSWER.as_bytes()).to_hex().to_string();
    // Sealed cases are served only through their cohort: the test door
    // reads the ledger row.
    let case = oneiron::test_doors::eval_repair_seed::eval_case(&fixture.vault, &case)?
        .expect("the confirmed seed's case is stored");
    assert_eq!(case.family, seed.family);
    assert_eq!(case.kind, oneiron::skill_optimize::DerivationKind::Repair);
    assert_eq!(case.receipts, vec![root(&source)]);
    assert_eq!(case.source_at, PROPOSED_AT);
    assert_eq!(case.labels.len(), 1);
    let label = &case.labels[0];
    assert_eq!(label.kind, EvalLabelKind::WorldOutcome);
    assert_eq!(
        label.value, expected,
        "the label holds the outcome's digest"
    );
    assert_eq!(
        label.reference,
        format!(
            "ag_ui:{}:{}#outcome/2",
            source.claim_ref, source.source_hash
        )
    );
    assert!(
        !format!("{case:?}").contains(ANSWER),
        "the case never holds the answer text"
    );
    Ok(())
}

#[test]
fn repair_seed_refuses_when_old_skill_passes() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let seed = settle(&fixture, &source, &response(ANSWER), &response(ANSWER))?;
    assert_eq!(
        seed.state,
        EvalRepairSeedState::Refused {
            reason: EvalRepairSeedRefusal::OldPassed,
            at: SETTLED_AT,
        }
    );
    assert_eq!(
        uncut_sealed_cases(&fixture)?,
        0,
        "a refused seed has no case"
    );
    Ok(())
}

#[test]
fn repair_seed_refuses_when_candidate_fails() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    // Exact bytes: a trailing space is not the observed answer.
    let seed = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response("fixed answer "),
    )?;
    assert_eq!(
        seed.state,
        EvalRepairSeedState::Refused {
            reason: EvalRepairSeedRefusal::CandidateFailed,
            at: SETTLED_AT,
        }
    );
    assert_eq!(
        uncut_sealed_cases(&fixture)?,
        0,
        "a refused seed has no case"
    );
    // The refusal stands: a later passing answer records no case.
    let again = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response(ANSWER),
    )?;
    assert_eq!(again, seed);
    assert_eq!(uncut_sealed_cases(&fixture)?, 0);
    Ok(())
}

#[test]
fn repair_seed_family_never_feeds_training() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let seed = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response(ANSWER),
    )?;
    assert!(matches!(seed.state, EvalRepairSeedState::Confirmed { .. }));
    assert!(!fixture.vault.eval_family_feeds_training(&seed.family)?);
    Ok(())
}

#[test]
fn repair_seed_refuses_leaked_answer() -> TestResult {
    let fixture = fixture()?;
    let leaked = json!({ "orders": [{ "id": "A-1", "note": ANSWER }] });
    let source = capture(&fixture, text_task(leaked), json!({ "response": ANSWER }))?;
    let refusal = propose(&fixture, &source).expect_err("a leaked answer is no task");
    assert!(refusal.contains("leaked"), "{refusal}");
    assert!(
        fixture
            .vault
            .eval_family_of_root(&EvalSeat::Companion, &root(&source))?
            .is_none(),
        "a refused proposal assigns no family"
    );
    assert!(fixture.vault.eval_repair_seed(&source)?.is_none());
    Ok(())
}

#[test]
fn a_root_already_in_development_is_never_sealed() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    fixture.vault.assign_eval_family(
        &EvalSeat::Companion,
        &BTreeSet::from([root(&source)]),
        FamilyPurpose::Development,
        500,
    )?;
    propose(&fixture, &source).expect_err("a development root keeps its purpose");
    assert!(fixture.vault.eval_repair_seed(&source)?.is_none());
    Ok(())
}

#[test]
fn a_tool_world_seed_grades_the_calls() -> TestResult {
    let fixture = fixture()?;
    let end = json!({ "orders": [{ "id": "A-1", "city": "Lyon" }] });
    let source = capture(&fixture, tool_task(), json!({ "state": end }))?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let set_city = |city: &str| EvalRepairToolCall {
        tool: "set_city".to_owned(),
        argument: json!(city),
    };
    // The old arm calls the tool with the wrong city; a text answer naming
    // the right end state is not graded as one.
    let seed = settle(
        &fixture,
        &source,
        &EvalRepairLegAnswer::ToolCalls(vec![set_city("Paris")]),
        &EvalRepairLegAnswer::ToolCalls(vec![set_city("Lyon")]),
    )?;
    assert!(
        matches!(seed.state, EvalRepairSeedState::Confirmed { .. }),
        "{:?}",
        seed.state
    );
    // A text-response world, in a fresh vault as each second capture is.
    let fixture = self::fixture()?;
    let other = text_capture(&fixture)?;
    propose(&fixture, &other).map_err(|refusal| format!("refused: {refusal}"))?;
    let text_world = settle(
        &fixture,
        &other,
        &response("wrong answer"),
        &EvalRepairLegAnswer::ToolCalls(vec![set_city("Lyon")]),
    )?;
    assert_eq!(
        text_world.state,
        EvalRepairSeedState::Refused {
            reason: EvalRepairSeedRefusal::CandidateFailed,
            at: SETTLED_AT,
        },
        "tool calls answer no text-response task"
    );
    Ok(())
}

#[test]
fn equal_arms_are_no_comparison() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let same = EvalRepairSeedRequest {
        source: source.clone(),
        old: arm("one-skill"),
        candidate: arm("one-skill"),
    };
    let refused = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .propose_eval_repair_seed(&same, PROPOSED_AT);
    assert!(refused.is_err(), "a seed compares two different arms");
    let unpinned = EvalRepairSeedRequest {
        candidate: EvalArmPin {
            skill_digest: None,
            ..arm("candidate")
        },
        ..request(&source)
    };
    let refused = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .propose_eval_repair_seed(&unpinned, PROPOSED_AT);
    assert!(refused.is_err(), "each arm pins its skill");
    assert!(fixture.vault.eval_repair_seed(&source)?.is_none());
    Ok(())
}

#[test]
fn an_erased_capture_takes_its_seed() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let claim = EntityId::from_hex(&source.claim_ref)?;
    let ran = oneiron::test_doors::inquiry::erase_actor_in_tables_in_order(
        &fixture.vault,
        &claim,
        &["SKILL_OPTIMIZE_EVAL_REPAIR_SEED"],
    )?;
    assert_eq!(ran, 1, "the seed table registers its scrub");
    assert!(fixture.vault.eval_repair_seed(&source)?.is_none());
    assert!(fixture.vault.pending_eval_repair_seeds()?.is_empty());
    Ok(())
}

/// A text-response task contract whose check is an adjudicated answer: the
/// app's outcome is no usable text.
fn adjudicated_task(initial_state: Value) -> Value {
    let mut task = text_task(initial_state);
    task["grader"] = json!({ "kind": "adjudicated_response" });
    task
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

#[test]
fn adjudicated_seed_waits_for_its_label() -> TestResult {
    let fixture = fixture()?;
    let source = adjudicated_capture(&fixture, clean_state())?;
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    assert_eq!(proposed.state, EvalRepairSeedState::AwaitingLabel);
    assert_eq!(proposed.adjudication, None);
    let family = fixture
        .vault
        .eval_family_of_root(&EvalSeat::Companion, &root(&source))?
        .expect("the proposal assigns the capture's root");
    assert_eq!(family.purpose, FamilyPurpose::SealedConfirmation);
    assert!(
        fixture.vault.pending_eval_repair_seeds()?.is_empty(),
        "the gate has nothing to grade before the label"
    );
    let early = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .settle_eval_repair_seed(
            &source,
            &response("wrong answer"),
            &response(ANSWER),
            &legs(),
            SETTLED_AT,
        );
    assert!(early.is_err(), "the gate refuses to grade before the label");
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(proposed));
    assert_eq!(uncut_sealed_cases(&fixture)?, 0);

    let labelled = label_seed(
        &fixture,
        &source,
        &audit(EvalLabelKind::AdjudicatedAudit, ANSWER),
    )?;
    assert_eq!(labelled.state, EvalRepairSeedState::Pending);
    let adjudication = labelled
        .adjudication
        .clone()
        .expect("the label is on the seed");
    assert_eq!(
        adjudication.answer_digest,
        *blake3::hash(ANSWER.as_bytes()).as_bytes()
    );
    assert_eq!(adjudication.reference, "audit:desk-1");
    assert_eq!(adjudication.at, LABELLED_AT);
    let stored = format!("{labelled:?}");
    assert!(
        !stored.contains(ANSWER),
        "a seed row never holds the adjudicated answer: {stored}"
    );
    assert_eq!(
        fixture.vault.pending_eval_repair_seeds()?,
        vec![labelled.clone()]
    );
    // The same label again changes nothing; another answer is refused.
    assert_eq!(
        label_seed(
            &fixture,
            &source,
            &audit(EvalLabelKind::AdjudicatedAudit, ANSWER)
        )?,
        labelled
    );
    assert!(
        label_seed(
            &fixture,
            &source,
            &audit(EvalLabelKind::AdjudicatedAudit, "another answer")
        )
        .is_err(),
        "the adjudicated label is set once"
    );

    // The old arm's answer must fail and the candidate's pass, exactly.
    let refused = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response(" fixed answer"),
    )?;
    assert_eq!(
        refused.state,
        EvalRepairSeedState::Refused {
            reason: EvalRepairSeedRefusal::CandidateFailed,
            at: SETTLED_AT,
        }
    );
    assert_eq!(uncut_sealed_cases(&fixture)?, 0);
    Ok(())
}

#[test]
fn adjudicated_seed_confirms_on_its_label() -> TestResult {
    let fixture = fixture()?;
    let source = adjudicated_capture(&fixture, clean_state())?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    label_seed(
        &fixture,
        &source,
        &audit(EvalLabelKind::AdjudicatedAudit, ANSWER),
    )?;
    let settled = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response(ANSWER),
    )?;
    let EvalRepairSeedState::Confirmed { case, .. } = settled.state else {
        panic!("the gate confirms the seed: {:?}", settled.state);
    };
    assert_eq!(uncut_sealed_cases(&fixture)?, 1);
    let case = oneiron::test_doors::eval_repair_seed::eval_case(&fixture.vault, &case)?
        .expect("the confirmed seed's case is stored");
    assert_eq!(case.family, settled.family);
    assert_eq!(case.receipts, vec![root(&source)]);
    assert_eq!(case.labels.len(), 1);
    let label = &case.labels[0];
    assert_eq!(label.kind, EvalLabelKind::AdjudicatedAudit);
    assert_eq!(
        label.value,
        blake3::hash(ANSWER.as_bytes()).to_hex().to_string(),
        "the label holds the adjudicated answer's digest"
    );
    assert_eq!(label.reference, "audit:desk-1");
    assert!((label.weight - 0.8).abs() < f64::EPSILON);
    assert_eq!(label.at, LABELLED_AT);
    assert!(
        !format!("{case:?}").contains(ANSWER),
        "the case never holds the answer text"
    );
    // A label after the gate settled is the same label or refused.
    assert!(
        label_seed(
            &fixture,
            &source,
            &audit(EvalLabelKind::AdjudicatedAudit, "another answer")
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn seed_label_refuses_owner_pick_and_judge() -> TestResult {
    let fixture = fixture()?;
    let source = adjudicated_capture(&fixture, clean_state())?;
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    for kind in [
        EvalLabelKind::OwnerPick,
        EvalLabelKind::JudgeVerdict,
        EvalLabelKind::WorldOutcome,
    ] {
        assert!(
            label_seed(&fixture, &source, &audit(kind, ANSWER)).is_err(),
            "a repair seed takes only an adjudicated audit, not {kind:?}"
        );
    }
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(proposed));
    Ok(())
}

#[test]
fn seed_label_refuses_a_leaked_or_unbounded_answer() -> TestResult {
    let fixture = fixture()?;
    let leaky = adjudicated_capture(
        &fixture,
        json!({ "draft": "the fixed answer, typed early" }),
    )?;
    let proposed = propose(&fixture, &leaky).map_err(|refusal| format!("refused: {refusal}"))?;
    let leaked = label_seed(
        &fixture,
        &leaky,
        &audit(EvalLabelKind::AdjudicatedAudit, ANSWER),
    );
    assert!(
        leaked
            .as_ref()
            .is_err_and(|refusal| refusal.contains("leaked")),
        "an adjudicated answer the workspace holds is no check: {leaked:?}"
    );
    let long = "a".repeat(513);
    assert!(
        label_seed(
            &fixture,
            &leaky,
            &audit(EvalLabelKind::AdjudicatedAudit, &long)
        )
        .is_err(),
        "a longer adjudicated answer is refused, never cut"
    );
    assert_eq!(fixture.vault.eval_repair_seed(&leaky)?, Some(proposed));

    // An observed-outcome task takes no adjudicated label.
    let observed = text_capture(&fixture)?;
    let proposed = propose(&fixture, &observed).map_err(|refusal| format!("refused: {refusal}"))?;
    assert!(
        label_seed(
            &fixture,
            &observed,
            &audit(EvalLabelKind::AdjudicatedAudit, ANSWER)
        )
        .is_err()
    );
    assert_eq!(fixture.vault.eval_repair_seed(&observed)?, Some(proposed));
    Ok(())
}

/// The companion seat's sealed families as one owner cut takes them: every
/// family whose cases all fall before `until`.
fn cut_before(fixture: &Fixture, until: u64) -> TestResult<usize> {
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
    Ok(report.cohorts_cut.len())
}

#[test]
fn a_repair_from_a_family_a_cohort_holds_is_not_held_out() -> TestResult {
    let fixture = fixture()?;
    // One failure carries three contracts: three task sources that share the
    // capture's root, and so its family.
    let contracts = json!({
        "first": text_task(clean_state()),
        "alt": text_task(json!({ "orders": [{ "id": "A-2", "city": "Nice" }] })),
        "third": text_task(json!({ "orders": [{ "id": "A-3", "city": "Metz" }] })),
    });
    let captured = capture(&fixture, contracts, json!({ "response": ANSWER }))?;
    let at_pointer = |pointer: &str| EvalRepairTaskSource {
        task_pointer: pointer.to_owned(),
        ..captured.clone()
    };
    let first = at_pointer("/value/task/first");
    let (held, late) = (
        at_pointer("/value/task/alt"),
        at_pointer("/value/task/third"),
    );
    propose(&fixture, &first).map_err(|refusal| format!("refused: {refusal}"))?;
    let waiting = propose(&fixture, &held).map_err(|refusal| format!("refused: {refusal}"))?;
    settle(
        &fixture,
        &first,
        &response("wrong answer"),
        &response(ANSWER),
    )?;
    assert_eq!(cut_before(&fixture, 1_500)?, 1, "the cut holds the family");
    // A seed proposed before the cut is refused at its gate: its case would
    // join a family the cohort holds, outside the cohort's membership.
    let seed = settle(
        &fixture,
        &held,
        &response("wrong answer"),
        &response(ANSWER),
    )?;
    // By its wire name: the red head has no such refusal to name.
    let EvalRepairSeedState::Refused { reason, at } = &seed.state else {
        panic!("the gate refuses the seed: {:?}", seed.state);
    };
    assert_eq!(serde_json::to_value(reason)?, json!("family_held"));
    assert_eq!(*at, SETTLED_AT);
    assert_eq!(seed.family, waiting.family);
    // A seed proposed after the cut is refused at once.
    let refusal = propose(&fixture, &late).expect_err("a held family takes no new seed");
    assert!(refusal.contains("a cohort already holds"), "{refusal}");
    assert!(fixture.vault.eval_repair_seed(&late)?.is_none());
    assert_eq!(
        uncut_sealed_cases(&fixture)?,
        0,
        "no case outside the cohort"
    );
    Ok(())
}

#[test]
fn a_withheld_capture_reveals_no_seed() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let coach = fixture.vault.coach_authority()?;
    let reader = fixture
        .vault
        .memory(coach.entity_ref(), coach.actor_class());
    let attempt = |source: &EvalRepairTaskSource| {
        reader.settle_eval_repair_seed(
            source,
            &response("wrong answer"),
            &response(ANSWER),
            &legs(),
            SETTLED_AT,
        )
    };
    // No seed yet: the withheld reader learns nothing, not even that.
    let before = attempt(&source)?;
    assert!(before.seed.is_none(), "{:?}", before.seed);
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let after = attempt(&source)?;
    assert!(after.seed.is_none(), "{:?}", after.seed);
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(proposed));
    Ok(())
}

#[test]
fn seed_label_refuses_an_answer_in_its_reference() -> TestResult {
    let fixture = fixture()?;
    let source = adjudicated_capture(&fixture, clean_state())?;
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let label = EvalLabel {
        reference: format!("audit:{ANSWER}"),
        ..audit(EvalLabelKind::AdjudicatedAudit, ANSWER)
    };
    let refusal = label_seed(&fixture, &source, &label).expect_err("the reference holds it");
    assert!(refusal.contains("reference holds its answer"), "{refusal}");
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(proposed));
    Ok(())
}

#[test]
fn a_task_whose_intent_holds_the_answer_is_refused() -> TestResult {
    let fixture = fixture()?;
    let told = format!("Reply with exactly this: {ANSWER}");
    // An observed answer the intent shows the candidate: no task.
    let mut observed = text_task(clean_state());
    observed["intent"] = json!(told);
    let source = capture(&fixture, observed, json!({ "response": ANSWER }))?;
    let refusal = propose(&fixture, &source).expect_err("the intent holds the answer");
    assert!(refusal.contains("leaked"), "{refusal}");
    assert!(fixture.vault.eval_repair_seed(&source)?.is_none());
    // An adjudicated answer the intent shows the candidate: no label.
    let mut adjudicated = adjudicated_task(clean_state());
    adjudicated["intent"] = json!(told);
    let source = capture(&fixture, adjudicated, json!({ "status": "resolved" }))?;
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let refusal = label_seed(
        &fixture,
        &source,
        &audit(EvalLabelKind::AdjudicatedAudit, ANSWER),
    )
    .expect_err("the intent holds the answer");
    assert!(refusal.contains("leaked"), "{refusal}");
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(proposed));
    Ok(())
}

#[test]
fn a_withheld_capture_takes_no_label() -> TestResult {
    let fixture = fixture()?;
    let source = adjudicated_capture(&fixture, clean_state())?;
    let coach = fixture.vault.coach_authority()?;
    let reader = fixture
        .vault
        .memory(coach.entity_ref(), coach.actor_class());
    let label = audit(EvalLabelKind::AdjudicatedAudit, ANSWER);
    // No seed yet: the withheld reader learns nothing, not even that.
    let before = reader.label_eval_repair_seed(&source, &label)?;
    assert!(before.seed.is_none(), "{:?}", before.seed);
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let after = reader.label_eval_repair_seed(&source, &label)?;
    assert!(after.seed.is_none(), "{:?}", after.seed);
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(proposed));
    Ok(())
}
