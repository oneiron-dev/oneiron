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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerRunnerStore,
};
use oneiron::ingest::{
    AgUiCustomMapping, AgUiFileImport, AgUiFileReadInput, AgUiObservationKind, AgUiRepairLinkStatus,
};
use oneiron::llm::manifest::{
    MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
};
use oneiron::llm::registry::{
    ModelBackendPin, ModelRegistryRow, ModelWireFormat, PricedModelBackend,
};
use oneiron::llm::{LlmCatalogCost, LlmCatalogEntry, ModelId, ModelLocality};
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use oneiron::skill_optimize::eval_doors::{EvalAuthorNowRequest, author_now};
use oneiron::skill_optimize::{
    CutDecision, EvalArmPin, EvalAuthoringInventory, EvalAuthoringPlan, EvalAuthoringReport,
    EvalCohortSetup, EvalLabel, EvalLabelKind, EvalRepairLegAnswer, EvalRepairSeed,
    EvalRepairSeedLegs, EvalRepairSeedRefusal, EvalRepairSeedRequest, EvalRepairSeedStanding,
    EvalRepairSeedState, EvalRepairSeedSummary, EvalRepairTaskSource, EvalRepairToolCall, EvalSeat,
    FamilyPurpose, RepairSeedDecision, eval_authoring_inventory, eval_authoring_inventory_sourced,
    eval_authoring_skill_id, setup_eval_cohorts,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, ModelTierRef, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
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
    fixture_on(VaultConfig::device())
}

fn fixture_on(config: VaultConfig) -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config)?;
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

/// The skill revision the hand-written Coach plan names as the one it ran.
const SKILL_REVISION: &str = "fixture-revision";

/// The Coach host queue's lease owner and budget line, as its worker admits.
const COACH_HOST: &str = "coach.host";

/// A v2 manifest binding every role, each to its own model (as
/// gate_pins_turn_retry_model_routing's): the extraction encoder on the
/// Oneironer slot and every other role on the LLM slot, all slots routed
/// on device.
fn manifest() -> TestResult<ModelManifest> {
    let mut roles = BTreeMap::new();
    for role in MODEL_ROLES {
        roles.insert(
            role,
            ModelBinding {
                model: ModelId::new(format!("seed-fixture/{role:?}@r1"))?,
                slot: if role == ModelRole::ExtractionEncoder {
                    ModelSlot::Oneironer
                } else {
                    ModelSlot::Llm
                },
                tier: ModelTierRef("seed-fixture".to_owned()),
                route_models: BTreeMap::new(),
                disposition: None,
                reads_audio: false,
            },
        );
    }
    Ok(ModelManifest {
        version: 2,
        roles,
        routes: BTreeMap::from([
            (ModelSlot::Llm, ModelLocality::OnDevice),
            (ModelSlot::Embedder, ModelLocality::OnDevice),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]),
        verdict: None,
        seat_policy: None,
    })
}

/// Pins `manifest` with a passing teacher-probe approval, as the bench
/// publishes one.
fn pin_manifest(vault: &Vault, manifest: &ModelManifest) -> TestResult {
    let policy = vault.teacher_probe_policy(None)?;
    let approval = TeacherProbeApproval::for_scored_checkpoint(manifest, &policy, 1_000_000)?;
    vault.set_model_manifest_with_teacher_approval(manifest, &approval)?;
    Ok(())
}

/// A priced registry row for `model`, served by one backend at r1 (as
/// coach_offer_run's).
fn registry_row(model: &ModelId) -> TestResult<ModelRegistryRow> {
    let priced = PricedModelBackend {
        pin: ModelBackendPin {
            model: model.clone(),
            backend: "fixture-backend".to_owned(),
            serving_revision: "r1".to_owned(),
            quantization: None,
            context_window_tokens: 4096,
        },
        price: LlmCatalogCost {
            input_per_million: "0".to_owned(),
            output_per_million: "0".to_owned(),
            cache_read_per_million: None,
            cache_write_per_million: None,
            currency: None,
        },
    };
    let mut metadata = BTreeMap::new();
    metadata.insert("backends".to_owned(), serde_json::to_value(vec![&priced])?);
    Ok(ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::Local,
        catalog: LlmCatalogEntry {
            model: model.clone(),
            display_name: model.as_str().to_owned(),
            locality: ModelLocality::OnDevice,
            context_window_tokens: 4096,
            max_output_tokens: None,
            cost: Some(priced.price.clone()),
            capabilities: Vec::new(),
            metadata,
        },
        scores: Default::default(),
        fetched_at: Default::default(),
        tokens_per_o200k: None,
        answer_tokens_per_o200k: None,
        stale_since: None,
        source_rows: None,
    })
}

/// Stores one SKILL.md revision of `name` at `version` with `body` as its
/// text, a Candidate and Proposed open revision forked from `parent`, and
/// answers its id with its content-hash hex.
fn put_skill(
    fixture: &Fixture,
    name: &str,
    version: &str,
    body: &str,
    parent: Option<EntityId>,
) -> TestResult<(EntityId, String)> {
    let id = EntityId::now();
    let markdown = format!(
        "---\nname: {name}\ndescription: {name} fixture\nversion: {version}\n---\n{body}\n"
    );
    let files = vec![HubFile::new("SKILL.md", markdown.into_bytes())];
    let hash = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let mut record = SkillRecord::new(
        name,
        format!("{name} fixture"),
        version,
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_content_hash(hash);
    if let Some(parent) = parent {
        record = record.with_forked_from(parent);
    }
    let mut package = HubPackage::new(record.clone(), files, SkillCapabilitySurface::default());
    package.format = SkillPackageFormat::Native;
    oneiron::test_doors::callable_skill::package_from_source(
        &record,
        package.files.clone(),
        SkillPackageFormat::Native,
    )?;
    oneiron::test_doors::callable_skill::put_skill_record_and_package(
        &fixture.vault,
        &id,
        &record,
        &package,
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    Ok((id, hash.to_hex()))
}

/// The Coach's leased eval-authoring attempt, as the nightly worker admits
/// it (as verb_vault_evals_cohorts_retire's).
fn coach_attempt(fixture: &Fixture, now: u64) -> TestResult<Box<DreamerAdmittedAttempt>> {
    let queued = author_now(&fixture.vault, &fixture.proof, EvalAuthorNowRequest {})?;
    let DreamerAdmissionOutcome::Admitted(nightly) = DreamerRunnerStore::new(&fixture.vault)
        .admit_next_coach_host_job(AdmitDreamerAttempt {
            lease_owner: COACH_HOST.to_owned(),
            now,
            budget_id: COACH_HOST.to_owned(),
            budget_total_units: 1 << 20,
            reserve_units: 1,
            started_milestone: None,
        })?
    else {
        panic!("the queued pass is admitted");
    };
    assert_eq!(
        EntityId::from_bytes(*nightly.status.attempt.id.as_bytes())?,
        queued.attempt
    );
    Ok(nightly)
}

/// A plan that decides nothing but one repair seed: r1 on the companion
/// seat with the `skills` pair.
fn seed_plan(inventory: &EvalAuthoringInventory, skills: &str) -> EvalAuthoringPlan {
    EvalAuthoringPlan {
        inventory_digest: inventory.inventory_digest.clone(),
        families: Vec::new(),
        cases: Vec::new(),
        cuts: Vec::new(),
        cohorts: Vec::new(),
        repair_seeds: vec![RepairSeedDecision {
            repair: "r1".to_owned(),
            seat: EvalSeat::Companion,
            skills: skills.to_owned(),
        }],
    }
}

#[test]
fn coach_plan_applies_repair_seed_decision() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let manifest = manifest()?;
    pin_manifest(&fixture.vault, &manifest)?;
    let model = manifest
        .binding(ModelRole::GenerativeReasoner)?
        .model
        .clone();
    fixture
        .vault
        .put_model_registry_row(&registry_row(&model)?)?;
    let (parent, old_hex) = put_skill(&fixture, "fixture.old", "1", "the old skill", None)?;
    let (child, candidate_hex) = put_skill(
        &fixture,
        "fixture.old",
        "2",
        "the candidate skill",
        Some(parent),
    )?;

    let now = fixture.vault.now_recorded_at();
    let inventory = eval_authoring_inventory(&fixture.vault, now)?;
    assert_eq!(inventory.repairs.len(), 1, "{inventory:?}");
    let repair = &inventory.repairs[0];
    assert_eq!(repair.id, "r1");
    assert_eq!(repair.claim_ref, source.claim_ref);
    assert_eq!(repair.source_hash, source.source_hash);
    assert_eq!(repair.outcome_ordinal, 2);
    assert_eq!(repair.task_pointer, "/value/task");
    assert_eq!(repair.app_id, "support-desk");
    assert!(repair.seeds.is_empty());
    assert_eq!(inventory.skill_pairs.len(), 1, "{inventory:?}");
    let pair = &inventory.skill_pairs[0];
    assert_eq!(pair.id, "k1");
    assert_eq!(pair.skill, child);
    assert_eq!(pair.name, "fixture.old");
    assert_eq!(pair.candidate, candidate_hex);
    assert_eq!(pair.old, old_hex);
    assert!(inventory.has_work());

    let nightly = coach_attempt(&fixture, now)?;
    let skill = eval_authoring_skill_id()?;
    let report = fixture.vault.run_coach_eval_authoring(
        &nightly,
        seed_plan(&inventory, "k1"),
        &inventory,
        (skill, SKILL_REVISION.to_owned()),
        now,
    )?;
    assert_eq!(report.repair_seeds_proposed, 1, "{report:?}");
    assert_eq!(report.repair_seeds_reused, 0);

    let seed = fixture
        .vault
        .eval_repair_seed(&source)?
        .expect("the plan's seed");
    assert_eq!(seed.state, EvalRepairSeedState::Pending);
    assert_eq!(
        seed.old,
        EvalArmPin {
            model: model.as_str().to_owned(),
            revision: "r1".to_owned(),
            skill_digest: Some(old_hex),
        }
    );
    assert_eq!(
        seed.candidate,
        EvalArmPin {
            model: model.as_str().to_owned(),
            revision: "r1".to_owned(),
            skill_digest: Some(candidate_hex),
        }
    );

    let now = fixture.vault.now_recorded_at();
    let inventory = eval_authoring_inventory(&fixture.vault, now)?;
    let repair = inventory
        .repairs
        .iter()
        .find(|row| row.id == "r1")
        .expect("r1 again");
    assert_eq!(repair.seeds.len(), 1);
    assert_eq!(repair.seeds[0].seat, EvalSeat::Companion);
    assert_eq!(repair.seeds[0].standing, EvalRepairSeedStanding::Pending);

    let report = fixture.vault.run_coach_eval_authoring(
        &nightly,
        seed_plan(&inventory, "k1"),
        &inventory,
        (skill, SKILL_REVISION.to_owned()),
        now,
    )?;
    assert_eq!(report.repair_seeds_proposed, 0, "{report:?}");
    assert_eq!(report.repair_seeds_reused, 1);

    let refused = EvalAuthoringPlan {
        repair_seeds: vec![RepairSeedDecision {
            repair: "r9".to_owned(),
            seat: EvalSeat::Companion,
            skills: "k1".to_owned(),
        }],
        ..seed_plan(&inventory, "k1")
    };
    let error = fixture
        .vault
        .run_coach_eval_authoring(
            &nightly,
            refused,
            &inventory,
            (skill, SKILL_REVISION.to_owned()),
            now,
        )
        .expect_err("a plan naming r9 is refused whole");
    assert!(
        error
            .to_string()
            .contains("names what its inventory did not hold"),
        "{error:?}"
    );

    let coach = fixture.vault.coach_authority()?;
    let read = fixture
        .vault
        .memory(coach.entity_ref(), coach.actor_class())
        .read_ag_ui_file(&AgUiFileReadInput {
            claim_ref: source.claim_ref.clone(),
            source_hash: source.source_hash.clone(),
        })?;
    assert!(
        read.source.is_none(),
        "the Coach's own read still withholds the capture"
    );
    Ok(())
}

#[test]
fn coach_second_pair_leaves_a_candidate_failed_seed() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let manifest = manifest()?;
    pin_manifest(&fixture.vault, &manifest)?;
    let model = manifest
        .binding(ModelRole::GenerativeReasoner)?
        .model
        .clone();
    fixture
        .vault
        .put_model_registry_row(&registry_row(&model)?)?;
    let (parent, _) = put_skill(&fixture, "fixture.old", "1", "the old skill", None)?;
    let (_, first_hex) = put_skill(
        &fixture,
        "fixture.old",
        "2",
        "the first candidate",
        Some(parent),
    )?;
    let (_, second_hex) = put_skill(
        &fixture,
        "fixture.old",
        "3",
        "the second candidate",
        Some(parent),
    )?;

    let now = fixture.vault.now_recorded_at();
    let nightly = coach_attempt(&fixture, now)?;
    let skill = eval_authoring_skill_id()?;
    let inventory = eval_authoring_inventory(&fixture.vault, now)?;
    let pair_id = |candidate: &str| {
        inventory
            .skill_pairs
            .iter()
            .find(|pair| pair.candidate == candidate)
            .expect("the pair")
            .id
            .clone()
    };
    let (first, second) = (pair_id(&first_hex), pair_id(&second_hex));

    let report = fixture.vault.run_coach_eval_authoring(
        &nightly,
        seed_plan(&inventory, &first),
        &inventory,
        (skill, SKILL_REVISION.to_owned()),
        now,
    )?;
    assert_eq!(report.repair_seeds_proposed, 1, "{report:?}");
    let proposed = fixture
        .vault
        .eval_repair_seed(&source)?
        .expect("the first seed");
    assert_eq!(proposed.state, EvalRepairSeedState::Pending);
    let settled = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response("another wrong answer"),
    )?;
    assert!(
        matches!(
            settled.state,
            EvalRepairSeedState::Refused {
                reason: EvalRepairSeedRefusal::CandidateFailed,
                ..
            }
        ),
        "{:?}",
        settled.state
    );

    // A second pair finds the refused seed standing: no candidate is chosen
    // by the sealed task's result.
    let now = fixture.vault.now_recorded_at();
    let inventory = eval_authoring_inventory(&fixture.vault, now)?;
    let report = fixture.vault.run_coach_eval_authoring(
        &nightly,
        seed_plan(&inventory, &second),
        &inventory,
        (skill, SKILL_REVISION.to_owned()),
        now,
    )?;
    assert_eq!(report.repair_seeds_proposed, 0, "{report:?}");
    assert_eq!(report.repair_seeds_reused, 1, "{report:?}");
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(settled));
    Ok(())
}

#[test]
fn an_answer_a_precondition_or_a_tool_shows_is_refused() -> TestResult {
    let fixture = fixture()?;
    // A leg is shown each precondition's pointer: an observed answer there
    // is no task.
    let pointer = "/orders/0/city";
    let mut observed = text_task(clean_state());
    observed["preconditions"] = json!([{ "pointer": pointer, "equals": "Lyon" }]);
    let source = capture(&fixture, observed.clone(), json!({ "response": pointer }))?;
    let refusal = propose(&fixture, &source).expect_err("the precondition holds the answer");
    assert!(refusal.contains("leaked"), "{refusal}");
    assert!(fixture.vault.eval_repair_seed(&source)?.is_none());
    // Nor is an adjudicated answer there a check.
    let mut adjudicated = observed;
    adjudicated["grader"] = json!({ "kind": "adjudicated_response" });
    let source = capture(&fixture, adjudicated, json!({ "status": "resolved" }))?;
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let refusal = label_seed(
        &fixture,
        &source,
        &audit(EvalLabelKind::AdjudicatedAudit, pointer),
    )
    .expect_err("the precondition holds the answer");
    assert!(refusal.contains("leaked"), "{refusal}");
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(proposed));
    // A leg is shown each declared tool's name: an end state that is one
    // is no task.
    let mut tool = tool_task();
    tool["world"] = json!({ "json_state_tools": { "tools": [
        { "name": "set_city", "effect": { "kind": "set", "pointer": "" } },
    ] } });
    tool["initial_state"] = json!("Paris");
    let source = capture(&fixture, tool, json!({ "state": "set_city" }))?;
    let refusal = propose(&fixture, &source).expect_err("the tool's name is the end state");
    assert!(refusal.contains("leaked"), "{refusal}");
    assert!(fixture.vault.eval_repair_seed(&source)?.is_none());
    Ok(())
}

#[test]
fn seed_label_refuses_an_answer_in_its_task_pointer() -> TestResult {
    let fixture = fixture()?;
    let source = adjudicated_capture(&fixture, clean_state())?;
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    // The seed keeps the source's task pointer as text.
    let answer = "value/task";
    assert!(source.task_pointer.contains(answer));
    let refusal = label_seed(
        &fixture,
        &source,
        &audit(EvalLabelKind::AdjudicatedAudit, answer),
    )
    .expect_err("the task pointer holds the answer");
    assert!(refusal.contains("task pointer"), "{refusal}");
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(proposed));
    Ok(())
}

#[test]
fn an_end_state_a_whole_shown_value_is_refused() -> TestResult {
    let fixture = fixture()?;
    let declaration = json!({ "name": "set_root", "effect": { "kind": "set", "pointer": "" } });
    let precondition = json!({ "pointer": "/city", "equals": "Paris" });
    let mut tool = tool_task();
    tool["world"] = json!({ "json_state_tools": { "tools": [declaration.clone()] } });
    tool["initial_state"] = json!({ "city": "Paris" });
    tool["preconditions"] = json!([precondition.clone()]);
    tool["tools"] = json!(["set_root"]);
    // A leg is shown each whole declared tool, each whole precondition and
    // the offered tools' list: an end state that is one of them, which a
    // leg can copy into a call, is no task.
    for end in [declaration, precondition, json!(["set_root"])] {
        let source = capture(&fixture, tool.clone(), json!({ "state": end }))?;
        let refusal = propose(&fixture, &source).expect_err("the leg's input holds the end state");
        assert!(refusal.contains("leaked"), "{refusal}");
        assert!(fixture.vault.eval_repair_seed(&source)?.is_none());
    }
    // An end state the input does not hold is a task.
    let source = capture(&fixture, tool, json!({ "state": { "city": "Lyon" } }))?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    Ok(())
}

#[test]
fn an_answer_that_is_the_json_of_a_shown_value_is_refused() -> TestResult {
    let fixture = fixture()?;
    // A leg is shown its input as JSON: the JSON text of a value in it is an
    // answer it can copy.
    let answer = clean_state()["orders"][0].to_string();
    let source = capture(
        &fixture,
        text_task(clean_state()),
        json!({ "response": answer }),
    )?;
    let refusal = propose(&fixture, &source).expect_err("the workspace's JSON holds the answer");
    assert!(refusal.contains("leaked"), "{refusal}");
    assert!(fixture.vault.eval_repair_seed(&source)?.is_none());
    // Nor is such an adjudicated answer a check.
    let source = adjudicated_capture(&fixture, clean_state())?;
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    let refusal = label_seed(
        &fixture,
        &source,
        &audit(EvalLabelKind::AdjudicatedAudit, &answer),
    )
    .expect_err("the workspace's JSON holds the answer");
    assert!(refusal.contains("leaked"), "{refusal}");
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(proposed));
    Ok(())
}

#[test]
fn seed_label_refuses_an_answer_that_is_a_seed_identifier() -> TestResult {
    let fixture = fixture()?;
    let mut source = adjudicated_capture(&fixture, clean_state())?;
    source.seat = EvalSeat::Named("ORCHID".to_owned());
    let proposed = propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    // The seed keeps its source and its arms' pins: an answer that is one of
    // them, whole, would sit in the seed as text.
    let pins = request(&source);
    for answer in [
        "ORCHID".to_owned(),
        source.claim_ref.clone(),
        source.source_hash.clone(),
        source.outcome_ordinal.to_string(),
        pins.old.model.clone(),
        pins.old.revision.clone(),
        pins.candidate.skill_digest.clone().unwrap_or_default(),
    ] {
        let refusal = label_seed(
            &fixture,
            &source,
            &audit(EvalLabelKind::AdjudicatedAudit, &answer),
        )
        .expect_err("the answer is one of the seed's identifiers");
        assert!(refusal.contains("identifiers"), "{answer}: {refusal}");
        assert_eq!(
            fixture.vault.eval_repair_seed(&source)?,
            Some(proposed.clone())
        );
    }
    Ok(())
}

#[test]
fn a_candidate_failed_seed_stands_against_another_candidate() -> TestResult {
    let fixture = fixture()?;
    let source = adjudicated_capture(&fixture, clean_state())?;
    propose(&fixture, &source).map_err(|refusal| format!("refused: {refusal}"))?;
    // The audit's answer is a digest neither arm holds.
    let answer = "5f2c8e0d4b7a9163";
    let labelled = label_seed(
        &fixture,
        &source,
        &audit(EvalLabelKind::AdjudicatedAudit, answer),
    )
    .map_err(|refusal| format!("refused: {refusal}"))?;
    assert_eq!(labelled.state, EvalRepairSeedState::Pending);
    let settled = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response("another wrong answer"),
    )?;
    assert!(
        matches!(
            settled.state,
            EvalRepairSeedState::Refused {
                reason: EvalRepairSeedRefusal::CandidateFailed,
                ..
            }
        ),
        "{:?}",
        settled.state
    );

    // Proposed again with the same old arm and another candidate: the
    // refused seed stands, label and all.
    let again = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .propose_eval_repair_seed(
            &EvalRepairSeedRequest {
                source: source.clone(),
                old: arm("old-skill-digest"),
                candidate: arm(answer),
            },
            PROPOSED_AT + 1,
        )?
        .seed
        .expect("the owner reads their own capture");
    assert_eq!(again, settled);
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(settled));
    Ok(())
}

#[test]
fn an_authoring_report_from_before_repair_seeds_decodes() -> TestResult {
    // An Applied execution keeps its report in a named-MessagePack side
    // table; one stored before repair seeds has neither count.
    let before = json!({
        "families_assigned": 1,
        "families_extended": 0,
        "cases_recorded": 2,
        "cases_reused": 0,
        "labels_added": 1,
        "cohorts_cut": [],
        "cuts_with_coverage_gaps": 0,
        "cohorts_retired": [],
        "cohorts_kept": 0,
        "skipped": [],
    });
    let report: EvalAuthoringReport = rmp_serde::from_slice(&rmp_serde::to_vec_named(&before)?)?;
    assert_eq!(report.cases_recorded, 2);
    assert_eq!(report.labels_added, 1);
    assert_eq!(
        (report.repair_seeds_proposed, report.repair_seeds_reused),
        (0, 0)
    );
    Ok(())
}

#[test]
fn the_repair_listing_is_bounded() -> TestResult {
    let fixture = fixture()?;
    // One failure holding twelve task contracts, and ten outcomes each
    // linking its repair: 120 rows, were the listing unbounded.
    let tasks: Vec<Value> = (0..12).map(|_| text_task(clean_state())).collect();
    let mut events = vec![
        json!({
            "type": "CUSTOM",
            "name": "desk.failure",
            "value": { "id": "f-1", "threadId": "t-1", "runId": "r-1", "tasks": tasks },
        }),
        json!({
            "type": "CUSTOM",
            "name": "desk.repair",
            "value": { "id": "p-1", "threadId": "t-1", "runId": "r-1", "failureId": "f-1" },
        }),
    ];
    for outcome in 0..10 {
        events.push(json!({
            "type": "CUSTOM",
            "name": "desk.outcome",
            "value": {
                "id": format!("o-{outcome}"),
                "threadId": "t-1",
                "runId": "r-1",
                "repairId": "p-1",
                "result": { "response": ANSWER },
            },
        }));
    }
    let jsonl = events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    fixture.vault.ingest_ag_ui_file(
        &fixture.proof,
        &AgUiFileImport {
            claim_ref: None,
            project_ref: fixture.project.to_hex(),
            app_id: "support-desk".to_owned(),
            custom_mappings: mappings(),
            jsonl,
        },
    )?;

    let inventory = eval_authoring_inventory(&fixture.vault, fixture.vault.now_recorded_at())?;
    let mut per_outcome: BTreeMap<usize, usize> = BTreeMap::new();
    for repair in &inventory.repairs {
        *per_outcome.entry(repair.outcome_ordinal).or_default() += 1;
    }
    // At most 8 contracts a failure, and 64 rows in all.
    assert_eq!(inventory.repairs.len(), 64, "{per_outcome:?}");
    assert!(
        per_outcome.values().all(|rows| *rows == 8),
        "{per_outcome:?}"
    );
    assert_eq!(
        inventory.repairs.last().map(|repair| repair.id.as_str()),
        Some("r64")
    );
    Ok(())
}

/// `text_task(clean_state())` with every object's keys in another order: the
/// same contract in other bytes.
fn reordered_text_task() -> Value {
    json!({
        "grader": { "pointer": "/response", "kind": "observed_response_equals" },
        "allowed_actions": ["respond"],
        "tools": [],
        "input": { "history": [{ "text": "Where does my parcel go?", "role": "user" }] },
        "intent": "Answer the customer with the delivery plan.",
        "preconditions": [],
        "initial_state": { "orders": [{ "status": "packed", "city": "Lyon", "id": "A-1" }] },
        "world": "text_response",
    })
}

#[test]
fn a_seeded_contract_takes_no_seed_from_another_source_or_seat() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let seed = propose(&fixture, &source)?;
    // The same contract imported again, its keys in another order: another
    // claim, so another source key. And the first source on another seat.
    let again = capture(
        &fixture,
        reordered_text_task(),
        json!({ "response": ANSWER }),
    )?;
    assert_ne!(again.claim_ref, source.claim_ref);
    let other_seat = EvalRepairTaskSource {
        seat: EvalSeat::Decision,
        ..source.clone()
    };
    for alias in [&again, &other_seat] {
        let refused = propose(&fixture, alias).expect_err("a seeded contract takes no second seed");
        assert!(refused.contains("contract already has a seed"), "{refused}");
        assert_eq!(fixture.vault.eval_repair_seed(alias)?, None);
    }
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(seed));

    // Another contract takes its own seed.
    let other = capture(
        &fixture,
        text_task(json!({ "orders": [] })),
        json!({ "response": ANSWER }),
    )?;
    assert_eq!(
        propose(&fixture, &other)?.state,
        EvalRepairSeedState::Pending
    );

    // An erase takes the seed with its capture, and the contract with it.
    let claim = EntityId::from_hex(&source.claim_ref)?;
    oneiron::test_doors::inquiry::erase_actor_in_tables_in_order(
        &fixture.vault,
        &claim,
        &["SKILL_OPTIMIZE_EVAL_REPAIR_SEED"],
    )?;
    assert_eq!(
        propose(&fixture, &again)?.state,
        EvalRepairSeedState::Pending
    );
    Ok(())
}

/// A plan that decides nothing but one repair seed: `repair` on the
/// companion seat with the `skills` pair.
fn seed_plan_for(
    inventory: &EvalAuthoringInventory,
    repair: &str,
    skills: &str,
) -> EvalAuthoringPlan {
    EvalAuthoringPlan {
        repair_seeds: vec![RepairSeedDecision {
            repair: repair.to_owned(),
            seat: EvalSeat::Companion,
            skills: skills.to_owned(),
        }],
        ..seed_plan(inventory, skills)
    }
}

/// The inventory's row for `source`'s capture.
fn repair_row<'a>(
    inventory: &'a EvalAuthoringInventory,
    source: &EvalRepairTaskSource,
) -> &'a oneiron::skill_optimize::EvalRepairCandidate {
    inventory
        .repairs
        .iter()
        .find(|repair| repair.claim_ref == source.claim_ref)
        .expect("the capture's row")
}

#[test]
fn coach_alias_of_a_seeded_contract_shows_its_standing_and_takes_no_seed() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let again = capture(
        &fixture,
        reordered_text_task(),
        json!({ "response": ANSWER }),
    )?;
    let manifest = manifest()?;
    pin_manifest(&fixture.vault, &manifest)?;
    let model = manifest
        .binding(ModelRole::GenerativeReasoner)?
        .model
        .clone();
    fixture
        .vault
        .put_model_registry_row(&registry_row(&model)?)?;
    let (parent, _) = put_skill(&fixture, "fixture.old", "1", "the old skill", None)?;
    let (_, first_hex) = put_skill(
        &fixture,
        "fixture.old",
        "2",
        "the first candidate",
        Some(parent),
    )?;
    let (_, second_hex) = put_skill(
        &fixture,
        "fixture.old",
        "3",
        "the second candidate",
        Some(parent),
    )?;

    let now = fixture.vault.now_recorded_at();
    let nightly = coach_attempt(&fixture, now)?;
    let skill = eval_authoring_skill_id()?;
    let inventory = eval_authoring_inventory(&fixture.vault, now)?;
    let pair_id = |candidate: &str| {
        inventory
            .skill_pairs
            .iter()
            .find(|pair| pair.candidate == candidate)
            .expect("the pair")
            .id
            .clone()
    };
    let (first, second) = (pair_id(&first_hex), pair_id(&second_hex));
    let report = fixture.vault.run_coach_eval_authoring(
        &nightly,
        seed_plan_for(&inventory, &repair_row(&inventory, &source).id, &first),
        &inventory,
        (skill, SKILL_REVISION.to_owned()),
        now,
    )?;
    assert_eq!(report.repair_seeds_proposed, 1, "{report:?}");
    let settled = settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response("another wrong answer"),
    )?;

    // The alias's row shows the refused seed of its contract, and a second
    // pair on it makes no seed: the sealed task's result picks no candidate.
    let now = fixture.vault.now_recorded_at();
    let inventory = eval_authoring_inventory(&fixture.vault, now)?;
    let alias = repair_row(&inventory, &again);
    assert_eq!(
        alias.seeds,
        vec![EvalRepairSeedSummary {
            seat: EvalSeat::Companion,
            standing: EvalRepairSeedStanding::Refused {
                reason: EvalRepairSeedRefusal::CandidateFailed,
            },
        }]
    );
    let report = fixture.vault.run_coach_eval_authoring(
        &nightly,
        seed_plan_for(&inventory, &alias.id, &second),
        &inventory,
        (skill, SKILL_REVISION.to_owned()),
        now,
    )?;
    assert_eq!(report.repair_seeds_proposed, 0, "{report:?}");
    assert_eq!(report.repair_seeds_reused, 0, "{report:?}");
    assert!(
        report.skipped.iter().any(
            |skip| skip.item == alias.id && skip.reason.contains("contract already has a seed")
        ),
        "{report:?}"
    );
    assert_eq!(fixture.vault.eval_repair_seed(&again)?, None);
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(settled));
    Ok(())
}

#[test]
fn a_capture_of_many_unlinked_outcomes_lists_in_linear_time() -> TestResult {
    let fixture = fixture()?;
    // 30,000 outcomes, each with its own id and a repair id no row holds.
    // Resolving each link by a scan of every row was some 2.7e9 compares
    // for a listing of no row.
    const OUTCOMES: usize = 30_000;
    let jsonl = (0..OUTCOMES)
        .map(|outcome| {
            json!({
                "type": "CUSTOM",
                "name": "desk.outcome",
                "value": {
                    "id": format!("o-{outcome}"),
                    "threadId": "t-1",
                    "runId": "r-1",
                    "repairId": format!("p-{outcome}"),
                    "result": { "response": ANSWER },
                },
            })
            .to_string()
        })
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
    assert_eq!(receipt.event_count, OUTCOMES);

    let started = Instant::now();
    let inventory = eval_authoring_inventory(&fixture.vault, fixture.vault.now_recorded_at())?;
    let listed_in = started.elapsed();
    assert!(inventory.repairs.is_empty(), "{:?}", inventory.repairs);
    assert!(
        listed_in < Duration::from_secs(10),
        "listed in {listed_in:?}"
    );
    Ok(())
}

#[test]
fn repair_links_keep_their_statuses() -> TestResult {
    let fixture = fixture()?;
    let event =
        |name: &str, value: Value| json!({ "type": "CUSTOM", "name": name, "value": value });
    let outcome = |id: &str, repair: &str| {
        event(
            "desk.outcome",
            json!({
                "id": id,
                "threadId": "t-1",
                "runId": "r-1",
                "repairId": repair,
                "result": { "response": ANSWER },
            }),
        )
    };
    let events = [
        event(
            "desk.failure",
            json!({ "id": "f-1", "threadId": "t-1", "runId": "r-1", "task": text_task(clean_state()) }),
        ),
        event(
            "desk.repair",
            json!({ "id": "p-1", "threadId": "t-1", "runId": "r-1", "failureId": "f-1" }),
        ),
        // 2 links; 3 names a repair no row holds.
        outcome("o-1", "p-1"),
        outcome("o-2", "p-2"),
        // 4 names a repair of another run.
        outcome("o-3", "p-9"),
        event(
            "desk.repair",
            json!({ "id": "p-9", "threadId": "t-1", "runId": "r-2", "failureId": "f-1" }),
        ),
        // 6 and 7 hold one id in one run.
        outcome("o-4", "p-1"),
        outcome("o-4", "p-1"),
        // 8 has no observed result.
        event(
            "desk.outcome",
            json!({ "id": "o-5", "threadId": "t-1", "runId": "r-1", "repairId": "p-1" }),
        ),
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
    let read = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_ag_ui_file(&AgUiFileReadInput {
            claim_ref: receipt.claim_ref,
            source_hash: receipt.source_hash,
        })?;
    let view = read.source.expect("the owner reads their own capture");
    let statuses: Vec<(usize, AgUiRepairLinkStatus)> = view
        .repair_links
        .iter()
        .map(|link| (link.outcome_ordinal, link.status.clone()))
        .collect();
    assert_eq!(
        statuses,
        vec![
            (2, AgUiRepairLinkStatus::Linked),
            (3, AgUiRepairLinkStatus::MissingLink),
            (4, AgUiRepairLinkStatus::NamespaceMismatch),
            (6, AgUiRepairLinkStatus::AmbiguousLink),
            (7, AgUiRepairLinkStatus::AmbiguousLink),
            (8, AgUiRepairLinkStatus::MissingOutcome),
        ]
    );
    let linked = &view.repair_links[0];
    assert_eq!(
        (linked.repair_ordinal, linked.failure_ordinal),
        (Some(1), Some(0))
    );
    Ok(())
}

#[test]
fn a_capture_of_many_unmapped_custom_events_lists_in_linear_time() -> TestResult {
    let fixture = fixture()?;
    // 40,000 mappings and 40,000 CUSTOM events whose names none of them
    // holds, every name of one length. Finding each event's mapping by a scan
    // of the mappings was some 1.6e9 name compares for a listing of no row.
    const MAPPINGS: usize = 40_000;
    let custom_mappings = (0..MAPPINGS)
        .map(|index| AgUiCustomMapping {
            id: None,
            thread_id: None,
            run_id: None,
            ..mapping(
                &format!("desk.unused.{index:06}"),
                AgUiObservationKind::Failure,
            )
        })
        .collect();
    let jsonl = (MAPPINGS..2 * MAPPINGS)
        .map(|index| {
            json!({ "type": "CUSTOM", "name": format!("desk.unused.{index:06}"), "value": {} })
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    let receipt = fixture.vault.ingest_ag_ui_file(
        &fixture.proof,
        &AgUiFileImport {
            claim_ref: None,
            project_ref: fixture.project.to_hex(),
            app_id: "support-desk".to_owned(),
            custom_mappings,
            jsonl,
        },
    )?;
    assert_eq!(receipt.event_count, MAPPINGS);

    let started = Instant::now();
    let inventory = eval_authoring_inventory(&fixture.vault, fixture.vault.now_recorded_at())?;
    let listed_in = started.elapsed();
    assert!(inventory.repairs.is_empty(), "{:?}", inventory.repairs);
    assert!(
        listed_in < Duration::from_secs(10),
        "listed in {listed_in:?}"
    );
    Ok(())
}

/// A seed holds its task contract until the erase takes it, also once its
/// capture is deleted, but a capture that no longer reads lends its seed's
/// seat and standing to no row: the contract's other rows are not listed,
/// since they can take no seed (Astra delta 2 J4; RULING
/// UNBUILT-P05E-CONTRACT-ALIAS = A).
#[test]
fn a_deleted_captures_seed_shows_on_no_alias_row() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let again = capture(
        &fixture,
        reordered_text_task(),
        json!({ "response": ANSWER }),
    )?;
    propose(&fixture, &source)?;
    settle(
        &fixture,
        &source,
        &response("wrong answer"),
        &response("another wrong answer"),
    )?;
    let refused = vec![EvalRepairSeedSummary {
        seat: EvalSeat::Companion,
        standing: EvalRepairSeedStanding::Refused {
            reason: EvalRepairSeedRefusal::CandidateFailed,
        },
    }];
    let inventory = eval_authoring_inventory(&fixture.vault, fixture.vault.now_recorded_at())?;
    assert_eq!(repair_row(&inventory, &again).seeds, refused);

    let claim = EntityId::from_hex(&source.claim_ref)?;
    assert!(
        fixture.vault.delete_entity(&claim)?,
        "the capture is deleted"
    );
    let inventory = eval_authoring_inventory(&fixture.vault, fixture.vault.now_recorded_at())?;
    assert!(
        inventory.repairs.is_empty(),
        "no row shows the deleted capture's seed: {:?}",
        inventory.repairs
    );
    // The refusal says no more than the listing: the row is not listed, and
    // nothing of the deleted capture's seed shows (Astra delta 3 K2).
    let held = propose(&fixture, &again).expect_err("the seed still holds its contract");
    assert!(held.contains(UNLISTED_REPAIR), "{held}");
    assert!(!held.contains("seed"), "{held}");
    assert_eq!(fixture.vault.eval_repair_seed(&again)?, None);
    Ok(())
}

/// An alias row shows the seed of a capture the listing no longer reaches
/// but that still reads (here, one older than the window), and the
/// inventory's rows name that capture: the seed's standing came from it
/// (Astra delta 2 J4).
#[test]
fn an_alias_rows_seed_names_its_capture_among_the_rows_read() -> TestResult {
    const T0: u64 = 1_780_000_000;
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let fixture = fixture_on(config)?;
    let source = text_capture(&fixture)?;
    propose(&fixture, &source)?;
    clock.set(T0 + 31 * 24 * 60 * 60);
    let again = capture(
        &fixture,
        reordered_text_task(),
        json!({ "response": ANSWER }),
    )?;

    let (inventory, rows) =
        eval_authoring_inventory_sourced(&fixture.vault, fixture.vault.now_recorded_at())?;
    assert!(
        inventory
            .repairs
            .iter()
            .all(|repair| repair.claim_ref != source.claim_ref),
        "the first capture is older than the window: {:?}",
        inventory.repairs
    );
    assert_eq!(
        repair_row(&inventory, &again).seeds,
        vec![EvalRepairSeedSummary {
            seat: EvalSeat::Companion,
            standing: EvalRepairSeedStanding::Pending,
        }]
    );
    let rows = rows.expect("the inventory knows the rows it read");
    assert!(
        rows.contains(&EntityId::from_hex(&source.claim_ref)?),
        "the seed's capture is among the rows read"
    );
    Ok(())
}

/// The refusal of a seed for a repair whose contract is held only by a seed
/// whose capture no longer reads: the listing leaves such a row out.
const UNLISTED_REPAIR: &str = "the repair is no longer listed";

/// A plan made while two captures of one contract had no seed applies after
/// the first took its seed and was deleted. The second's refusal says only
/// that its row is no longer listed, as a listing now leaves it out, never
/// that a seed holds its contract (Astra delta 3 K2; RULING
/// UNBUILT-P05E-WITHDRAWN-SEED = A).
#[test]
fn an_apply_shows_nothing_of_a_seed_whose_capture_no_longer_reads() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let again = capture(
        &fixture,
        reordered_text_task(),
        json!({ "response": ANSWER }),
    )?;
    let manifest = manifest()?;
    pin_manifest(&fixture.vault, &manifest)?;
    let model = manifest
        .binding(ModelRole::GenerativeReasoner)?
        .model
        .clone();
    fixture
        .vault
        .put_model_registry_row(&registry_row(&model)?)?;
    let (parent, _) = put_skill(&fixture, "fixture.old", "1", "the old skill", None)?;
    let (_, candidate_hex) =
        put_skill(&fixture, "fixture.old", "2", "the candidate", Some(parent))?;

    let now = fixture.vault.now_recorded_at();
    let nightly = coach_attempt(&fixture, now)?;
    let skill = eval_authoring_skill_id()?;
    let inventory = eval_authoring_inventory(&fixture.vault, now)?;
    let alias = repair_row(&inventory, &again);
    assert!(alias.seeds.is_empty(), "{alias:?}");
    let pair = inventory
        .skill_pairs
        .iter()
        .find(|pair| pair.candidate == candidate_hex)
        .expect("the pair")
        .id
        .clone();

    // The first capture takes its seed and is deleted: the seed still holds
    // the contract, and no listing shows it.
    propose(&fixture, &source)?;
    let claim = EntityId::from_hex(&source.claim_ref)?;
    assert!(
        fixture.vault.delete_entity(&claim)?,
        "the capture is deleted"
    );

    let report = fixture.vault.run_coach_eval_authoring(
        &nightly,
        seed_plan_for(&inventory, &alias.id, &pair),
        &inventory,
        (skill, SKILL_REVISION.to_owned()),
        now,
    )?;
    assert_eq!(report.repair_seeds_proposed, 0, "{report:?}");
    assert_eq!(report.repair_seeds_reused, 0, "{report:?}");
    let reasons: Vec<&str> = report
        .skipped
        .iter()
        .filter(|skip| skip.item == alias.id)
        .map(|skip| skip.reason.as_str())
        .collect();
    assert_eq!(reasons, vec![UNLISTED_REPAIR], "{report:?}");
    assert_eq!(fixture.vault.eval_repair_seed(&again)?, None);
    Ok(())
}

#[test]
fn a_mapping_of_one_long_pointer_lists_in_linear_time() -> TestResult {
    let fixture = fixture()?;
    // One mapping whose id pointer is a single escaped token of 256 Ki
    // tildes (512 KiB) that no event holds, and 40,000 small CUSTOM events
    // of its name. Unescaping the pointer again at every event was some
    // 2e10 bytes of work for a listing of no row (Astra delta 3 K1).
    const EVENTS: usize = 40_000;
    let custom_mappings = vec![AgUiCustomMapping {
        id: Some(format!("/{}", "~0".repeat(256 * 1024))),
        thread_id: None,
        run_id: None,
        ..mapping("desk.long", AgUiObservationKind::Failure)
    }];
    let jsonl =
        vec![json!({ "type": "CUSTOM", "name": "desk.long", "value": {} }).to_string(); EVENTS]
            .join("\n");
    let receipt = fixture.vault.ingest_ag_ui_file(
        &fixture.proof,
        &AgUiFileImport {
            claim_ref: None,
            project_ref: fixture.project.to_hex(),
            app_id: "support-desk".to_owned(),
            custom_mappings,
            jsonl,
        },
    )?;
    assert_eq!(receipt.event_count, EVENTS);

    let started = Instant::now();
    let inventory = eval_authoring_inventory(&fixture.vault, fixture.vault.now_recorded_at())?;
    let listed_in = started.elapsed();
    assert!(inventory.repairs.is_empty(), "{:?}", inventory.repairs);
    assert!(
        listed_in < Duration::from_secs(10),
        "listed in {listed_in:?}"
    );
    Ok(())
}

#[test]
fn a_capture_of_many_outcomes_of_one_repair_lists_in_linear_time() -> TestResult {
    let fixture = fixture()?;
    // One failure whose id is 2 MiB long, one repair naming it, and 40,000
    // outcomes of that repair. Resolving the repair's failure again for
    // every outcome hashed the long id 40,000 times, some 8e10 bytes of
    // work for a listing of no row: the failure holds no task contract
    // (Astra delta 4 L1).
    const OUTCOMES: usize = 40_000;
    let failure_id = "f".repeat(2 * 1024 * 1024);
    let event =
        |name: &str, value: Value| json!({ "type": "CUSTOM", "name": name, "value": value });
    let jsonl = [
        event(
            "desk.failure",
            json!({ "id": failure_id.as_str(), "threadId": "t-1", "runId": "r-1" }),
        ),
        event(
            "desk.repair",
            json!({
                "id": "p-1",
                "threadId": "t-1",
                "runId": "r-1",
                "failureId": failure_id.as_str(),
            }),
        ),
    ]
    .iter()
    .map(Value::to_string)
    .chain((0..OUTCOMES).map(|outcome| {
        event(
            "desk.outcome",
            json!({
                "id": format!("o-{outcome}"),
                "threadId": "t-1",
                "runId": "r-1",
                "repairId": "p-1",
                "result": { "response": ANSWER },
            }),
        )
        .to_string()
    }))
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
    assert_eq!(receipt.event_count, OUTCOMES + 2);

    let started = Instant::now();
    let inventory = eval_authoring_inventory(&fixture.vault, fixture.vault.now_recorded_at())?;
    let listed_in = started.elapsed();
    assert!(inventory.repairs.is_empty(), "{:?}", inventory.repairs);
    assert!(
        listed_in < Duration::from_secs(10),
        "listed in {listed_in:?}"
    );
    // Every outcome links through the one repair to the long failure.
    let read = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_ag_ui_file(&AgUiFileReadInput {
            claim_ref: receipt.claim_ref,
            source_hash: receipt.source_hash,
        })?;
    let view = read.source.expect("the owner reads their own capture");
    assert_eq!(view.repair_links.len(), OUTCOMES);
    assert!(view.repair_links.iter().all(|link| {
        link.status == AgUiRepairLinkStatus::Linked
            && (link.repair_ordinal, link.failure_ordinal) == (Some(1), Some(0))
    }));
    Ok(())
}

/// The measuring host is handed no seed whose capture no longer reads: the
/// gate settles no such seed, and no listing shows it (RULING
/// UNBUILT-P05E-WITHDRAWN-SEED = A). The seed itself stays until the erase
/// takes it (Astra delta 4 L2).
#[test]
fn the_host_is_handed_no_seed_whose_capture_no_longer_reads() -> TestResult {
    let fixture = fixture()?;
    let source = text_capture(&fixture)?;
    let seed = propose(&fixture, &source)?;
    assert_eq!(
        fixture.vault.pending_eval_repair_seeds()?,
        vec![seed.clone()]
    );

    let claim = EntityId::from_hex(&source.claim_ref)?;
    assert!(
        fixture.vault.delete_entity(&claim)?,
        "the capture is deleted"
    );
    assert!(
        fixture.vault.pending_eval_repair_seeds()?.is_empty(),
        "the host measures no seed of a deleted capture"
    );
    assert_eq!(fixture.vault.eval_repair_seed(&source)?, Some(seed));
    Ok(())
}
