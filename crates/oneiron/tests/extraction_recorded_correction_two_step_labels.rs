//! A lent correction folded from the candidates of two steps whose words carry different
//! relationship labels is asked about the head it corrects (FIX row
//! LENT-RECORDED-CORRECTION-OVER-TWO-STEP-LABELS-NO-TEST, left by #9938's review round 1).
//!
//! The attempt queues two turns about owen: the first MESSAGE carries no label, the second
//! carries relationship A. A stored food head about owen is scoped to A, and the Dreamer reads
//! A's MESSAGEs and CLAIMs. Step 1 cites the unlabelled turn, so its set is unbound, and keeps a
//! candidate that names relationship B; step 2 cites the labelled turn, so its set is {A}, and
//! keeps the same proposal naming no relationship. Both may correct the head, so both assemble
//! to its identity and fold into one union operand. The union carries step 1's `rel` B and is
//! assembled under the set of both steps' turns, {A}.
//!
//! The pack check (`extraction_pack/reads.rs` `check_pack_candidates`) holds a proposed
//! relationship inside the operand's set, except for a correction that names its recorded
//! candidates: each naming step kept its candidate's relationship inside its own set. Before
//! that exception the union that corrects the head was refused ("extraction relationship
//! crossed branch scope"); now the observations page asks it about the head. The same union
//! with `corrects` removed is still refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_recorded_correction_two_step_labels`.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/labelled_turns.rs"]
mod labelled_turns;
#[path = "extraction_steps/support.rs"]
mod step_support;

use std::sync::Arc;

use labelled_turns::{
    grant_relationship_claims, grant_relationship_messages, store_relationship,
    witness_labelled_turns,
};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MemoryResult};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::extraction_inputs::enqueue_admitted_extraction_attempt;
use oneiron::test_doors::extraction_steps::{ExtractionStepFixture, attach_extraction_step_lender};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::write_envelope::claim_body::relationship_scope_of;
use oneiron::{EntityId, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use step_support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    open_extraction_step_vault, page_turns_with_versions, read_bound_extraction_page,
};

/// The verb that serves the bound candidate and correction-listing facts.
const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.extraction.observations.page";

/// The host clock the observations page takes, in Unix milliseconds.
const OBSERVATION_NOW_MS: u64 = 21_000;

/// The predicate shared by the stored head and the proposed value.
const FOOD: &str = "preference.food";

/// The value of the stored head about owen.
const HEAD_VALUE: &str = "green tea";

/// The value both steps propose, which corrects the head.
const PROPOSED_VALUE: &str = "black tea";

/// The words of the first turn, whose MESSAGE carries no label.
const UNLABELLED_WORDS: &str = "owen savors black tea";

/// The words of the second turn, whose MESSAGE carries relationship A.
const LABELLED_WORDS: &str = "owen now likes black tea";

/// Lands one active, stated food preference about `subject` scoped to `relationship`, a plain
/// public put on the default facet with Auto approval.
fn land_relationship_head(
    vault: &Vault,
    subject: EntityId,
    relationship: EntityId,
) -> ExtractionStepTestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        FOOD,
        ClaimSubject::Entity(subject),
        RmpValue::from(HEAD_VALUE),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.scope = Some(RmpValue::Map(vec![(
        RmpValue::from("sensitivity"),
        RmpValue::from(0u64),
    )]));
    body.scope_facet = vault.default_facet()?;
    body.rel = relationship_scope_of(Some(relationship));
    let now = vault.now_recorded_at();
    vault.put_claim(
        &id,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(id)
}

/// One finished lent step: its step ref and the candidate it kept at reply index 0.
struct KeptStep {
    /// Names the step as the operand's `from_steps` names it.
    step: String,
    /// Holds the decoded candidate at reply index 0.
    candidate: Value,
}

/// Two lent steps on one attempt over two turns about owen, one unlabelled and one labelled A,
/// with a stored head about owen scoped to A.
struct TwoStepFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Keeps the vault open beside the bindings.
    _vault: Arc<Vault>,
    /// Holds the binding without a loan that reads the observations page.
    binding: DreamerAttemptBinding,
    /// Holds the attempt as the pages name it.
    attempt: String,
    /// Names owen, the listed subject.
    subject: EntityId,
    /// Names the stored head about owen, scoped to A.
    head: EntityId,
    /// Names relationship A, the label of the second turn's words and the head's set.
    labelled: EntityId,
    /// Names relationship B, which step 1's candidate names.
    other: EntityId,
    /// Holds step 1, over the unlabelled turn.
    unlabelled_step: KeptStep,
    /// Holds step 2, over the labelled turn.
    labelled_step: KeptStep,
}

/// Builds one extraction reply with one candidate about owen (`P2`) proposing the corrected
/// value from the quoted words, naming `rel` when one is given.
fn correcting_reply(rel: Option<&str>) -> String {
    let mut candidate = json!({
        "subject": "P2",
        "predicate": FOOD,
        "value": PROPOSED_VALUE,
        "confidence": 0.9,
        "evidence_refs": [{"source": "T1", "quote": PROPOSED_VALUE}],
    });
    if let Some(rel) = rel {
        candidate["rel"] = json!(rel);
    }
    json!({"persons": [], "candidates": [candidate]}).to_string()
}

/// Lends one step on a fresh binding of `admitted` whose model answers `reply`, submits it over
/// `turn` at `version`, and checks that it finished, listed owen with the head, and kept the
/// candidate about owen.
fn run_step(
    vault: &Arc<Vault>,
    admitted: &DreamerAdmittedAttempt,
    (turn, version): &(String, Value),
    subject: EntityId,
    reply: String,
) -> ExtractionStepTestResult<KeptStep> {
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let lent = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(vault, admitted)?, &lent);
    let submit = invoke_bound_step(
        &binding,
        extraction_step_request(json!([extraction_step_evidence(
            turn,
            version.clone(),
            None
        )])),
    )?;
    assert_eq!(
        submit["result"]["status"],
        json!("finished"),
        "FIXTURE: the step over turn {turn} finishes: {submit}"
    );
    let texts = backend.request_texts();
    assert_eq!(texts.len(), 1, "FIXTURE: the step asks its model once");
    assert!(
        texts[0].contains("entity P2 \"owen\"\n"),
        "FIXTURE: the request lists owen as P2: {}",
        texts[0]
    );
    assert!(
        texts[0].contains(&format!("{FOOD} = \"{HEAD_VALUE}\"")),
        "FIXTURE: the request lists the head scoped to A, so the step may correct it: {}",
        texts[0]
    );
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "FIXTURE: the step keeps its candidate: {decoded}"
    );
    let candidate = decoded["candidates"][0].clone();
    assert_eq!(
        candidate["subject"],
        json!({"listed": subject.to_hex()}),
        "FIXTURE: the kept candidate is about owen"
    );
    let step = submit["step_ref"]
        .as_str()
        .ok_or("FIXTURE: the submit answers its step ref")?
        .to_owned();
    Ok(KeptStep { step, candidate })
}

/// Seeds owen, stores relationships A and B, lands the head scoped to A, witnesses the
/// unlabelled turn and the turn labelled A, grants the Dreamer A's MESSAGEs and CLAIMs, admits
/// one attempt over both turns, and runs step 1 (naming B) and step 2 (naming none).
fn two_step_fixture() -> ExtractionStepTestResult<TwoStepFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&directory)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let labelled = store_relationship(&vault)?;
    let other = store_relationship(&vault)?;
    let head = land_relationship_head(&vault, subject, labelled)?;
    let witnessed = witness_labelled_turns(
        &vault,
        &[
            (UNLABELLED_WORDS, None),
            (LABELLED_WORDS, Some(json!({"rel": labelled.to_hex()}))),
        ],
    )?;
    grant_relationship_messages(&vault, labelled)?;
    grant_relationship_claims(&vault, labelled)?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let attempt = extraction_attempt_hex(attempt);
    let turns = page_turns_with_versions(&read_bound_extraction_page(&binding, &attempt)?);
    let served = |turn: EntityId| -> ExtractionStepTestResult<(String, Value)> {
        let hex = turn.to_hex();
        turns
            .iter()
            .find(|(served, _)| *served == hex)
            .cloned()
            .ok_or_else(|| format!("FIXTURE: the inputs page serves turn {hex}: {turns:?}").into())
    };
    let unlabelled_turn = served(witnessed.turns[0])?;
    let labelled_turn = served(witnessed.turns[1])?;
    let unlabelled_step = run_step(
        &vault,
        &admitted,
        &unlabelled_turn,
        subject,
        correcting_reply(Some(&other.to_hex())),
    )?;
    assert_eq!(
        unlabelled_step.candidate["rel"],
        json!([other.to_hex()]),
        "FIXTURE: step 1's set is unbound, so it keeps relationship B"
    );
    let labelled_step = run_step(
        &vault,
        &admitted,
        &labelled_turn,
        subject,
        correcting_reply(None),
    )?;
    assert!(
        labelled_step.candidate.get("rel").is_none(),
        "FIXTURE: step 2's candidate names no relationship: {}",
        labelled_step.candidate
    );
    Ok(TwoStepFixture {
        _directory: directory,
        _vault: vault,
        binding,
        attempt,
        subject,
        head,
        labelled,
        other,
        unlabelled_step,
        labelled_step,
    })
}

impl TwoStepFixture {
    /// Reads one observations page for `operand` alone.
    fn observe(&self, operand: &Value) -> MemoryResult<Value> {
        self.binding
            .invoke(
                OBSERVATIONS_PAGE_VERB,
                json!({
                    "attempt": self.attempt,
                    "now_ms": OBSERVATION_NOW_MS,
                    "candidates": [operand],
                }),
                None,
            )
            .map(|answer| answer["value"].clone())
    }

    /// Builds the operand that names `steps`' kept candidates: owen, the proposal with step
    /// 1's relationship when `rel` is set, every named candidate's quotes, and the head as its
    /// correction when `corrects` is set.
    fn operand(&self, steps: &[&KeptStep], rel: bool, corrects: bool) -> Value {
        let evidence: Vec<Value> = steps
            .iter()
            .flat_map(|step| {
                step.candidate["evidence"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        let mut operand = json!({
            "subject": self.subject.to_hex(),
            "predicate": FOOD,
            "value": PROPOSED_VALUE,
            "evidence": evidence,
            "from_steps": steps
                .iter()
                .map(|step| json!({"step": step.step, "index": 0}))
                .collect::<Vec<_>>(),
        });
        if rel {
            operand["rel"] = json!([self.other.to_hex()]);
        }
        if corrects {
            operand["corrects"] = json!(self.head.to_hex());
        }
        operand
    }

    /// Checks that `page` lists the head and asks its one candidate about it alone.
    fn assert_asked_about_head(&self, page: &Value, what: &str) {
        let listed = page["listed"]
            .as_array()
            .unwrap_or_else(|| panic!("{what}: the page has a listed rows array: {page}"));
        let at = listed
            .iter()
            .position(|row| row["claim"] == json!(self.head.to_hex()))
            .unwrap_or_else(|| panic!("{what}: the page lists the head: {page}"));
        assert_eq!(
            page["candidates"][0]["correctable"],
            json!([at]),
            "{what}: the candidate is asked about the head alone: {page}"
        );
        assert_eq!(
            page["candidates"][0]["corrects"],
            json!(self.head.to_hex()),
            "{what}: the candidate corrects the head"
        );
    }
}

/// Checks that `result` is refused as a bad request whose message holds `part`.
fn assert_bad_request(result: MemoryResult<Value>, part: &str) {
    let error = result.expect_err("the request is refused");
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "the request is invalid: {error:?}"
    );
    assert!(
        error.message.contains(part),
        "the refusal holds {part:?}; it was {:?}",
        error.message
    );
}

/// The union of both steps' candidates that corrects the head is asked about it, with the
/// head's id. Each member alone, named with its own step and correcting the head, asks too:
/// those are the fixture's controls.
#[test]
fn a_recorded_correction_over_two_steps_labels_is_asked_about_the_head()
-> ExtractionStepTestResult<()> {
    let fixture = two_step_fixture()?;
    let first = fixture
        .observe(&fixture.operand(&[&fixture.unlabelled_step], true, true))
        .map_err(|error| {
            format!("FIXTURE: step 1's candidate alone corrects the head: {error:?}")
        })?;
    fixture.assert_asked_about_head(&first, "FIXTURE: step 1's candidate alone");
    let second = fixture
        .observe(&fixture.operand(&[&fixture.labelled_step], false, true))
        .map_err(|error| {
            format!("FIXTURE: step 2's candidate alone corrects the head: {error:?}")
        })?;
    fixture.assert_asked_about_head(&second, "FIXTURE: step 2's candidate alone");
    let union = fixture.operand(
        &[&fixture.unlabelled_step, &fixture.labelled_step],
        true,
        true,
    );
    let page = fixture.observe(&union).unwrap_or_else(|error| {
        panic!(
            "the union of step 1's candidate (relationship {}) and step 2's (words labelled {}) \
             that corrects the head is asked about it, yet the page refused it: {error:?}",
            fixture.other.to_hex(),
            fixture.labelled.to_hex()
        )
    });
    fixture.assert_asked_about_head(&page, "the union");
    Ok(())
}

/// The same union with its correction removed names relationship B outside the folded set
/// {A}, so it is still refused by name.
#[test]
fn the_same_union_without_its_correction_is_refused() -> ExtractionStepTestResult<()> {
    let fixture = two_step_fixture()?;
    let union = fixture.operand(
        &[&fixture.unlabelled_step, &fixture.labelled_step],
        true,
        false,
    );
    assert_bad_request(
        fixture.observe(&union),
        "extraction relationship crossed branch scope",
    );
    Ok(())
}
