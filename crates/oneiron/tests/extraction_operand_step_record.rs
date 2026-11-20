//! A lent operand that names its recorded step candidates is compared with them.
//!
//! One bound attempt runs a real lent generation step and reads the observations page (and, in
//! one test, asks a verdict) over the same attempt. An operand built from a recorded candidate
//! asks as its inline form does. An operand that differs from its recorded candidate in a
//! field, a quote, or a cited claim is refused by name before any verdict model is asked. An
//! index the step skipped, kept only as a declaration, or never held is refused by name. A
//! step this attempt did not record, another attempt's among them, answers as an unknown
//! step does. A reader without the attempt's binding may name no recorded step.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_operand_step_record`
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod step_support;
#[path = "extraction_verdict/support.rs"]
mod verdict_support;

use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{ExtractionStepFixture, attach_extraction_step_lender};
use oneiron::test_doors::extraction_verdict::{
    ExtractionVerdictFixture, attach_extraction_verdict_lender,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};
use std::slice::from_ref;
use std::sync::Arc;
use step_support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    invoke_bound_step_receipt, open_extraction_step_vault, page_turns_with_versions,
    read_bound_extraction_page, step_plain_reply,
};
use verdict_support::{ParityReasoner, extraction_verdict_request};

/// The verb that serves the bound candidate and correction-listing facts.
const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.extraction.observations.page";

/// The host clock the observations page takes, in Unix milliseconds.
const OBSERVATION_NOW_MS: u64 = 21_000;

/// The predicate shared by the step replies and the proposed values.
const FOOD: &str = "preference.food";

/// The words of the first witnessed turn, which name owen.
const FIRST_WORDS: &str = "owen savors green tea";

/// The words of the second witnessed turn, which name owen.
const SECOND_WORDS: &str = "owen cooks daily";

/// The quote of the first turn the replies cite: a proper part of its words.
const FIRST_QUOTE: &str = "green tea";

/// One bound attempt over witnessed turns that name owen, with one scripted step reply.
struct RecordFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Holds the vault the verdict leg rebinds from.
    vault: Arc<Vault>,
    /// Holds the admission every binding of the attempt binds from.
    admitted: DreamerAdmittedAttempt,
    /// Holds the live extraction binding with its step loan attached.
    binding: DreamerAttemptBinding,
    /// Holds the attempt as the pages name it.
    attempt: String,
    /// Holds the served turn refs with their pinned versions in page order.
    turns: Vec<(String, Value)>,
    /// Names owen, the listed subject.
    subject: EntityId,
    /// Keeps the lent step resources alive beside the binding.
    _step: Arc<ExtractionStepFixture>,
}

/// Seeds owen, witnesses `words`, admits one attempt over them, and lends one step whose
/// model answers `reply`.
fn record_fixture(words: &[&str], reply: String) -> ExtractionStepTestResult<RecordFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&directory)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, words)?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let attempt = extraction_attempt_hex(attempt);
    let page = read_bound_extraction_page(&binding, &attempt)?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(
        turns.len(),
        words.len(),
        "The inputs page serves every witnessed turn."
    );
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(binding, &step);
    Ok(RecordFixture {
        _directory: directory,
        vault,
        admitted,
        binding,
        attempt,
        turns,
        subject,
        _step: step,
    })
}

impl RecordFixture {
    /// Submits one step over the whole served first turn.
    fn submit_first_turn(&self) -> MemoryResult<Value> {
        let (turn, version) = &self.turns[0];
        invoke_bound_step(
            &self.binding,
            extraction_step_request(json!([extraction_step_evidence(
                turn,
                version.clone(),
                None
            )])),
        )
    }

    /// Reads one observations page for `candidates` on the step-lent binding.
    fn observe(&self, candidates: &[Value]) -> MemoryResult<Value> {
        self.binding
            .invoke(
                OBSERVATIONS_PAGE_VERB,
                json!({
                    "attempt": self.attempt,
                    "now_ms": OBSERVATION_NOW_MS,
                    "candidates": candidates,
                }),
                None,
            )
            .map(|answer| answer["value"].clone())
    }

    /// Binds the same attempt again with a verdict loan on `reasoner`.
    fn verdict_binding(
        &self,
        reasoner: &Arc<ParityReasoner>,
    ) -> ExtractionStepTestResult<DreamerAttemptBinding> {
        let fixture = ExtractionVerdictFixture::new(reasoner.clone())?;
        Ok(attach_extraction_verdict_lender(
            bind_extraction(&self.vault, &self.admitted)?,
            &fixture,
        ))
    }
}

/// Builds the operand the shipped job builds from a decoded recorded candidate: its listed
/// subject, predicate, value, and TURN evidence, with its claim pins when it cites any.
fn operand_from_candidate(candidate: &Value) -> Value {
    let mut operand = json!({
        "subject": candidate["subject"]["listed"],
        "predicate": candidate["predicate"],
        "value": candidate["value"],
        "evidence": candidate["evidence"],
    });
    if let Some(cited) = candidate.get("claim_evidence") {
        operand["claim_evidence"] = cited.clone();
    }
    operand
}

/// Names `indexes` of `step` on `operand` as its recorded candidates.
fn with_from_steps(mut operand: Value, step: &str, indexes: &[usize]) -> Value {
    operand["from_steps"] = Value::Array(
        indexes
            .iter()
            .map(|index| json!({"step": step, "index": index}))
            .collect(),
    );
    operand
}

/// Builds one extraction reply with `candidates` and no declared people.
fn listed_reply(candidates: Value) -> String {
    json!({"persons": [], "candidates": candidates}).to_string()
}

/// Builds one reply candidate about `subject` proposing `value` with one quote of `source`.
fn quoted_candidate(
    subject: &str,
    predicate: &str,
    value: &str,
    source: &str,
    quote: &str,
) -> Value {
    json!({
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "confidence": 0.9,
        "evidence_refs": [{"source": source, "quote": quote}],
    })
}

/// Returns the candidate row at operand `index`.
fn page_candidate(page: &Value, index: u64) -> &Value {
    page["candidates"]
        .as_array()
        .expect("The page has a candidate rows array.")
        .iter()
        .find(|row| row["index"] == json!(index))
        .expect("The page serves the requested candidate row.")
}

/// Checks that `result` is refused as a bad request whose message holds every `part`.
fn assert_bad_request(result: MemoryResult<Value>, parts: &[&str]) {
    let error = result.expect_err("The request is refused.");
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "The request is invalid: {error:?}."
    );
    for part in parts {
        assert!(
            error.message.contains(part),
            "The refusal holds {part:?}; it was {:?}.",
            error.message,
        );
    }
}

/// Builds the one-candidate reply about owen that the first-turn tests script.
fn first_turn_reply() -> String {
    listed_reply(json!([quoted_candidate(
        "P2",
        FOOD,
        "green tea",
        "T1",
        FIRST_QUOTE
    )]))
}

/// An operand built from a recorded candidate asks as its inline form does: the observations
/// page answers both, with the same derived claim.
#[test]
fn a_recorded_candidate_is_taken_as_its_inline_operand_is() -> ExtractionStepTestResult<()> {
    let fixture = record_fixture(&[FIRST_WORDS, SECOND_WORDS], first_turn_reply())?;
    let submit = fixture.submit_first_turn()?;
    assert_eq!(
        submit["result"]["status"],
        json!("finished"),
        "The step over the first turn finishes."
    );
    let step = submit["step_ref"]
        .as_str()
        .expect("The submit answers its step ref.")
        .to_owned();
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "The step keeps its one candidate."
    );
    let candidate = &decoded["candidates"][0];
    assert_eq!(
        candidate["subject"],
        json!({"listed": fixture.subject.to_hex()}),
        "The kept candidate is about owen."
    );
    let operand = operand_from_candidate(candidate);
    let plain = fixture
        .observe(from_ref(&operand))
        .expect("The inline operand asks.");
    let named = fixture
        .observe(from_ref(&with_from_steps(operand, &step, &[0])))
        .expect("The operand that names its recorded candidate asks.");
    assert_eq!(
        page_candidate(&plain, 0)["claim"],
        page_candidate(&named, 0)["claim"],
        "Both forms derive the same claim."
    );
    Ok(())
}

/// An operand that differs from its recorded candidate is refused by name on the page, and a
/// verdict over it is refused before its model is asked.
#[test]
fn an_operand_that_differs_from_its_recorded_candidate_is_refused() -> ExtractionStepTestResult<()>
{
    let fixture = record_fixture(&[FIRST_WORDS, SECOND_WORDS], first_turn_reply())?;
    let submit = fixture.submit_first_turn()?;
    assert_eq!(submit["result"]["status"], json!("finished"));
    let step = submit["step_ref"]
        .as_str()
        .expect("The submit answers its step ref.")
        .to_owned();
    let operand = operand_from_candidate(&submit["result"]["json"]["candidates"][0]);

    let mut value = operand.clone();
    value["value"] = json!("black coffee");
    assert_bad_request(
        fixture.observe(from_ref(&with_from_steps(value, &step, &[0]))),
        &["differs from the recorded candidates it names", "its value"],
    );

    let mut predicate = operand.clone();
    predicate["predicate"] = json!("preference.drink");
    assert_bad_request(
        fixture.observe(from_ref(&with_from_steps(predicate, &step, &[0]))),
        &[
            "differs from the recorded candidates it names",
            "its predicate",
        ],
    );

    let mut topic = operand.clone();
    topic["topic"] = json!("a topic the reply did not name");
    assert_bad_request(
        fixture.observe(from_ref(&with_from_steps(topic, &step, &[0]))),
        &["differs from the recorded candidates it names", "its topic"],
    );

    let (turn, version) = &fixture.turns[0];
    let mut span = operand.clone();
    span["evidence"] = json!([{"turn": turn, "version": version}]);
    assert_bad_request(
        fixture.observe(from_ref(&with_from_steps(span, &step, &[0]))),
        &[
            "differs from the recorded candidates it names",
            "it cites a TURN quote none of them carries",
        ],
    );

    let reasoner = Arc::new(ParityReasoner::new("unused".to_owned(), 100, 50));
    let binding = fixture.verdict_binding(&reasoner)?;
    let mut refused = operand.clone();
    refused["value"] = json!("black coffee");
    let pack = json!({
        "read": "correction",
        "part": {"kind": "whole"},
        "candidates": [with_from_steps(refused, &step, &[0])],
        "listed": [],
        "priors": [],
        "questions": [{"key": ["0", "0"], "options": ["none"]}],
        "earlier": [],
    });
    assert_bad_request(
        verdict_support::invoke_bound_verdict(
            &binding,
            extraction_verdict_request("correction", json!(["none"]), pack),
        ),
        &["differs from the recorded candidates it names", "its value"],
    );
    assert_eq!(
        reasoner.call_count(),
        0,
        "The refused verdict asks no model."
    );
    Ok(())
}

/// An index the step skipped, kept only as a declaration, or never held is refused by name.
#[test]
fn a_candidate_the_step_did_not_keep_is_refused() -> ExtractionStepTestResult<()> {
    let reply = json!({
        "persons": [{"id": "new:P1", "name": "theo", "evidence_turn_refs": ["T1"]}],
        "candidates": [
            quoted_candidate("P2", FOOD, "green tea", "T1", FIRST_QUOTE),
            quoted_candidate("P9", FOOD, "black coffee", "T1", FIRST_QUOTE),
            quoted_candidate("new:P1", FOOD, "rye bread", "T1", FIRST_WORDS),
        ],
    })
    .to_string();
    let fixture = record_fixture(&[FIRST_WORDS, SECOND_WORDS], reply)?;
    let submit = fixture.submit_first_turn()?;
    assert_eq!(
        submit["result"]["status"],
        json!("finished"),
        "The reply with one skipped candidate finishes."
    );
    let decoded = &submit["result"]["json"];
    let skipped = decoded["skipped"]
        .as_array()
        .expect("The reply carries its skips.");
    assert!(
        skipped.iter().any(|row| row["index"] == json!(1)
            && row["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("unlisted subject"))),
        "The reply skips candidate 1 for its unlisted subject: {decoded}."
    );
    assert_eq!(
        decoded["candidates"][0]["index"],
        json!(0),
        "The first kept row is candidate 0."
    );
    let step = submit["step_ref"]
        .as_str()
        .expect("The submit answers its step ref.")
        .to_owned();
    let operand = operand_from_candidate(&decoded["candidates"][0]);

    assert_bad_request(
        fixture.observe(from_ref(&with_from_steps(operand.clone(), &step, &[1]))),
        &[
            "names a recorded candidate its step did not keep",
            "the step skipped candidate 1",
        ],
    );
    assert_bad_request(
        fixture.observe(from_ref(&with_from_steps(operand.clone(), &step, &[2]))),
        &[
            "names a recorded candidate its step did not keep",
            "is about a person the reply declares",
        ],
    );
    assert_bad_request(
        fixture.observe(from_ref(&with_from_steps(operand, &step, &[9]))),
        &[
            "names a recorded candidate its step did not keep",
            "the step's reply holds no candidate 9",
        ],
    );
    Ok(())
}

/// A step no record holds answers as an unknown step does: a well-formed hash no step has
/// answers with the receipt door's code, while another spelling is a bad request.
#[test]
fn a_step_this_attempt_did_not_record_answers_as_unknown() -> ExtractionStepTestResult<()> {
    let fixture = record_fixture(&[FIRST_WORDS, SECOND_WORDS], first_turn_reply())?;
    let (turn, version) = &fixture.turns[0];
    let operand = json!({
        "subject": fixture.subject.to_hex(),
        "predicate": FOOD,
        "value": "green tea",
        "evidence": [{"turn": turn, "version": version}],
    });

    let unknown = "0".repeat(64);
    let receipt = invoke_bound_step_receipt(&fixture.binding, &unknown)
        .expect_err("A hash no step has has no receipt.");
    let page = fixture
        .observe(from_ref(&with_from_steps(operand.clone(), &unknown, &[0])))
        .expect_err("A step no record holds is refused.");
    assert_eq!(
        page.code, receipt.code,
        "The page answers as the receipt door does."
    );
    assert_ne!(
        page.code, MEMORY_CODE_BAD_REQUEST,
        "An unknown step is not a bad request."
    );
    assert_eq!(
        page.code, MEMORY_CODE_NOT_FOUND,
        "An unknown step is not found: {page:?}."
    );

    assert_bad_request(
        fixture.observe(from_ref(&with_from_steps(operand, "abc", &[0]))),
        &["an extraction step key must be 64 lowercase hex digits"],
    );
    Ok(())
}

/// Another attempt's step answers as an unknown step does: its own attempt reads its
/// receipt, while a page of the first attempt that names it is refused with the code an
/// unknown hash gets.
#[test]
fn another_attempts_step_answers_as_an_unknown_step_does() -> ExtractionStepTestResult<()> {
    let fixture = record_fixture(&[FIRST_WORDS, SECOND_WORDS], first_turn_reply())?;
    let (turn, version) = &fixture.turns[0];
    let operand = json!({
        "subject": fixture.subject.to_hex(),
        "predicate": FOOD,
        "value": "green tea",
        "evidence": [{"turn": turn, "version": version}],
    });
    let unknown = invoke_bound_step_receipt(&fixture.binding, &"0".repeat(64))
        .expect_err("A hash no step has has no receipt.");

    let witnessed = witness_extraction_turns(&fixture.vault, &["owen likes tea"])?;
    let (other_id, other_admitted) =
        enqueue_admitted_extraction_attempt(&fixture.vault, &witnessed.turns, QUEUE_NOW)?;
    let other_binding = bind_extraction(&fixture.vault, &other_admitted)?;
    let other_page = read_bound_extraction_page(&other_binding, &extraction_attempt_hex(other_id))?;
    let other_turns = page_turns_with_versions(&other_page);
    assert_eq!(other_turns.len(), 1);
    let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
    let lent = ExtractionStepFixture::new(backend)?;
    let other_binding = attach_extraction_step_lender(other_binding, &lent);
    let (other_turn, other_version) = &other_turns[0];
    let other_submit = invoke_bound_step(
        &other_binding,
        extraction_step_request(json!([extraction_step_evidence(
            other_turn,
            other_version.clone(),
            None
        )])),
    )?;
    assert_eq!(other_submit["result"]["status"], json!("finished"));
    let other_ref = other_submit["step_ref"]
        .as_str()
        .expect("The other submit answers its step ref.")
        .to_owned();
    invoke_bound_step_receipt(&other_binding, &other_ref)
        .expect("The step's own attempt reads its receipt.");
    let foreign = fixture
        .observe(from_ref(&with_from_steps(operand, &other_ref, &[0])))
        .expect_err("Another attempt's step is refused.");
    assert_eq!(
        foreign.code, unknown.code,
        "Another attempt's step answers as an unknown step does."
    );
    assert_eq!(
        foreign.code, MEMORY_CODE_NOT_FOUND,
        "Another attempt's step is not found: {foreign:?}."
    );
    Ok(())
}

/// A reader without the attempt's binding may name no recorded step: the owner's page over
/// an operand that names one is refused by name, since a step's saved reply is read back
/// only where its receipt is served.
#[test]
fn the_unbound_page_refuses_an_operand_that_names_a_recorded_step() -> ExtractionStepTestResult<()>
{
    let fixture = record_fixture(&[FIRST_WORDS, SECOND_WORDS], first_turn_reply())?;
    let submit = fixture.submit_first_turn()?;
    assert_eq!(submit["result"]["status"], json!("finished"));
    let step = submit["step_ref"]
        .as_str()
        .expect("The submit answers its step ref.")
        .to_owned();
    let operand = operand_from_candidate(&submit["result"]["json"]["candidates"][0]);
    let owner = fixture.vault.ensure_embedded_owner_actor()?;
    let refused = invoke(
        &fixture.vault.memory(owner, EdgeActorClass::Human),
        OBSERVATIONS_PAGE_VERB,
        json!({
            "attempt": fixture.attempt,
            "now_ms": OBSERVATION_NOW_MS,
            "candidates": [with_from_steps(operand, &step, &[0])],
        }),
    );
    assert_bad_request(refused, &["only through its own attempt's binding"]);
    Ok(())
}

/// An operand folded from two recorded candidates carries both quotes: naming both asks,
/// while naming only the first is refused for the quote it does not carry.
#[test]
fn an_operand_folded_from_two_recorded_candidates_carries_both_quotes()
-> ExtractionStepTestResult<()> {
    const WORDS: &str = "owen savors green tea daily";
    let fixture = record_fixture(
        &[WORDS, SECOND_WORDS],
        listed_reply(json!([
            quoted_candidate("P2", FOOD, "green tea", "T1", "owen savors green tea"),
            quoted_candidate("P2", FOOD, "green tea", "T1", "green tea daily"),
        ])),
    )?;
    let submit = fixture.submit_first_turn()?;
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "The step keeps both candidates."
    );
    assert_eq!(decoded["candidates"][0]["index"], json!(0));
    assert_eq!(decoded["candidates"][1]["index"], json!(1));
    let step = submit["step_ref"]
        .as_str()
        .expect("The submit answers its step ref.")
        .to_owned();
    let mut operand = operand_from_candidate(&decoded["candidates"][0]);
    let mut evidence = operand["evidence"]
        .as_array()
        .expect("The first candidate quotes its turn.")
        .clone();
    evidence.extend(
        decoded["candidates"][1]["evidence"]
            .as_array()
            .expect("The second candidate quotes its turn.")
            .iter()
            .cloned(),
    );
    operand["evidence"] = Value::Array(evidence);
    fixture
        .observe(from_ref(&with_from_steps(operand.clone(), &step, &[0, 1])))
        .expect("The operand that names both recorded candidates asks.");
    assert_bad_request(
        fixture.observe(from_ref(&with_from_steps(operand, &step, &[0]))),
        &[
            "differs from the recorded candidates it names",
            "it cites a TURN quote none of them carries",
        ],
    );
    Ok(())
}
