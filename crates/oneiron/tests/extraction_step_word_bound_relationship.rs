//! A lent extraction step over words that carry a relationship label holds its scope to that
//! label, and skips a candidate that names a relationship outside it (FIX row
//! LENT-STEP-RELATIONSHIP-OUT-OF-SET-SKIP-NO-TEST).
//!
//! The one witnessed MESSAGE carries relationship A, and the Dreamer reads A's MESSAGEs, so the
//! step's scope holds the set {A}: the request lists A as `relationship R1` (the word-bound
//! listing line) and the reply reader takes A, by label or by id. A candidate that names
//! another stored relationship B by its full id is skipped with native's words, "extraction
//! relationship crossed branch scope", and the reply stands. Before that check, the step kept
//! the candidate with B, and the pack check later refused the whole request over it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_step_word_bound_relationship`.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/labelled_turns.rs"]
mod labelled_turns;
#[path = "extraction_steps/support.rs"]
mod step_support;

use std::sync::Arc;

use labelled_turns::{grant_relationship_messages, store_relationship, witness_labelled_turns};
use oneiron::dreamer_runner::DreamerAttemptBinding;
use oneiron::memory::MemoryResult;
use oneiron::test_doors::extraction_inputs::enqueue_admitted_extraction_attempt;
use oneiron::test_doors::extraction_steps::{ExtractionStepFixture, attach_extraction_step_lender};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EntityId, Vault};
use serde_json::{Value, json};
use step_support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    open_extraction_step_vault, page_turns_with_versions, read_bound_extraction_page,
};

/// The predicate every candidate here proposes.
const FOOD: &str = "preference.food";

/// The words of the one witnessed turn, which name owen.
const WORDS: &str = "owen likes tea";

/// One lent step attempt over one witnessed turn whose MESSAGE carries relationship A, with
/// one scripted reply.
struct WordBoundFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Keeps the vault open beside the binding.
    _vault: Arc<Vault>,
    /// Holds the live extraction binding with its loan attached.
    binding: DreamerAttemptBinding,
    /// Names the one served turn.
    turn: String,
    /// Holds the served turn's pinned version.
    turn_version: Value,
    /// Names owen, the listed subject.
    subject: EntityId,
    /// Names relationship A, the label the turn's words carry.
    labelled: EntityId,
    /// Names relationship B, stored beside A, which no word carries.
    other: EntityId,
    /// Captures the requests that reached the scripted backend.
    backend: Arc<CapturingStepBackend>,
    /// Keeps the lent step resources alive beside the binding.
    _step: Arc<ExtractionStepFixture>,
}

/// Seeds owen, stores relationships A and B, witnesses the one turn with its MESSAGE labelled
/// A, grants the Dreamer A's MESSAGEs, and lends one step whose model answers what `reply`
/// builds from A's and B's ids.
fn word_bound_fixture(
    reply: impl FnOnce(EntityId, EntityId) -> String,
) -> ExtractionStepTestResult<WordBoundFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&directory)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let labelled = store_relationship(&vault)?;
    let other = store_relationship(&vault)?;
    let witnessed =
        witness_labelled_turns(&vault, &[(WORDS, Some(json!({"rel": labelled.to_hex()})))])?;
    grant_relationship_messages(&vault, labelled)?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    let mut turns = page_turns_with_versions(&page);
    assert_eq!(
        turns.len(),
        1,
        "FIXTURE: the inputs page serves the one labelled turn"
    );
    let (turn, turn_version) = turns.remove(0);
    let backend = Arc::new(CapturingStepBackend::new(reply(labelled, other), 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(binding, &step);
    Ok(WordBoundFixture {
        _directory: directory,
        _vault: vault,
        binding,
        turn,
        turn_version,
        subject,
        labelled,
        other,
        backend,
        _step: step,
    })
}

impl WordBoundFixture {
    /// Submits the one step over the whole served turn.
    fn submit(&self) -> MemoryResult<Value> {
        invoke_bound_step(
            &self.binding,
            extraction_step_request(json!([extraction_step_evidence(
                &self.turn,
                self.turn_version.clone(),
                None
            )])),
        )
    }

    /// Checks that the one request lists relationship A as `R1`, the word-bound listing line,
    /// and owen as `P2`. Every reply here names owen by that label.
    fn assert_listed(&self) {
        let texts = self.backend.request_texts();
        assert_eq!(texts.len(), 1, "the step asks its model once");
        assert!(
            texts[0].contains("relationship R1\n"),
            "FIXTURE: the request lists the words' relationship as R1: {}",
            texts[0]
        );
        assert!(
            texts[0].contains("entity P2 \"owen\"\n"),
            "FIXTURE: the request lists owen as P2: {}",
            texts[0]
        );
    }
}

/// Builds one extraction reply with one candidate about owen (`P2`) that names `rel` and
/// quotes the whole turn.
fn reply_naming(rel: &str) -> String {
    json!({
        "persons": [],
        "candidates": [{
            "subject": "P2",
            "predicate": FOOD,
            "value": "tea",
            "confidence": 0.9,
            "rel": rel,
            "evidence_refs": [{"source": "T1", "quote": WORDS}],
        }],
    })
    .to_string()
}

/// The step's scope holds the words' label: the request lists it as `R1`, and a candidate
/// that names `R1` is kept with A's id.
#[test]
fn the_words_relationship_is_listed_and_a_candidate_naming_it_is_kept()
-> ExtractionStepTestResult<()> {
    let fixture = word_bound_fixture(|_, _| reply_naming("R1"))?;
    let submit = fixture.submit()?;
    assert_eq!(
        submit["result"]["status"],
        json!("finished"),
        "the step finishes: {submit}"
    );
    fixture.assert_listed();
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "a candidate that names the words' relationship is not skipped"
    );
    assert_eq!(
        decoded["candidates"][0]["subject"],
        json!({"listed": fixture.subject.to_hex()})
    );
    assert_eq!(
        decoded["candidates"][0]["rel"],
        json!([fixture.labelled.to_hex()]),
        "the label reads back to the words' relationship"
    );
    Ok(())
}

/// A candidate that names a relationship outside the step's set, by its full id, is skipped
/// by native's words, and the reply stands.
#[test]
fn a_candidate_naming_a_relationship_outside_the_words_label_is_skipped()
-> ExtractionStepTestResult<()> {
    let fixture = word_bound_fixture(|_, other| reply_naming(&other.to_hex()))?;
    let submit = fixture.submit()?;
    assert_eq!(
        submit["result"]["status"],
        json!("finished"),
        "a candidate outside the step's relationship set refuses no reply: {submit}"
    );
    fixture.assert_listed();
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["candidates"],
        json!([]),
        "the step keeps no candidate that names relationship {} outside the words' label {}, \
         yet it kept: {}",
        fixture.other.to_hex(),
        fixture.labelled.to_hex(),
        decoded["candidates"]
    );
    assert_eq!(decoded["skipped"][0]["index"], json!(0));
    assert_eq!(
        decoded["skipped"][0]["reason"],
        json!("extraction relationship crossed branch scope")
    );
    Ok(())
}

/// The words' relationship named by its full id is inside the set and is kept, so the skip
/// above is the set's and not the id form's.
#[test]
fn a_candidate_naming_the_words_relationship_by_its_id_is_kept() -> ExtractionStepTestResult<()> {
    let fixture = word_bound_fixture(|labelled, _| reply_naming(&labelled.to_hex()))?;
    let submit = fixture.submit()?;
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(decoded["skipped"], json!([]));
    assert_eq!(
        decoded["candidates"][0]["rel"],
        json!([fixture.labelled.to_hex()])
    );
    Ok(())
}
