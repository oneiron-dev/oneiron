//! A lent extraction verdict sends its model call under the rows its input was read from:
//! the rows of every recorded step the asked operands name, the pack's evidence and the
//! stored rows the call labels. A read over an operand that names no recorded step sends
//! unsourced. Over one turn, the lent correction read sends under the same rows as the
//! native correction read.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_verdict_sources`
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod step_support;
#[path = "extraction_verdict/support.rs"]
mod verdict_support;

use std::slice::from_ref;
use std::sync::Arc;

use oneiron::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::MemoryResult;
use oneiron::test_doors::derive::grant_derive_rows;
use oneiron::test_doors::extraction_decisions::run_native_extraction_decisions;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{
    ExtractionStepFixture, attach_extraction_step_lender, fixture_step_bound_source_rows,
};
use oneiron::test_doors::extraction_verdict::{
    ExtractionVerdictFixture, attach_extraction_verdict_lender,
    dreamer_extraction_verdict_source_version,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{
    ClaimCandidate, EdgeActorClass, EntityId, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use step_support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    open_extraction_step_vault, page_turns_with_versions, read_bound_extraction_page,
};
use verdict_support::{
    ParityReasoner, extraction_verdict_request, invoke_bound_verdict, native_resolution_options,
};

/// The host clock shared by the observations page and the native oracle.
const NOW_MS: u64 = QUEUE_NOW * 1_000;

/// The predicate of the stored head and its proposed replacement.
const FOOD: &str = "preference.food";

/// A served turn and the one visible message it projects.
struct ServedTurn {
    /// Names the turn as the pages name it.
    id: String,
    /// Holds the turn's pinned version as the inputs page served it.
    version: Value,
    /// Names the turn's one visible message.
    message: String,
}

/// A recorded candidate's inline operand, the step that kept it, and that step's rows.
struct RecordedOperand {
    /// Holds the operand the job builds from the decoded candidate, naming no step.
    inline: Value,
    /// Names the step by its receipt's step reference.
    step: String,
    /// Lists the rows the step's own model call was sent under.
    sources: Vec<String>,
}

impl RecordedOperand {
    /// Names candidate zero of the step that kept this operand.
    fn named(&self) -> Value {
        let mut operand = self.inline.clone();
        operand["from_steps"] = json!([{"step": self.step, "index": 0}]);
        operand
    }
}

/// A fresh admitted extraction attempt whose generation steps have their own recording route.
struct SourceFixture {
    /// Holds the vault the attempt runs in.
    vault: Arc<Vault>,
    /// Holds the admitted attempt, bound again for each verdict loan.
    admitted: DreamerAdmittedAttempt,
    /// Holds the live extraction binding with its step loan attached.
    binding: DreamerAttemptBinding,
    /// Holds the lent step resources, whose route records each step's rows.
    step: Arc<ExtractionStepFixture>,
    /// Holds the attempt as the pages name it.
    attempt: String,
    /// Lists the served turns in witness order.
    turns: Vec<ServedTurn>,
    /// Names owen, the listed subject.
    subject: EntityId,
    /// Names the landed head about owen, when the fixture lands one.
    head: Option<EntityId>,
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
}

impl SourceFixture {
    /// Seeds owen, optionally lands a food preference, and admits one attempt over the turns.
    fn new(
        words: &[&str],
        replies: Vec<String>,
        with_head: bool,
    ) -> ExtractionStepTestResult<Self> {
        let directory = tempfile::tempdir()?;
        let vault = Arc::new(open_extraction_step_vault(&directory)?);
        stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
        let subject = EntityId::now();
        seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
        let head = with_head
            .then(|| land_food_claim(&vault, subject))
            .transpose()?;
        let witnessed = witness_extraction_turns(&vault, words)?;
        let (id, admitted) =
            enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
        let binding = bind_extraction(&vault, &admitted)?;
        let attempt = extraction_attempt_hex(id);
        let page = read_bound_extraction_page(&binding, &attempt)?;
        let served = page_turns_with_versions(&page);
        assert_eq!(
            served.len(),
            words.len(),
            "The inputs page serves every witnessed turn."
        );
        let turns = witnessed
            .turns
            .iter()
            .zip(&witnessed.messages)
            .map(|(turn, message)| {
                let id = turn.to_hex();
                let (_, version) = served
                    .iter()
                    .find(|(served_id, _)| served_id == &id)
                    .expect("The inputs page serves the witnessed turn.");
                ServedTurn {
                    id,
                    version: version.clone(),
                    message: message.to_hex(),
                }
            })
            .collect();
        let backend = Arc::new(CapturingStepBackend::scripted(replies, 100, 50));
        let step = ExtractionStepFixture::new(backend)?;
        let binding = attach_extraction_step_lender(binding, &step);
        Ok(Self {
            vault,
            admitted,
            binding,
            step,
            attempt,
            turns,
            subject,
            head,
            _directory: directory,
        })
    }

    /// Submits the whole turn and takes candidate zero and the rows from that step alone.
    fn submit(&self, index: usize) -> ExtractionStepTestResult<RecordedOperand> {
        let turn = &self.turns[index];
        let receipt = invoke_bound_step(
            &self.binding,
            extraction_step_request(json!([extraction_step_evidence(
                &turn.id,
                turn.version.clone(),
                None,
            )])),
        )?;
        assert_eq!(
            receipt["result"]["status"],
            json!("finished"),
            "The extraction step finishes."
        );
        let recorded = fixture_step_bound_source_rows(&self.step);
        let [sources]: [Vec<String>; 1] = recorded
            .try_into()
            .expect("The step binds its source rows exactly once.");
        assert!(
            sources.contains(&turn.id),
            "The step binds the TURN it reads."
        );
        assert!(
            sources.contains(&turn.message),
            "The step binds the MESSAGE behind the TURN."
        );
        let decoded = &receipt["result"]["json"];
        assert_eq!(
            decoded["skipped"],
            json!([]),
            "The step keeps its candidate."
        );
        let candidate = &decoded["candidates"][0];
        assert_eq!(
            candidate["index"],
            json!(0),
            "The receipt keeps candidate zero."
        );
        assert_eq!(
            candidate["subject"]["listed"],
            json!(self.subject.to_hex()),
            "The candidate names the seeded subject."
        );
        let inline = json!({
            "subject": candidate["subject"]["listed"],
            "predicate": candidate["predicate"],
            "value": candidate["value"],
            "evidence": candidate["evidence"],
        });
        let step = receipt["step_ref"]
            .as_str()
            .expect("The receipt names its step.")
            .to_owned();
        Ok(RecordedOperand {
            inline,
            step,
            sources,
        })
    }

    /// Lends the verdict role on a separate recording route and returns both handles.
    fn verdict_binding(
        &self,
        reply: String,
    ) -> ExtractionStepTestResult<(DreamerAttemptBinding, Arc<ExtractionVerdictFixture>)> {
        let reasoner = Arc::new(ParityReasoner::new(reply, 100, 50));
        let fixture = ExtractionVerdictFixture::new(reasoner)?;
        let binding = attach_extraction_verdict_lender(
            bind_extraction(&self.vault, &self.admitted)?,
            &fixture,
        );
        Ok((binding, fixture))
    }

    /// Requests one whole correction read over the operand and the one stored head.
    fn correction_request(&self, operand: Value) -> ExtractionStepTestResult<Value> {
        let head = self
            .head
            .expect("The correction fixture has a stored head.");
        let pin = dreamer_extraction_verdict_source_version(&self.vault, head)?
            .expect("The Dreamer reads the stored head.");
        let options = json!(["none", head.to_hex()]);
        let pack = json!({
            "read": "correction",
            "part": {"kind": "whole"},
            "candidates": [operand],
            "listed": [{"claim": head.to_hex(), "version": serde_json::to_value(pin)?}],
            "priors": [],
            "questions": [{"key": ["0", "0"], "options": options}],
            "earlier": [],
        });
        Ok(extraction_verdict_request("correction", options, pack))
    }

    /// Reads the derived claim IDs for the two operands before either claim is written.
    fn member_claims(&self, operands: &[Value; 2]) -> MemoryResult<[String; 2]> {
        let answer = self.binding.invoke(
            "vault.consolidation.extraction.observations.page",
            json!({"attempt": self.attempt, "now_ms": NOW_MS, "candidates": operands}),
            None,
        )?;
        let claim = |index: usize| {
            let row = &answer["value"]["candidates"][index];
            assert_eq!(
                row["index"],
                json!(index),
                "The observations page serves the operand in order."
            );
            row["claim"]
                .as_str()
                .expect("The observations page names the derived claim.")
                .to_owned()
        };
        Ok([claim(0), claim(1)])
    }
}

/// Lands an active generated food preference under the subject's attributed write permit.
fn land_food_claim(vault: &Vault, subject: EntityId) -> ExtractionStepTestResult<EntityId> {
    grant_derive_rows(vault, &[subject])?;
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    let envelope = WriteEnvelope::new(
        WriteActor::new(subject, EdgeActorClass::Human),
        ClaimSource::Generated,
        WriteProvenance::new(RmpValue::from("generated-head-fixture"))?,
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(
            &id,
            ClaimCandidate::new(
                FOOD,
                ClaimSubject::Entity(subject),
                RmpValue::from("green tea"),
                1.0,
            ),
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .commit()?;
    Ok(id)
}

/// Returns a scripted extraction reply about the listed owen with one TURN quote and no claim citation.
fn step_reply(predicate: &str, value: &str, quote: &str) -> String {
    json!({
        "persons": [],
        "candidates": [{
            "subject": "P2",
            "predicate": predicate,
            "value": value,
            "confidence": 0.9,
            "evidence_refs": [{"source": "T1", "quote": quote}],
        }],
    })
    .to_string()
}

/// Creates a correction fixture with one landed head and one proposed value that differs.
fn correction_fixture() -> ExtractionStepTestResult<SourceFixture> {
    let words = "owen savors black tea";
    SourceFixture::new(&[words], vec![step_reply(FOOD, "black tea", words)], true)
}

/// Answers the one correction question by choosing the listed head.
fn correction_reply() -> String {
    json!({"Q1": {"none": 0.1, "C1": 0.9}}).to_string()
}

/// Creates two separately sourced steps about owen with different values for the same key.
fn resolution_fixture() -> ExtractionStepTestResult<SourceFixture> {
    SourceFixture::new(
        &["owen likes tea", "owen likes coffee"],
        vec![
            step_reply("profile.hobby", "tea", "owen likes tea"),
            step_reply("profile.hobby", "coffee", "owen likes coffee"),
        ],
        false,
    )
}

/// Lends a whole resolution read that accumulates both candidates without selecting an identity.
fn read_resolution(
    fixture: &SourceFixture,
    operands: [Value; 2],
) -> ExtractionStepTestResult<Vec<Vec<String>>> {
    let reply = json!({
        "Q1": {"merge": 0.05, "supersede": 0.05, "accumulate": 0.85, "escalate": 0.05},
        "Q2": {"none": 0.7, "C1": 0.2, "C2": 0.1},
    });
    let (binding, verdict) = fixture.verdict_binding(reply.to_string())?;
    let options = native_resolution_options();
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": operands,
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": options},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
    });
    invoke_bound_verdict(
        &binding,
        extraction_verdict_request("resolution", options, pack),
    )
    .expect("The whole resolution verdict answers.");
    Ok(verdict.take_bound_source_rows())
}

/// A whole correction binds every step row, the listed head, the cited TURN and the subject.
#[test]
fn a_correction_read_over_a_recorded_candidate_sends_under_its_steps_rows()
-> ExtractionStepTestResult<()> {
    let fixture = correction_fixture()?;
    let recorded = fixture.submit(0)?;
    let (binding, verdict) = fixture.verdict_binding(correction_reply())?;
    invoke_bound_verdict(&binding, fixture.correction_request(recorded.named())?)
        .expect("The whole correction verdict answers.");

    let calls = verdict.take_bound_source_rows();
    assert!(
        !calls.is_empty(),
        "The correction verdict binds its source rows."
    );
    assert_eq!(
        calls.len(),
        1,
        "The whole correction verdict binds one call."
    );
    let rows = &calls[0];
    for source in &recorded.sources {
        assert!(
            rows.contains(source),
            "The correction verdict binds step source row {source}."
        );
    }
    let head = fixture
        .head
        .expect("The correction fixture has a stored head.");
    assert!(
        rows.contains(&head.to_hex()),
        "The correction verdict binds the listed head."
    );
    assert!(
        rows.contains(&fixture.turns[0].id),
        "The correction verdict binds the cited TURN."
    );
    assert!(
        rows.contains(&fixture.subject.to_hex()),
        "The correction verdict binds the labelled subject."
    );
    Ok(())
}

/// The inline operand still answers the correction question but has no known step rows.
#[test]
fn a_correction_read_over_an_operand_that_names_no_step_sends_unsourced()
-> ExtractionStepTestResult<()> {
    let fixture = correction_fixture()?;
    let recorded = fixture.submit(0)?;
    let (binding, verdict) = fixture.verdict_binding(correction_reply())?;
    invoke_bound_verdict(&binding, fixture.correction_request(recorded.inline)?)
        .expect("The correction verdict over an inline operand answers.");
    assert!(
        verdict.take_bound_source_rows().is_empty(),
        "The inline operand leaves the correction verdict unsourced."
    );
    Ok(())
}

/// The conflict binds the rows of both steps but neither derived claim, and binds no rows
/// when even one member does not name its step.
#[test]
fn a_resolution_read_sends_under_every_members_rows() -> ExtractionStepTestResult<()> {
    let fixture = resolution_fixture()?;
    let first = fixture.submit(0)?;
    let second = fixture.submit(1)?;
    assert!(
        !first.sources.contains(&fixture.turns[1].message)
            && !second.sources.contains(&fixture.turns[0].message),
        "Each step binds its own MESSAGE, not the other step's MESSAGE."
    );
    let operands = [first.named(), second.named()];
    let claims = fixture.member_claims(&operands)?;
    assert_ne!(
        claims[0], claims[1],
        "The conflict members have distinct derived claims."
    );
    let calls = read_resolution(&fixture, operands)?;
    assert!(
        !calls.is_empty(),
        "The resolution verdict binds its source rows."
    );
    assert_eq!(
        calls.len(),
        1,
        "The whole resolution verdict binds one call for both questions."
    );
    let rows = &calls[0];
    for source in first.sources.iter().chain(&second.sources) {
        assert!(
            rows.contains(source),
            "The resolution verdict binds member step source row {source}."
        );
    }
    for claim in &claims {
        assert!(
            !rows.contains(claim),
            "The resolution verdict does not bind unwritten member claim {claim}."
        );
    }

    let fixture = resolution_fixture()?;
    let first = fixture.submit(0)?;
    let second = fixture.submit(1)?;
    let calls = read_resolution(&fixture, [first.named(), second.inline])?;
    assert!(
        calls.is_empty(),
        "One inline member leaves the entire resolution verdict unsourced."
    );
    Ok(())
}

/// The native and lent whole correction reads over the same one-turn slice bind equal rows.
#[test]
fn a_lent_correction_read_sends_under_the_rows_the_native_read_sends_under()
-> ExtractionStepTestResult<()> {
    let fixture = correction_fixture()?;
    let recorded = fixture.submit(0)?;
    let (binding, verdict) = fixture.verdict_binding(correction_reply())?;
    let native = run_native_extraction_decisions(
        &fixture.vault,
        &fixture.admitted,
        from_ref(&recorded.inline),
        NOW_MS,
        &verdict,
    )?;
    let head = fixture
        .head
        .expect("The correction fixture has a stored head.")
        .to_hex();
    assert_eq!(
        native.corrections[0].corrects.as_deref(),
        Some(head.as_str()),
        "The native correction chooses the same listed head."
    );
    let native_rows = verdict.take_bound_source_rows();
    assert_eq!(
        native_rows.len(),
        1,
        "The native oracle binds one correction call and no resolution call."
    );

    invoke_bound_verdict(&binding, fixture.correction_request(recorded.named())?)
        .expect("The lent correction verdict answers.");
    let lent_rows = verdict.take_bound_source_rows();
    assert_eq!(
        lent_rows, native_rows,
        "The lent and native correction reads bind identical source rows."
    );
    Ok(())
}
