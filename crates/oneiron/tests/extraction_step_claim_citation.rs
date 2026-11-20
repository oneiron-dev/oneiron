//! A bound extraction step keeps a candidate that cites a listed claim, as the native reply
//! may. The decoded candidate carries the claim as a pin at the version the step read, the
//! observations page takes that pin, and the reply check applies native's restatement rule.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_step_claim_citation`.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod step_support;

use std::sync::Arc;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_runner::DreamerAttemptBinding;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MemoryResult};
use oneiron::test_doors::derive::grant_derive_rows;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{ExtractionStepFixture, attach_extraction_step_lender};
use oneiron::test_doors::extraction_verdict::dreamer_extraction_verdict_source_version;
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

/// The verb that serves the bound candidate and correction-listing facts.
const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.extraction.observations.page";

/// The host clock the observations page takes, in Unix milliseconds.
const OBSERVATION_NOW_MS: u64 = 21_000;

/// The predicate shared by the stored head and the proposed values.
const FOOD: &str = "preference.food";

/// The value of the one stored head about owen.
const HEAD_VALUE: &str = "green tea";

/// The words of the one witnessed turn, which name owen.
const WORDS: &str = "owen savors green tea";

/// Lands one active food preference about `subject` with Auto approval.
///
/// A stated head is a plain public put on the default facet. A generated head lands
/// attributed, under the subject's actor-bound permit: the write gate pends an unattributed
/// generated put at Auto on source trust. This is the recipe of
/// `tests/extraction_claim_evidence.rs`.
fn land_food_claim(
    vault: &Vault,
    subject: EntityId,
    value: &str,
    source: ClaimSource,
) -> ExtractionStepTestResult<EntityId> {
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    if source == ClaimSource::Generated {
        grant_derive_rows(vault, &[subject])?;
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
                    RmpValue::from(value),
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
        return Ok(id);
    }
    let mut body = ClaimBody::new(
        FOOD,
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(source);
    body.scope = Some(RmpValue::Map(vec![(
        RmpValue::from("sensitivity"),
        RmpValue::from(0u64),
    )]));
    body.scope_facet = vault.default_facet()?;
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

/// One lent step attempt over one witnessed turn that names owen, with one landed head
/// about him and one scripted reply.
struct CitationFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Holds the vault the claim pin is read from.
    vault: Arc<Vault>,
    /// Holds the live extraction binding with its loan attached.
    binding: DreamerAttemptBinding,
    /// Holds the attempt as the pages name it.
    attempt: String,
    /// Names the one served turn.
    turn: String,
    /// Holds the served turn's pinned version.
    turn_version: Value,
    /// Names owen, the listed subject.
    subject: EntityId,
    /// Names the one landed head about owen.
    claim: EntityId,
    /// Captures the requests that reached the scripted backend.
    backend: Arc<CapturingStepBackend>,
    /// Keeps the lent step resources alive beside the binding.
    _step: Arc<ExtractionStepFixture>,
}

/// Seeds owen, lands one head about him from `source`, witnesses the turn, and lends one
/// step whose model answers `reply`.
fn citation_fixture(
    source: ClaimSource,
    reply: String,
) -> ExtractionStepTestResult<CitationFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&directory)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let claim = land_food_claim(&vault, subject, HEAD_VALUE, source)?;
    let witnessed = witness_extraction_turns(&vault, &[WORDS])?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let attempt = extraction_attempt_hex(attempt);
    let page = read_bound_extraction_page(&binding, &attempt)?;
    let mut turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1, "the inputs page serves the one turn");
    let (turn, turn_version) = turns.remove(0);
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(binding, &step);
    Ok(CitationFixture {
        _directory: directory,
        vault,
        binding,
        attempt,
        turn,
        turn_version,
        subject,
        claim,
        backend,
        _step: step,
    })
}

impl CitationFixture {
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

    /// Checks that the one request lists owen as `P2` with the head as `C1`, marked
    /// uncitable or not. Every reply here names those two labels.
    fn assert_listed(&self, uncitable: bool) {
        let texts = self.backend.request_texts();
        assert_eq!(texts.len(), 1, "the step asks its model once");
        let mark = if uncitable { " (uncitable)" } else { "" };
        let lines = format!("entity P2 \"owen\"\n  claim C1 {FOOD} = \"{HEAD_VALUE}\"{mark}\n");
        assert!(
            texts[0].contains(&lines),
            "the request lists owen as P2 with the head as C1: {}",
            texts[0]
        );
    }

    /// Pins the head at the version the Dreamer reads it at now.
    fn claim_pin(&self) -> ExtractionStepTestResult<Value> {
        let version = dreamer_extraction_verdict_source_version(&self.vault, self.claim)?
            .ok_or("the Dreamer reads the fixture head")?;
        Ok(json!({"claim": self.claim.to_hex(), "version": serde_json::to_value(version)?}))
    }

    /// Reads one observations page for the operand the decoded `candidate` builds, as the
    /// job builds it: the listed subject, the proposal, the turn evidence and the claim pins.
    fn observe(&self, candidate: &Value) -> MemoryResult<Value> {
        let mut operand = json!({
            "subject": candidate["subject"]["listed"],
            "predicate": candidate["predicate"],
            "value": candidate["value"],
            "evidence": candidate["evidence"],
        });
        if let Some(cited) = candidate.get("claim_evidence") {
            operand["claim_evidence"] = cited.clone();
        }
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
}

/// Builds one extraction reply with one candidate about owen (`P2`) proposing `value`
/// with `refs` as its evidence.
fn citing_reply(value: &str, refs: Value) -> String {
    json!({
        "persons": [],
        "candidates": [{
            "subject": "P2",
            "predicate": FOOD,
            "value": value,
            "confidence": 0.9,
            "evidence_refs": refs,
        }],
    })
    .to_string()
}

/// A candidate that quotes its turn and cites the listed head it restates is kept: its
/// quote keeps its span, the head is carried as a pin at the version the Dreamer reads, and
/// the observations page takes that pin and asks about no claim.
#[test]
fn a_candidate_that_cites_a_listed_claim_keeps_it_as_a_pin() -> ExtractionStepTestResult<()> {
    let fixture = citation_fixture(
        ClaimSource::UserStated,
        citing_reply(
            HEAD_VALUE,
            json!([{"source": "T1", "quote": WORDS}, {"claim": "C1"}]),
        ),
    )?;
    let submit = fixture.submit()?;
    assert_eq!(submit["result"]["status"], json!("finished"));
    fixture.assert_listed(false);
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "a candidate that cites a listed claim is not skipped"
    );
    let candidate = &decoded["candidates"][0];
    assert_eq!(
        candidate["subject"],
        json!({"listed": fixture.subject.to_hex()})
    );
    assert_eq!(
        candidate["evidence"],
        json!([{
            "turn": fixture.turn,
            "version": fixture.turn_version,
            "span": {"start": 0, "end": WORDS.len()},
        }])
    );
    assert_eq!(
        candidate["claim_evidence"],
        json!([fixture.claim_pin()?]),
        "the cited head is pinned at the version the step read"
    );
    let page = fixture
        .observe(candidate)
        .expect("the observations page takes the step's claim pin");
    assert_eq!(
        page["listed"],
        json!([]),
        "the restated head is the only head and is not asked about"
    );
    Ok(())
}

/// A candidate whose only evidence is the listed head it restates is kept with no turn
/// evidence and one pin, and the observations page takes it.
#[test]
fn a_candidate_that_cites_only_a_listed_claim_is_kept() -> ExtractionStepTestResult<()> {
    let fixture = citation_fixture(
        ClaimSource::UserStated,
        citing_reply(HEAD_VALUE, json!([{"claim": "C1"}])),
    )?;
    let submit = fixture.submit()?;
    assert_eq!(submit["result"]["status"], json!("finished"));
    fixture.assert_listed(false);
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "a candidate that cites only a listed claim is not skipped"
    );
    let candidate = &decoded["candidates"][0];
    assert_eq!(candidate["evidence"], json!([]));
    assert_eq!(candidate["claim_evidence"], json!([fixture.claim_pin()?]));
    let page = fixture
        .observe(candidate)
        .expect("the observations page takes a claim as the only evidence");
    assert_eq!(page["listed"], json!([]));
    Ok(())
}

/// A candidate that restates a generated head and cites it is asked no correction, so it
/// surely reaches verification, which takes no generated head as evidence: the reply is
/// refused and asked again, as the native citation check refuses it.
#[test]
fn a_restated_generated_head_refuses_the_reply() -> ExtractionStepTestResult<()> {
    let fixture = citation_fixture(
        ClaimSource::Generated,
        citing_reply(
            HEAD_VALUE,
            json!([{"source": "T1", "quote": WORDS}, {"claim": "C1"}]),
        ),
    )?;
    let submit = fixture.submit()?;
    fixture.assert_listed(true);
    assert_eq!(
        submit["result"]["status"],
        json!("failed"),
        "a restated generated head is no evidence: {submit}"
    );
    let message = submit["result"]["failure"]["message"]
        .as_str()
        .ok_or("the refused submit names its failure")?;
    assert!(
        message.contains("cites outside its source: generated claim cannot corroborate"),
        "the refusal names the generated head: {message}"
    );
    Ok(())
}

/// A candidate that cites a generated head and proposes another value is asked whether it
/// corrects that head, so the step keeps it with the pin and the verdict side judges the
/// head: the observations page refuses the pin by name.
#[test]
fn a_generated_head_cited_with_another_value_is_kept_for_the_verdict()
-> ExtractionStepTestResult<()> {
    let fixture = citation_fixture(
        ClaimSource::Generated,
        citing_reply(
            "black tea",
            json!([{"source": "T1", "quote": WORDS}, {"claim": "C1"}]),
        ),
    )?;
    let submit = fixture.submit()?;
    fixture.assert_listed(true);
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "a candidate a correction is asked about keeps its cited head"
    );
    let candidate = &decoded["candidates"][0];
    assert_eq!(candidate["claim_evidence"], json!([fixture.claim_pin()?]));
    let refused = fixture
        .observe(candidate)
        .expect_err("the observations page refuses a generated head as evidence");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        refused
            .message
            .contains("generated claim cannot corroborate"),
        "the refusal names the generated head: {}",
        refused.message
    );
    Ok(())
}

/// A candidate that restates the listed head it cites is asked no correction, so a quote
/// of words its turn does not hold refuses the reply, as the native citation check refuses
/// it.
#[test]
fn an_unbound_quote_beside_a_restated_claim_refuses_the_reply() -> ExtractionStepTestResult<()> {
    let fixture = citation_fixture(
        ClaimSource::UserStated,
        citing_reply(
            HEAD_VALUE,
            json!([{"source": "T1", "quote": "owen savors black coffee"}, {"claim": "C1"}]),
        ),
    )?;
    let submit = fixture.submit()?;
    fixture.assert_listed(false);
    assert_eq!(
        submit["result"]["status"],
        json!("failed"),
        "nothing is asked about a restated head, so an unbound quote refuses: {submit}"
    );
    let message = submit["result"]["failure"]["message"]
        .as_str()
        .ok_or("the refused submit names its failure")?;
    assert!(
        message.contains("cites outside its source"),
        "the refusal names the unbound quote: {message}"
    );
    Ok(())
}

/// A candidate that cites the listed head and proposes another value is asked whether it
/// corrects that head, so a quote of words its turn does not hold skips the candidate and
/// the reply stands, as native skips it.
#[test]
fn an_unbound_quote_beside_a_cited_claim_with_another_value_is_skipped()
-> ExtractionStepTestResult<()> {
    let fixture = citation_fixture(
        ClaimSource::UserStated,
        citing_reply(
            "black coffee",
            json!([{"source": "T1", "quote": "owen savors black coffee"}, {"claim": "C1"}]),
        ),
    )?;
    let submit = fixture.submit()?;
    fixture.assert_listed(false);
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(decoded["candidates"], json!([]));
    assert_eq!(decoded["skipped"][0]["index"], json!(0));
    let reason = decoded["skipped"][0]["reason"]
        .as_str()
        .ok_or("the skipped candidate names its reason")?;
    assert!(
        reason.starts_with("quote unbound ("),
        "the candidate is skipped for its unbound quote: {reason}"
    );
    Ok(())
}
