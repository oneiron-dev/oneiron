//! A project-bound extraction step skips a candidate whose sources share no one branch
//! project. The branch is queued bound to the default project; its one TURN is settled into
//! another project, and the one stored head about owen stays in the default project. The
//! request still lists that head, so a candidate that quotes the TURN and cites the head names
//! sources of two projects and is skipped, while one that cites the head alone lands in the
//! bound project and is kept.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_step_project_bound_citation`.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod step_support;

use std::sync::Arc;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    default_project_id,
};
use oneiron::dreamer_runner::DreamerAttemptBinding;
use oneiron::test_doors::extraction_inputs::{
    settle_extraction_rows_in_project, witness_extraction_turns,
};
use oneiron::test_doors::extraction_project_bound::enqueue_admitted_project_bound_extraction_attempt;
use oneiron::test_doors::extraction_steps::{ExtractionStepFixture, attach_extraction_step_lender};
use oneiron::test_doors::extraction_verdict::dreamer_extraction_verdict_source_version;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EntityId, TimeRange, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use step_support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    open_extraction_step_vault, page_turns_with_versions, read_bound_extraction_page,
};

/// The predicate of the stored head and the proposed value.
const FOOD: &str = "preference.food";

/// The value of the one stored head about owen.
const HEAD_VALUE: &str = "green tea";

/// The words of the one witnessed turn, which name owen.
const WORDS: &str = "owen savors green tea";

/// The reason the step gives a candidate whose sources share no one branch project.
const NO_ONE_PROJECT: &str = "extracted candidate's sources share no one branch project";

/// Lands one active, user-stated food preference about `subject` in the default project: a
/// plain public put on the default facet, as `tests/extraction_step_claim_citation.rs` lands
/// its stated head.
fn land_stated_food_claim(vault: &Vault, subject: EntityId) -> ExtractionStepTestResult<EntityId> {
    let id = EntityId::now();
    let now = vault.now_recorded_at();
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

/// One lent step attempt bound to the default project, over one witnessed turn settled into
/// another project, with one stated head about owen and one scripted reply.
struct ProjectBoundFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Holds the vault the claim pin is read from.
    vault: Arc<Vault>,
    /// Holds the live extraction binding with its loan attached.
    binding: DreamerAttemptBinding,
    /// Names the one served turn.
    turn: String,
    /// Holds the served turn's pinned version.
    turn_version: Value,
    /// Names owen, the listed subject.
    subject: EntityId,
    /// Names the one stored head about owen.
    claim: EntityId,
    /// Captures the requests that reached the scripted backend.
    backend: Arc<CapturingStepBackend>,
    /// Keeps the lent step resources alive beside the binding.
    _step: Arc<ExtractionStepFixture>,
}

/// Seeds owen, lands his head in the default project, witnesses the turn and settles it and
/// its message into a fresh project, then queues the attempt bound to the default project with
/// owen readable and the head held, and lends one step whose model answers `reply`.
fn project_bound_fixture(reply: String) -> ExtractionStepTestResult<ProjectBoundFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&directory)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let claim = land_stated_food_claim(&vault, subject)?;
    let witnessed = witness_extraction_turns(&vault, &[WORDS])?;
    let elsewhere = EntityId::now();
    settle_extraction_rows_in_project(
        &vault,
        &[witnessed.turns[0], witnessed.messages[0]],
        elsewhere,
    )?;
    let (attempt, admitted) = enqueue_admitted_project_bound_extraction_attempt(
        &vault,
        &witnessed.turns,
        default_project_id(),
        &[subject],
        &[claim],
        QUEUE_NOW,
    )?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    let mut turns = page_turns_with_versions(&page);
    assert_eq!(
        turns.len(),
        1,
        "FIXTURE: the inputs page serves the one turn of the other project"
    );
    let (turn, turn_version) = turns.remove(0);
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let step = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(binding, &step);
    Ok(ProjectBoundFixture {
        _directory: directory,
        vault,
        binding,
        turn,
        turn_version,
        subject,
        claim,
        backend,
        _step: step,
    })
}

impl ProjectBoundFixture {
    /// Submits the one step over the whole served turn and returns its answer.
    fn submit(&self) -> ExtractionStepTestResult<Value> {
        invoke_bound_step(
            &self.binding,
            extraction_step_request(json!([extraction_step_evidence(
                &self.turn,
                self.turn_version.clone(),
                None
            )])),
        )
        .map_err(|error| format!("the bound step answers: {error}").into())
    }

    /// Checks that the one request lists owen as `P2` with the head as `C1`: the bound
    /// project's head is listed although the turn lies in another project.
    fn assert_listed(&self) {
        let texts = self.backend.request_texts();
        assert_eq!(texts.len(), 1, "FIXTURE: the step asks its model once");
        let lines = format!("entity P2 \"owen\"\n  claim C1 {FOOD} = \"{HEAD_VALUE}\"\n");
        assert!(
            texts[0].contains(&lines),
            "FIXTURE: the request lists owen as P2 with the head as C1: {}",
            texts[0]
        );
    }

    /// Pins the head at the version the Dreamer reads it at now.
    fn claim_pin(&self) -> ExtractionStepTestResult<Value> {
        let version = dreamer_extraction_verdict_source_version(&self.vault, self.claim)?
            .ok_or("FIXTURE: the Dreamer reads the head")?;
        Ok(json!({"claim": self.claim.to_hex(), "version": serde_json::to_value(version)?}))
    }
}

/// Builds one extraction reply with one candidate about owen (`P2`) restating the head, with
/// `refs` as its evidence.
fn citing_reply(refs: Value) -> String {
    json!({
        "persons": [],
        "candidates": [{
            "subject": "P2",
            "predicate": FOOD,
            "value": HEAD_VALUE,
            "confidence": 0.9,
            "evidence_refs": refs,
        }],
    })
    .to_string()
}

/// A candidate that quotes the turn of another project and cites the listed head of the bound
/// project names sources that share no one branch project: it is skipped with that reason,
/// and the reply stands.
#[test]
fn a_candidate_citing_a_turn_and_a_head_of_two_projects_is_skipped() -> ExtractionStepTestResult<()>
{
    let fixture = project_bound_fixture(citing_reply(json!([
        {"source": "T1", "quote": WORDS},
        {"claim": "C1"},
    ])))?;
    let submit = fixture.submit()?;
    fixture.assert_listed();
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([{"index": 0, "reason": NO_ONE_PROJECT}]),
        "a candidate whose turn and head lie in two projects is skipped: {decoded}"
    );
    assert_eq!(
        decoded["candidates"],
        json!([]),
        "the skipped candidate is not decoded: {decoded}"
    );
    assert_eq!(submit["result"]["status"], json!("finished"));
    Ok(())
}

/// The guard: a candidate that cites the listed head alone lands in the bound project and is
/// kept with the head as its one pin, so the skip above comes from the two projects.
#[test]
fn a_candidate_citing_only_the_head_of_the_bound_project_is_kept() -> ExtractionStepTestResult<()> {
    let fixture = project_bound_fixture(citing_reply(json!([{"claim": "C1"}])))?;
    let submit = fixture.submit()?;
    fixture.assert_listed();
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["skipped"],
        json!([]),
        "a candidate that cites only the bound project's head is not skipped: {decoded}"
    );
    let candidate = &decoded["candidates"][0];
    assert_eq!(
        candidate["subject"],
        json!({"listed": fixture.subject.to_hex()})
    );
    assert_eq!(candidate["evidence"], json!([]));
    assert_eq!(candidate["claim_evidence"], json!([fixture.claim_pin()?]));
    Ok(())
}
