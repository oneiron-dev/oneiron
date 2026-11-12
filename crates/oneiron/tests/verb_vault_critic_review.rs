//! Row 4 CRITIC-ATTRIBUTION, PR 1 (ruling LEARN-CRITIC Q1 = B): a critic
//! review merges findings on a checkable flaw identity, the target, the flaw's
//! kind and its location, and keeps every critic's evidence and attribution.
//! Two flaws at one location stay apart, one kind at two locations stays
//! apart, a finding that names no flaw merges with no other, and critics that
//! disagree on one flaw keep the most cautious verdict and never resolve it
//! without a person. A hard check's veto and a replayed review are unchanged.
//!
//! The review runs the production path a host's door runs: the public
//! `CriticReviewSubmit::bind` and `review_artifact`, with a scripted local
//! decision rung and notes read from JSON. The verb itself is host-only on the
//! embedded engine, so this file drives the engine review it calls. On main
//! (with the commit that reads a note from JSON) the notes' `flaw` is
//! ignored and the old key merges on verdict, evidence and edit.

use std::collections::BTreeMap;
use std::time::Duration;

use oneiron::critic::review::{
    CriticReviewOutcome, CriticReviewSubmit, REVIEW_DIAL, ReviewDecisions, ReviewFinding,
    ReviewNote, ReviewNotes, ReviewResult, ReviewWording, review_artifact,
};
use oneiron::critic::{CRITIC_LENS_CATALOG_SCHEMA_VERSION, CritiqueArtifactStore};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionLadder, DecisionProvider,
    DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin,
};
use oneiron::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CONTRACT_A: &str = "Lens a: judge the target's guards.";
const CONTRACT_B: &str = "Lens b: judge the target's bounds.";
const VERDICT_WORDING: &str = "Which verdict does this lens give?";
const SEVERITY_WORDING: &str = "How severe is the finding?";
const HARD_CHECK_WORDING: &str = "Does the target pass this lens's hard check?";
const OUT_OF_SCOPE_WORDING: &str = "Is the target outside this lens's scope?";

/// One vault with its owner, a session, a target turn and the two lenses'
/// stored skills.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    session: EntityId,
    target: EntityId,
    lens_a: EntityId,
    lens_b: EntityId,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config)?;
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    assert_eq!(
        vault.profile_local_open(Some(b"critic-review-fixture"), true)?,
        oneiron::authority::LocalOpenProfile::RootedAndProfiled,
    );
    let owner = vault.ensure_embedded_owner_actor()?;
    let session = EntityId::now();
    vault.put_entity(
        &session,
        ENTITY_TYPE_SESSION,
        TimeRange { start: 10, end: 10 },
        10,
        &rmp_serde::to_vec_named(&json!({"title": "critic review fixture"}))?,
    )?;
    let target = EntityId::now();
    vault.put_entity(
        &target,
        ENTITY_TYPE_TURN,
        TimeRange { start: 11, end: 11 },
        11,
        &rmp_serde::to_vec_named(&body())?,
    )?;
    let lens_a = put_lens_skill(&vault, "critic-review.lens-a")?;
    let lens_b = put_lens_skill(&vault, "critic-review.lens-b")?;
    Ok(Fixture {
        _dir: dir,
        vault,
        owner,
        session,
        target,
        lens_a,
        lens_b,
    })
}

/// The target's body. Its JSON text, the text a flaw's byte range counts in,
/// holds a two-byte character past byte 8.
fn body() -> Value {
    json!({"text": "alpha beta gamma délta"})
}

/// A lens's stored skill: an owner-authored candidate, which is all a review
/// reads of it.
fn put_lens_skill(vault: &Vault, name: &str) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    let tree = oneiron::skill::canonical_skill_tree_hash([("SKILL.md", name.as_bytes())])?;
    let record = oneiron::skill::SkillRecord::new(
        name,
        "A critic lens for the review fixture",
        "1.0.0",
        oneiron::ClaimApprovalStatus::Approved,
        oneiron::skill::SkillLifecycle::Candidate,
        oneiron::ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("critic-review-fixture"),
        )]),
    )
    .with_content_hash(tree);
    vault.put_skill_record(&id, &record, TimeRange { start: 12, end: 12 }, 12)?;
    Ok(id)
}

/// One lens's typed answers.
#[derive(Clone, Copy)]
struct Answers {
    verdict: &'static str,
    severity: &'static str,
    hard_check: bool,
}

const REVISE_HIGH: Answers = Answers {
    verdict: "revise",
    severity: "high",
    hard_check: true,
};

/// The local rung: it answers each question from the lens's prompt contract
/// and the question's wording, the two parts of the question's text.
struct Script {
    by_contract: BTreeMap<&'static str, Answers>,
}

fn answer(answer: DecisionAnswer, probability: f64) -> ProviderDecision {
    ProviderDecision {
        answer,
        probability: Some(probability),
        paired: None,
        person: None,
        served: None,
        cost_per_thousand: None,
    }
}

fn noul(value: bool) -> ProviderDecision {
    answer(DecisionAnswer::Noul(value), if value { 0.95 } else { 0.05 })
}

impl DecisionProvider for Script {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "critic-review-fixture".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        let (contract, wording) = call
            .question
            .text
            .split_once("\n\n")
            .ok_or_else(|| oneiron::Error::InvalidConfig("unscripted question".into()))?;
        let answers = self
            .by_contract
            .get(contract)
            .ok_or_else(|| oneiron::Error::InvalidConfig("unscripted lens".into()))?;
        Ok(match wording {
            VERDICT_WORDING => answer(DecisionAnswer::Choice(answers.verdict.into()), 0.95),
            SEVERITY_WORDING => answer(DecisionAnswer::Choice(answers.severity.into()), 0.95),
            HARD_CHECK_WORDING => noul(answers.hard_check),
            OUT_OF_SCOPE_WORDING => noul(false),
            _ => return Err(oneiron::Error::InvalidConfig("unscripted wording".into())),
        })
    }
}

/// A rung a replayed review must never reach.
struct NeverAsked;

impl DecisionProvider for NeverAsked {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "critic-review-fixture".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, _: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        panic!("a replayed review asked its questions again");
    }
}

struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> oneiron::Result<()> {
        Err(oneiron::Error::InvalidConfig(
            "the critic review fixture queues no person ask".into(),
        ))
    }
}

/// Notes read from JSON, one per lens: each call gets one finding.
struct JsonNotes {
    by_lens: BTreeMap<&'static str, Value>,
}

impl ReviewNotes for JsonNotes {
    fn notes(&self, findings: &[ReviewFinding]) -> oneiron::Result<Vec<ReviewNote>> {
        findings
            .iter()
            .map(|finding| {
                let note = self
                    .by_lens
                    .get(finding.input.lens.id.as_str())
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                serde_json::from_value::<ReviewNote>(note)
                    .map_err(|error| oneiron::Error::InvalidConfig(error.to_string()))
            })
            .collect()
    }
}

/// Notes a replayed review must never ask for.
struct NeverNoted;

impl ReviewNotes for NeverNoted {
    fn notes(&self, _: &[ReviewFinding]) -> oneiron::Result<Vec<ReviewNote>> {
        panic!("a replayed review asked for its notes again");
    }
}

/// A note naming `flaw`, with its own evidence and edit.
fn note(evidence: &str, edit: &str, flaw: Value) -> Value {
    json!({
        "evidence_refs": [evidence],
        "suggested_edit": edit,
        "prediction": null,
        "flaw": flaw,
    })
}

fn flaw(kind: &str, start: usize, end: usize) -> Value {
    json!({"kind": kind, "location": {"type": "body_bytes", "start": start, "end": end}})
}

/// One review: its run, lens a's hard check, the threshold, each lens's
/// answers and, unless `None`, each lens's note.
struct Case {
    run: String,
    hard_a: bool,
    threshold: f64,
    a: Answers,
    b: Answers,
    notes: Option<[Value; 2]>,
}

impl Case {
    fn new(a: Answers, b: Answers, notes: Option<[Value; 2]>) -> Self {
        Self {
            run: format!("critic-review-{}", EntityId::now().to_hex()),
            hard_a: false,
            threshold: 0.5,
            a,
            b,
            notes,
        }
    }
}

/// The state a host's door builds from the target: the caller's view, whole.
fn state(fx: &Fixture) -> Value {
    json!({
        "kind": "document",
        "target": {
            "id": fx.target.to_hex(),
            "kind": "turn",
            "occurred_start": 11,
            "occurred_end": 11,
            "learned_at": 11,
            "body": body(),
        },
        "cut_at_bytes": null,
    })
}

fn submit(fx: &Fixture, case: &Case) -> Result<CriticReviewSubmit, Box<dyn std::error::Error>> {
    let lens = |id: &str, contract: &str, hard_check: bool| {
        json!({
            "id": id,
            "prompt_contract": contract,
            "output_schema": "critique.v1 { verdict, severity, evidence_refs, suggested_edit }",
            "hard_check": hard_check,
            "domain": "docs",
        })
    };
    let critic = |id: &str, skill: EntityId| {
        json!({
            "lens_id": id,
            "lens_ref": skill.to_hex(),
            "actor_ref": fx.owner.to_hex(),
            "actor_class": 0,
        })
    };
    Ok(serde_json::from_value(json!({
        "target_ref": fx.target.to_hex(),
        "kind": "document",
        "session_ref": fx.session.to_hex(),
        "run_ref": case.run,
        "type_node": "document_review",
        "type_tree_version": 1,
        "axis": "quality",
        "auto_resolve_threshold": case.threshold,
        "catalog": {
            "schema_version": CRITIC_LENS_CATALOG_SCHEMA_VERSION,
            "lenses": [
                lens("lens_a", CONTRACT_A, case.hard_a),
                lens("lens_b", CONTRACT_B, false),
            ],
        },
        "critics": [critic("lens_a", fx.lens_a), critic("lens_b", fx.lens_b)],
        "spawn_attempt_ref": null,
        "project_ref": null,
    }))?)
}

fn wording() -> ReviewWording {
    ReviewWording {
        verdict: VERDICT_WORDING.to_owned(),
        severity: SEVERITY_WORDING.to_owned(),
        hard_check: HARD_CHECK_WORDING.to_owned(),
        out_of_scope: OUT_OF_SCOPE_WORDING.to_owned(),
    }
}

/// The review through `local` and `notes`, at the vault's clock (a review's
/// key holds no time, so a replay keys the same review).
fn run_review(
    fx: &Fixture,
    case: &Case,
    local: &dyn DecisionProvider,
    notes: Option<&dyn ReviewNotes>,
) -> oneiron::Result<ReviewResult> {
    let submit =
        submit(fx, case).map_err(|error| oneiron::Error::InvalidConfig(error.to_string()))?;
    let (request, catalog) = submit.bind(
        WriteActor::new(fx.owner, EdgeActorClass::Human),
        fx.vault.now_recorded_at(),
    )?;
    let state = state(fx);
    let decisions = ReviewDecisions {
        ladder: DecisionLadder {
            rule: None,
            local: Some(local),
            system_one: None,
            escalation: None,
            big: None,
            human: &NoPerson,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "critic-review-queue".into(),
                version: "1".into(),
            },
            ask_to: None,
            paired: None,
            person: None,
            presence: None,
            correlation: None,
        },
        principal: fx.owner,
        dial: REVIEW_DIAL,
        bands: DecisionBandPolicy::default(),
        state: &state,
        budget: Duration::from_secs(3600),
        wording: wording(),
        notes,
    };
    review_artifact(&fx.vault, &request, &catalog, &decisions)
}

/// The scripted review of `case`, and its outcome as the verb returns it.
fn review(fx: &Fixture, case: &Case) -> Result<(ReviewResult, Value), Box<dyn std::error::Error>> {
    let script = Script {
        by_contract: BTreeMap::from([(CONTRACT_A, case.a), (CONTRACT_B, case.b)]),
    };
    let notes = case.notes.clone().map(|[a, b]| JsonNotes {
        by_lens: BTreeMap::from([("lens_a", a), ("lens_b", b)]),
    });
    let result = run_review(
        fx,
        case,
        &script,
        notes.as_ref().map(|notes| notes as &dyn ReviewNotes),
    )?;
    let outcome = serde_json::to_value(CriticReviewOutcome::from(result.clone()))?;
    Ok((result, outcome))
}

/// Each lens's artifact id in the review's result.
fn artifact_of(result: &ReviewResult, lens: &str) -> String {
    result
        .artifacts
        .iter()
        .find(|artifact| artifact.lens_id == lens)
        .map(|artifact| artifact.artifact_id.clone())
        .expect("one artifact per lens")
}

fn findings(outcome: &Value) -> Vec<Value> {
    outcome["triage"]["findings"]
        .as_array()
        .cloned()
        .expect("the triage lists its findings")
}

fn ids(finding: &Value) -> Vec<String> {
    finding["artifact_ids"]
        .as_array()
        .expect("a finding lists its artifacts")
        .iter()
        .map(|id| id.as_str().expect("an artifact id").to_owned())
        .collect()
}

#[test]
fn one_flaw_from_two_critics_is_one_finding_with_both_evidence() -> TestResult {
    let fx = fixture()?;
    let case = Case::new(
        REVISE_HIGH,
        REVISE_HIGH,
        Some([
            note("evidence-one", "fix one", flaw("missing_guard", 0, 4)),
            note("evidence-two", "fix two", flaw("missing_guard", 0, 4)),
        ]),
    );
    let (result, outcome) = review(&fx, &case)?;
    let findings = findings(&outcome);
    assert_eq!(findings.len(), 1, "one flaw is one finding: {findings:?}");
    let finding = &findings[0];
    let (a, b) = (
        artifact_of(&result, "lens_a"),
        artifact_of(&result, "lens_b"),
    );
    let mut both = vec![a.clone(), b.clone()];
    both.sort();
    assert_eq!(ids(finding), both, "both critics are attributed");
    assert_eq!(
        finding["evidence_refs"],
        json!(["evidence-one", "evidence-two"]),
        "both critics' evidence is kept"
    );
    assert_eq!(finding["verdict"], json!("revise"));
    assert_eq!(finding["conflict"], json!(false));
    // The finding shows the edit of the first critic by artifact id; each
    // critic's own edit, evidence and flaw stay on its artifact.
    let first_edit = if both[0] == a { "fix one" } else { "fix two" };
    assert_eq!(finding["suggested_edit"], json!(first_edit));
    let store = CritiqueArtifactStore::new(&fx.vault);
    for (artifact, json_artifact) in result.artifacts.iter().zip(
        outcome["artifacts"]
            .as_array()
            .expect("the outcome lists its artifacts"),
    ) {
        let (evidence, edit) = if artifact.artifact_id == a {
            ("evidence-one", "fix one")
        } else {
            ("evidence-two", "fix two")
        };
        assert_eq!(artifact.evidence_refs, vec![evidence.to_owned()]);
        assert_eq!(artifact.suggested_edit.as_deref(), Some(edit));
        assert_eq!(json_artifact["flaw"], flaw("missing_guard", 0, 4));
        assert_eq!(
            store
                .get(artifact.branch_attempt, &artifact.artifact_id)?
                .as_ref(),
            Some(artifact),
            "the stored artifact is the one returned"
        );
    }
    Ok(())
}

#[test]
fn two_flaw_kinds_at_one_location_stay_two_findings() -> TestResult {
    let fx = fixture()?;
    let case = Case::new(
        REVISE_HIGH,
        REVISE_HIGH,
        Some([
            note("evidence-one", "fix it", flaw("missing_guard", 0, 4)),
            note("evidence-one", "fix it", flaw("invalid_bound", 0, 4)),
        ]),
    );
    let (result, outcome) = review(&fx, &case)?;
    let findings = findings(&outcome);
    assert_eq!(findings.len(), 2, "two kinds are two flaws: {findings:?}");
    let mut seen = findings.iter().flat_map(ids).collect::<Vec<_>>();
    seen.sort();
    let mut both = vec![
        artifact_of(&result, "lens_a"),
        artifact_of(&result, "lens_b"),
    ];
    both.sort();
    assert_eq!(seen, both, "each finding is one critic's");
    Ok(())
}

#[test]
fn one_flaw_kind_at_two_locations_stays_two_findings() -> TestResult {
    let fx = fixture()?;
    let case = Case::new(
        REVISE_HIGH,
        REVISE_HIGH,
        Some([
            note("evidence-one", "fix it", flaw("missing_guard", 0, 4)),
            note("evidence-one", "fix it", flaw("missing_guard", 4, 8)),
        ]),
    );
    let (_, outcome) = review(&fx, &case)?;
    let findings = findings(&outcome);
    assert_eq!(
        findings.len(),
        2,
        "two locations are two flaws: {findings:?}"
    );
    assert!(findings.iter().all(|finding| ids(finding).len() == 1));
    Ok(())
}

#[test]
fn findings_that_name_no_flaw_never_merge() -> TestResult {
    let fx = fixture()?;
    // No notes: both critics give the same verdict with no evidence and no
    // edit, which the old key merged.
    let case = Case::new(REVISE_HIGH, REVISE_HIGH, None);
    let (_, outcome) = review(&fx, &case)?;
    let findings = findings(&outcome);
    assert_eq!(
        findings.len(),
        2,
        "no flaw identity, no merge: {findings:?}"
    );
    Ok(())
}

#[test]
fn critics_disagreeing_on_one_flaw_keep_the_cautious_verdict_and_never_resolve_alone() -> TestResult
{
    let fx = fixture()?;
    let mut case = Case::new(
        Answers {
            verdict: "accept",
            severity: "low",
            hard_check: true,
        },
        Answers {
            verdict: "discard",
            severity: "high",
            hard_check: true,
        },
        Some([
            note("evidence-one", "fix it", flaw("missing_guard", 0, 4)),
            note("evidence-one", "fix it", flaw("missing_guard", 0, 4)),
        ]),
    );
    // Even at a zero threshold a disagreement waits for a person.
    case.threshold = 0.0;
    let (result, outcome) = review(&fx, &case)?;
    let findings = findings(&outcome);
    assert_eq!(findings.len(), 1, "one flaw is one finding: {findings:?}");
    let finding = &findings[0];
    assert_eq!(
        finding["verdict"],
        json!("discard"),
        "the cautious verdict shows"
    );
    assert_eq!(finding["severity"], json!("high"));
    assert_eq!(finding["conflict"], json!(true));
    assert_eq!(finding["auto_resolved"], json!(false));
    assert_eq!(
        finding["confidence"],
        json!(0.5),
        "only the discarding critic, unmeasured, backs the shown verdict"
    );
    assert_eq!(outcome["triage"]["auto_resolved"], json!(false));
    for artifact in &result.artifacts {
        let expected = if artifact.lens_id == "lens_a" {
            "accept"
        } else {
            "discard"
        };
        assert_eq!(
            serde_json::to_value(artifact.verdict)?,
            json!(expected),
            "each critic keeps its own verdict"
        );
    }
    for claim in fx.vault.claims_for_subject(&result.verdict_claim)? {
        let body = fx.vault.get_claim(&claim)?.expect("a listed claim reads");
        assert_ne!(
            body.predicate, "review.automatic_outcome",
            "a disagreement writes no automatic outcome"
        );
    }
    Ok(())
}

#[test]
fn a_flaw_outside_the_reviewed_body_refuses_the_review() -> TestResult {
    let fx = fixture()?;
    let text = body().to_string();
    let past_the_end = Case::new(
        REVISE_HIGH,
        REVISE_HIGH,
        Some([
            note(
                "evidence-one",
                "fix it",
                flaw("missing_guard", 0, text.len() + 1),
            ),
            note("evidence-one", "fix it", flaw("missing_guard", 0, 4)),
        ]),
    );
    assert!(
        review(&fx, &past_the_end).is_err(),
        "a range past the body names no place in it"
    );
    let inside = text.find('é').expect("the body holds a two-byte character") + 1;
    let mid_character = Case::new(
        REVISE_HIGH,
        REVISE_HIGH,
        Some([
            note("evidence-one", "fix it", flaw("missing_guard", 0, inside)),
            note("evidence-one", "fix it", flaw("missing_guard", 0, 4)),
        ]),
    );
    assert!(
        review(&fx, &mid_character).is_err(),
        "a range that splits a character names no place in the body"
    );
    Ok(())
}

#[test]
fn a_hard_check_veto_stands_over_a_merged_flaw() -> TestResult {
    let fx = fixture()?;
    let accept = Answers {
        verdict: "accept",
        severity: "info",
        hard_check: true,
    };
    let mut case = Case::new(
        Answers {
            hard_check: false,
            ..accept
        },
        accept,
        Some([
            note("evidence-one", "fix it", flaw("missing_guard", 0, 4)),
            note("evidence-two", "fix it", flaw("missing_guard", 0, 4)),
        ]),
    );
    case.hard_a = true;
    let (result, outcome) = review(&fx, &case)?;
    assert_eq!(outcome["triage"]["verdict"], json!("discard"));
    assert_eq!(
        outcome["triage"]["hard_veto_artifact_ids"],
        json!([artifact_of(&result, "lens_a")]),
        "the failed hard check vetoes; no reassurance outvotes it"
    );
    Ok(())
}

#[test]
fn a_replayed_review_returns_the_stored_review_without_asking_again() -> TestResult {
    let fx = fixture()?;
    let case = Case::new(
        REVISE_HIGH,
        REVISE_HIGH,
        Some([
            note("evidence-one", "fix one", flaw("missing_guard", 0, 4)),
            note("evidence-two", "fix two", flaw("missing_guard", 0, 4)),
        ]),
    );
    let (first, first_outcome) = review(&fx, &case)?;
    let replay = run_review(&fx, &case, &NeverAsked, Some(&NeverNoted))?;
    assert_eq!(replay.verdict_claim, first.verdict_claim);
    assert_eq!(
        serde_json::to_value(CriticReviewOutcome::from(replay))?,
        first_outcome,
        "the replay is the stored review, not a new merge"
    );
    Ok(())
}
