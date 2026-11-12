//! FIX-LIST CLAIM-SCOPE-STRING-REFUSED (OPUS-GATECENSUS row 2, Engine ruling
//! 12 Nov 16:2x): a critic's `review.outcome` claim carries its finding key as
//! a String `scope` (critic/review/outcomes.rs), which the scope contract
//! allows: "a `scope` value that is not a map carries no recognized entry at
//! all" (oneiron-store write_envelope/claim_body/scope.rs). Readers that took
//! only a map refused such a claim with `scope must be a map`, so the owner's
//! demotion, an ask answered about it and a SameAs derive naming it all
//! failed. Each test drives a public door on a real critic outcome claim,
//! made by the critic's own producer (`record_review_outcome`).
//!
//! The review fixture is the one of `tests/verb_vault_critic_review.rs`: the
//! public `CriticReviewSubmit::bind` and `review_artifact`, with a scripted
//! local decision rung and notes read from JSON.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_scope_string_readers` (the derive test reaches
//! the derivation batch through `oneiron::test_doors::derive`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use oneiron::critic::CRITIC_LENS_CATALOG_SCHEMA_VERSION;
use oneiron::critic::ReliabilityOutcomeSource;
use oneiron::critic::review::{
    CriticReviewOutcome, CriticReviewSubmit, REVIEW_DIAL, ReviewDecisions, ReviewFinding,
    ReviewNote, ReviewNotes, ReviewResult, ReviewWording, record_review_outcome, review_artifact,
};
use oneiron::llm::decision::questions::{OutcomeBinding, OutcomeSource};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionLadder, DecisionProvider,
    DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin,
};
use oneiron::memory::{ClaimDemoteActionInput, ClaimDemoteRequest};
use oneiron::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskOption, TaskAskOptionId, TaskAskQuestion,
    TaskAskSpec, TaskAskStatus, TaskAskTarget, TaskAskWord,
};
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

/// Two critic outcome claims, one per lens: the lenses name two flaw kinds at
/// one location, so the review keeps two findings, and the owner accepts each
/// lens's artifact through the critic's public outcome door.
fn outcome_claims(fx: &Fixture) -> Result<[EntityId; 2], Box<dyn std::error::Error>> {
    let case = Case::new(
        REVISE_HIGH,
        REVISE_HIGH,
        Some([
            note("evidence-one", "fix one", flaw("missing_guard", 0, 4)),
            note("evidence-two", "fix two", flaw("invalid_bound", 0, 4)),
        ]),
    );
    let (result, _) = review(fx, &case)?;
    let mut claims = Vec::with_capacity(2);
    for lens in ["lens_a", "lens_b"] {
        let claim = record_review_outcome(
            &fx.vault,
            &result,
            WriteActor::new(fx.owner, EdgeActorClass::Human),
            &artifact_of(&result, lens),
            ReliabilityOutcomeSource::OwnerVerdict,
            true,
            fx.vault.now_recorded_at(),
        )?;
        // The producer's own shape, the one the readers refused: the finding
        // key as a String scope.
        let body = fx
            .vault
            .get_claim(&claim)?
            .ok_or("the outcome claim is stored")?;
        assert_eq!(body.predicate, "review.outcome");
        assert!(
            matches!(body.scope, Some(rmpv::Value::String(_))),
            "a critic outcome keeps its finding key as a String scope: {:?}",
            body.scope
        );
        claims.push(claim);
    }
    let [first, second] = claims.as_slice() else {
        return Err("two outcome claims".into());
    };
    Ok([*first, *second])
}

/// G139 (claim_demotion_rung) and the demotion's rung stamp: the owner marks
/// a critic outcome claim stale through the Memory demotion door. On main the
/// door refuses with `scope must be a map`.
#[test]
fn the_owner_demotes_a_critic_outcome_claim() -> TestResult {
    let fx = fixture()?;
    let [claim, _] = outcome_claims(&fx)?;
    let view = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .claim_demote(&ClaimDemoteRequest {
            claim_ref: claim.to_hex(),
            action: ClaimDemoteActionInput::Stale,
        })
        .map_err(|error| format!("the owner's demotion of a critic outcome: {error:?}"))?;
    assert_eq!(view.rung, "stale");
    assert!(view.stale);
    let body = fx.vault.get_claim(&claim)?.ok_or("the demoted claim")?;
    assert!(body.stale, "the demoted claim reads stale");
    Ok(())
}

/// G71 (with_evidence_taint) and with_private_reader on the task-ask answer:
/// an ask about a critic outcome claim, with an outcome binding, settles on
/// the owner's answer and binds that answer as a claim, which copies the
/// outcome's scope. On main the answer refuses with `scope must be a map`.
#[test]
fn an_ask_about_a_critic_outcome_claim_binds_its_answer() -> TestResult {
    let fx = fixture()?;
    let [claim, _] = outcome_claims(&fx)?;
    let memory = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Claim(claim));
    let option = TaskAskOptionId::new("upheld")?;
    question
        .options
        .insert(option.clone(), TaskAskOption::new("upheld"));
    question.outcome_binding = Some(OutcomeBinding {
        source: OutcomeSource::Claim {
            predicate: "review.outcome".to_owned(),
        },
        horizon: 3600,
        mapping: BTreeMap::from([("upheld".to_owned(), true)]),
        noise_weight: 0.5,
        linked_by: None,
    });
    let spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(BTreeSet::from([fx.owner]))),
        question,
        None,
        TaskAskDefault::AskMe,
    );
    let handle = memory
        .tasks_ask(&spec)
        .map_err(|error| format!("the ask: {error:?}"))?
        .handle;
    let mut word = TaskAskWord::new(claim);
    word.option = Some(option);
    memory
        .tasks_answer(&handle, &word)
        .map_err(|error| format!("the owner's answer about a critic outcome: {error:?}"))?;
    let TaskAskStatus::Settled(result) = memory
        .tasks_ask_status(handle)
        .map_err(|error| format!("the ask's status: {error:?}"))?
    else {
        return Err("the owner's answer settles the ask".into());
    };
    let answer = result
        .settlement
        .outcome_answer_ref
        .ok_or("the settled answer is bound as a claim")?;
    let body = fx
        .vault
        .get_claim(&answer)?
        .ok_or("the bound answer claim is stored")?;
    assert_eq!(body.predicate, "judgment.answer");
    let Some(rmpv::Value::Map(scope)) = &body.scope else {
        return Err(format!("the answer's scope is a map: {:?}", body.scope).into());
    };
    for key in ["evidence_taint", "typed_question_principal"] {
        assert!(
            scope.iter().any(|(entry, _)| entry.as_str() == Some(key)),
            "the answer carries its {key} stamp: {scope:?}"
        );
    }
    Ok(())
}

/// G71 (with_evidence_taint) on the derive SameAs: a SameAs between two
/// critic outcome claims copies the anchor's scope onto its proposed status
/// claim, then stamps the evidence taint. On main the whole derive commit
/// aborts with `scope must be a map`.
#[cfg(oneiron_test_support)]
#[test]
fn a_same_as_between_critic_outcome_claims_commits() -> TestResult {
    use oneiron::test_doors::derive::{Derived, Named, SameAs, commit};

    let fx = fixture()?;
    let [first, second] = outcome_claims(&fx)?;
    let committed = commit(
        &fx.vault,
        fx.owner,
        EdgeActorClass::Human,
        "run-links",
        &[Derived::SameAs(SameAs {
            local: "same_as",
            source: Named::Stored(first),
            target: Named::Stored(second),
        })],
    )
    .map_err(|error| format!("the derive commit naming two critic outcomes: {error:?}"))?;
    let [item] = committed.items.as_slice() else {
        return Err(format!("one item: {:?}", committed.items).into());
    };
    assert!(item.landed, "the SameAs proposal lands: {:?}", item.reasons);
    let [status] = item.rows.as_slice() else {
        return Err(format!("one status claim: {:?}", item.rows).into());
    };
    let body = fx
        .vault
        .get_claim(status)?
        .ok_or("the proposed status claim is stored")?;
    let Some(rmpv::Value::Map(scope)) = &body.scope else {
        return Err(format!("the status claim's scope is a map: {:?}", body.scope).into());
    };
    assert!(
        scope
            .iter()
            .any(|(entry, _)| entry.as_str() == Some("evidence_taint")),
        "the status claim carries the evidence taint: {scope:?}"
    );
    Ok(())
}
