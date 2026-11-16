//! A review stands when its dissent's target is outside the dissent
//! question's lane (Sol F2 on #8105; FIX SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS).
//!
//! A review keeps the prediction of a critique that triage overruled as a
//! NOTE and a standing question, asked as the review's principal with no
//! live lane (`critic::review::dissent`). Since #8105 the reader of such a
//! question rebuilds under the access gate for a principal that is no live
//! owner, so it refuses the owner's MESSAGE that names no relationship and
//! no private scope unless an access grant admits it. The dissent then read
//! its target for its first answer, and that refusal failed the whole review
//! after the review had persisted, and every replay of it.
//!
//! The dissent now keeps its NOTE and its question unanswered, and the
//! review stands. Red on #8105 (e59c71b9d44): the agent's review of the
//! owner's unscoped MESSAGE fails with EntityNotFound.
//!
//! No case here proves a lane that does read the target: that dissent's
//! first answer takes the MESSAGE's own substrate facet, which is no stored
//! FACET, so the claim birth gate refuses it with InvalidFacet. That path is
//! main's, and #8105 does not change it (FIX
//! STANDING-ANSWER-TAKES-UNSTORED-SUBSTRATE-FACET). Its guards come back
//! with that row's fix.
//!
//! The agent holds the owner's full-access approval ceiling and read row in
//! the policy (`Vault::grant_agent_principal`), so its review persists and
//! the policy check passes; it holds no agent Grant, so only the access gate
//! decides the MESSAGE.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test review_dissent_access_gate`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::critic::CRITIC_LENS_CATALOG_SCHEMA_VERSION;
use oneiron::critic::review::{
    CriticReviewSubmit, REVIEW_DIAL, ReviewDecisions, ReviewDissent, ReviewFinding, ReviewNote,
    ReviewNotes, ReviewResult, ReviewWording, preserve_review_dissent, review_artifact,
};
use oneiron::llm::decision::questions::answer_records;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionLadder, DecisionProvider,
    DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_SESSION;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

/// The vault clock's fixed time for every test here.
const T0: u64 = 1_780_000_000;

const CONTRACT_A: &str = "Lens a: judge the target's guards.";
const CONTRACT_B: &str = "Lens b: judge the target's bounds.";
const VERDICT_WORDING: &str = "Which verdict does this lens give?";
const SEVERITY_WORDING: &str = "How severe is the finding?";
const HARD_CHECK_WORDING: &str = "Does the target pass this lens's hard check?";
const OUT_OF_SCOPE_WORDING: &str = "Is the target outside this lens's scope?";

const MESSAGE_TEXT: &str = "The spring garden needs a watering rota.";
/// The claim predicate whose fact settles lens a's prediction.
const OUTCOME_PREDICATE: &str = "garden.rota_posted";
/// Seconds from the review to the prediction's horizon.
const HORIZON: u64 = 86_400;

/// A rooted vault with its install enrolled and its embedded owner, a review
/// session, the two lenses' stored skills, and the owner's MESSAGE that names
/// no relationship and no private scope in one conversation.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    session: EntityId,
    lens_a: EntityId,
    lens_b: EntityId,
    message: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let session = EntityId::now();
    vault
        .put_entity(
            &session,
            ENTITY_TYPE_SESSION,
            TimeRange { start: 10, end: 10 },
            10,
            &rmp_serde::to_vec_named(&json!({"title": "review dissent fixture"}))
                .expect("session body"),
        )
        .expect("the session");
    let lens_a = put_lens_skill(&vault, "review-dissent.lens-a");
    let lens_b = put_lens_skill(&vault, "review-dissent.lens-b");
    let conversation = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            thread_audience: None,
            occurred_at: 1,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: MESSAGE_TEXT.to_owned(),
                parts: None,
                metadata: Some(json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        })
        .expect("the owner's turn lands");
    Fixture {
        vault,
        _dir: dir,
        owner,
        session,
        lens_a,
        lens_b,
        message,
    }
}

fn owner_proof(fixture: &Fixture) -> AuthenticatedOwner {
    fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// A lens's stored skill: an owner-authored candidate, which is all a review
/// reads of it.
fn put_lens_skill(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let tree = oneiron::skill::canonical_skill_tree_hash([("SKILL.md", name.as_bytes())])
        .expect("skill tree");
    let record = oneiron::skill::SkillRecord::new(
        name,
        "A critic lens for the review dissent fixture",
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
            rmpv::Value::from("review-dissent-fixture"),
        )]),
    )
    .with_content_hash(tree);
    vault
        .put_skill_record(&id, &record, TimeRange { start: 12, end: 12 }, 12)
        .expect("the lens skill");
    id
}

/// A critic agent the owner creates, approved and enabled, with the owner's
/// full-access approval ceiling and read row in the policy
/// (`Vault::grant_agent_principal`, ARCH-0028), so its review's Auto verdict
/// claim lands. It holds no agent Grant.
fn review_agent(fixture: &Fixture, name: &str) -> EntityId {
    let agent = fixture.vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        &fixture.vault,
        &owner_proof(fixture),
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": name,
                "desc": "review dissent fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("the owner creates the critic agent");
    fixture
        .vault
        .grant_agent_principal(&owner_proof(fixture), &agent.to_hex(), AgentCeiling::Auto)
        .expect("the owner gives the critic the full-access ceiling");
    agent
}

/// One lens's typed answers.
#[derive(Clone, Copy)]
struct Answers {
    verdict: &'static str,
    severity: &'static str,
}

/// Lens a accepts the target; lens b's severe revise overrules it.
const ACCEPT: Answers = Answers {
    verdict: "accept",
    severity: "low",
};

const REVISE: Answers = Answers {
    verdict: "revise",
    severity: "high",
};

/// The local rung: it answers each question from the lens's prompt contract
/// and the question's wording.
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
            model: "review-dissent-fixture".into(),
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
            HARD_CHECK_WORDING => noul(true),
            OUT_OF_SCOPE_WORDING => noul(false),
            _ => return Err(oneiron::Error::InvalidConfig("unscripted wording".into())),
        })
    }
}

struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> oneiron::Result<()> {
        Err(oneiron::Error::InvalidConfig(
            "the review dissent fixture queues no person ask".into(),
        ))
    }
}

/// Lens a's note carries `prediction`; every other lens's note is empty.
struct PredictionNotes {
    prediction: Value,
}

impl ReviewNotes for PredictionNotes {
    fn notes(&self, findings: &[ReviewFinding]) -> oneiron::Result<Vec<ReviewNote>> {
        findings
            .iter()
            .map(|finding| {
                let note = if finding.input.lens.id == "lens_a" {
                    json!({ "prediction": self.prediction })
                } else {
                    json!({})
                };
                serde_json::from_value::<ReviewNote>(note)
                    .map_err(|error| oneiron::Error::InvalidConfig(error.to_string()))
            })
            .collect()
    }
}

/// Lens a's prediction, made at `at`: a fact of the outcome predicate
/// within the horizon settles it.
fn prediction(at: u64) -> Value {
    json!({
        "what": "The watering rota is posted before the first frost.",
        "by_when": at + HORIZON,
        "how_checked": {
            "source": {"kind": "claim", "predicate": OUTCOME_PREDICATE},
            "horizon": HORIZON,
            "mapping": {"true": true, "false": false},
            "noise_weight": 1.0,
            "linked_by": null,
        },
    })
}

fn wording() -> ReviewWording {
    ReviewWording {
        verdict: VERDICT_WORDING.to_owned(),
        severity: SEVERITY_WORDING.to_owned(),
        hard_check: HARD_CHECK_WORDING.to_owned(),
        out_of_scope: OUT_OF_SCOPE_WORDING.to_owned(),
    }
}

/// `critic`'s review of the owner's MESSAGE under the run `run`, through the
/// production review path a host's door runs: lens a accepts it with a
/// prediction, lens b's severe revise overrules lens a, so the review keeps
/// lens a's dissent. The same `run` is the same review: a second call
/// replays the persisted one.
fn review(fixture: &Fixture, critic: WriteActor, run: &str) -> oneiron::Result<ReviewResult> {
    let lens = |id: &str, contract: &str| {
        json!({
            "id": id,
            "prompt_contract": contract,
            "output_schema": "critique.v1 { verdict, severity, evidence_refs, suggested_edit }",
            "hard_check": false,
            "domain": "docs",
        })
    };
    let class = critic.actor_class() as u8;
    let binding = |id: &str, skill: EntityId| {
        json!({
            "lens_id": id,
            "lens_ref": skill.to_hex(),
            "actor_ref": critic.entity_ref().to_hex(),
            "actor_class": class,
        })
    };
    let submit: CriticReviewSubmit = serde_json::from_value(json!({
        "target_ref": fixture.message.to_hex(),
        "kind": "document",
        "session_ref": fixture.session.to_hex(),
        "run_ref": run,
        "type_node": "document_review",
        "type_tree_version": 1,
        "axis": "quality",
        "auto_resolve_threshold": 0.5,
        "catalog": {
            "schema_version": CRITIC_LENS_CATALOG_SCHEMA_VERSION,
            "lenses": [lens("lens_a", CONTRACT_A), lens("lens_b", CONTRACT_B)],
        },
        "critics": [binding("lens_a", fixture.lens_a), binding("lens_b", fixture.lens_b)],
        "spawn_attempt_ref": null,
        "project_ref": null,
    }))
    .expect("review submit");
    let at = fixture.vault.now_recorded_at();
    let (request, catalog) = submit.bind(critic, at).expect("bind the review");
    let script = Script {
        by_contract: BTreeMap::from([(CONTRACT_A, ACCEPT), (CONTRACT_B, REVISE)]),
    };
    let notes = PredictionNotes {
        prediction: prediction(at),
    };
    let state = json!({
        "kind": "document",
        "target": {
            "id": fixture.message.to_hex(),
            "kind": "message",
            "occurred_start": 1,
            "occurred_end": 1,
            "learned_at": T0,
            "body": {"content": MESSAGE_TEXT},
        },
        "cut_at_bytes": null,
    });
    let decisions = ReviewDecisions {
        ladder: DecisionLadder {
            rule: None,
            local: Some(&script),
            system_one: None,
            escalation: None,
            big: None,
            human: &NoPerson,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "review-dissent-queue".into(),
                version: "1".into(),
            },
            ask_to: None,
            paired: None,
            person: None,
            presence: None,
            correlation: None,
        },
        principal: critic.entity_ref(),
        dial: REVIEW_DIAL,
        bands: DecisionBandPolicy::default(),
        state: &state,
        budget: Duration::from_secs(3600),
        wording: wording(),
        notes: Some(&notes),
    };
    review_artifact(&fixture.vault, &request, &catalog, &decisions)
}

/// Lens a's dissent as the review keeps it: preserving it again authors
/// nothing new and hands back what it holds.
fn lens_a_dissent(fixture: &Fixture, result: &ReviewResult) -> ReviewDissent {
    let artifact = result
        .artifacts
        .iter()
        .find(|artifact| artifact.lens_id == "lens_a")
        .expect("one critique per lens");
    assert_eq!(
        artifact.verdict,
        oneiron::critic::CritiqueVerdict::Accept,
        "precondition: lens a accepts the target"
    );
    assert_ne!(
        result.triage.verdict,
        oneiron::critic::CritiqueVerdict::Accept,
        "precondition: triage overrules lens a"
    );
    preserve_review_dissent(
        &fixture.vault,
        result,
        &artifact.artifact_id,
        fixture.vault.now_recorded_at(),
    )
    .expect("lens a's dissent reads back")
    .expect("precondition: the review keeps lens a's overruled prediction as a dissent")
}

/// The answers the dissent's standing question holds.
fn dissent_answers(fixture: &Fixture, principal: EntityId, dissent: &ReviewDissent) -> usize {
    let question = dissent
        .question
        .expect("the dissent keeps its standing question");
    answer_records(&fixture.vault, principal, question)
        .expect("the dissent question's answers read")
        .len()
}

#[test]
fn an_agents_review_stands_when_the_access_gate_refuses_its_dissents_target() {
    let fixture = fixture();
    let agent = review_agent(&fixture, "review-dissent.refused");
    let critic = WriteActor::new(agent, EdgeActorClass::Agent);

    let result = review(&fixture, critic, "review-dissent-refused").unwrap_or_else(|error| {
        panic!(
            "expected the agent's review to stand though its dissent's question reads no \
             unscoped MESSAGE under the access gate: {error:?}"
        )
    });

    let dissent = lens_a_dissent(&fixture, &result);
    assert!(
        dissent.note.is_some(),
        "expected the dissent to keep its NOTE: {dissent:?}"
    );
    assert_eq!(
        dissent_answers(&fixture, agent, &dissent),
        0,
        "expected the dissent's question to hold no answer: its target is outside its lane"
    );
    let replayed = review(&fixture, critic, "review-dissent-refused")
        .unwrap_or_else(|error| panic!("expected the replayed review to stand too: {error:?}"));
    assert_eq!(
        replayed.verdict_claim, result.verdict_claim,
        "precondition: the second call replays the persisted review"
    );
}
