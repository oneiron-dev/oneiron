//! Row 4 CRITIC-ATTRIBUTION, PR 3 (rulings LEARN-CRITIC Q3 = B, LEARN-GRANT = A,
//! LEARN-CRITIC-ANCHOR): `vault.critic.outcome` records the anchored outcome of one
//! critique of a persisted review, and `vault.critic.findings` reads the review back
//! with each critique's standing outcome and its critics' cells, provenance cut to the
//! review. Both run through `oneiron::task_verb::sdk::invoke`, JSON in and JSON out.
//!
//! The owner states a verdict on any review. An agent acts only on a review it wrote,
//! on its own live owner Grant listing the verb, and never states a verdict or sends a
//! success flag: it names the sealed try whose completed directed recheck judged the
//! reviewed result, and the engine reads what the recheck's findings settle. A found
//! flaw upholds a critique that did not accept the target; a clear recheck settles only
//! when it judged every objective the try confessed. One recheck settles one critique
//! per critic cell.
//!
//! Reviews run the production path a host's door runs (`CriticReviewSubmit::bind` and
//! `review_artifact` with a scripted local rung), as `verb_vault_critic_review` does;
//! the sealed try is a hosted `tasks.update` DONE, as `verb_tasks_done_executor_stamp`
//! does, confessed and rechecked through the owner's seal doors.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_critic_outcome`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::critic::CRITIC_LENS_CATALOG_SCHEMA_VERSION;
use oneiron::critic::review::{
    CriticReviewSubmit, REVIEW_DIAL, ReviewDecisions, ReviewResult, ReviewWording, review_artifact,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::learning::{Anchor, Observation, TypeRef};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionLadder, DecisionProvider,
    DecisionRung, HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin,
};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError,
};
use oneiron::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use oneiron::self_heal::audit::doors::{SealCompleteRequest, complete_as_owner, confess_as_owner};
use oneiron::self_heal::audit::{AttemptConfession, ObjectiveConfession};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::task_verb::{AttemptHandle, HostBinding, TaskHandle};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const OUTCOME: &str = "vault.critic.outcome";
const FINDINGS: &str = "vault.critic.findings";

/// The vault clock's fixed time for every test here.
const T0: u64 = 1_780_000_000;

const CONTRACT_A: &str = "Lens a: judge the target's guards.";
const CONTRACT_B: &str = "Lens b: judge the target's bounds.";
const VERDICT_WORDING: &str = "Which verdict does this lens give?";
const SEVERITY_WORDING: &str = "How severe is the finding?";
const HARD_CHECK_WORDING: &str = "Does the target pass this lens's hard check?";
const OUT_OF_SCOPE_WORDING: &str = "Is the target outside this lens's scope?";

/// The model and revision the host ran the executor's run on.
const RUN_MODEL: &str = "fixture/run-model@rev-a";
/// An independent judge: another model than the executor's.
const JUDGE_MODEL: &str = "fixture/judge-model@rev-j";
const RUN_LEASE_OWNER: &str = "critic-outcome-host";
const OBJECTIVE: &str = "summarize the week's notes";
const SECOND_OBJECTIVE: &str = "name every source note";

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    session: EntityId,
    lens_a: EntityId,
    lens_b: EntityId,
}

/// A rooted vault with its install enrolled and its embedded owner, a review
/// session and the two lenses' stored skills.
fn rooted_vault() -> Fixture {
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
            &rmp_serde::to_vec_named(&json!({"title": "critic outcome fixture"}))
                .expect("session body"),
        )
        .expect("the session");
    let lens_a = put_lens_skill(&vault, "critic-outcome.lens-a");
    let lens_b = put_lens_skill(&vault, "critic-outcome.lens-b");
    Fixture {
        vault,
        _dir: dir,
        owner,
        session,
        lens_a,
        lens_b,
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

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

fn agent_memory(fixture: &Fixture, agent: EntityId) -> Memory<'_> {
    fixture.vault.memory(agent, EdgeActorClass::Agent)
}

/// A lens's stored skill: an owner-authored candidate, which is all a review
/// reads of it.
fn put_lens_skill(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let tree = oneiron::skill::canonical_skill_tree_hash([("SKILL.md", name.as_bytes())])
        .expect("skill tree");
    let record = oneiron::skill::SkillRecord::new(
        name,
        "A critic lens for the outcome fixture",
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
            rmpv::Value::from("critic-outcome-fixture"),
        )]),
    )
    .with_content_hash(tree);
    vault
        .put_skill_record(&id, &record, TimeRange { start: 12, end: 12 }, 12)
        .expect("the lens skill");
    id
}

/// A critic agent the owner creates, approved and enabled, with the owner's live
/// Grant naming full access (`read`, `propose`, `write`) and `verbs`; the agent and
/// the Grant's row. Full access names no critic verb: only `verbs` lists one.
fn critic_agent(fixture: &Fixture, name: &str, verbs: &[&str]) -> (EntityId, EntityId) {
    let agent = fixture.vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        &fixture.vault,
        &owner_proof(fixture),
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": name,
                "desc": "critic outcome fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("the owner creates the critic agent");
    let mut scope = Scope::top();
    let mut named: BTreeSet<String> = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    named.extend(verbs.iter().map(|verb| (*verb).to_owned()));
    scope.verbs = ScopeAxis::Some(named);
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof(fixture),
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
        },
    )
    .expect("the owner grants the critic");
    assert!(minted.grant.confers, "the critic's Grant confers");
    (agent, minted.grant.grant_ref)
}

fn revoke_grant(fixture: &Fixture, grant_ref: EntityId) {
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &owner_proof(fixture),
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref,
            seen: None,
        },
    )
    .expect("the owner revokes the Grant");
    assert!(revoked.changed, "the revoke lands");
}

/// A TURN the critics review, with `text` as its body.
fn put_target(fixture: &Fixture, text: &str) -> EntityId {
    let id = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &rmp_serde::to_vec_named(&target_body(text)).expect("a TURN body"),
        )
        .expect("the target");
    id
}

fn target_body(text: &str) -> Value {
    json!({ "text": text })
}

/// One lens's typed answers.
#[derive(Clone, Copy)]
struct Answers {
    verdict: &'static str,
    severity: &'static str,
}

const ACCEPT: Answers = Answers {
    verdict: "accept",
    severity: "low",
};

const REVISE: Answers = Answers {
    verdict: "revise",
    severity: "high",
};

/// The local rung: it answers each question from the lens's prompt contract and
/// the question's wording.
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
            model: "critic-outcome-fixture".into(),
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
            "the critic outcome fixture queues no person ask".into(),
        ))
    }
}

/// Who reviews: the actor every critic binding names.
#[derive(Clone, Copy)]
struct Critic {
    actor: EntityId,
    class: EdgeActorClass,
}

/// One review of `target` by `critic` under the run `run`: lens a answers `a`,
/// lens b answers `b`.
struct Review<'a> {
    critic: Critic,
    target: EntityId,
    text: &'a str,
    run: &'a str,
    a: Answers,
    b: Answers,
}

fn wording() -> ReviewWording {
    ReviewWording {
        verdict: VERDICT_WORDING.to_owned(),
        severity: SEVERITY_WORDING.to_owned(),
        hard_check: HARD_CHECK_WORDING.to_owned(),
        out_of_scope: OUT_OF_SCOPE_WORDING.to_owned(),
    }
}

/// The scripted review, persisted through the production review path.
fn review(fixture: &Fixture, spec: &Review<'_>) -> ReviewResult {
    let lens = |id: &str, contract: &str| {
        json!({
            "id": id,
            "prompt_contract": contract,
            "output_schema": "critique.v1 { verdict, severity, evidence_refs, suggested_edit }",
            "hard_check": false,
            "domain": "docs",
        })
    };
    let class = spec.critic.class as u8;
    let binding = |id: &str, skill: EntityId| {
        json!({
            "lens_id": id,
            "lens_ref": skill.to_hex(),
            "actor_ref": spec.critic.actor.to_hex(),
            "actor_class": class,
        })
    };
    let submit: CriticReviewSubmit = serde_json::from_value(json!({
        "target_ref": spec.target.to_hex(),
        "kind": "document",
        "session_ref": fixture.session.to_hex(),
        "run_ref": spec.run,
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
    let (request, catalog) = submit
        .bind(
            WriteActor::new(spec.critic.actor, spec.critic.class),
            fixture.vault.now_recorded_at(),
        )
        .expect("bind the review");
    let script = Script {
        by_contract: BTreeMap::from([(CONTRACT_A, spec.a), (CONTRACT_B, spec.b)]),
    };
    let state = json!({
        "kind": "document",
        "target": {
            "id": spec.target.to_hex(),
            "kind": "turn",
            "occurred_start": T0,
            "occurred_end": T0,
            "learned_at": T0,
            "body": target_body(spec.text),
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
                model: "critic-outcome-queue".into(),
                version: "1".into(),
            },
            ask_to: None,
            paired: None,
            person: None,
            presence: None,
            correlation: None,
        },
        principal: spec.critic.actor,
        dial: REVIEW_DIAL,
        bands: DecisionBandPolicy::default(),
        state: &state,
        budget: Duration::from_secs(3600),
        wording: wording(),
        notes: None,
    };
    review_artifact(&fixture.vault, &request, &catalog, &decisions).expect("the review persists")
}

/// The review's critique by `lens`.
fn artifact_of(result: &ReviewResult, lens: &str) -> String {
    result
        .artifacts
        .iter()
        .find(|artifact| artifact.lens_id == lens)
        .map(|artifact| artifact.artifact_id.clone())
        .expect("one critique per lens")
}

fn receipt_of(result: &ReviewResult, artifact: &str) -> String {
    format!("critic.review:{}:{artifact}", result.verdict_claim.to_hex())
}

fn outcome_call(
    memory: &Memory<'_>,
    result: &ReviewResult,
    target: EntityId,
    artifact: &str,
    anchor: Value,
) -> Result<Value, MemoryError> {
    invoke(
        memory,
        OUTCOME,
        json!({
            "verdict_ref": result.verdict_claim.to_hex(),
            "target_ref": target.to_hex(),
            "artifact_id": artifact,
            "anchor": anchor,
        }),
    )
}

fn findings_call(
    memory: &Memory<'_>,
    result: &ReviewResult,
    target: EntityId,
) -> Result<Value, MemoryError> {
    invoke(
        memory,
        FINDINGS,
        json!({
            "verdict_ref": result.verdict_claim.to_hex(),
            "target_ref": target.to_hex(),
        }),
    )
}

fn owner_verdict(accepted: bool) -> Value {
    json!({ "kind": "owner_verdict", "accepted": accepted })
}

fn seal_recheck(attempt: AttemptId) -> Value {
    json!({ "kind": "seal_recheck", "attempt_ref": attempt_hex(attempt) })
}

fn attempt_hex(attempt: AttemptId) -> String {
    attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assert_code(result: Result<Value, MemoryError>, code: &str, why: &str) {
    match result {
        Ok(value) => panic!("{why}: the call answered {value}"),
        Err(error) => assert_eq!(error.code, code, "{why}: {error:?}"),
    }
}

fn anchor_json(anchor: Anchor) -> Value {
    serde_json::to_value(anchor).expect("anchor wire")
}

fn success_json(success: bool) -> Value {
    serde_json::to_value(Observation::Success(success)).expect("observation wire")
}

/// The findings' cell entry that calibrates `artifact`.
fn cell_of<'a>(findings: &'a Value, artifact: &str) -> &'a Value {
    findings["cells"]
        .as_array()
        .expect("cells")
        .iter()
        .find(|cell| {
            cell["artifact_ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(artifact)))
        })
        .unwrap_or_else(|| panic!("no cell calibrates {artifact}: {findings}"))
}

fn evidence_receipts(cell: &Value) -> Vec<String> {
    cell["cell"]["view"]["provenance"]["evidence"]
        .as_array()
        .expect("provenance evidence")
        .iter()
        .map(|row| row["receipt"].as_str().expect("receipt").to_owned())
        .collect()
}

// --- the sealed try a recheck judges -------------------------------------------------

/// The executor agent: defined by the owner, with an owner Grant of base reach so
/// its task calls read the TASK they name.
fn executor_agent(fixture: &Fixture) -> EntityId {
    let agent = define_agent(&fixture.vault, "critic-outcome-executor").expect("agent");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof(fixture),
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
        },
    )
    .expect("the owner grants the executor base reach");
    assert!(minted.grant.confers, "the executor's grant confers");
    agent
}

/// One run of `agent`, dispatched, leased and stamped with the host's model.
fn stamped_run(fixture: &Fixture, agent: EntityId) -> AttemptRecord {
    let now = fixture.vault.now_recorded_at();
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&fixture.vault)
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("dispatch the executor's run")
    else {
        panic!("the executor's run was not dispatched");
    };
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(&fixture.vault)
        .claim(ClaimAttempt {
            lease_owner: RUN_LEASE_OWNER.into(),
            now,
        })
        .expect("claim the run")
    else {
        panic!("the executor's run was not leased");
    };
    assert_eq!(leased.id, status.attempt.id, "the dispatched run is leased");
    AttemptQueue::new(&fixture.vault)
        .set_executor_model(leased.id, RUN_LEASE_OWNER, leased.attempt_count, RUN_MODEL)
        .expect("the host stamps its run's model")
}

/// The executor's met DONE of an owner TASK, through a host-bound run, naming a
/// fresh TURN as its result: the completed try and its result.
fn completed_try(fixture: &Fixture, executor: EntityId, text: &str) -> (AttemptId, EntityId) {
    let run = stamped_run(fixture, executor);
    let created = invoke(
        &owner_memory(fixture),
        "tasks.create",
        json!({
            "spec": { "summary": OBJECTIVE },
            "assignee": { "child": { "actor_ref": executor.to_hex() } },
        }),
    )
    .expect("the owner creates the task");
    let task: EntityId = serde_json::from_value(created["task_ref"].clone())
        .unwrap_or_else(|error| panic!("no created task ({error}): {created}"));
    let memory = agent_memory(fixture, executor)
        .with_task_host(HostBinding::from_leased(&run, None).expect("host binding"));
    let accepted = invoke(
        &memory,
        "tasks.accept",
        json!({ "task_ref": task.to_hex(), "intent_key": "take-the-task" }),
    )
    .expect("the executor accepts");
    let handle: AttemptHandle =
        match serde_json::from_value::<TaskHandle>(accepted["handle"].clone()) {
            Ok(TaskHandle::Attempt(handle)) => handle,
            other => panic!("the accept named no try ({other:?}): {accepted}"),
        };
    let result = put_target(fixture, text);
    invoke(
        &memory,
        "tasks.update",
        json!({
            "task_ref": task.to_hex(),
            "report_key": "done-once",
            "attempt": serde_json::to_value(&handle).expect("handle wire"),
            "report": { "done": { "result_ref": result.to_hex() } },
        }),
    )
    .expect("the DONE lands");
    let record = AttemptQueue::new(&fixture.vault)
        .get(handle.attempt_ref)
        .expect("read the try")
        .expect("the try exists");
    assert_eq!(
        record.state,
        AttemptState::Completed,
        "the DONE completes the try"
    );
    assert_eq!(
        record.executor_model.as_deref(),
        Some(RUN_MODEL),
        "the try carries the host run's model"
    );
    (handle.attempt_ref, result)
}

/// The owner's seal confession of `attempt`: `objectives` as (name, uncertain).
/// An uncertain objective asks for a directed recheck. Gives back the recheck's
/// request time.
fn confess(
    fixture: &Fixture,
    attempt: AttemptId,
    subject: EntityId,
    objectives: &[(&str, bool)],
) -> u64 {
    let sealed = confess_as_owner(
        &fixture.vault,
        &owner_proof(fixture),
        &AttemptConfession {
            attempt,
            subject,
            type_ref: TypeRef::root(1),
            objectives: objectives
                .iter()
                .map(|(objective, uncertain)| ObjectiveConfession {
                    objective: (*objective).to_owned(),
                    met: Some(true),
                    flaw: None,
                    uncertainty: uncertain.then(|| "the summary may omit a note".to_owned()),
                })
                .collect(),
        },
    )
    .expect("the owner seals the try");
    let sealed = serde_json::to_value(&sealed).expect("seal wire");
    sealed["receipt"]["checks"][0]["request"]["created_at"]
        .as_u64()
        .unwrap_or_else(|| panic!("the confession asked for no directed recheck: {sealed}"))
}

/// The owner's attested independent recheck of `attempt`: one finding per
/// `(objective, flaw_present)`.
fn complete_recheck(
    fixture: &Fixture,
    attempt: AttemptId,
    asked_at: u64,
    findings: &[(&str, bool)],
) {
    let request: SealCompleteRequest = serde_json::from_value(json!({
        "attempt": attempt,
        "kind": "confession_recheck",
        "outcome": {
            "judge_revision": JUDGE_MODEL,
            "checked_at": asked_at,
            "findings": findings
                .iter()
                .map(|(objective, flaw)| json!({
                    "objective": objective,
                    "flaw_present": flaw,
                    "evidence_ref": "independent-recheck-1",
                }))
                .collect::<Vec<_>>(),
        },
    }))
    .expect("seal completion wire");
    complete_as_owner(&fixture.vault, &owner_proof(fixture), &request)
        .expect("the owner attests the independent recheck");
}

// --- the owner ---------------------------------------------------------------------

#[test]
fn the_owner_records_a_verdict_on_a_critique_and_its_critic_cell_counts_it() -> TestResult {
    let fixture = rooted_vault();
    let target = put_target(&fixture, "alpha beta gamma");
    let owner = Critic {
        actor: fixture.owner,
        class: EdgeActorClass::Human,
    };
    let result = review(
        &fixture,
        &Review {
            critic: owner,
            target,
            text: "alpha beta gamma",
            run: "owner-review-1",
            a: REVISE,
            b: ACCEPT,
        },
    );
    let artifact = artifact_of(&result, "lens_a");
    let memory = owner_memory(&fixture);

    let held = outcome_call(&memory, &result, target, &artifact, owner_verdict(true))?;
    assert_eq!(held["outcome"]["source"], "owner_verdict", "{held}");
    assert_eq!(held["outcome"]["accepted"], true, "{held}");
    assert_eq!(held["artifact_id"], artifact.as_str(), "{held}");
    assert_eq!(
        held["calibration_receipt"],
        receipt_of(&result, &artifact),
        "{held}"
    );
    assert_eq!(
        held["evidence"]["anchor"],
        anchor_json(Anchor::OwnerVerdict),
        "{held}"
    );
    assert_eq!(
        held["evidence"]["observation"],
        success_json(true),
        "{held}"
    );
    assert!(
        held.get("grant_ref").is_none(),
        "the owner acts on no Grant: {held}"
    );

    let replay = outcome_call(&memory, &result, target, &artifact, owner_verdict(true))?;
    assert_eq!(
        replay["outcome_ref"], held["outcome_ref"],
        "the same verdict again keeps the standing outcome"
    );

    let overruled = outcome_call(&memory, &result, target, &artifact, owner_verdict(false))?;
    assert_ne!(
        overruled["outcome_ref"], held["outcome_ref"],
        "another verdict supersedes the standing outcome"
    );
    assert_eq!(
        overruled["evidence"]["observation"],
        success_json(false),
        "{overruled}"
    );
    Ok(())
}

#[test]
fn findings_show_one_reviews_outcomes_and_only_its_evidence_in_a_shared_cell() -> TestResult {
    let fixture = rooted_vault();
    let target = put_target(&fixture, "alpha beta gamma");
    let owner = Critic {
        actor: fixture.owner,
        class: EdgeActorClass::Human,
    };
    let spec = |run| Review {
        critic: owner,
        target,
        text: "alpha beta gamma",
        run,
        a: REVISE,
        b: ACCEPT,
    };
    let first = review(&fixture, &spec("owner-review-1"));
    let second = review(&fixture, &spec("owner-review-2"));
    let memory = owner_memory(&fixture);
    let first_a = artifact_of(&first, "lens_a");
    let second_a = artifact_of(&second, "lens_a");
    outcome_call(&memory, &first, target, &first_a, owner_verdict(true))?;
    outcome_call(&memory, &second, target, &second_a, owner_verdict(false))?;

    let findings = findings_call(&memory, &first, target)?;
    assert_eq!(
        findings["review"]["verdict_claim_ref"],
        first.verdict_claim.to_hex(),
        "{findings}"
    );
    assert_eq!(findings["target_ref"], target.to_hex(), "{findings}");
    assert_eq!(
        findings["session_ref"],
        fixture.session.to_hex(),
        "{findings}"
    );
    let outcomes = findings["outcomes"].as_array().expect("outcomes");
    assert_eq!(
        outcomes.len(),
        1,
        "only lens a's critique has an outcome: {findings}"
    );
    assert_eq!(outcomes[0]["artifact_id"], first_a.as_str(), "{findings}");
    assert_eq!(outcomes[0]["outcome"]["accepted"], true, "{findings}");

    let receipt = receipt_of(&first, &first_a);
    let cell_a = cell_of(&findings, &first_a);
    assert_eq!(evidence_receipts(cell_a), vec![receipt.clone()], "{cell_a}");
    assert_eq!(
        cell_a["undisclosed_evidence"], 1,
        "the other review's evidence in the shared cell is counted, not shown: {cell_a}"
    );
    assert_eq!(
        cell_a["cell"]["view"]["attributed_outcome_receipts"],
        json!([receipt]),
        "{cell_a}"
    );
    for head in cell_a["cell"]["view"]["provenance"]["heads"]
        .as_array()
        .expect("heads")
    {
        for cited in head["evidence_receipts"].as_array().expect("citations") {
            assert_eq!(
                cited,
                &json!(receipt),
                "a head cites only this review: {cell_a}"
            );
        }
    }
    let cell_b = cell_of(&findings, &artifact_of(&first, "lens_b"));
    assert!(
        evidence_receipts(cell_b).is_empty(),
        "lens b holds no evidence: {cell_b}"
    );

    let wire = findings.to_string();
    assert!(
        !wire.contains(&second.verdict_claim.to_hex()),
        "nothing of the other review is shown: {wire}"
    );
    Ok(())
}

// --- an agent's admission ----------------------------------------------------------

#[test]
fn an_agent_reads_only_a_review_it_wrote_on_a_grant_naming_the_verb() -> TestResult {
    let fixture = rooted_vault();
    let target = put_target(&fixture, "alpha beta gamma");
    let (critic, grant) = critic_agent(&fixture, "critic-outcome-reader", &[FINDINGS]);
    let (bystander, _) = critic_agent(&fixture, "critic-outcome-bystander", &[]);
    let own = review(
        &fixture,
        &Review {
            critic: Critic {
                actor: critic,
                class: EdgeActorClass::Agent,
            },
            target,
            text: "alpha beta gamma",
            run: "agent-review-1",
            a: REVISE,
            b: ACCEPT,
        },
    );
    let owners = review(
        &fixture,
        &Review {
            critic: Critic {
                actor: fixture.owner,
                class: EdgeActorClass::Human,
            },
            target,
            text: "alpha beta gamma",
            run: "owner-review-1",
            a: REVISE,
            b: ACCEPT,
        },
    );
    let memory = agent_memory(&fixture, critic);

    let findings = findings_call(&memory, &own, target)?;
    assert_eq!(
        findings["review"]["verdict_claim_ref"],
        own.verdict_claim.to_hex(),
        "the agent reads its own review: {findings}"
    );
    assert_code(
        findings_call(&memory, &owners, target),
        MEMORY_CODE_NOT_FOUND,
        "another principal's review answers as a missing one",
    );
    assert_code(
        findings_call(&agent_memory(&fixture, bystander), &own, target),
        MEMORY_CODE_FORBIDDEN,
        "an agent whose Grant does not list the verb is refused",
    );
    revoke_grant(&fixture, grant);
    match findings_call(&memory, &own, target) {
        Ok(value) => panic!("a revoked Grant admits nothing: the call answered {value}"),
        // The row's reference check reads the target with the caller's own key
        // first, and a revoked Grant may read it no more.
        Err(error) => assert!(
            [MEMORY_CODE_FORBIDDEN, "INVENTED_REFERENCE"].contains(&error.code.as_str()),
            "a revoked Grant admits nothing: {error:?}"
        ),
    }
    Ok(())
}

#[test]
fn an_agent_never_states_a_verdict_or_sends_a_success_flag() -> TestResult {
    let fixture = rooted_vault();
    let target = put_target(&fixture, "alpha beta gamma");
    let (critic, _) = critic_agent(&fixture, "critic-outcome-writer", &[OUTCOME, FINDINGS]);
    let own = review(
        &fixture,
        &Review {
            critic: Critic {
                actor: critic,
                class: EdgeActorClass::Agent,
            },
            target,
            text: "alpha beta gamma",
            run: "agent-review-1",
            a: REVISE,
            b: ACCEPT,
        },
    );
    let artifact = artifact_of(&own, "lens_a");
    let memory = agent_memory(&fixture, critic);

    assert_code(
        outcome_call(&memory, &own, target, &artifact, owner_verdict(true)),
        MEMORY_CODE_FORBIDDEN,
        "an owner verdict is the owner's own act",
    );
    let forged = json!({
        "kind": "seal_recheck",
        "attempt_ref": attempt_hex(AttemptId::now()),
        "accepted": true,
    });
    assert_code(
        outcome_call(&memory, &own, target, &artifact, forged),
        MEMORY_CODE_BAD_REQUEST,
        "a success flag is no field of a recheck anchor",
    );
    assert_code(
        outcome_call(
            &memory,
            &own,
            target,
            &artifact,
            seal_recheck(AttemptId::now()),
        ),
        MEMORY_CODE_NOT_FOUND,
        "a try that was never sealed settles nothing",
    );
    let findings = findings_call(&memory, &own, target)?;
    assert_eq!(
        findings["outcomes"],
        json!([]),
        "no refused call left an outcome: {findings}"
    );
    Ok(())
}

// --- a recheck settles an agent's critiques -----------------------------------------

#[test]
fn an_agent_settles_its_critiques_from_a_completed_recheck_that_found_a_flaw() -> TestResult {
    let fixture = rooted_vault();
    let executor = executor_agent(&fixture);
    let text = "a summary of the week";
    let (attempt, result) = completed_try(&fixture, executor, text);
    let (critic, grant) = critic_agent(&fixture, "critic-outcome-settler", &[OUTCOME, FINDINGS]);
    let agent = Critic {
        actor: critic,
        class: EdgeActorClass::Agent,
    };
    let spec = |run| Review {
        critic: agent,
        target: result,
        text,
        run,
        a: ACCEPT,
        b: REVISE,
    };
    let own = review(&fixture, &spec("agent-review-1"));
    let asked_at = confess(&fixture, attempt, executor, &[(OBJECTIVE, true)]);
    complete_recheck(&fixture, attempt, asked_at, &[(OBJECTIVE, true)]);
    let memory = agent_memory(&fixture, critic);
    let accepting = artifact_of(&own, "lens_a");
    let revising = artifact_of(&own, "lens_b");

    let missed = outcome_call(&memory, &own, result, &accepting, seal_recheck(attempt))?;
    assert_eq!(missed["outcome"]["source"], "seal_recheck", "{missed}");
    assert_eq!(
        missed["outcome"]["accepted"], false,
        "an accept missed the flaw: {missed}"
    );
    assert_eq!(
        missed["outcome"]["seal_attempt_ref"],
        attempt_hex(attempt),
        "{missed}"
    );
    assert_eq!(missed["grant_ref"], grant.to_hex(), "{missed}");
    assert_eq!(
        missed["evidence"]["anchor"],
        anchor_json(Anchor::Audit { rate: 1.0 }),
        "{missed}"
    );
    assert_eq!(
        missed["evidence"]["observation"],
        success_json(false),
        "{missed}"
    );
    assert_eq!(
        missed["evidence"]["judge"], JUDGE_MODEL,
        "the evidence carries the recheck's judge: {missed}"
    );
    assert_eq!(
        missed["evidence"]["at"], asked_at,
        "the evidence is dated when the recheck checked: {missed}"
    );

    let caught = outcome_call(&memory, &own, result, &revising, seal_recheck(attempt))?;
    assert_eq!(
        caught["outcome"]["accepted"], true,
        "a revise caught the flaw: {caught}"
    );

    let replay = outcome_call(&memory, &own, result, &accepting, seal_recheck(attempt))?;
    assert_eq!(
        replay["outcome_ref"], missed["outcome_ref"],
        "the same recheck again keeps the standing outcome"
    );

    let again = review(&fixture, &spec("agent-review-2"));
    assert_code(
        outcome_call(
            &memory,
            &again,
            result,
            &artifact_of(&again, "lens_a"),
            seal_recheck(attempt),
        ),
        MEMORY_CODE_INVALID_STATE,
        "one recheck is one observation of a critic cell",
    );

    let findings = findings_call(&memory, &own, result)?;
    let outcomes = findings["outcomes"].as_array().expect("outcomes");
    assert_eq!(
        outcomes.len(),
        2,
        "both critiques stand settled: {findings}"
    );
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome["outcome"]["source"] == "seal_recheck"),
        "{findings}"
    );

    let owner = outcome_call(
        &owner_memory(&fixture),
        &own,
        result,
        &accepting,
        owner_verdict(true),
    )?;
    assert_ne!(owner["outcome_ref"], missed["outcome_ref"], "{owner}");
    assert_eq!(
        owner["evidence"]["anchor"],
        anchor_json(Anchor::OwnerVerdict),
        "a later owner verdict replaces the recheck's evidence: {owner}"
    );
    Ok(())
}

#[test]
fn a_clear_recheck_of_every_confessed_objective_settles_both_ways() -> TestResult {
    let fixture = rooted_vault();
    let executor = executor_agent(&fixture);
    let text = "a summary of the week";
    let (attempt, result) = completed_try(&fixture, executor, text);
    let (critic, _) = critic_agent(&fixture, "critic-outcome-clear", &[OUTCOME]);
    let own = review(
        &fixture,
        &Review {
            critic: Critic {
                actor: critic,
                class: EdgeActorClass::Agent,
            },
            target: result,
            text,
            run: "agent-review-1",
            a: ACCEPT,
            b: REVISE,
        },
    );
    let asked_at = confess(&fixture, attempt, executor, &[(OBJECTIVE, true)]);
    complete_recheck(&fixture, attempt, asked_at, &[(OBJECTIVE, false)]);
    let memory = agent_memory(&fixture, critic);

    let upheld = outcome_call(
        &memory,
        &own,
        result,
        &artifact_of(&own, "lens_a"),
        seal_recheck(attempt),
    )?;
    assert_eq!(
        upheld["outcome"]["accepted"], true,
        "an accept of a clear result held: {upheld}"
    );
    let alarm = outcome_call(
        &memory,
        &own,
        result,
        &artifact_of(&own, "lens_b"),
        seal_recheck(attempt),
    )?;
    assert_eq!(
        alarm["outcome"]["accepted"], false,
        "a revise of a clear result did not: {alarm}"
    );
    Ok(())
}

#[test]
fn a_recheck_that_settles_nothing_is_refused() -> TestResult {
    let fixture = rooted_vault();
    let executor = executor_agent(&fixture);
    let text = "a summary of the week";
    let (attempt, result) = completed_try(&fixture, executor, text);
    let (critic, _) = critic_agent(&fixture, "critic-outcome-refused", &[OUTCOME, FINDINGS]);
    let agent = Critic {
        actor: critic,
        class: EdgeActorClass::Agent,
    };
    let own = review(
        &fixture,
        &Review {
            critic: agent,
            target: result,
            text,
            run: "agent-review-1",
            a: ACCEPT,
            b: REVISE,
        },
    );
    let elsewhere = put_target(&fixture, "another text");
    let other = review(
        &fixture,
        &Review {
            critic: agent,
            target: elsewhere,
            text: "another text",
            run: "agent-review-2",
            a: ACCEPT,
            b: REVISE,
        },
    );
    let memory = agent_memory(&fixture, critic);
    let artifact = artifact_of(&own, "lens_a");
    let asked_at = confess(
        &fixture,
        attempt,
        executor,
        &[(OBJECTIVE, true), (SECOND_OBJECTIVE, false)],
    );

    assert_code(
        outcome_call(&memory, &own, result, &artifact, seal_recheck(attempt)),
        MEMORY_CODE_INVALID_STATE,
        "a recheck still pending settles nothing",
    );
    complete_recheck(&fixture, attempt, asked_at, &[(OBJECTIVE, false)]);
    assert_code(
        outcome_call(&memory, &own, result, &artifact, seal_recheck(attempt)),
        MEMORY_CODE_INVALID_STATE,
        "a clear recheck of part of the confession settles no critique",
    );
    assert_code(
        outcome_call(
            &memory,
            &other,
            elsewhere,
            &artifact_of(&other, "lens_a"),
            seal_recheck(attempt),
        ),
        MEMORY_CODE_INVALID_STATE,
        "a recheck of another result settles no critique of this one",
    );
    let findings = findings_call(&memory, &own, result)?;
    assert_eq!(
        findings["outcomes"],
        json!([]),
        "nothing was recorded: {findings}"
    );
    Ok(())
}
