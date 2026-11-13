//! Plan mode: a run starts from a plan only at the revision the owner approved.
//!
//! Canon (agent-runtime-v1.md, "Plan mode reuses built review parts"): plan
//! mode is propose-only execution, a plan-doc NOTE, comment review and
//! "execute-on-approve through the gate". The census row (UNBUILT Top 15,
//! item 4): "a run started from a plan carries the approved revision's hash,
//! and an edit after approval reopens review". Engine ruling RUN = A (Fri 13
//! Nov 03:05): a plan-doc pin's digest is the plan's revision, and a
//! `tasks.create` that pins a plan-doc is refused unless the owner approved
//! the plan at the pinned revision; the owner's own `tasks.create` is never
//! refused.
//!
//! An agent with an owner Grant of base reach proposes a plan, then posts a
//! TASK whose brief pins the plan in its read-first context. On a tree where
//! a plan-doc pin digests the NOTE's stored row, each post that pins the
//! revision is refused as a moved pin, so every test here fails there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test plan_mode_run`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::note::{
    NoteProgramEdit, PlanDocProposeRequest, PlanDocRequest, PlanDocSettlementView, PlanDocState,
    PlanDocVerdictRequest, PlanDocView, approve_plan_doc_as, reject_plan_doc_as,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{
    QueueTaskBrief, TaskCallReceipt, TaskHandle, TaskOutcome, TaskPost, TaskStatusQuery,
    brief_digest, task_confession_objectives,
};
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

/// The refusal a post meets when it pins a plan the owner has not approved
/// at the pinned revision.
const PLAN_NOT_APPROVED: &str = "gate.plan_not_approved";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    _dir: tempfile::TempDir,
}

/// A rooted vault with its install enrolled, its embedded owner, and an agent
/// definition with an owner Grant of base reach: the brief's reference check
/// reads the pinned plan with the poster's own key.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
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
    let agent = define_agent(&vault, "tide-planner").expect("agent");
    let fixture = Fixture {
        vault,
        owner,
        agent,
        _dir: dir,
    };
    grant_base_reach(&fixture);
    fixture
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

fn grant_base_reach(fixture: &Fixture) {
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
            agent: fixture.agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner grants the agent base reach");
    assert!(minted.grant.confers, "the grant confers");
}

fn agent(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.agent, EdgeActorClass::Agent)
}

fn owner(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

const TITLE: &str = "Tidy the tide log";
const STEPS: [&str; 2] = [
    "Read the last week of tide entries",
    "Merge the duplicate dawn readings",
];
const SCOPE: &str = "notes tagged tide";
const BUDGET: u64 = 400;

/// The agent's propose request, with `extra` fields beside the plan. Built
/// from JSON, so it reads on a tree whose request lacks a field it names.
fn propose_request(extra: Value) -> PlanDocProposeRequest {
    let mut request = json!({
        "plan": {"title": TITLE, "steps": STEPS, "scope_asked": [SCOPE], "budget": BUDGET},
    });
    if let (Some(fields), Value::Object(extra)) = (request.as_object_mut(), extra) {
        fields.extend(extra);
    }
    serde_json::from_value(request).expect("a propose request")
}

/// The agent proposes its plan; returns the plan-doc's view.
fn propose(fixture: &Fixture) -> PlanDocView {
    agent(fixture)
        .propose_plan_doc(&propose_request(json!({})))
        .expect("the agent proposes its plan")
}

/// The agent proposes its plan naming agent definition `runner` to run it.
fn propose_run_by(fixture: &Fixture, runner: EntityId) -> MemoryResult<PlanDocView> {
    agent(fixture).propose_plan_doc(&propose_request(json!({"agent_def_ref": runner.to_hex()})))
}

/// Plan-doc `plan` as the owner reads it now.
fn read(fixture: &Fixture, plan: EntityId) -> PlanDocView {
    owner(fixture)
        .read_plan_doc(&PlanDocRequest { plan_ref: plan })
        .expect("the owner reads the plan")
        .value
        .expect("the plan-doc")
}

fn verdict(plan: EntityId, revision: &str) -> PlanDocVerdictRequest {
    PlanDocVerdictRequest {
        plan_ref: plan,
        expected_revision: revision.to_owned(),
    }
}

fn approve(fixture: &Fixture, plan: EntityId, revision: &str) -> PlanDocSettlementView {
    approve_plan_doc_as(
        &fixture.vault,
        &owner_proof(fixture),
        verdict(plan, revision),
    )
    .expect("the owner approves the revision read")
}

fn reject(fixture: &Fixture, plan: EntityId, revision: &str) -> PlanDocSettlementView {
    reject_plan_doc_as(
        &fixture.vault,
        &owner_proof(fixture),
        verdict(plan, revision),
    )
    .expect("the owner rejects the revision read")
}

/// The run a verdict landed, read from its wire shape: `Err` when the
/// settlement names no run field at all.
fn run_of(settled: &PlanDocSettlementView) -> Result<Option<EntityId>, String> {
    let wire = serde_json::to_value(settled).expect("a settlement encodes");
    match wire.get("run_task_ref") {
        None => Err(format!("the settlement names no run: {wire}")),
        Some(Value::Null) => Ok(None),
        Some(run) => Ok(Some(
            serde_json::from_value(run.clone()).expect("a run TASK id"),
        )),
    }
}

/// The owner's edit that appends a line to plan-doc `plan`.
fn edit(fixture: &Fixture, plan: EntityId) {
    let doc = fixture
        .vault
        .note_program_document(plan)
        .expect("read the document")
        .expect("the plan-doc's document");
    let edit = NoteProgramEdit::InsertAfter {
        anchor: doc
            .anchor(doc.text().chars().count())
            .expect("the end anchor"),
        text: "\nOne more pass at dusk.\n".to_owned(),
    };
    fixture
        .vault
        .edit_note(
            plan,
            &edit,
            WriteActor::new(fixture.owner, EdgeActorClass::Human),
        )
        .expect("the owner's edit lands");
}

/// A TASK for the agent's definition whose brief pins plan-doc `plan` at
/// `digest` (64 hex) as its read-first context.
fn plan_run(fixture: &Fixture, key: &str, plan: EntityId, digest: &str) -> TaskPost {
    serde_json::from_value(json!({
        "intent_key": format!("plan-run/{key}"),
        "assignee": {"agent_def": {"agent_def_ref": fixture.agent.to_hex()}},
        "brief": {
            "schema": 1,
            "type_ref": {"node_id": EntityId::now().to_hex(), "tree_version": 1},
            "objective": "Tidy the tide log",
            "intent": {"need": "Tidy the tide log", "care": "light"},
            "context": {"read_first": [{"target": plan.to_hex(), "digest": digest}]},
            "success": {
                "question": "Is the tide log tidy?",
                "criteria": {"yes_if_all": [{"text": "The duplicate dawn readings are merged."}]},
            },
            "settled": [],
            "escalation": {
                "to": {"people": [fixture.owner.to_hex()]},
                "triggers": [],
                "default": "proceed",
                "reversibility": "reversible_read",
            },
        },
    }))
    .expect("a task post")
}

fn post(memory: &Memory<'_>, run: TaskPost) -> MemoryResult<TaskCallReceipt> {
    memory.tasks_post(run)
}

/// Holds that `result` is the refusal of a plan the owner has not approved
/// at the pinned revision.
fn assert_plan_refusal(result: MemoryResult<TaskCallReceipt>, why: &str) {
    match result {
        Err(MemoryError { message, .. }) if message.contains(PLAN_NOT_APPROVED) => {}
        other => panic!("{why}: expected {PLAN_NOT_APPROVED}, got {other:?}"),
    }
}

#[test]
fn a_run_start_is_refused_before_approval() {
    let fixture = fixture();
    let plan = propose(&fixture);
    assert_eq!(plan.state, PlanDocState::InReview);
    let in_review = post(
        &agent(&fixture),
        plan_run(&fixture, "in-review", plan.plan_ref, &plan.revision),
    );
    assert_plan_refusal(in_review, "a plan in review starts no run");
    reject(&fixture, plan.plan_ref, &plan.revision);
    let rejected = post(
        &agent(&fixture),
        plan_run(&fixture, "rejected", plan.plan_ref, &plan.revision),
    );
    assert_plan_refusal(rejected, "a rejected plan starts no run");
}

#[test]
fn approval_admits_the_run_with_the_plan_hash() {
    let fixture = fixture();
    let plan = propose(&fixture);
    approve(&fixture, plan.plan_ref, &plan.revision);
    assert_eq!(read(&fixture, plan.plan_ref).state, PlanDocState::Approved);
    let pin = agent(&fixture)
        .pin_brief_ref(plan.plan_ref)
        .expect("the agent pins the plan");
    let pinned: String = pin
        .digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        pinned, plan.revision,
        "a plan-doc pin carries the plan's revision hash"
    );
    let receipt = post(
        &agent(&fixture),
        plan_run(&fixture, "approved", plan.plan_ref, &plan.revision),
    )
    .expect("an approved plan admits its run");
    assert!(
        !receipt.idempotent_replay,
        "the run is a new post: {receipt:?}"
    );
}

#[test]
fn an_edit_after_approval_refuses_the_run_pin() {
    let fixture = fixture();
    let plan = propose(&fixture);
    approve(&fixture, plan.plan_ref, &plan.revision);
    edit(&fixture, plan.plan_ref);
    let edited = read(&fixture, plan.plan_ref);
    assert_eq!(
        edited.state,
        PlanDocState::InReview,
        "the edit reopened review"
    );
    assert_ne!(edited.revision, plan.revision);
    let stale = post(
        &agent(&fixture),
        plan_run(&fixture, "stale", plan.plan_ref, &plan.revision),
    );
    assert_plan_refusal(stale, "the approved revision is no longer the plan's text");
    let unanswered = post(
        &agent(&fixture),
        plan_run(&fixture, "unanswered", plan.plan_ref, &edited.revision),
    );
    assert_plan_refusal(unanswered, "the edited revision is in review");
    approve(&fixture, plan.plan_ref, &edited.revision);
    post(
        &agent(&fixture),
        plan_run(&fixture, "reapproved", plan.plan_ref, &edited.revision),
    )
    .expect("the owner's approval of the edited revision admits the run");
}

#[test]
fn the_owners_run_needs_no_approval() {
    let fixture = fixture();
    let plan = propose(&fixture);
    assert_eq!(plan.state, PlanDocState::InReview);
    post(
        &owner(&fixture),
        plan_run(&fixture, "owner", plan.plan_ref, &plan.revision),
    )
    .expect("the owner's own TASK is never refused for a plan in review");
}

/// The brief the approval of plan `plan` at `revision` lands, under the
/// type stamp `type_ref` the TASK holds: the plan's title, scope, budget and
/// steps, the plan pinned at the revision, escalating to the owner.
fn expected_run_brief(
    fixture: &Fixture,
    type_ref: Value,
    plan: EntityId,
    revision: &str,
) -> QueueTaskBrief {
    serde_json::from_value(json!({
        "schema": 1,
        "type_ref": type_ref,
        "objective": TITLE,
        "intent": {"need": TITLE},
        "constraints": {"notes": [SCOPE], "pins": {"budget": BUDGET}},
        "context": {"read_first": [{"target": plan.to_hex(), "digest": revision}]},
        "success": {
            "question": format!("Is the approved plan \"{TITLE}\" carried out?"),
            "criteria": {"yes_if_all": STEPS.map(|step| json!({"text": step}))},
        },
        "settled": [],
        "escalation": {
            "to": {"people": [fixture.owner.to_hex()]},
            "triggers": ["blocked", "scope_widen", "spend_over"],
            "default": "hold",
            "reversibility": "reversible_read",
        },
    }))
    .expect("the expected brief")
}

#[test]
fn an_approval_starts_the_named_agents_run_at_the_plan_hash() {
    let fixture = fixture();
    let plan = propose_run_by(&fixture, fixture.agent).expect("the agent proposes its run");
    assert_eq!(plan.state, PlanDocState::InReview);
    let settled = approve(&fixture, plan.plan_ref, &plan.revision);
    let run = run_of(&settled)
        .expect("the settlement reads")
        .expect("the approval starts the plan's run");
    let status = owner(&fixture)
        .tasks_status(TaskStatusQuery {
            handle: TaskHandle::Task { task_ref: run },
            after: None,
        })
        .expect("the owner reads the run's TASK");
    let view = match status.outcome {
        TaskOutcome::Snapshot(view) => view,
        other => panic!("a status read answers a snapshot: {other:?}"),
    };
    let stamp = view.brief_current.expect("the run's TASK holds a brief");
    assert_eq!(stamp.rev, 1);
    let expected = expected_run_brief(
        &fixture,
        serde_json::to_value(stamp.type_ref).expect("the type stamp encodes"),
        plan.plan_ref,
        &plan.revision,
    );
    assert_eq!(
        stamp.digest,
        brief_digest(&expected),
        "the run's brief pins the plan at the approved revision, with its steps and budget"
    );
    let mut objectives = vec![format!("Is the approved plan \"{TITLE}\" carried out?")];
    objectives.extend(STEPS.map(str::to_owned));
    assert_eq!(
        task_confession_objectives(&fixture.vault, run).expect("read the run's objectives"),
        Some(objectives),
    );
}

#[test]
fn a_revision_approved_again_keeps_its_run() {
    let fixture = fixture();
    let plan = propose_run_by(&fixture, fixture.agent).expect("the agent proposes its run");
    let first = run_of(&approve(&fixture, plan.plan_ref, &plan.revision))
        .expect("the settlement reads")
        .expect("the approval starts the plan's run");
    let rejected = run_of(&reject(&fixture, plan.plan_ref, &plan.revision));
    assert_eq!(rejected, Ok(None), "a rejection starts no run");
    let again = run_of(&approve(&fixture, plan.plan_ref, &plan.revision));
    assert_eq!(
        again,
        Ok(Some(first)),
        "the revision approved again keeps its first run"
    );
}

#[test]
fn a_plan_naming_no_agent_definition_starts_no_run() {
    let fixture = fixture();
    let plan = propose(&fixture);
    let settled = approve(&fixture, plan.plan_ref, &plan.revision);
    assert_eq!(run_of(&settled), Ok(None));
}

#[test]
fn a_plan_naming_an_unknown_agent_definition_is_refused() {
    let fixture = fixture();
    let refused = propose_run_by(&fixture, EntityId::now());
    assert!(
        refused.is_err(),
        "a run by no agent definition is refused at propose: {refused:?}"
    );
}
