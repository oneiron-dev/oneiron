//! Plan mode: the owner sets each agent's plan mode.
//!
//! Canon (agent-runtime-v1.md, "Plan mode reuses built review parts"):
//! "Per-agent plan_mode: required | optional | off". Engine ruling SETTING = A
//! (Fri 13 Nov 03:05): the mode is the owner's authority, set only by
//! `vault.agents.plan_mode.set`; `required` refuses a non-owner creator's run
//! without an approved plan, and the owner's own TASK is never refused; `off`
//! refuses a plan that agent proposes; an agent with no row is `optional`.
//!
//! An agent with an owner Grant of base reach posts TASKs for its own
//! definition, as in `plan_mode_run.rs`. The tests set the mode through the
//! verb by name, so on a tree without it each fails at run time as an
//! unknown verb.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test plan_mode_setting`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::{Memory, MemoryResult};
use oneiron::note::{
    PlanDocProposeRequest, PlanDocVerdictRequest, PlanDocView, approve_plan_doc_as,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{TaskCallReceipt, TaskPost};
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const SET: &str = "vault.agents.plan_mode.set";
/// The refusal of a run of a `required` agent that pins no approved plan.
const PLAN_MODE_REQUIRED: &str = "gate.deny.plan_mode.required";
/// The refusal of a plan an `off` agent proposes.
const PLAN_MODE_OFF: &str = "gate.deny.plan_mode.off";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    _dir: tempfile::TempDir,
}

/// A rooted vault whose handle holds the writer lease (the owner verbs
/// answer the embedded owner on it), with its install enrolled, its embedded
/// owner, and an agent definition with an owner Grant of base reach.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("owned vault");
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

/// `memory` sets the agent's plan mode from `expected` to `plan_mode` through
/// the verb, by name.
fn set_mode(
    fixture: &Fixture,
    memory: &Memory<'_>,
    expected: &str,
    plan_mode: &str,
) -> Result<Value, String> {
    oneiron::task_verb::sdk::invoke(
        memory,
        SET,
        json!({
            "agent_def_ref": fixture.agent.to_hex(),
            "expected": expected,
            "plan_mode": plan_mode,
        }),
    )
    .map_err(|error| format!("{error:?}"))
}

/// The owner sets the agent's plan mode from `expected` to `plan_mode`.
fn owner_sets(fixture: &Fixture, expected: &str, plan_mode: &str) {
    let set = set_mode(fixture, &owner(fixture), expected, plan_mode)
        .unwrap_or_else(|error| panic!("the owner sets {plan_mode}: {error}"));
    assert_eq!(
        set.pointer("/plan_mode").and_then(Value::as_str),
        Some(plan_mode),
        "the setter answers the mode it set: {set}"
    );
    assert_eq!(
        set.pointer("/agent_def_ref").and_then(Value::as_str),
        Some(fixture.agent.to_hex().as_str()),
        "the setter answers the agent it set: {set}"
    );
}

/// The agent proposes a plan.
fn propose(memory: &Memory<'_>) -> MemoryResult<PlanDocView> {
    let request: PlanDocProposeRequest = serde_json::from_value(json!({
        "plan": {
            "title": "Tidy the tide log",
            "steps": ["Merge the duplicate dawn readings"],
            "scope_asked": ["notes tagged tide"],
            "budget": 400,
        },
    }))
    .expect("a propose request");
    memory.propose_plan_doc(&request)
}

/// A TASK for the agent's definition whose brief pins `read_first`.
fn run(fixture: &Fixture, key: &str, read_first: &Value) -> TaskPost {
    serde_json::from_value(json!({
        "intent_key": format!("plan-mode/{key}"),
        "assignee": {"agent_def": {"agent_def_ref": fixture.agent.to_hex()}},
        "brief": {
            "schema": 1,
            "type_ref": {"node_id": EntityId::now().to_hex(), "tree_version": 1},
            "objective": "Tidy the tide log",
            "intent": {"need": "Tidy the tide log", "care": "light"},
            "context": {"read_first": read_first},
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

/// The read-first pin of plan-doc `plan` at its revision.
fn plan_pin(plan: &PlanDocView) -> Value {
    json!([{"target": plan.plan_ref.to_hex(), "digest": plan.revision}])
}

fn assert_refused<T: std::fmt::Debug>(result: Result<T, String>, reason: &str, why: &str) {
    match result {
        Err(error) if error.contains(reason) => {}
        other => panic!("{why}: expected {reason}, got {other:?}"),
    }
}

fn post(memory: &Memory<'_>, run: TaskPost) -> Result<TaskCallReceipt, String> {
    memory.tasks_post(run).map_err(|error| format!("{error:?}"))
}

#[test]
fn a_required_agent_is_refused_a_run_without_an_approved_plan() {
    let fixture = fixture();
    owner_sets(&fixture, "optional", "required");
    assert_refused(
        post(&agent(&fixture), run(&fixture, "unplanned", &json!([]))),
        PLAN_MODE_REQUIRED,
        "a required agent's run that pins no plan",
    );
    let plan = propose(&agent(&fixture)).expect("a required agent proposes its plan");
    assert!(
        post(
            &agent(&fixture),
            run(&fixture, "in-review", &plan_pin(&plan))
        )
        .is_err(),
        "a plan in review admits no run"
    );
    approve_plan_doc_as(
        &fixture.vault,
        &owner_proof(&fixture),
        PlanDocVerdictRequest {
            plan_ref: plan.plan_ref,
            expected_revision: plan.revision.clone(),
        },
    )
    .expect("the owner approves the plan");
    post(
        &agent(&fixture),
        run(&fixture, "approved", &plan_pin(&plan)),
    )
    .expect("the approved plan admits the run");
}

#[test]
fn the_owners_task_for_a_required_agent_is_not_gated() {
    let fixture = fixture();
    owner_sets(&fixture, "optional", "required");
    post(&owner(&fixture), run(&fixture, "owner", &json!([])))
        .expect("the owner's own TASK for a required agent is never refused");
}

#[test]
fn an_off_agent_cannot_propose() {
    let fixture = fixture();
    owner_sets(&fixture, "optional", "off");
    assert_refused(
        propose(&agent(&fixture)).map_err(|error| format!("{error:?}")),
        PLAN_MODE_OFF,
        "an off agent's plan",
    );
    owner_sets(&fixture, "off", "optional");
    propose(&agent(&fixture)).expect("an optional agent proposes its plan");
}

#[test]
fn only_the_owner_sets_the_mode_and_only_from_the_mode_it_has() {
    let fixture = fixture();
    assert!(
        set_mode(&fixture, &agent(&fixture), "optional", "off").is_err(),
        "an agent sets no plan mode, its own included"
    );
    assert!(
        set_mode(&fixture, &owner(&fixture), "required", "off").is_err(),
        "a set from a mode the agent does not have is refused"
    );
    // No row reads optional, and the refused sets above changed nothing.
    owner_sets(&fixture, "optional", "required");
    owner_sets(&fixture, "required", "optional");
}
