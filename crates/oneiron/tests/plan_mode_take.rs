//! Plan mode: an agent's take of a parked post lands no run from a plan the
//! owner rejected after the post parked.
//!
//! A clerk agent posts a TASK for the planner agent's definition whose brief
//! pins the planner's plan at the revision the owner approved. The clerk's
//! ceiling is not Auto, so the post parks and the planner is asked whether to
//! take it; the take's scripted Local rung answers yes. The planner is bound
//! under the host key, so L02's rule proves it as the taker on this rooted
//! vault. In
//! `a_take_after_the_owner_rejects_the_plan_lands_no_run` the owner rejects
//! the plan while the rung is asked, before the take's writer runs. That
//! writer judges the plan again, so no TASK lands and the proposal stays in
//! the owner's tray. On a tree whose settlement does not judge the plan, the
//! take lands its TASK and that test fails. `an_agents_take_lands_the_run_of
//! _an_approved_plan` holds that the same take lands while the plan stays
//! approved. In `a_take_for_an_agent_made_required_lands_no_unplanned_run`
//! the post pins no plan and the owner sets the planner's plan mode to
//! `required` while the rung is asked; the take's writer lands no run.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test plan_mode_take`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use oneiron::agent_def::AgentPlanMode;
use oneiron::authority::{ActSurface, AgentTier, HostSlipIssuer, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::llm::decision::catalogue::TASK_SURFACE;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial,
    DecisionLadder, DecisionProvider, DecisionRung, HumanDecisionQueue, HumanDecisionRequest,
    ProviderDecision, ProviderPin,
};
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::note::{
    PlanDocProposeRequest, PlanDocRequest, PlanDocState, PlanDocVerdictRequest, PlanDocView,
    approve_plan_doc_as, reject_plan_doc_as,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{
    TaskCall, TaskCallReceipt, TaskDecisions, TaskHandle, TaskOutcome, TaskPost, TaskVia,
};
use oneiron::test_doors::authority_view_grant::bind_agent;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

/// The reason a refused take leaves on its proposal.
const TAKE_REFUSED: &str = "tasks.take.refused";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// The agent the TASK is for: it proposed the plan and takes the post.
    planner: EntityId,
    /// The agent that posts the TASK.
    clerk: EntityId,
    issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

/// A rooted vault with its install enrolled, its embedded owner, and two
/// agent definitions, each with an owner Grant of base reach.
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
    let planner = define_agent(&vault, "tide-planner").expect("planner agent");
    let clerk = define_agent(&vault, "tide-clerk").expect("clerk agent");
    let fixture = Fixture {
        vault,
        owner,
        planner,
        clerk,
        issuer,
        _dir: dir,
    };
    grant_base_reach(&fixture, fixture.planner);
    grant_base_reach(&fixture, fixture.clerk);
    fixture
}

fn owner_proof(vault: &Vault, owner: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn grant_base_reach(fixture: &Fixture, agent: EntityId) {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof(&fixture.vault, fixture.owner),
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner grants the agent base reach");
    assert!(minted.grant.confers, "the grant confers");
}

/// Binds the planner under the host key: L02's rule proves a taker by its
/// authority binding on a rooted vault. The binder rebinds the host key away
/// from the embedded owner, so the owner's Grants, the plan and its approval
/// come first.
fn bind_planner(fixture: &Fixture) {
    bind_agent(&fixture.vault, &fixture.issuer, fixture.planner)
        .expect("the planner is bound under the host key");
}

/// The planner's plan: two steps, one asked scope, a budget, and no agent
/// named to run it.
fn propose_request() -> PlanDocProposeRequest {
    serde_json::from_value(json!({
        "plan": {
            "title": "Tidy the tide log",
            "steps": [
                "Read the last week of tide entries",
                "Merge the duplicate dawn readings",
            ],
            "scope_asked": ["notes tagged tide"],
            "budget": 400,
        },
    }))
    .expect("a plan-doc propose request")
}

/// The planner proposes its plan and the owner approves the revision read;
/// returns the plan-doc's view as proposed.
fn approved_plan(fixture: &Fixture) -> PlanDocView {
    let plan = fixture
        .vault
        .memory(fixture.planner, EdgeActorClass::Agent)
        .propose_plan_doc(&propose_request())
        .expect("the planner proposes its plan");
    approve_plan_doc_as(
        &fixture.vault,
        &owner_proof(&fixture.vault, fixture.owner),
        PlanDocVerdictRequest {
            plan_ref: plan.plan_ref,
            expected_revision: plan.revision.clone(),
        },
    )
    .expect("the owner approves the revision read");
    assert_eq!(state(fixture, plan.plan_ref), PlanDocState::Approved);
    plan
}

/// Plan-doc `plan`'s state as the owner reads it now.
fn state(fixture: &Fixture, plan: EntityId) -> PlanDocState {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .read_plan_doc(&PlanDocRequest { plan_ref: plan })
        .expect("the owner reads the plan")
        .value
        .expect("the plan-doc")
        .state
}

/// A TASK for the planner's definition whose brief pins plan-doc `plan` at
/// `revision` (64 hex) as its read-first context.
fn plan_run(fixture: &Fixture, plan: EntityId, revision: &str) -> TaskPost {
    run(
        fixture,
        &json!([{"target": plan.to_hex(), "digest": revision}]),
    )
}

/// A TASK for the planner's definition whose brief's read-first context is
/// `read_first`.
fn run(fixture: &Fixture, read_first: &Value) -> TaskPost {
    serde_json::from_value(json!({
        "intent_key": "plan-take/tide",
        "assignee": {"agent_def": {"agent_def_ref": fixture.planner.to_hex()}},
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

/// An owner's act that lands while the planner is asked.
type Interject<'a> = Box<dyn Fn() + Send + Sync + 'a>;

/// The take's Local rung: it answers yes, after `interject`.
struct TakeRung<'a> {
    interject: Option<Interject<'a>>,
    asked: AtomicUsize,
}

impl DecisionProvider for TakeRung<'_> {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "plan-take-fixture".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if let Some(interject) = &self.interject {
            interject();
        }
        Ok(ProviderDecision {
            answer: DecisionAnswer::Noul(true),
            probability: Some(0.95),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> oneiron::Result<()> {
        Err(oneiron::Error::InvalidConfig(
            "the plan take fixture queues no person ask".into(),
        ))
    }
}

/// The clerk posts `post` under a decision path whose only rung is `rung`.
fn post_with_take(fixture: &Fixture, rung: &TakeRung<'_>, post: TaskPost) -> TaskCallReceipt {
    let question = |which: &[u8], wording: &str| {
        TASK_SURFACE
            .question(&[which], wording.to_owned(), AnswerContract::Noul)
            .expect("a task surface question")
    };
    let decisions = TaskDecisions {
        ladder: DecisionLadder {
            rule: None,
            local: Some(rung),
            system_one: None,
            escalation: None,
            big: None,
            human: &NoPerson,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "plan-take-queue".into(),
                version: "1".into(),
            },
            ask_to: None,
            paired: None,
            person: None,
            presence: None,
            correlation: None,
        },
        dial: DecisionDial {
            first: DecisionRung::Local,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        take: question(
            b"take".as_slice(),
            "Should this agent take the proposed task?",
        ),
        done: question(
            b"done_met".as_slice(),
            "Does the result meet what done means?",
        ),
        ask_up: question(b"ask_up".as_slice(), "Should this be asked up now?"),
        budget: Duration::from_secs(3600),
    };
    fixture
        .vault
        .memory(fixture.clerk, EdgeActorClass::Agent)
        .tasks_highway_with_decisions(TaskVia::Wire, TaskCall::Post(post), Some(&decisions))
        .expect("the clerk's post parks and the planner is asked")
}

fn lifecycle_field<'a>(receipt: &'a TaskCallReceipt, key: &str) -> Option<&'a str> {
    receipt
        .lifecycle
        .as_ref()
        .and_then(|lifecycle| lifecycle.fields.get(key))
        .map(String::as_str)
}

fn landed_task(receipt: &TaskCallReceipt) -> Option<EntityId> {
    receipt.related.iter().find_map(|handle| match handle {
        TaskHandle::Task { task_ref } => Some(*task_ref),
        _ => None,
    })
}

#[test]
fn an_agents_take_lands_the_run_of_an_approved_plan() {
    let fixture = fixture();
    let plan = approved_plan(&fixture);
    bind_planner(&fixture);
    let rung = TakeRung {
        interject: None,
        asked: AtomicUsize::new(0),
    };
    let receipt = post_with_take(
        &fixture,
        &rung,
        plan_run(&fixture, plan.plan_ref, &plan.revision),
    );
    assert_eq!(
        rung.asked.load(Ordering::SeqCst),
        1,
        "the planner is asked once"
    );
    assert_eq!(
        lifecycle_field(&receipt, "take"),
        Some("yes"),
        "{receipt:?}"
    );
    assert!(
        matches!(receipt.outcome, TaskOutcome::Created { .. }),
        "the take of an approved plan's run lands its TASK: {receipt:?}"
    );
    assert!(landed_task(&receipt).is_some(), "{receipt:?}");
}

#[test]
fn a_take_after_the_owner_rejects_the_plan_lands_no_run() {
    let fixture = fixture();
    let plan = approved_plan(&fixture);
    bind_planner(&fixture);
    let (vault, owner, plan_ref) = (&fixture.vault, fixture.owner, plan.plan_ref);
    let revision = plan.revision.clone();
    let rung = TakeRung {
        interject: Some(Box::new(move || {
            reject_plan_doc_as(
                vault,
                &owner_proof(vault, owner),
                PlanDocVerdictRequest {
                    plan_ref,
                    expected_revision: revision.clone(),
                },
            )
            .expect("the owner rejects the plan while the planner is asked");
        })),
        asked: AtomicUsize::new(0),
    };
    let receipt = post_with_take(
        &fixture,
        &rung,
        plan_run(&fixture, plan.plan_ref, &plan.revision),
    );
    assert_eq!(
        rung.asked.load(Ordering::SeqCst),
        1,
        "the planner is asked once"
    );
    assert_eq!(
        state(&fixture, plan.plan_ref),
        PlanDocState::Rejected,
        "the owner's rejection landed while the planner was asked"
    );
    assert_eq!(
        lifecycle_field(&receipt, "take"),
        Some("yes"),
        "{receipt:?}"
    );
    assert_take_refused(
        &receipt,
        "a take lands no TASK from a plan the owner rejected",
    );
}

#[test]
fn a_take_for_an_agent_made_required_lands_no_unplanned_run() {
    let fixture = fixture();
    bind_planner(&fixture);
    let (vault, owner, planner) = (&fixture.vault, fixture.owner, fixture.planner);
    let rung = TakeRung {
        interject: Some(Box::new(move || {
            vault
                .set_agent_plan_mode_as(
                    &owner_proof(vault, owner),
                    planner,
                    AgentPlanMode::Optional,
                    AgentPlanMode::Required,
                )
                .expect("the owner makes the planner's plan mode required while it is asked");
        })),
        asked: AtomicUsize::new(0),
    };
    let receipt = post_with_take(&fixture, &rung, run(&fixture, &json!([])));
    assert_eq!(
        rung.asked.load(Ordering::SeqCst),
        1,
        "the planner is asked once"
    );
    assert_eq!(
        lifecycle_field(&receipt, "take"),
        Some("yes"),
        "{receipt:?}"
    );
    assert_take_refused(
        &receipt,
        "a take lands no unplanned run of an agent whose plan mode turned required",
    );
}

/// Holds that `receipt` is a take refused in its writer by plan mode, not by
/// L02's rule: no TASK landed and the proposal stays in the owner's tray.
fn assert_take_refused(receipt: &TaskCallReceipt, why: &str) {
    assert!(landed_task(receipt).is_none(), "{why}: {receipt:?}");
    match &receipt.outcome {
        TaskOutcome::Proposed { reason_codes, .. } => assert!(
            reason_codes.iter().any(|code| code == TAKE_REFUSED),
            "{why}: the take is refused and the proposal stays in the owner's tray: {receipt:?}"
        ),
        other => panic!("{why}: expected the parked proposal, got {other:?}"),
    }
    let refused = lifecycle_field(receipt, "take_refused");
    assert!(refused.is_some(), "{why}: {receipt:?}");
    assert_ne!(
        refused,
        Some(MEMORY_CODE_FORBIDDEN),
        "{why}: plan mode refuses the take, not L02's rule: {receipt:?}"
    );
}
