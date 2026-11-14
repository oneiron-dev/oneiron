//! A composed post waits for a person: no agent takes it (census L8-07,
//! review #7818 P1).
//!
//! Engine ruling 14 Nov 09:11, L8-07-APPROVAL = A: a composed brief always
//! lands as a proposal, whatever the caller's ceiling, because a model wrote
//! its text and no person has read it. A post for an agent's definition by a
//! caller who is not the owner asks that agent whether to take it, and the
//! agent's yes approves the proposal and lands its TASK. For a composed post
//! that yes would start model text no person has read.
//!
//! A clerk agent posts for the planner agent's definition under a decision
//! path whose one Local rung answers yes. The planner is bound under the host
//! key, so L02's rule admits its take on this rooted vault. The test first
//! holds that the planner takes the clerk's written post, so the fixture's
//! take path lands a TASK. Then the clerk's composed one-liner for the same
//! agent is never put to the planner and stays a proposal. On a tree whose
//! post path asks the agent about a composed post, the planner is asked a
//! second time and the test fails.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test tasks_composed_post_waits_for_a_person`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use oneiron::authority::{ActSurface, AgentTier, HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, base_world_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::llm::decision::catalogue::TASK_SURFACE;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial,
    DecisionLadder, DecisionProvider, DecisionRung, HumanDecisionQueue, HumanDecisionRequest,
    ProviderDecision, ProviderPin,
};
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::store::GateDecisionId;
use oneiron::task_type::TaskTypeTree;
use oneiron::task_verb::{TaskCreateReceipt, TaskDecisions};
use oneiron::test_doors::authority_view_grant::bind_agent;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::test_doors::task_brief_compose::{install_scripted_brief_model, parked_post_brief};
use oneiron::verbs::{
    AgentGrantMintRequest, TaskCreateRequest, mint_agent_grant_as, task_create_spec,
};
use oneiron::{EdgeActorClass, EntityId, ModelLocality, Vault, VaultConfig};
use serde_json::{Value, json};

const ONE_LINER: &str = "Find out why the dawn tide readings run high";
const LOCAL_MODEL: &str = "scripted-local-reasoner";
const OBJECTIVE: &str = "Explain the high dawn tide readings";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// The agent the posts are for: it is asked whether to take each.
    planner: EntityId,
    /// The agent that posts them.
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
        },
    )
    .expect("the owner grants the agent base reach");
    assert!(minted.grant.confers, "the grant confers");
}

/// The take's Local rung: it answers yes and counts each ask.
struct TakeRung {
    asked: AtomicUsize,
}

impl DecisionProvider for TakeRung {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "composed-take-fixture".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        self.asked.fetch_add(1, Ordering::SeqCst);
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
            "the composed take fixture queues no person ask".into(),
        ))
    }
}

/// A decision path whose only rung is `rung`.
fn decisions(rung: &TakeRung) -> TaskDecisions<'_> {
    let question = |which: &[u8], wording: &str| {
        TASK_SURFACE
            .question(&[which], wording.to_owned(), AnswerContract::Noul)
            .expect("a task surface question")
    };
    TaskDecisions {
        ladder: DecisionLadder {
            rule: None,
            local: Some(rung),
            system_one: None,
            escalation: None,
            big: None,
            human: &NoPerson,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "composed-take-queue".into(),
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
    }
}

/// The id a brief's `type_ref` names the seeded `research` node by.
fn research_node() -> EntityId {
    TaskTypeTree::seeded()
        .node("research")
        .expect("the seeded research node")
        .entity_id()
        .expect("node id")
}

/// The scripted model's draft.
fn draft() -> String {
    json!({
        "objective": OBJECTIVE,
        "need": "The harbour log's dawn readings disagree with the gauge.",
        "type": "research",
        "notes": ["Read the harbour log before the gauge data."],
        "question": "Is the cause of the high dawn readings found?",
        "yes_if_all": ["The cause is named with the log rows that show it."],
        "no_if_any": []
    })
    .to_string()
}

/// `tasks.create` as its verb row runs it: the request through the verb's
/// own mapping, then the create.
fn create(memory: &Memory<'_>, request: Value) -> MemoryResult<TaskCreateReceipt> {
    let input: TaskCreateRequest = serde_json::from_value(request)
        .map_err(|error| MemoryError::bad_request(format!("request: {error}")))?;
    let spec = task_create_spec(memory, input)?;
    memory.tasks_create(&spec)
}

/// The planner's definition as a post's assignee.
fn for_planner(fixture: &Fixture) -> Value {
    json!({"agent_def": {"agent_def_ref": fixture.planner.to_hex()}})
}

/// A written brief for the planner.
fn written_request(fixture: &Fixture, key: &str) -> Value {
    json!({
        "spec": null,
        "intent_key": key,
        "assignee": for_planner(fixture),
        "brief": {
            "schema": 1,
            "type_ref": {"node_id": research_node().to_hex(), "tree_version": 1},
            "objective": OBJECTIVE,
            "intent": {"need": "The dawn readings disagree with the gauge."},
            "success": {
                "question": "Is the cause of the high dawn readings found?",
                "criteria": {"yes_if_all": [{"text": "The cause is named."}]},
            },
            "settled": [],
            "escalation": {
                "to": {"people": [fixture.owner.to_hex()]},
                "triggers": [],
                "default": "proceed",
                "reversibility": "reversible_read",
            },
        },
    })
}

/// A one-liner for the planner, composed with no lens rows.
fn one_liner_request(fixture: &Fixture, key: &str) -> Value {
    json!({
        "spec": null,
        "intent_key": key,
        "assignee": for_planner(fixture),
        "one_liner": ONE_LINER,
        "lens_refs": [],
    })
}

#[test]
fn an_agent_never_takes_a_composed_post() {
    let fixture = fixture();
    bind_agent(&fixture.vault, &fixture.issuer, fixture.planner)
        .expect("the planner is bound under the host key");
    let model = install_scripted_brief_model(
        &fixture.vault,
        LOCAL_MODEL,
        ModelLocality::OnDevice,
        &draft(),
    );
    let rung = TakeRung {
        asked: AtomicUsize::new(0),
    };
    let clerk = fixture
        .vault
        .memory(fixture.clerk, EdgeActorClass::Agent)
        .with_task_decisions(decisions(&rung));

    let written = match create(&clerk, written_request(&fixture, "dawn-tide/written")) {
        Ok(receipt) => receipt,
        Err(error) => panic!("the clerk's written post lands: {error:?}"),
    };
    assert_eq!(
        rung.asked.load(Ordering::SeqCst),
        1,
        "precondition: the planner is asked to take the clerk's written post: {written:?}"
    );
    assert!(
        written.approval == ClaimApprovalStatus::Approved && written.task_ref.is_some(),
        "precondition: the planner takes the clerk's written post, so the fixture's take \
         path lands a TASK: {written:?}"
    );

    let composed = match create(&clerk, one_liner_request(&fixture, "dawn-tide/composed")) {
        Ok(receipt) => receipt,
        Err(error) => panic!("the clerk's one-liner create composes its brief: {error:?}"),
    };
    assert_eq!(
        model.calls().len(),
        1,
        "precondition: one model call composes the clerk's brief"
    );
    assert_eq!(
        rung.asked.load(Ordering::SeqCst),
        1,
        "no agent is asked to take a composed post: {composed:?}"
    );
    assert_eq!(
        (composed.approval, composed.task_ref),
        (ClaimApprovalStatus::Proposed, None),
        "a composed post stays a proposal for a person to read: {composed:?}"
    );
    let proposal = composed.proposal_ref.expect("the parked proposal");
    assert!(
        parked_post_brief(&fixture.vault, proposal)
            .expect("read the proposal")
            .is_some(),
        "the proposal still holds the composed brief"
    );
}
