//! HOUSE-SOURCE-READ (OF-501; FIX 22357, #6857): the house mind's project
//! question reads the person's turn it is about. The house reads the source
//! MESSAGE under its own agent key and the relationship gate, and a key no
//! scoped grant names reads nothing, so before the house's read row shipped
//! every question settled `Unread` and the host's ladder was never asked.
//!
//! Each case witnesses one owner turn, runs the queued question on a ladder
//! whose one rung counts its calls and answers "no", and reads the outcome:
//! a question that reached the ladder settles `NotAProject`, one whose source
//! the house may not read settles `Unread` with no call. No `cfg` is needed.
//! The bound-house case names the role the house runs its org at, which the
//! bind takes since HOUSE-BIND = A; the other two cases use doors on main.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::agent_dispatch::{AgentDispatcher, ProjectDetection, ProjectDetectionRun};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::FederationGrantRole;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionProvider,
    DecisionRung, HeldLadder, ProviderDecision, ProviderPin,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_ORG;
use oneiron::store::GateDecisionId;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig};

const LEASE_OWNER: &str = "house-source-read-test";
const WORKSPACE: &str = "house-source-read-workspace";

/// The host's Big rung: it answers every question "no", sure of it, and
/// counts each call.
struct CountingDecider {
    calls: AtomicUsize,
}

impl CountingDecider {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl DecisionProvider for CountingDecider {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "house-source-read".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let _ = self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(ProviderDecision {
            answer: DecisionAnswer::Noul(false),
            probability: Some(0.99),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

/// The host's project question over `decider`, its dial at Big, as the host
/// assembles it (`oneiron-server` `ai_host/lifecycle.rs`).
fn detection(decider: &Arc<CountingDecider>) -> ProjectDetection {
    ProjectDetection {
        ladder: HeldLadder {
            big: Some(Arc::clone(decider) as Arc<dyn DecisionProvider>),
            ..HeldLadder::unstaffed()
        },
        dial: DecisionDial {
            first: DecisionRung::Big,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        wording: "Does this sound like a project?".to_owned(),
        budget: Duration::from_secs(30),
    }
}

/// A claim time past every question the turns below queued.
fn claim_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
        + 60
}

/// The owner's on-record turn in a fresh conversation, which queues the
/// house's project question. `metadata` is the MESSAGE's own.
fn owner_turn(vault: &Vault, owner: EntityId, metadata: serde_json::Value) {
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            occurred_at: 1,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "Let's plan the spring garden: the beds, the seeds and a watering rota."
                    .into(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            assertions: Default::default(),
        })
        .expect("the owner's turn lands");
}

/// Runs the oldest queued project question.
fn ask(vault: &Vault, decider: &Arc<CountingDecider>) -> ProjectDetectionRun {
    AgentDispatcher::new(vault)
        .run_project_detection(&detection(decider), LEASE_OWNER, claim_time())
        .expect("the project question runs")
}

#[test]
fn the_seeded_house_reads_the_owners_unscoped_message_on_a_fresh_vault() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let decider = CountingDecider::new();

    owner_turn(&vault, owner, serde_json::json!({}));
    assert_eq!(
        ask(&vault, &decider),
        ProjectDetectionRun::NotAProject,
        "the seeded house (sys.team_lead) reads the owner's unscoped MESSAGE, so the question reaches the ladder"
    );
    assert_eq!(decider.calls(), 1, "the ladder's one rung was asked once");
    Ok(())
}

#[test]
fn a_relationship_scoped_message_stays_withheld_from_the_house() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let decider = CountingDecider::new();

    // The MESSAGE names a relationship the house holds no grant over.
    owner_turn(
        &vault,
        owner,
        serde_json::json!({ "rel": EntityId::now().to_hex() }),
    );
    assert_eq!(
        ask(&vault, &decider),
        ProjectDetectionRun::Unread,
        "the relationship gate withholds a relationship-scoped MESSAGE from the house"
    );
    assert_eq!(
        decider.calls(),
        0,
        "a withheld source is never sent to the ladder"
    );
    Ok(())
}

#[test]
fn after_a_workspace_finish_the_bound_house_reads_the_owners_unscoped_message() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    // A host start: the vault is rooted under the host, the owner bound, and
    // the root takes its first signature (`oneiron-server` `sign_root_project`).
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let signer = vault.owner_project_signer(&issuer)?;
    let root = vault.root_project()?;
    vault.sign_owner_project(&owner_proof, &signer, root)?;

    // The owner's finish of a workspace whose house is a seeded AGENT_DEF
    // other than the root's seeded leader.
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    let org = EntityId::from_bytes([0xB2; 16])?;
    vault.put_entity(
        &org,
        ENTITY_TYPE_ORG,
        TimeRange { start: 1, end: 1 },
        1,
        b"house source read org",
    )?;
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: 41,
        org_ref: org,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault.establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)?;
    vault.bind_workspace_house_leader(
        WORKSPACE,
        FederationGrantRole::Member,
        &owner_proof,
        &signer,
    )?;
    assert_eq!(
        vault.project(root)?.map(|project| project.leader),
        Some(house.to_hex()),
        "the workspace's house leads the root"
    );

    let decider = CountingDecider::new();
    owner_turn(&vault, owner, serde_json::json!({}));
    assert_eq!(
        ask(&vault, &decider),
        ProjectDetectionRun::NotAProject,
        "the bound house reads the owner's unscoped MESSAGE, so the question reaches the ladder"
    );
    assert_eq!(decider.calls(), 1, "the ladder's one rung was asked once");

    // The row is part of the vault's seeded default: the seeded upgrade at
    // the next open keeps it while that house leads.
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    owner_turn(&vault, owner, serde_json::json!({}));
    assert_eq!(
        ask(&vault, &decider),
        ProjectDetectionRun::NotAProject,
        "after a reopen the bound house still reads the owner's unscoped MESSAGE"
    );
    assert_eq!(
        decider.calls(),
        2,
        "the second question reached the ladder too"
    );
    Ok(())
}
