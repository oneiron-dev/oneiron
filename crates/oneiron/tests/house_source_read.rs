//! HOUSE-SOURCE-READ (OF-501; FIX 22357, #6857): the house mind's project
//! question reads the person's turn it is about. The house reads the source
//! MESSAGE under its own agent key and the relationship gate, and a key no
//! scoped grant names reads nothing, so before the house's read row shipped
//! every question settled `Unread` and the host's ladder was never asked.
//!
//! The project-question cases witness one owner turn and run the queued
//! question on a ladder whose one rung counts its calls and answers "no":
//! a question that reached the ladder settles `NotAProject`, one whose source
//! the house may not read settles `Unread` with no call. The CLAIM cases keep
//! the no-proof MESSAGE floor separate from its own Grant or verified slip.
//! No `cfg` is needed: every door used here is on main for the red run.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::agent_dispatch::{AgentDispatcher, ProjectDetection, ProjectDetectionRun};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::claim::{PointRead, ScopedReadActorKey};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionProvider,
    DecisionRung, HeldLadder, ProviderDecision, ProviderPin,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{ClaimInput, EntityId, Result, Vault, VaultConfig};

const LEASE_OWNER: &str = "house-source-read-test";

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

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn seeded_house(vault: &Vault) -> Result<EntityId> {
    Ok(vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")?
        .expect("the fresh vault seeds sys.team_lead")
        .0)
}

fn owner_claim(vault: &Vault, owner: EntityId) -> TestResult<EntityId> {
    let id = EntityId::now();
    let claim_hex = id.to_hex();
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(claim_hex.clone()),
            predicate: "preference.travel.seat".to_owned(),
            subject_ref: owner.to_hex(),
            value: serde_json::json!({ "seat": "window" }),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        })?;
    assert_eq!(
        receipt.claim.as_ref().map(|claim| claim.id.as_str()),
        Some(claim_hex.as_str()),
        "the owner's unscoped base-world CLAIM lands with the requested id"
    );
    let written = vault
        .memory(owner, EdgeActorClass::Human)
        .get_entity(&claim_hex)?;
    assert_eq!(
        written.value.as_ref().map(|claim| claim.id_hex.as_str()),
        Some(claim_hex.as_str()),
        "the owner can point-read the unscoped base-world CLAIM"
    );
    Ok(id)
}

#[test]
fn the_seeded_houses_own_grant_still_reads_a_claim() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let house = seeded_house(&vault)?;
    // The owner's Grant act needs a carrier: this install rooted, then
    // profiled in the vault's roster under its own keys, as `oneiron init`
    // does before the owner's first act.
    let issuer = HostSlipIssuer::from_secret(b"house-source-read-grant")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let claim = owner_claim(&vault, owner)?;
    let claim_hex = claim.to_hex();

    let no_proof = vault
        .scoped_read(
            ScopedReadActorKey::with_actor_class(house.to_hex(), "agent")
                .expect("the seeded house has an agent read key"),
        )
        .read(&[PointRead::id(claim)], None)?
        .single();
    assert_eq!(
        no_proof.value.as_ref().map(|row| row.id),
        None,
        "the seeded house's no-proof key must not read an owner CLAIM outside the MESSAGE band"
    );

    let owner_proof =
        vault.authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())?;
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: house,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
        },
    )?;
    assert_eq!(
        minted.grant.agent, house,
        "the owner grants the seeded house"
    );
    assert!(minted.grant.confers, "the owner-minted read Grant is live");

    let read = vault
        .memory(house, EdgeActorClass::Agent)
        .get_entity(&claim_hex)?;
    assert_eq!(
        read.value.as_ref().map(|row| row.id_hex.as_str()),
        Some(claim_hex.as_str()),
        "the seeded house's own live read Grant must still point-read the owner's CLAIM"
    );
    Ok(())
}

#[test]
fn the_seeded_houses_verified_read_slip_still_reads_a_claim() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let house = seeded_house(&vault)?;
    let issuer = HostSlipIssuer::from_secret(b"house-source-read-slip")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let claim = owner_claim(&vault, owner)?;

    let mut claims = root.claims;
    claims.slip_id = [0xa9; 32];
    claims.holder_ref = house.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    claims.expires_at = claims.issued_at + 600;
    claims.ttl_secs = 600;
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let challenge = b"house-claim-point-read";
    let signature = issuer.binding_proof(&slip, challenge)?;
    let proof = vault.verify_capability_slip(&issuer.public_key(), &slip, challenge, &signature)?;
    assert_eq!(proof.claims().holder_ref, house.to_hex());
    assert_eq!(proof.claims().actor_class.as_deref(), Some("agent"));
    let key = ScopedReadActorKey::from_verified_slip(&proof)
        .expect("the house's verified slip carries read");
    let read = vault
        .scoped_read(key)
        .read(&[PointRead::id(claim)], None)?
        .single();
    assert_eq!(
        read.value.as_ref().map(|row| row.id),
        Some(claim),
        "the seeded house's verified read slip must still point-read the owner's CLAIM"
    );
    Ok(())
}
