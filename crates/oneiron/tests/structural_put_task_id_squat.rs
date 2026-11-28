//! FIX TASK-ID-SQUAT-BY-STRUCTURAL-PUT: a TASK's id is the engine's.
//!
//! `vault.structural.put` took a caller-supplied id for kind TASK. A post
//! names its TASK by a derived id (`EntityId::derive` over the poster and the
//! hashed intent key), and so do a settled create proposal and an ask member.
//! A caller who could predict one landed an Owner-less TASK there first, and
//! the later post refused ("task post id is already occupied"). Canon: "Minted
//! engine ids are opaque ULIDs ... Deterministic ids the engine derives follow
//! a separate rule" (llms-full.txt, the entity id rule, ruled 2026-07-29).
//!
//! The structural door now refuses a caller-supplied id for kind TASK; a
//! structural TASK with no id still lands at a minted id. The posts read
//! through public doors, so on main the squatted post fails at run time.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test structural_put_task_id_squat`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::{Memory, StructuralPutInput};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{TaskCallReceipt, TaskHandle, TaskPost};
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_contracts::entity_id::derived_domains::TASK_POST;
use serde_json::json;

/// The derivation context of a post's hashed intent key, as
/// `task_verb::highway_post::key` names it.
const POST_KEY_CONTEXT: &str = "oneiron tasks post intent key v1";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    _dir: tempfile::TempDir,
}

/// A rooted vault whose handle holds the writer lease, its embedded owner,
/// and an agent definition with an owner Grant of base reach (as in
/// `plan_mode_setting.rs`).
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
    let agent = define_agent(&vault, "errand-runner").expect("agent");
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

/// The TASK id a wire post of `key` by `poster` names: the poster's id and
/// the intent key's hash under the `TASK_POST` domain. Anyone who knows the
/// poster and the key can compute it.
fn post_task_id(poster: EntityId, key: &str) -> EntityId {
    let stored = blake3::Hasher::new_derive_key(POST_KEY_CONTEXT)
        .update(key.as_bytes())
        .finalize()
        .to_hex()
        .to_string();
    EntityId::derive(TASK_POST, &[poster.as_bytes(), stored.as_bytes()]).expect("a post id")
}

/// The owner's post of a TASK for the agent's definition under `key`.
fn run(fixture: &Fixture, key: &str) -> TaskPost {
    serde_json::from_value(json!({
        "intent_key": key,
        "assignee": {"agent_def": {"agent_def_ref": fixture.agent.to_hex()}},
        "brief": {
            "schema": 1,
            "type_ref": {"node_id": EntityId::now().to_hex(), "tree_version": 1},
            "objective": "Water the balcony herbs",
            "intent": {"need": "Water the balcony herbs", "care": "light"},
            "context": {"read_first": []},
            "success": {
                "question": "Are the herbs watered?",
                "criteria": {"yes_if_all": [{"text": "Every pot is damp."}]},
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

/// The TASK a post's receipt names, on its handle or a related one.
fn posted_task(receipt: &TaskCallReceipt) -> Option<EntityId> {
    std::iter::once(&receipt.handle)
        .chain(&receipt.related)
        .find_map(|handle| match handle {
            TaskHandle::Task { task_ref } => Some(*task_ref),
            TaskHandle::Attempt(attempt) => Some(attempt.task_ref),
            _ => None,
        })
}

/// A structural TASK the agent writes, at `id` when given.
fn structural_task(id: Option<EntityId>, title: &str) -> StructuralPutInput {
    StructuralPutInput {
        id: id.map(|id| id.to_hex()),
        kind: "TASK".into(),
        body: json!({"title": title, "role": 1}),
        text_fields: None,
        edges: None,
        occurred_at: 1_780_000_000,
        learned_at: None,
    }
}

#[test]
fn the_post_id_oracle_names_the_task_a_post_mints() {
    let fixture = fixture();
    let receipt = owner(&fixture)
        .tasks_post(run(&fixture, "herbs/control"))
        .expect("the owner posts a TASK");
    assert_eq!(
        posted_task(&receipt),
        Some(post_task_id(fixture.owner, "herbs/control")),
        "the post's TASK sits at the derived id: {receipt:?}"
    );
}

#[test]
fn a_structural_task_at_a_predicted_post_id_is_refused_and_the_post_mints() {
    let fixture = fixture();
    let predicted = post_task_id(fixture.owner, "herbs/daily");
    let squat = agent(&fixture).put_structural(&structural_task(Some(predicted), "squat"));
    // The harm first: the owner's post under the predicted key must still
    // mint its TASK at its derived id.
    let receipt = owner(&fixture)
        .tasks_post(run(&fixture, "herbs/daily"))
        .unwrap_or_else(|error| {
            panic!("the owner's post after a squat attempt (squat answered {squat:?}): {error:?}")
        });
    assert_eq!(
        posted_task(&receipt),
        Some(predicted),
        "the post mints at its derived id: {receipt:?}"
    );
    assert!(
        !receipt.idempotent_replay,
        "the post is a fresh mint, not a replay of the squatter's row: {receipt:?}"
    );
    match squat {
        Err(error) => assert!(
            error.message.contains("TASK"),
            "the refusal names the kind: {error:?}"
        ),
        Ok(receipt) => panic!("a caller-supplied TASK id is refused: {receipt:?}"),
    }
}

#[test]
fn a_structural_task_at_any_caller_id_is_refused() {
    let fixture = fixture();
    let chosen = EntityId::now();
    match agent(&fixture).put_structural(&structural_task(Some(chosen), "chosen")) {
        Err(error) => assert!(
            error.message.contains("TASK"),
            "the refusal names the kind: {error:?}"
        ),
        Ok(receipt) => panic!("a caller-supplied TASK id is refused: {receipt:?}"),
    }
    assert!(
        fixture.vault.get_raw(&chosen).expect("raw read").is_none(),
        "nothing lands at the chosen id"
    );
}

#[test]
fn a_structural_task_without_an_id_still_lands() {
    let fixture = fixture();
    let receipt = agent(&fixture)
        .put_structural(&structural_task(None, "minted"))
        .expect("a structural TASK with no id lands at a minted id");
    let id = EntityId::from_hex(&receipt.id_hex).expect("the receipt's id");
    assert!(
        fixture.vault.get_raw(&id).expect("raw read").is_some(),
        "the TASK is stored"
    );
}
