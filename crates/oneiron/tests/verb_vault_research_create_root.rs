//! `vault.research.create_root` through the generated verb dispatch
//! (`oneiron::task_verb::sdk::invoke`), as a client calls it: JSON in, JSON out, on the
//! caller's own `Memory`. The owner, or an agent whose live owner Grant lists the verb,
//! enqueues one parentless root with a run of its own, and the existing
//! `vault.research.bind` accepts that root. An agent with no Grant, or a revoked one, is
//! refused FORBIDDEN (on a pending intent too); a repeat of a pending intent returns its
//! root; the creator gains no control of the root, while the root's own leased agent and
//! the owner keep it; a root dispatched without a run stays unbindable.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_research_create_root`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::HostBinding;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::dreamer_attempt_payload::decode_dreamer_attempt_payload;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VERB: &str = "vault.research.create_root";
const BIND_VERB: &str = "vault.research.bind";
const BRIEF: &str = "Search the parameter axis for a better quality score.";

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// A rooted vault with its install enrolled, its embedded owner and proof. The owner's
/// Grant acts on `ThisInstall` need the full five-step install first.
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
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
    }
}

/// A dispatchable agent definition the root runs: approved, active, enabled.
fn root_agent(fixture: &Fixture) -> EntityId {
    define_agent(&fixture.vault, "research-root-target").expect("define the root's agent")
}

/// An enabled, active agent definition the owner creates: the creating caller.
fn creator_agent(fixture: &Fixture) -> EntityId {
    let id = fixture.vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": "research-root-creator",
                "desc": "research root creation fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("owner creates the creator agent");
    id
}

/// The owner's live Grant naming `read` and this verb for `agent`; the grant's row.
fn grant_create_root(fixture: &Fixture, agent: EntityId) -> EntityId {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), VERB.to_owned()]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("owner mints the create_root Grant");
    assert!(minted.grant.confers, "the create_root Grant confers");
    minted.grant.grant_ref
}

fn revoke_grant(fixture: &Fixture, grant_ref: EntityId) {
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref,
            seen: None,
        },
    )
    .expect("owner revokes the grant");
    assert!(revoked.changed, "the revoke lands");
}

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

fn call_root(
    memory: &Memory<'_>,
    agent: EntityId,
    intent_key: &str,
    briefing: &str,
) -> Result<Value, MemoryError> {
    invoke(
        memory,
        VERB,
        json!({ "agent": agent.to_hex(), "intent_key": intent_key, "briefing": briefing }),
    )
}

/// What a `create_root` receipt names.
struct Created {
    root_hex: String,
    root: AttemptId,
    run_id: String,
    enqueued: bool,
}

fn created(receipt: &Value) -> Created {
    let root_hex = receipt["root"]
        .as_str()
        .expect("the receipt names its root")
        .to_owned();
    let root = AttemptId::from_bytes(
        EntityId::from_hex(&root_hex)
            .expect("the root is an id")
            .as_bytes(),
    )
    .expect("the root is an attempt id");
    Created {
        root_hex,
        root,
        run_id: receipt["run_id"]
            .as_str()
            .expect("the receipt names its run")
            .to_owned(),
        enqueued: receipt["enqueued"]
            .as_bool()
            .expect("the receipt says whether it enqueued"),
    }
}

/// A general config campaign over `root`: three distinct dataset revisions, a primary
/// metric, a positive lease ceiling, and an incumbent pinned by the sha256 of its bytes.
fn bind_spec(root_hex: &str) -> Value {
    let incumbent: &[u8] = br#"{"parameter":"baseline"}"#;
    let digest: String = Sha256::digest(incumbent)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({
        "root": root_hex,
        "config": {
            "campaign_id": "root-admission-fixture",
            "search_axes": [{ "name": "parameter", "values": ["baseline", "alternative"] }],
            "metric_set": {
                "set_id": "fixture-quality",
                "revision": "r1",
                "axes": [{ "name": "quality", "direction": "higher", "role": "primary" }],
            },
            "splits": {
                "search": { "dataset_id": "fixture-search", "revision": "r1" },
                "held_out": { "dataset_id": "fixture-held-out", "revision": "r1" },
                "sealed": { "dataset_id": "fixture-sealed", "revision": "r1" },
            },
            "budget": { "budget_id": "fixture-lease", "max_units": 100, "exploration_units": 10 },
            "decide": { "kind": "dominance" },
        },
        "target": { "config": { "subject": "root-admission-fixture" } },
        "holder": null,
        "confirmation": null,
        "share": null,
        "incumbent": { "config_ref": "fixture-config:baseline", "config_sha256": digest },
        "prior_ladder": [],
        "execution": null,
    })
}

fn assert_forbidden(error: &MemoryError, what: &str) {
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "{what}: FORBIDDEN, not the unknown-verb code; got {}: {}",
        error.code, error.message,
    );
}

#[test]
fn owner_creates_a_root_with_a_run_that_bind_accepts() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let owner = owner_memory(&fixture);
    let receipt =
        call_root(&owner, target, "owner-intent", BRIEF).expect("the owner creates a root");
    let root = created(&receipt);
    assert!(root.enqueued, "a new intent enqueues its root");
    assert!(
        root.run_id.starts_with("research:"),
        "the engine mints the root's run: {}",
        root.run_id
    );
    let record = AttemptQueue::new(&fixture.vault)
        .get(root.root)
        .expect("read the root")
        .expect("the root is queued");
    assert_eq!(record.run_id.as_deref(), Some(root.run_id.as_str()));
    assert_eq!(record.state, AttemptState::Queued);
    let payload = decode_dreamer_attempt_payload(&record.payload).expect("the root's payload");
    assert_eq!(payload.parent_attempt, None, "the root has no parent");

    let binding = invoke(&owner, BIND_VERB, bind_spec(&root.root_hex))
        .expect("the existing bind accepts the created root");
    assert_eq!(binding["run_id"].as_str(), Some(root.run_id.as_str()));
}

#[test]
fn granted_agent_creates_a_root_it_does_not_control() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let creator = creator_agent(&fixture);
    grant_create_root(&fixture, creator);
    let agent = fixture.vault.memory(creator, EdgeActorClass::Agent);
    let receipt = call_root(&agent, target, "agent-intent", BRIEF)
        .expect("an agent whose Grant lists the verb creates a root");
    let root = created(&receipt);
    let record = AttemptQueue::new(&fixture.vault)
        .get(root.root)
        .expect("read the root")
        .expect("the root is queued");
    assert_eq!(record.run_id.as_deref(), Some(root.run_id.as_str()));

    let error = invoke(&agent, BIND_VERB, bind_spec(&root.root_hex))
        .expect_err("the creator does not control the root it created");
    assert_forbidden(&error, "the creator's bind");
    invoke(
        &owner_memory(&fixture),
        BIND_VERB,
        bind_spec(&root.root_hex),
    )
    .expect("the owner binds the agent-created root");
}

#[test]
fn agent_without_a_grant_is_refused() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let creator = creator_agent(&fixture);
    let agent = fixture.vault.memory(creator, EdgeActorClass::Agent);
    let error = call_root(&agent, target, "no-grant-intent", BRIEF)
        .expect_err("an agent with no Grant is refused");
    assert_forbidden(&error, "a no-grant create");
    assert!(
        error.message.contains(VERB),
        "the refusal names the verb: {}",
        error.message
    );
}

#[test]
fn revoked_grant_is_refused_on_a_pending_intent_and_a_new_one() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let creator = creator_agent(&fixture);
    let grant = grant_create_root(&fixture, creator);
    let agent = fixture.vault.memory(creator, EdgeActorClass::Agent);
    call_root(&agent, target, "revoked-intent", BRIEF).expect("the granted agent creates a root");
    revoke_grant(&fixture, grant);

    let replay = call_root(&agent, target, "revoked-intent", BRIEF)
        .expect_err("a revoked Grant does not replay its pending root");
    assert_forbidden(&replay, "a revoked replay");
    let fresh = call_root(&agent, target, "revoked-new-intent", BRIEF)
        .expect_err("a revoked Grant creates no new root");
    assert_forbidden(&fresh, "a revoked create");
}

#[test]
fn repeat_of_a_pending_intent_returns_its_root() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let owner = owner_memory(&fixture);
    let first = created(&call_root(&owner, target, "repeat-intent", BRIEF).expect("first create"));
    let second =
        created(&call_root(&owner, target, "repeat-intent", BRIEF).expect("repeat create"));
    assert_eq!(
        second.root, first.root,
        "the repeat returns the pending root"
    );
    assert_eq!(
        second.run_id, first.run_id,
        "the repeat keeps the root's run"
    );
    assert!(
        first.enqueued && !second.enqueued,
        "only the first call enqueues"
    );
    let runs = AttemptQueue::new(&fixture.vault)
        .list_run(&first.run_id)
        .expect("list the run");
    assert_eq!(runs.len(), 1, "the run holds one root");

    let other = created(&call_root(&owner, target, "other-intent", BRIEF).expect("other create"));
    assert_ne!(other.root, first.root, "another intent is another root");
    assert_ne!(other.run_id, first.run_id, "another root has its own run");
    assert!(other.enqueued);

    call_root(
        &owner,
        target,
        "repeat-intent",
        "A different brief for the same intent.",
    )
    .expect_err("a changed brief on a pending intent is refused, not reused");
}

#[test]
fn root_without_a_run_stays_unbindable() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let owner = owner_memory(&fixture);
    let AgentDispatchOutcome::Dispatched(spawned) = AgentDispatcher::new(&fixture.vault)
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(target),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: fixture.vault.now_recorded_at(),
        })
        .expect("ordinary dispatch")
    else {
        panic!("the ordinary root was not dispatched");
    };
    assert_eq!(
        spawned.attempt.run_id, None,
        "ordinary dispatch mints no run"
    );
    let spawned_hex = EntityId::from_bytes(*spawned.attempt.id.as_bytes())
        .expect("attempt id")
        .to_hex();
    invoke(&owner, BIND_VERB, bind_spec(&spawned_hex))
        .expect_err("a root without a run stays unbindable");

    let root = created(&call_root(&owner, target, "run-bearing-intent", BRIEF).expect("create"));
    invoke(&owner, BIND_VERB, bind_spec(&root.root_hex)).expect("the run-bearing root binds");
}

#[test]
fn root_agent_binds_its_own_leased_root() {
    let fixture = rooted_vault();
    let target = root_agent(&fixture);
    let owner = owner_memory(&fixture);
    let root = created(&call_root(&owner, target, "leased-intent", BRIEF).expect("create"));
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(&fixture.vault)
        .claim(ClaimAttempt {
            lease_owner: "research-root-host".into(),
            now: fixture.vault.now_recorded_at(),
        })
        .expect("claim")
    else {
        panic!("the created root was not leased");
    };
    assert_eq!(
        leased.id, root.root,
        "the created root is the leased attempt"
    );

    let bare = fixture.vault.memory(target, EdgeActorClass::Agent);
    let error = invoke(&bare, BIND_VERB, bind_spec(&root.root_hex))
        .expect_err("the agent outside its leased try does not control the root");
    assert_forbidden(&error, "a bind without the root's lease");
    let binding = HostBinding::from_leased(&leased, None).expect("host binding");
    let hosted = fixture
        .vault
        .memory(target, EdgeActorClass::Agent)
        .with_task_host(binding);
    invoke(&hosted, BIND_VERB, bind_spec(&root.root_hex))
        .expect("the root's own leased agent binds it");
}
