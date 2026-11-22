//! The owner sets the optional recall an agent takes as a reader (census
//! L9-32).
//!
//! Canon ARCH-0004 #reader-budget: "Held-out outcomes for the actual reader
//! and task pick the optional memory budget and the tier." Engine ruling
//! L9-32-PICK-WRITER (Sat 14 Nov 07:43): `vault.agents.optional_memory.set`
//! is an owner act that writes the definition's next version with a default
//! plus per-family choice, and refuses a row that is not an agent
//! definition. Ruling L9-32-NO-PROFILE = A (07:52): the choice is the
//! definition's own field, so it reaches an agent with no window profile and
//! leaves the window as authored.
//!
//! The tests call the verb by name, so on a tree without it each fails at
//! run time as an unknown verb.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_optional_memory_set`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::{AgentDefinition, encode_agent_definition};
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const SET: &str = "vault.agents.optional_memory.set";
const GET: &str = "vault.agents.get";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    _dir: tempfile::TempDir,
}

/// A rooted vault whose handle holds the writer lease (the owner verbs
/// answer the embedded owner on it), with its install enrolled, its embedded
/// owner, and an agent definition with no window profile that holds an
/// owner Grant of base reach.
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
    let agent = define_agent(&vault, "tide-reader").expect("agent");
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
            check_in_ref: None,
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

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Result<Value, String> {
    oneiron::task_verb::sdk::invoke(memory, verb, input).map_err(|error| format!("{error:?}"))
}

/// The definition version the owner reads before a set.
fn version(fixture: &Fixture) -> String {
    let read = call(
        &owner(fixture),
        GET,
        json!({"agent_def_ref": fixture.agent.to_hex()}),
    )
    .expect("the owner reads the definition");
    read.pointer("/definition/version")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the read names its version: {read}"))
        .to_owned()
}

fn stored(fixture: &Fixture) -> AgentDefinition {
    fixture
        .vault
        .get_agent_definition(&fixture.agent)
        .expect("definition read")
        .expect("the definition is stored")
}

/// A default of 2048 tokens at standard detail; `event_ordering` takes no
/// optional recall and `multi_session_reasoning` 512 tokens at summary.
fn picked(target: EntityId, expected_version: &str) -> Value {
    json!({
        "agent_def_ref": target.to_hex(),
        "expected_version": expected_version,
        "default": {"kind": "budget", "tokens": 2048, "view": "standard"},
        "families": {
            "event_ordering": {"kind": "none"},
            "multi_session_reasoning": {"kind": "budget", "tokens": 512, "view": "summary"},
        },
    })
}

/// The stored definition's body, key by key, as the codec writes it.
fn stored_body(fixture: &Fixture) -> Vec<(String, rmpv::Value)> {
    let bytes = encode_agent_definition(&stored(fixture)).expect("encode");
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap() else {
        panic!("the body is a map");
    };
    entries
        .into_iter()
        .map(|(key, value)| (key.as_str().unwrap().to_owned(), value))
        .collect()
}

fn without(body: &[(String, rmpv::Value)], keys: &[&str]) -> Vec<(String, rmpv::Value)> {
    body.iter()
        .filter(|(key, _)| !keys.contains(&key.as_str()))
        .cloned()
        .collect()
}

/// [`picked`] as the body codec stores it.
fn picked_body() -> rmpv::Value {
    let budget = |tokens: u64, view: &str| {
        rmpv::Value::Map(vec![
            ("tokens".into(), tokens.into()),
            ("view".into(), view.into()),
        ])
    };
    rmpv::Value::Map(vec![
        ("default".into(), budget(2048, "standard")),
        (
            "families".into(),
            rmpv::Value::Map(vec![
                ("event_ordering".into(), "none".into()),
                ("multi_session_reasoning".into(), budget(512, "summary")),
            ]),
        ),
    ])
}

fn assert_refused(result: Result<Value, String>, reason: &str, why: &str) {
    match result {
        Err(error) if error.contains(reason) => {}
        other => panic!("{why}: expected {reason}, got {other:?}"),
    }
}

#[test]
fn the_owner_sets_a_readers_optional_memory_on_its_next_version() {
    let fixture = fixture();
    let before = stored_body(&fixture);
    assert!(
        before
            .iter()
            .all(|(key, _)| key != "memory_profile" && key != "optional_memory"),
        "the fixture has no window profile and no optional memory"
    );
    let read = version(&fixture);

    let set = call(&owner(&fixture), SET, picked(fixture.agent, &read))
        .unwrap_or_else(|error| panic!("the owner sets the optional memory: {error}"));
    let now = set
        .pointer("/version")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the setter answers the new version: {set}"))
        .to_owned();
    assert_ne!(now, read, "the set writes the definition's next version");
    assert!(now.starts_with("optional-memory-"), "{now}");
    assert_eq!(
        set.pointer("/agent_def_ref").and_then(Value::as_str),
        Some(fixture.agent.to_hex().as_str())
    );
    assert_eq!(
        set.pointer("/families/multi_session_reasoning/tokens")
            .and_then(Value::as_u64),
        Some(512),
        "the setter answers what it set: {set}"
    );
    assert_eq!(version(&fixture), now, "the owner's next read names it");

    let after = stored_body(&fixture);
    assert_eq!(
        without(&after, &["version", "optional_memory"]),
        without(&before, &["version"]),
        "only the optional memory and the version change; the window stays absent"
    );
    assert_eq!(
        after.last(),
        Some(&("optional_memory".to_owned(), picked_body())),
        "the choice is the body's own last key"
    );
}

#[test]
fn a_set_on_a_moved_definition_is_refused_and_writes_nothing() {
    let fixture = fixture();
    let read = version(&fixture);
    call(&owner(&fixture), SET, picked(fixture.agent, &read)).expect("the first set lands");
    let landed = stored(&fixture);

    let stale = json!({
        "agent_def_ref": fixture.agent.to_hex(),
        "expected_version": read,
        "default": {"kind": "none"},
    });
    assert_refused(
        call(&owner(&fixture), SET, stale),
        "agent definition revision changed",
        "a set at the version the first set replaced",
    );
    assert_eq!(stored(&fixture), landed, "the refused set wrote nothing");

    let again = call(
        &owner(&fixture),
        SET,
        picked(fixture.agent, &landed.version),
    )
    .expect("the same setting again");
    assert_eq!(
        again.pointer("/version").and_then(Value::as_str),
        Some(landed.version.as_str()),
        "a setting the definition already carries writes no new version"
    );
    assert_eq!(stored(&fixture), landed);
}

#[test]
fn only_the_owner_sets_it_and_only_on_an_agent_definition() {
    let fixture = fixture();
    let read = version(&fixture);
    let before = stored(&fixture);

    assert!(
        call(&agent(&fixture), SET, picked(fixture.agent, &read)).is_err(),
        "an agent sets no optional memory, its own included"
    );
    assert_refused(
        call(&owner(&fixture), SET, picked(fixture.owner, &read)),
        "not a type-17 AGENT_DEF",
        "the owner's own PERSON row is not an agent definition",
    );
    assert!(
        call(&owner(&fixture), SET, picked(EntityId::now(), &read)).is_err(),
        "an id that names no row"
    );
    assert_refused(
        call(
            &owner(&fixture),
            SET,
            json!({
                "agent_def_ref": fixture.agent.to_hex(),
                "expected_version": read,
                "default": {"kind": "budget", "tokens": 0, "view": "standard"},
            }),
        ),
        "0 tokens is no limit",
        "a budget of 0 tokens",
    );
    assert_eq!(stored(&fixture), before, "no refused set wrote anything");
}
