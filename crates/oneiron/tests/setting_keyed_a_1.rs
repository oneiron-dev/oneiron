//! DESIGN 15-setting-primitive, stage 1, lane SETTING-KEYED-A, PR K1: three plain tables become
//! catalogue keys, and their kept readers read the keys.
//! - `calendar.imip_transport` (was `CALENDAR_IMIP_TRANSPORT`): reads none until the owner
//!   installs a transport with `vault.settings.set`; the host read `imip_transport` returns what
//!   the owner set; the value's check refuses an endpoint or a custody name the old door refused;
//!   a cleared row reads none again.
//! - `edit_distance.publisher.enabled` and `edit_distance.publisher.install_default` (were
//!   `EDIT_DISTANCE_PUBLISHER_ENABLED` and `_INSTALL_DEFAULT`): `publisher_enabled` reads the
//!   owner's dial, else the install profile's default, else off; the install default is a
//!   choice about this machine (`sync: install`).
//! - an agent's change to any of them waits on a check-in: they are owner acts.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_keyed_a_1`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::calendar::connectors::door::imip_transport;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edit_distance::publisher::publisher_enabled;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const SET: &str = "vault.settings.set";
const T0: u64 = 1_790_000_000;

const IMIP: &str = "calendar.imip_transport";
const DIAL: &str = "edit_distance.publisher.enabled";
const INSTALL: &str = "edit_distance.publisher.install_default";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
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
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// An enabled, active agent the owner creates, with the owner's live Grant naming the
    /// setting verbs.
    fn granted_agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("keyed-a-agent-{}", id.to_hex()),
                    "desc": "setting keyed-a fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            ["read", GET, SET]
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent: id,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the Grant");
        assert!(minted.grant.confers, "the Grant confers");
        id
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> String {
    format!(
        "{:?}",
        invoke(memory, verb, input).expect_err("the call is refused")
    )
}

fn set(key: &str, value: Value) -> Value {
    json!({ "key": key, "scope": { "kind": "vault" }, "value": value })
}

fn get(memory: &Memory<'_>, key: &str) -> Value {
    call(memory, GET, json!({ "key": key }))
}

#[test]
fn the_imip_transport_is_a_setting_the_host_read_returns() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let unset = get(&me, IMIP);
    assert_eq!(unset["value"], Value::Null, "{unset}");
    assert_eq!(unset["source"], json!({ "from": "default" }));
    assert_eq!(imip_transport(&fx.vault).expect("host read"), None);

    let transport =
        json!({ "endpoint": "https://mail.example.com/submit", "secret_ref": "imip-cred" });
    let applied = call(&me, SET, set(IMIP, transport.clone()));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(get(&me, IMIP)["value"], transport);
    let read = imip_transport(&fx.vault)
        .expect("host read")
        .expect("the owner's transport");
    assert_eq!(read.endpoint, "https://mail.example.com/submit");
    assert_eq!(read.secret_ref, "imip-cred");

    let plain_http = refused(
        &me,
        SET,
        set(
            IMIP,
            json!({ "endpoint": "http://mail.example.com/submit", "secret_ref": "imip-cred" }),
        ),
    );
    assert!(plain_http.contains("HTTPS"), "{plain_http}");
    let with_query = refused(
        &me,
        SET,
        set(
            IMIP,
            json!({ "endpoint": "https://mail.example.com/submit?x=1", "secret_ref": "imip-cred" }),
        ),
    );
    assert!(with_query.contains("HTTPS"), "{with_query}");
    for bad in [String::new(), "x".repeat(257), "imip\ncred".to_owned()] {
        let bounded = refused(
            &me,
            SET,
            set(
                IMIP,
                json!({ "endpoint": "https://mail.example.com/submit", "secret_ref": bad }),
            ),
        );
        assert!(bounded.contains("custody name"), "{bounded}");
    }
    assert_eq!(
        imip_transport(&fx.vault)
            .expect("host read")
            .map(|config| config.secret_ref),
        Some("imip-cred".to_owned()),
        "a refused change leaves the owner's transport"
    );
    let loopback = json!({ "endpoint": "http://127.0.0.1:2525/submit", "secret_ref": "imip-cred" });
    call(&me, SET, set(IMIP, loopback));
    assert_eq!(
        imip_transport(&fx.vault)
            .expect("host read")
            .map(|config| config.endpoint),
        Some("http://127.0.0.1:2525/submit".to_owned()),
        "loopback HTTP is admitted, as before"
    );

    call(&me, SET, set(IMIP, Value::Null));
    assert_eq!(get(&me, IMIP)["source"], json!({ "from": "default" }));
    assert_eq!(imip_transport(&fx.vault).expect("host read"), None);
}

#[test]
fn the_publisher_dial_reads_the_owners_row_then_the_install_row_then_off() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    assert!(!publisher_enabled(&fx.vault).expect("dial"), "compiled off");

    call(&me, SET, set(INSTALL, json!(true)));
    assert!(
        publisher_enabled(&fx.vault).expect("dial"),
        "the install profile's default decides with no owner row"
    );

    call(&me, SET, set(DIAL, json!(false)));
    assert!(
        !publisher_enabled(&fx.vault).expect("dial"),
        "the owner's dial sits over the install profile"
    );
    call(&me, SET, set(DIAL, json!(true)));
    call(&me, SET, set(INSTALL, json!(false)));
    assert!(publisher_enabled(&fx.vault).expect("dial"));

    call(&me, SET, set(DIAL, Value::Null));
    assert!(
        !publisher_enabled(&fx.vault).expect("dial"),
        "a cleared dial falls back to the install row"
    );
    call(&me, SET, set(INSTALL, Value::Null));
    assert!(!publisher_enabled(&fx.vault).expect("dial"));

    let listed = call(&me, LIST, json!({ "prefix": "edit_distance.publisher." }));
    let keys = listed["keys"].as_array().expect("keys");
    let names: Vec<&str> = keys
        .iter()
        .map(|entry| entry["key"].as_str().expect("a name"))
        .collect();
    assert_eq!(names, [DIAL, INSTALL], "{listed}");
    assert_eq!(keys[0]["sync"], json!("vault"));
    assert_eq!(keys[1]["sync"], json!("install"));
    assert_eq!(keys[0]["default"], json!(false));
    assert_eq!(keys[0]["set_by"], json!("owner"));
}

#[test]
fn an_agents_change_to_these_keys_waits_on_a_check_in() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let agent = fx.granted_agent();
    let them = fx.vault.memory(agent, EdgeActorClass::Agent);

    for (key, value) in [
        (
            IMIP,
            json!({ "endpoint": "https://mail.example.com/submit", "secret_ref": "imip-cred" }),
        ),
        (DIAL, json!(true)),
        (INSTALL, json!(true)),
    ] {
        let pending = call(&them, SET, set(key, value));
        assert_eq!(pending["status"], json!("pending"), "{key}: {pending}");
        assert_eq!(
            get(&me, key)["source"],
            json!({ "from": "default" }),
            "{key}: nothing applied"
        );
    }
    assert_eq!(imip_transport(&fx.vault).expect("host read"), None);
    assert!(!publisher_enabled(&fx.vault).expect("dial"));
}
