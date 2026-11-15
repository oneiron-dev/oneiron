//! DESIGN 15-setting-primitive, stage 1, lane SETTING-DIALS PR D2b: the owner's model pack
//! preference becomes the catalogue key `models.pack_preference`.
//! - the key is in the catalogue and reads its old default (follow the latest pack), through the
//!   verb, through `Vault::model_pack_preference` and through `vault.settings.model_pack`;
//! - the owner sets it through `vault.settings.set`, and `vault.settings.model_pack.replace` is
//!   gone;
//! - a pin no installed, served pack meets is refused in the write, as the replace door refused
//!   it, and so is a pin row of the key: the preference is one value row;
//! - it stays an owner act: an agent's change waits on a check-in, and an agent with no class
//!   does not read it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dials_2b`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::settings::model_pack::ModelPackPreference;
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
const SET: &str = "vault.settings.set";
const VIEW: &str = "vault.settings.model_pack";
const REPLACE: &str = "vault.settings.model_pack.replace";
const PREFERENCE: &str = "models.pack_preference";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
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
            _issuer: issuer,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn as_agent(&self, agent: EntityId) -> Memory<'_> {
        self.vault.memory(agent, EdgeActorClass::Agent)
    }

    /// An enabled, active agent definition the owner creates.
    fn agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("dials-agent-{}", id.to_hex()),
                    "desc": "setting dials fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        id
    }

    /// The owner's live Grant for `agent` naming `read` and `verbs`.
    fn grant(&self, agent: EntityId, verbs: &[&str]) {
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
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

fn set(value: Value) -> Value {
    json!({ "key": PREFERENCE, "scope": { "kind": "vault" }, "value": value })
}

fn get(memory: &Memory<'_>) -> Value {
    call(memory, GET, json!({ "key": PREFERENCE }))
}

fn follow_latest() -> Value {
    json!({ "mode": "auto_upgrade" })
}

#[test]
fn the_pack_preference_reads_its_old_default() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let read = get(&me);
    assert_eq!(read["value"], follow_latest(), "{read}");
    assert_eq!(read["source"], json!({ "from": "default" }), "{read}");
    assert_eq!(
        fx.vault.model_pack_preference().expect("read"),
        ModelPackPreference::AutoUpgrade
    );
    let view = call(&me, VIEW, json!({}));
    assert_eq!(view["preference"], follow_latest(), "{view}");
    assert_eq!(
        view["active"],
        Value::Null,
        "no model pack installed: {view}"
    );
}

#[test]
fn the_owner_sets_it_through_the_set_verb_and_the_replace_verb_is_gone() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let applied = call(&me, SET, set(follow_latest()));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert!(applied["sequence"].is_u64(), "a row is written: {applied}");
    let read = get(&me);
    assert_eq!(read["value"], follow_latest(), "{read}");
    assert_eq!(read["source"]["from"], json!("row"), "{read}");
    assert_eq!(
        call(&me, VIEW, json!({}))["preference"],
        follow_latest(),
        "the owner's view reads the key"
    );

    refused(&me, REPLACE, follow_latest());
}

#[test]
fn a_pin_no_installed_served_pack_meets_is_refused() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    for pin in [
        json!({ "mode": "pinned_pack", "pack": "dials-pack" }),
        json!({ "mode": "pinned", "stack": "dials-season" }),
    ] {
        let error = refused(&me, SET, set(pin.clone()));
        assert!(
            error.contains("installed, still-served pack"),
            "{pin}: {error}"
        );
    }
    let read = get(&me);
    assert_eq!(read["value"], follow_latest(), "nothing stored: {read}");
    assert_eq!(read["source"], json!({ "from": "default" }), "{read}");
}

#[test]
fn a_pin_row_of_the_preference_is_refused() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let error = refused(
        &me,
        SET,
        json!({
            "key": PREFERENCE,
            "scope": { "kind": "vault" },
            "pin": true,
            "value": follow_latest(),
        }),
    );
    assert!(error.contains("one value row"), "{error}");
    let read = get(&me);
    assert_eq!(
        read["source"],
        json!({ "from": "default" }),
        "no pin stored: {read}"
    );
}

#[test]
fn it_stays_an_owner_act() {
    let fx = Fixture::rooted();
    let asker = fx.agent();
    fx.grant(asker, &[SET, GET]);
    let them = fx.as_agent(asker);

    let pending = call(&them, SET, set(follow_latest()));
    assert_eq!(pending["status"], json!("pending"), "{pending}");
    let read = get(&fx.as_owner());
    assert_eq!(
        read["source"],
        json!({ "from": "default" }),
        "nothing applied: {read}"
    );

    refused(&them, GET, json!({ "key": PREFERENCE }));
}
