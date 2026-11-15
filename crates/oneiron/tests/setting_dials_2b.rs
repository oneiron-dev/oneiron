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
//! - an owner pin of an installed pack lands and moves the pack, recorded as the owner's setting;
//! - a revert pins the previous pack with the owner as setter, recorded as a revert;
//! - an install with a pin in force keeps the pinned pack.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dials_2b`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::inbox::{INBOX_PAGE_DEFAULT, NotificationKind};
use oneiron::llm::model_pack::{MODEL_PACK_CHANGE_NOTIFICATION_PRODUCER, ModelPackRevertRequest};
use oneiron::memory::Memory;
use oneiron::settings::model_pack::ModelPackPreference;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallStatus};
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
const PACK_A_NAME: &str = "dials.pack-a";
const PACK_B_NAME: &str = "dials.pack-b";
const SEASON: &str = "dials-season";
// At T0 = 1_790_000_000 the vault's today is day 20717 (1790000000/86400); both packs release
// before it and carry no retirement, so both are served.
const DAY_A: u32 = 20700;
const DAY_B: u32 = 20710;

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

fn pinned_pack(name: &str) -> Value {
    json!({ "mode": "pinned_pack", "pack": name })
}

fn pack_md(name: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: Test model pack {name} for setting dials.\n\
         version: 1.0.0\nkind: model\n---\nA data-only seasonal model stack.\n"
    )
}

fn model_pack_json(released_epoch_day: u32) -> String {
    json!({
        "format": 1,
        "season": SEASON,
        "released_epoch_day": released_epoch_day,
        "roles": {
            "generative_reasoner": [
                {
                    "access": { "kind": "hosted", "provider": "dials-provider" },
                    "model": "dials-provider/dials-model@r1",
                    "when": "Default pick for the test role."
                }
            ]
        }
    })
    .to_string()
}

fn model_pack_files(name: &str, day: u32) -> Vec<HubFile> {
    vec![
        HubFile::new("PACK.md", pack_md(name)),
        HubFile::new("knowledge/model-pack.json", model_pack_json(day)),
    ]
}

fn install_model_pack(fx: &Fixture, name: &str, day: u32) {
    match fx
        .vault
        .put_pack(&fx.owner_proof, model_pack_files(name, day))
    {
        Ok(PackInstallDisposition::Installed(receipt)) => {
            assert_eq!(receipt.pack_name, name, "the put names the pack");
            assert_eq!(
                receipt.status,
                PackInstallStatus::Active,
                "an owner put lands a model pack Active"
            );
        }
        other => panic!("{name} installs Active via owner put: {other:?}"),
    }
}

fn active_pack_name(fx: &Fixture) -> Option<String> {
    fx.vault
        .active_model_pack()
        .expect("the active pack reads")
        .map(|active| active.pack.id.as_str().to_owned())
}

fn owner_pack_notice_detail(fx: &Fixture, change_ref: &str) -> String {
    let page = fx
        .as_owner()
        .inbox_list(None, INBOX_PAGE_DEFAULT)
        .expect("the owner lists the inbox");
    let notice = page
        .rows
        .iter()
        .find(|row| {
            row.kind == NotificationKind::ModelPackChanged
                && row.source.result.as_deref() == Some(change_ref)
        })
        .expect("the change has its notice");
    assert_eq!(
        notice.source.producer, MODEL_PACK_CHANGE_NOTIFICATION_PRODUCER,
        "the notice is the pack change's"
    );
    notice
        .source
        .detail
        .clone()
        .expect("the notice names the packs")
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

#[test]
fn an_owner_pin_of_an_installed_pack_lands_and_moves_the_pack() {
    let fx = Fixture::rooted();
    install_model_pack(&fx, PACK_A_NAME, DAY_A);
    install_model_pack(&fx, PACK_B_NAME, DAY_B);
    assert_eq!(
        active_pack_name(&fx).as_deref(),
        Some(PACK_B_NAME),
        "FIXTURE: B is active under the default follow-latest"
    );

    let me = fx.as_owner();
    let applied = call(&me, SET, set(pinned_pack(PACK_A_NAME)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert!(applied["sequence"].is_u64(), "a row is written: {applied}");
    let read = get(&me);
    assert_eq!(read["value"], pinned_pack(PACK_A_NAME), "{read}");
    assert_eq!(
        active_pack_name(&fx).as_deref(),
        Some(PACK_A_NAME),
        "the pin moves the pack to A"
    );

    let setting = fx
        .vault
        .model_pack_setting_as_owner(&fx.owner_proof)
        .expect("the setting reads");
    assert_eq!(
        setting
            .active
            .as_ref()
            .map(|view| view.receipt.pack.as_str()),
        Some(PACK_A_NAME),
        "the setting selects A: {setting:?}"
    );
    assert_eq!(
        setting
            .previous
            .as_ref()
            .map(|receipt| receipt.pack.as_str()),
        Some(PACK_B_NAME),
        "the change moved off B: {setting:?}"
    );
    let change_ref = setting
        .change_ref
        .clone()
        .expect("the pin recorded a change");
    let detail = owner_pack_notice_detail(&fx, &change_ref);
    assert!(
        detail.contains("the owner's model pack setting"),
        "the notice names the owner's setting: {detail}"
    );
}

#[test]
fn a_revert_pins_the_previous_pack_with_the_owner_as_setter() {
    let fx = Fixture::rooted();
    install_model_pack(&fx, PACK_A_NAME, DAY_A);
    install_model_pack(&fx, PACK_B_NAME, DAY_B);
    let me = fx.as_owner();
    let install = fx
        .vault
        .model_pack_setting_as_owner(&fx.owner_proof)
        .expect("the setting reads");
    let change_ref = install
        .change_ref
        .clone()
        .expect("the install recorded a change");

    let revert = fx
        .vault
        .revert_model_pack_change_as_owner(&fx.owner_proof, &ModelPackRevertRequest { change_ref })
        .expect("the revert runs");
    assert_eq!(
        revert.blocked, None,
        "nothing blocks the revert: {revert:?}"
    );
    assert_eq!(
        active_pack_name(&fx).as_deref(),
        Some(PACK_A_NAME),
        "the revert moves the pack back to A"
    );
    assert_eq!(
        revert
            .setting
            .active
            .as_ref()
            .map(|view| view.receipt.pack.as_str()),
        Some(PACK_A_NAME),
        "the setting selects A: {revert:?}"
    );
    assert_eq!(
        revert
            .setting
            .previous
            .as_ref()
            .map(|receipt| receipt.pack.as_str()),
        Some(PACK_B_NAME),
        "the revert moved off B: {revert:?}"
    );
    let revert_ref = revert
        .setting
        .change_ref
        .clone()
        .expect("the revert recorded a change");
    let detail = owner_pack_notice_detail(&fx, &revert_ref);
    assert!(
        detail.contains("a revert"),
        "the notice names a revert: {detail}"
    );
    let read = get(&me);
    assert_eq!(
        read["value"],
        pinned_pack(PACK_A_NAME),
        "the key pins A: {read}"
    );
    let listed = call(&me, "vault.settings.list", json!({ "prefix": PREFERENCE }));
    let row = listed["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .find(|entry| entry["key"] == json!(PREFERENCE))
        .and_then(|entry| entry["rows"].as_array())
        .and_then(|rows| rows.first().cloned())
        .unwrap_or_else(|| panic!("the revert wrote a row: {listed}"));
    assert_eq!(
        row["setter"]["as"],
        json!("owner"),
        "the revert writes as the owner: {row}"
    );
}

#[test]
fn an_install_with_a_pin_in_force_keeps_the_pinned_pack() {
    let fx = Fixture::rooted();
    install_model_pack(&fx, PACK_A_NAME, DAY_A);
    let me = fx.as_owner();
    let applied = call(&me, SET, set(pinned_pack(PACK_A_NAME)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");

    install_model_pack(&fx, PACK_B_NAME, DAY_B);
    assert_eq!(
        active_pack_name(&fx).as_deref(),
        Some(PACK_A_NAME),
        "a pin is not moved by a newer install"
    );
    let setting = fx
        .vault
        .model_pack_setting_as_owner(&fx.owner_proof)
        .expect("the setting reads");
    assert_eq!(
        setting
            .active
            .as_ref()
            .map(|view| view.receipt.pack.as_str()),
        Some(PACK_A_NAME),
        "the setting still selects A: {setting:?}"
    );
    assert_eq!(
        setting.installed.len(),
        2,
        "both packs installed: {setting:?}"
    );
}
