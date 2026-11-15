//! DESIGN 15-setting-primitive, stage 0.3: the Setting primitive's other callers and doors.
//! - the engine sets a value row of any key with no ask and no bound, records the ask it
//!   answers, never pins, and its row is the owner's to a holder;
//! - a live person sets only their own row of a key set by its subject, and only tighter;
//! - a read below the vault answers what the vault's read answers;
//! - the side-row wall reads every setting value before it is stored: a secret never lands raw;
//! - a key's after-commit hook runs once per applied change, after the write commits;
//! - a leave keeps the rows of a key about this machine and drops a vault key's.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_primitive_callers`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{EngineControlClass, Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingMode, SettingScope, SettingSource};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
#[cfg(feature = "sync")]
use oneiron::test_doors::setting::leave_keeps_setting_row;
use oneiron::test_doors::setting::{
    after_commit_seen, after_commits, owner_number_read_both_ways, set_setting_as_engine,
    set_setting_as_person, set_settings_in_one_write,
};
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
                    "agent_id": format!("setting-agent-{}", id.to_hex()),
                    "desc": "setting primitive fixture",
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

    /// The owner's `engine.controls` grant of `class` to `agent`.
    fn controls(&self, agent: EntityId, class: EngineControlClass) {
        self.vault
            .grant_engine_controls(&self.owner_proof, agent, &[class].into_iter().collect())
            .expect("the owner's engine.controls grant");
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn vault_scope() -> Value {
    json!({ "kind": "vault" })
}

fn project(id: EntityId) -> Value {
    json!({ "kind": "project", "id": id.to_hex() })
}

fn person(id: EntityId) -> Value {
    json!({ "kind": "person", "id": id.to_hex() })
}

fn set(key: &str, scope: Value, value: Value) -> Value {
    json!({ "key": key, "scope": scope, "value": value })
}

fn get(memory: &Memory<'_>, key: &str, at: Value) -> Value {
    call(memory, GET, json!({ "key": key, "at": at }))
}

/// The stored rows of `key`, as the owner lists them.
fn rows(memory: &Memory<'_>, key: &str) -> Vec<Value> {
    let listed = call(memory, LIST, json!({ "prefix": key }));
    listed["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .find(|entry| entry["key"] == json!(key))
        .and_then(|entry| entry["rows"].as_array().cloned())
        .unwrap_or_else(|| panic!("{key} is listed: {listed}"))
}

fn applied(outcome: &SetSettingOutcome) -> bool {
    matches!(
        outcome,
        SetSettingOutcome::Applied {
            sequence: Some(_),
            ..
        }
    )
}

fn at(key: &str, scope: SettingScope, value: Value) -> SetSetting {
    SetSetting {
        scope,
        ..SetSetting::vault_value(key, value)
    }
}

#[test]
fn the_engine_sets_a_value_row_with_no_ask_and_never_a_pin() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.owner_number";
    let own = set_setting_as_engine(&fx.vault, None, SetSetting::vault_value(key, json!(3)))
        .expect("the engine sets a value row of its own");
    assert!(applied(&own), "{own:?}");
    assert_eq!(get(&me, key, json!([]))["value"], json!(3));
    let listed = rows(&me, key);
    assert_eq!(
        listed[0]["setter"],
        json!({ "as": "engine", "ask": null }),
        "{listed:?}"
    );
    assert_eq!(listed[0]["by"], Value::Null, "no actor set it: {listed:?}");

    let ask = fx.vault.new_entity_id().expect("ask id");
    let answered =
        set_setting_as_engine(&fx.vault, Some(ask), SetSetting::vault_value(key, json!(4)))
            .expect("the engine applies the owner's answer");
    assert!(applied(&answered), "{answered:?}");
    let listed = rows(&me, key);
    assert_eq!(
        listed[0]["setter"],
        json!({ "as": "engine", "ask": ask.to_hex() }),
        "{listed:?}"
    );

    let pin = SetSetting {
        mode: SettingMode::Pin,
        ..SetSetting::vault_value(key, json!(5))
    };
    let refused = set_setting_as_engine(&fx.vault, None, pin).expect_err("the engine never pins");
    assert!(
        format!("{refused:?}").contains("never a pin"),
        "{refused:?}"
    );
    assert_eq!(get(&me, key, json!([]))["value"], json!(4), "nothing moved");
}

#[test]
fn a_holder_asks_before_it_replaces_a_row_the_engine_set() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    fx.grant(agent, &[SET]);
    fx.controls(agent, EngineControlClass::WorkBudget);
    let them = fx.as_agent(agent);
    let key = "test.work_budget";
    let own = call(&them, SET, set(key, vault_scope(), json!(6)));
    assert_eq!(
        own["status"],
        json!("applied"),
        "a holder sets a row no owner set: {own}"
    );
    let engine = set_setting_as_engine(&fx.vault, None, SetSetting::vault_value(key, json!(8)))
        .expect("the engine replaces the holder's row");
    assert!(applied(&engine), "{engine:?}");
    let asked = call(&them, SET, set(key, vault_scope(), json!(5)));
    assert_eq!(
        asked["status"],
        json!("pending"),
        "the engine's row is the owner's: the holder asks: {asked}"
    );
    assert_eq!(get(&fx.as_owner(), key, json!([]))["value"], json!(8));
}

#[test]
fn a_person_sets_only_their_own_row_of_a_subject_key_and_only_tighter() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.person_quiet";
    let mine = SettingScope::Person(fx.owner);
    let tighter = set_setting_as_person(
        &fx.vault,
        &fx.owner_proof,
        at(key, mine.clone(), json!(true)),
    )
    .expect("a person tightens their own row");
    assert!(applied(&tighter), "{tighter:?}");
    assert_eq!(
        get(&me, key, json!([person(fx.owner)]))["value"],
        json!(true)
    );
    let listed = rows(&me, key);
    assert_eq!(
        listed[0]["setter"],
        json!({ "as": "subject" }),
        "{listed:?}"
    );
    assert_eq!(listed[0]["by"], json!(fx.owner.to_hex()), "{listed:?}");

    let other = EntityId::now();
    for (what, request) in [
        ("a looser value", at(key, mine.clone(), json!(false))),
        (
            "another person's row",
            at(key, SettingScope::Person(other), json!(true)),
        ),
        ("the vault's row", at(key, SettingScope::Vault, json!(true))),
        (
            "a key set by the owner",
            SetSetting::vault_value("test.owner_number", json!(1)),
        ),
        (
            "a pin",
            SetSetting {
                mode: SettingMode::Pin,
                ..at(key, mine.clone(), json!(true))
            },
        ),
    ] {
        let refused = set_setting_as_person(&fx.vault, &fx.owner_proof, request)
            .expect_err("the person's change is refused");
        assert!(
            format!("{refused:?}").contains("a person sets only"),
            "{what}: {refused:?}"
        );
    }
    assert_eq!(
        get(&me, key, json!([person(fx.owner)]))["value"],
        json!(true)
    );
    assert_eq!(get(&me, key, json!([]))["value"], json!(false));
    assert_eq!(get(&me, "test.owner_number", json!([]))["value"], json!(7));
}

#[test]
fn a_read_below_the_vault_answers_what_the_vault_read_answers() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let place = EntityId::now();
    call(
        &me,
        SET,
        set("test.owner_number", project(place), json!(11)),
    );
    for known in [vec![], vec![SettingScope::Project(place)]] {
        let (through_vault, below) =
            owner_number_read_both_ways(&fx.vault, &known).expect("both reads");
        assert_eq!(through_vault, below, "{known:?}");
    }
    let (_, below) = owner_number_read_both_ways(&fx.vault, &[SettingScope::Project(place)])
        .expect("the project's read");
    assert_eq!(below.value, 11);
    assert_eq!(
        below.source,
        SettingSource::Row(SettingScope::Project(place))
    );
    let (_, below) = owner_number_read_both_ways(&fx.vault, &[]).expect("the vault's read");
    assert_eq!((below.value, below.source), (7, SettingSource::Default));
}

#[test]
fn a_secret_in_a_setting_value_never_lands_raw() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.member_banner";
    let token = "TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    match invoke(&me, SET, set(key, vault_scope(), json!(token))) {
        Ok(answer) => {
            assert_eq!(answer["status"], json!("applied"), "{answer}");
            let stored = get(&me, key, json!([]))["value"].clone();
            let text = stored.as_str().expect("a banner is text");
            assert!(
                !text.contains("ghp_0123456789"),
                "the wall lifted the token before the row was written: {text}"
            );
            assert!(!text.is_empty(), "the row holds the admitted value: {text}");
            assert_eq!(answer["value"], stored, "the answer shows the stored value");
        }
        Err(error) => assert_eq!(
            get(&me, key, json!([]))["value"],
            json!(""),
            "a refused change writes nothing: {error:?}"
        ),
    }
}

#[test]
fn an_after_commit_hook_runs_once_per_applied_change_and_reads_the_committed_value() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.after_commit";
    let before = after_commits();
    call(&me, SET, set(key, vault_scope(), json!(5)));
    assert_eq!(after_commits(), before + 1);
    assert_eq!(
        after_commit_seen(),
        5,
        "the hook's own read sees the committed value"
    );
    call(&me, SET, set(key, vault_scope(), json!(5)));
    assert_eq!(
        after_commits(),
        before + 1,
        "an equal value writes nothing and runs nothing"
    );

    let outcomes = set_settings_in_one_write(
        &fx.vault,
        &fx.owner_proof,
        &[
            SetSetting::vault_value(key, json!(6)),
            SetSetting::vault_value(key, json!(7)),
        ],
        false,
    )
    .expect("both changes commit");
    assert!(outcomes.iter().all(applied), "{outcomes:?}");
    assert_eq!(
        after_commits(),
        before + 3,
        "once per applied change, after the caller's write"
    );
    assert_eq!(after_commit_seen(), 7);

    set_settings_in_one_write(
        &fx.vault,
        &fx.owner_proof,
        &[SetSetting::vault_value(key, json!(8))],
        true,
    )
    .expect_err("the caller's write fails");
    assert_eq!(
        after_commits(),
        before + 3,
        "a write that failed runs nothing"
    );
    assert_eq!(get(&me, key, json!([]))["value"], json!(7));
}

#[cfg(feature = "sync")]
#[test]
fn a_leave_keeps_the_rows_of_a_key_about_this_machine() {
    assert!(leave_keeps_setting_row(
        "test.install_mode",
        SettingScope::Vault
    ));
    assert!(!leave_keeps_setting_row(
        "test.owner_number",
        SettingScope::Vault
    ));
    assert!(!leave_keeps_setting_row(
        "test.no_such_key",
        SettingScope::Vault
    ));
}
