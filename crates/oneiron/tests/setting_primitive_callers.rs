//! DESIGN 15-setting-primitive, stage 0.3: the Setting primitive's other callers and doors.
//! - the engine sets a value row of any key with no ask and no bound, records the ask it
//!   answers, never pins, and its row is the owner's to a holder;
//! - a live person sets only their own row of a key set by its subject, and only tighter;
//! - a read below the vault answers what the vault's read answers;
//! - the side-row wall reads every setting value before it is stored: a secret never lands raw;
//! - a key's after-commit hook runs once per applied change, after the write commits;
//! - a leave keeps the rows of a key about this machine and drops a vault key's;
//! - an agent whose Grant lists a key's own line sets its value rows as the owner does, never a
//!   pin, and the key's read line reads it; a line of another key, or none, asks;
//! - a dials key reads for a whole-vault grant naming any `engine.controls` class, not for a
//!   plain agent;
//! - a holder never raises a key past its default where the owner set no row;
//! - an erase takes the erased entity out of a value whose key says how.
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
use oneiron::setting::{
    SetSetting, SetSettingOutcome, SettingMode, SettingScope, SettingSource, get_line, set_line,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
#[cfg(feature = "sync")]
use oneiron::test_doors::setting::leave_keeps_setting_row;
use oneiron::test_doors::setting::{
    after_commit_seen, after_commits, erase_entity_from_settings, owner_number_read_both_ways,
    set_setting_as_engine, set_setting_as_person, set_settings_in_one_write,
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

/// `verb` refused for a reader who may not read the key, by the read's own refusal.
fn read_refused(memory: &Memory<'_>, verb: &str, input: Value) {
    let refused = invoke(memory, verb, input).expect_err("refused");
    assert!(
        format!("{refused:?}").contains("needs the owner"),
        "the read's own refusal: {refused:?}"
    );
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

#[test]
fn an_agent_whose_grant_lists_a_keys_line_sets_it_as_the_owner_and_its_read_line_reads_it() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.owner_number";
    call(&me, SET, set(key, vault_scope(), json!(3)));

    let lined = fx.agent();
    let budget = "test.work_budget";
    fx.grant(lined, &[SET, GET, &set_line(key), &set_line(budget)]);
    let them = fx.as_agent(lined);
    let replaced = call(&them, SET, set(key, vault_scope(), json!(9)));
    assert_eq!(
        replaced["status"],
        json!("applied"),
        "the line replaces the owner's row: {replaced}"
    );
    assert_eq!(get(&me, key, json!([]))["value"], json!(9));
    let listed = rows(&me, key);
    assert_eq!(listed[0]["setter"]["as"], json!("key_grant"), "{listed:?}");
    assert_eq!(listed[0]["by"], json!(lined.to_hex()), "{listed:?}");
    let pin = call(
        &them,
        SET,
        json!({ "key": key, "scope": vault_scope(), "pin": true, "value": 1 }),
    );
    assert_eq!(pin["status"], json!("pending"), "a line never pins: {pin}");
    let widened = call(&them, SET, set(budget, vault_scope(), json!(20)));
    assert_eq!(widened["status"], json!("applied"), "{widened}");
    assert_eq!(
        get(&me, budget, json!([]))["value"],
        json!(20),
        "its row is the owner's: no default caps it"
    );
    read_refused(&them, GET, json!({ "key": key }));

    let reader = fx.agent();
    fx.grant(reader, &[SET, GET, &get_line(key)]);
    let read = get(&fx.as_agent(reader), key, json!([]));
    assert_eq!(read["value"], json!(9), "the read line reads it: {read}");

    let unlined = fx.agent();
    fx.grant(unlined, &[SET, GET, &set_line("test.hooked")]);
    let asked = call(
        &fx.as_agent(unlined),
        SET,
        set(key, vault_scope(), json!(5)),
    );
    assert_eq!(
        asked["status"],
        json!("pending"),
        "another key's line asks: {asked}"
    );
    read_refused(&fx.as_agent(unlined), GET, json!({ "key": key }));
    assert_eq!(get(&me, key, json!([]))["value"], json!(9), "nothing moved");
}

#[test]
fn a_dials_key_reads_for_a_whole_vault_engine_controls_grant_and_not_for_a_plain_agent() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.dial_number";
    call(&me, SET, set(key, vault_scope(), json!(4)));

    let steward = fx.agent();
    fx.grant(steward, &[SET, GET]);
    fx.controls(steward, EngineControlClass::WakeCadence);
    let them = fx.as_agent(steward);
    assert_eq!(get(&them, key, json!([]))["value"], json!(4));
    read_refused(&them, GET, json!({ "key": "test.owner_number" }));

    let plain = fx.agent();
    fx.grant(plain, &[SET, GET]);
    read_refused(&fx.as_agent(plain), GET, json!({ "key": key }));
}

#[test]
fn a_holder_never_raises_a_key_past_its_default_where_the_owner_set_no_row() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let holder = fx.agent();
    fx.grant(holder, &[SET, GET]);
    fx.controls(holder, EngineControlClass::WorkBudget);
    let them = fx.as_agent(holder);
    // Default 10, lower is tighter.
    let key = "test.work_budget";
    let place = EntityId::now();

    let above = call(&them, SET, set(key, project(place), json!(12)));
    assert_eq!(
        above["status"],
        json!("pending"),
        "above the default: {above}"
    );
    let inside = call(&them, SET, set(key, project(place), json!(9)));
    assert_eq!(inside["status"], json!("applied"), "{inside}");

    call(&me, SET, set(key, vault_scope(), json!(20)));
    let raised = call(&them, SET, set(key, project(place), json!(15)));
    assert_eq!(
        raised["status"],
        json!("applied"),
        "inside the owner's row: {raised}"
    );
    assert_eq!(get(&them, key, json!([project(place)]))["value"], json!(15));

    call(&me, SET, json!({ "key": key, "scope": vault_scope() }));
    let capped = get(&them, key, json!([project(place)]));
    assert_eq!(
        capped["value"],
        json!(10),
        "the default caps the holder's row: {capped}"
    );
    assert_eq!(capped["source"], json!({ "from": "default" }));
    let stored = rows(&me, key);
    assert_eq!(stored.len(), 1, "the holder's row stays stored: {stored:?}");
    assert_eq!(stored[0]["value"], json!(15));
}

#[test]
fn an_erase_takes_the_erased_entity_out_of_a_value_whose_key_says_how() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.mentioned_ids";
    let (gone, kept) = (EntityId::now(), EntityId::now());
    call(
        &me,
        SET,
        set(key, vault_scope(), json!([gone.to_hex(), kept.to_hex()])),
    );
    let banner = format!("ask {}", gone.to_hex());
    call(
        &me,
        SET,
        set("test.member_banner", vault_scope(), json!(banner)),
    );
    let before = rows(&me, key)[0]["revision"].clone();

    erase_entity_from_settings(&fx.vault, gone).expect("the settings scrub");
    assert_eq!(get(&me, key, json!([]))["value"], json!([kept.to_hex()]));
    let after = rows(&me, key);
    assert_eq!(
        after[0]["revision"], before,
        "rewritten in place, with no change row: {after:?}"
    );
    assert_eq!(
        get(&me, "test.member_banner", json!([]))["value"],
        json!(banner),
        "a key with no erase rule keeps its value"
    );

    erase_entity_from_settings(&fx.vault, gone).expect("a second scrub");
    assert_eq!(
        rows(&me, key)[0]["revision"],
        before,
        "a value that no longer names it stays"
    );
}
