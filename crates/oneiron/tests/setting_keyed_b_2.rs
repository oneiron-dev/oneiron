//! DESIGN 15-setting-primitive, stage 4 (SETTING-KEYED-B, KB2): six tables become seven catalogue
//! keys, each read through its kept public reader or `vault.settings.get`.
//! - `memory.diary.read_review` (vault and agent rows), read by `Vault::agent_diary_read_review`;
//! - `agents.plan_mode` (vault and agent rows), read by `Vault::agent_plan_mode`;
//! - `disclosure.model_ceiling` (one dial per connection and class), read through
//!   `vault.settings.get`: with no row there is no dial;
//! - `sync.retained_work.wait_secs` (one wait per queue), read by `Vault::retained_work_wait_secs`;
//! - `origin.scan_threshold` (one threshold per engine scan), read by `Vault::scan_threshold`;
//! - `policy.notification.mode` and `policy.notification.digest_interval_secs` (vault and person
//!   rows, set by the subject), read through `vault.settings.get`.
//!
//! For each: the key is in the catalogue with its scopes, item, set_by and sync; with no row the
//! reader returns the old default; the owner's row, set through `Vault::set_setting`, is what the
//! reader returns; the old check refuses what it refused; a live person sets only their own
//! notification row; an agent's change of the plan mode waits on a check-in under its own Grant.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_keyed_b_2`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::AgentPlanMode;
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::disclosure::{DisclosureBand, DisclosureDataClass};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::policy_model::PolicyNotificationMode;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{
    ScopeKind, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope,
    SettingSync,
};
use oneiron::store::{DEFAULT_SCAN_CHECK_THRESHOLD, EngineScan, GateDecisionId};
use oneiron::sync::federation_burst::RetainedWorkQueue;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const DIARY: &str = "memory.diary.read_review";
const PLAN: &str = "agents.plan_mode";
const CEILING: &str = "disclosure.model_ceiling";
const WAIT: &str = "sync.retained_work.wait_secs";
const THRESHOLD: &str = "origin.scan_threshold";
const NOTIF_MODE: &str = "policy.notification.mode";
const NOTIF_INTERVAL: &str = "policy.notification.digest_interval_secs";
const T0: u64 = 1_790_000_000;

/// A temporary vault with a process-memory device keystore, as the crate's test opener opens one.
fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    (dir, vault)
}

/// The vault's embedded owner, authenticated: what an owner door takes.
fn embedded_owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

/// The owner sets `request` through `Vault::set_setting`: it applies.
fn set_applied(vault: &Vault, owner: &AuthenticatedOwner, request: SetSetting) {
    let outcome = vault
        .set_setting(SettingCaller::Owner(owner), request)
        .expect("the owner's write applies");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's write applies: {outcome:?}"
    );
}

/// The owner sets `request` through `Vault::set_setting`: it is refused.
fn set_refused(vault: &Vault, owner: &AuthenticatedOwner, request: SetSetting) -> String {
    format!(
        "{:?}",
        vault
            .set_setting(SettingCaller::Owner(owner), request)
            .expect_err("the write is refused")
    )
}

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
                    "agent_id": format!("keyed-b2-agent-{}", id.to_hex()),
                    "desc": "setting keyed-b2 fixture",
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

    /// A live person who is not the owner.
    fn person(&self) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .expect("person row");
        id
    }

    /// `person`'s proof: any live person authenticates, owner of the vault or not.
    fn person_proof(&self, person: EntityId) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("person proof")
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn vault_scope() -> Value {
    json!({ "kind": "vault" })
}

fn person_scope(id: EntityId) -> Value {
    json!({ "kind": "person", "id": id.to_hex() })
}

fn set(key: &str, scope: Value, value: Value) -> Value {
    json!({ "key": key, "scope": scope, "value": value })
}

fn get(memory: &Memory<'_>, key: &str, at: Value) -> Value {
    call(memory, GET, json!({ "key": key, "at": at }))
}

fn get_item(memory: &Memory<'_>, key: &str, item: &str, at: Value) -> Value {
    call(memory, GET, json!({ "key": key, "item": item, "at": at }))
}

fn mode_json(mode: PolicyNotificationMode) -> Value {
    serde_json::to_value(mode).expect("a mode encodes")
}

#[test]
fn the_diary_and_plan_keys_are_in_the_catalogue() {
    for key in [DIARY, PLAN] {
        let spec = oneiron::setting::spec_named(key).expect("the key is in the catalogue");
        assert!(
            spec.admits_scope(ScopeKind::Vault),
            "a vault row stands for {key}"
        );
        assert!(
            spec.admits_scope(ScopeKind::Agent),
            "an agent row stands for {key}"
        );
        assert!(
            !spec.admits_scope(ScopeKind::Person),
            "no person row stands for {key}"
        );
        assert!(spec.item.is_none(), "{key} is one setting, not a family");
        assert_eq!(spec.set_by, SetBy::Owner, "the owner sets {key}");
        assert_eq!(
            spec.sync,
            SettingSync::Vault,
            "{key} holds on every machine"
        );
        spec.check_item(None).expect("no item");
        assert!(spec.check_item(Some("x")).is_err(), "{key} takes no item");
    }
}

#[test]
fn the_item_keys_are_in_the_catalogue() {
    let probe = EntityId::now();

    let spec = oneiron::setting::spec_named(CEILING).expect("the ceiling is in the catalogue");
    assert!(
        spec.admits_scope(ScopeKind::Vault),
        "a vault row stands for {CEILING}"
    );
    assert!(
        !spec.admits_scope(ScopeKind::Agent),
        "no agent row stands for {CEILING}"
    );
    assert!(
        !spec.admits_scope(ScopeKind::Person),
        "no person row stands for {CEILING}"
    );
    assert_eq!(spec.set_by, SetBy::Owner, "the owner sets {CEILING}");
    assert_eq!(
        spec.sync,
        SettingSync::Vault,
        "{CEILING} holds on every machine"
    );
    let domain = spec.item.expect("the ceiling is a family");
    assert_eq!(
        domain.name, "model connection and data class",
        "the ceiling names its dials"
    );
    let dial = format!(
        "agent:{}/{}",
        probe.to_hex(),
        DisclosureDataClass::Names.as_str()
    );
    spec.check_item(Some(&dial)).expect("an agent dial stands");
    let whole = format!("owner:{0}/*", probe.to_hex());
    spec.check_item(Some(&whole))
        .expect("a whole-connection dial stands");
    for bad in [
        "bogus".to_owned(),
        "agent:zzz/names".to_owned(),
        format!("agent:{}/bogus", probe.to_hex()),
    ] {
        let refused = format!(
            "{:?}",
            spec.check_item(Some(&bad))
                .expect_err("a stray dial is refused")
        );
        assert!(
            refused.contains("not one of"),
            "a stray dial is refused: {refused}"
        );
    }

    let spec = oneiron::setting::spec_named(WAIT).expect("the wait is in the catalogue");
    assert!(
        spec.admits_scope(ScopeKind::Vault),
        "a vault row stands for {WAIT}"
    );
    assert!(
        !spec.admits_scope(ScopeKind::Agent),
        "no agent row stands for {WAIT}"
    );
    assert!(
        !spec.admits_scope(ScopeKind::Person),
        "no person row stands for {WAIT}"
    );
    assert_eq!(spec.set_by, SetBy::Owner, "the owner sets {WAIT}");
    assert_eq!(
        spec.sync,
        SettingSync::Vault,
        "{WAIT} holds on every machine"
    );
    let domain = spec.item.expect("the wait is a family");
    assert_eq!(
        domain.name, "retained work queue",
        "the wait names its queues"
    );
    for queue in ["federation_burst", "maintenance_ingest", "facet_stamp"] {
        spec.check_item(Some(queue)).expect("the queue stands");
    }
    let refused = format!(
        "{:?}",
        spec.check_item(Some("bogus"))
            .expect_err("a stray queue is refused")
    );
    assert!(
        refused.contains("not one of"),
        "a stray queue is refused: {refused}"
    );

    let spec = oneiron::setting::spec_named(THRESHOLD).expect("the threshold is in the catalogue");
    assert!(
        spec.admits_scope(ScopeKind::Vault),
        "a vault row stands for {THRESHOLD}"
    );
    assert!(
        !spec.admits_scope(ScopeKind::Agent),
        "no agent row stands for {THRESHOLD}"
    );
    assert!(
        !spec.admits_scope(ScopeKind::Person),
        "no person row stands for {THRESHOLD}"
    );
    assert_eq!(spec.set_by, SetBy::Owner, "the owner sets {THRESHOLD}");
    assert_eq!(
        spec.sync,
        SettingSync::Install,
        "{THRESHOLD} is this machine's"
    );
    let domain = spec.item.expect("the threshold is a family");
    assert_eq!(domain.name, "engine scan", "the threshold names its scans");
    spec.check_item(Some(EngineScan::TypeIndexRows.code()))
        .expect("a scan stands");
    let refused = format!(
        "{:?}",
        spec.check_item(Some(EngineScan::DependentWalkRows.code()))
            .expect_err("the dependent walk is refused")
    );
    assert!(
        refused.contains("not one of"),
        "the dependent walk keeps its own policy: {refused}"
    );
    let refused = format!(
        "{:?}",
        spec.check_item(Some("bogus"))
            .expect_err("a stray scan is refused")
    );
    assert!(
        refused.contains("not one of"),
        "a stray scan is refused: {refused}"
    );
}

#[test]
fn the_notification_keys_are_in_the_catalogue() {
    for key in [NOTIF_MODE, NOTIF_INTERVAL] {
        let spec = oneiron::setting::spec_named(key).expect("the key is in the catalogue");
        assert!(
            spec.admits_scope(ScopeKind::Vault),
            "a vault row stands for {key}"
        );
        assert!(
            spec.admits_scope(ScopeKind::Person),
            "a person row stands for {key}"
        );
        assert!(
            !spec.admits_scope(ScopeKind::Agent),
            "no agent row stands for {key}"
        );
        assert!(spec.item.is_none(), "{key} is one setting, not a family");
        assert_eq!(spec.set_by, SetBy::Subject, "the subject sets {key}");
        assert_eq!(
            spec.sync,
            SettingSync::Vault,
            "{key} holds on every machine"
        );
        spec.check_item(None).expect("no item");
        assert!(spec.check_item(Some("x")).is_err(), "{key} takes no item");
    }
}

#[test]
fn the_diary_review_reads_off_until_the_owners_row() {
    let (_dir, vault) = open_vault();
    let owner = embedded_owner_proof(&vault);
    let agent = EntityId::now();
    let other = EntityId::now();

    assert!(
        !vault.agent_diary_read_review(agent).expect("the read"),
        "with no row the review is off"
    );

    set_applied(
        &vault,
        &owner,
        SetSetting {
            key: DIARY.to_owned(),
            item: None,
            scope: SettingScope::Agent(agent),
            mode: SettingMode::Value,
            value: Some(json!(true)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert!(
        vault.agent_diary_read_review(agent).expect("the read"),
        "the agent's row is its review"
    );
    assert!(
        !vault.agent_diary_read_review(other).expect("the read"),
        "another agent keeps the default"
    );

    set_applied(
        &vault,
        &owner,
        SetSetting {
            key: DIARY.to_owned(),
            item: None,
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!(true)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert!(
        vault.agent_diary_read_review(other).expect("the read"),
        "the vault's row is every other agent's"
    );
}

#[test]
fn the_plan_mode_reads_optional_until_the_owners_row() {
    let (_dir, vault) = open_vault();
    let owner = embedded_owner_proof(&vault);
    let agent = EntityId::now();
    let other = EntityId::now();

    assert_eq!(
        vault.agent_plan_mode(agent).expect("the read"),
        AgentPlanMode::Optional,
        "with no row the mode is optional"
    );

    set_applied(
        &vault,
        &owner,
        SetSetting {
            key: PLAN.to_owned(),
            item: None,
            scope: SettingScope::Agent(agent),
            mode: SettingMode::Value,
            value: Some(json!("required")),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert_eq!(
        vault.agent_plan_mode(agent).expect("the read"),
        AgentPlanMode::Required,
        "the agent's row is its mode"
    );
    assert_eq!(
        vault.agent_plan_mode(other).expect("the read"),
        AgentPlanMode::Optional,
        "another agent keeps the default"
    );

    set_applied(
        &vault,
        &owner,
        SetSetting {
            key: PLAN.to_owned(),
            item: None,
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!("off")),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert_eq!(
        vault.agent_plan_mode(other).expect("the read"),
        AgentPlanMode::Off,
        "the vault's row is every other agent's"
    );
    assert_eq!(
        vault.agent_plan_mode(agent).expect("the read"),
        AgentPlanMode::Required,
        "the agent's own row still decides for it"
    );
}

#[test]
fn the_retained_work_wait_reads_its_default_until_the_owners_row() {
    let (_dir, vault) = open_vault();
    let owner = embedded_owner_proof(&vault);
    let queue = RetainedWorkQueue::FederationBurst;
    let other = RetainedWorkQueue::FacetStamp;

    assert_eq!(
        vault.retained_work_wait_secs(queue).expect("the read"),
        queue.default_wait_secs(),
        "with no row the queue's default holds"
    );
    assert_eq!(
        vault.retained_work_wait_secs(other).expect("the read"),
        other.default_wait_secs(),
        "another queue reads its own default"
    );

    set_applied(
        &vault,
        &owner,
        SetSetting {
            key: WAIT.to_owned(),
            item: Some(queue.code().to_owned()),
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!(12345)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert_eq!(
        vault.retained_work_wait_secs(queue).expect("the read"),
        12345,
        "the owner's row is the wait"
    );
    assert_eq!(
        vault.retained_work_wait_secs(other).expect("the read"),
        other.default_wait_secs(),
        "another queue keeps its default"
    );
}

#[test]
fn the_scan_threshold_reads_its_default_until_the_owners_row() {
    let (_dir, vault) = open_vault();
    let owner = embedded_owner_proof(&vault);
    let scan = EngineScan::TypeIndexRows;
    let other = EngineScan::RoomPageRows;

    assert_eq!(
        vault.scan_threshold(scan).expect("the read"),
        DEFAULT_SCAN_CHECK_THRESHOLD,
        "with no row the scan's default holds"
    );
    assert_eq!(
        vault.scan_threshold(other).expect("the read"),
        DEFAULT_SCAN_CHECK_THRESHOLD,
        "another scan reads its own default"
    );

    set_applied(
        &vault,
        &owner,
        SetSetting {
            key: THRESHOLD.to_owned(),
            item: Some(scan.code().to_owned()),
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!(42)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert_eq!(
        vault.scan_threshold(scan).expect("the read"),
        42,
        "the owner's row is the threshold"
    );
    assert_eq!(
        vault.scan_threshold(other).expect("the read"),
        DEFAULT_SCAN_CHECK_THRESHOLD,
        "another scan keeps its default"
    );

    let policy = vault.dependent_walk_policy().expect("the policy");
    assert_eq!(
        vault
            .scan_threshold(EngineScan::DependentWalkRows)
            .expect("the read"),
        policy.check_threshold,
        "the dependent walk reads its own policy"
    );
}

#[test]
fn the_ceiling_reads_no_dial_until_the_owners_row() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let agent = fx.agent();
    let dial = format!(
        "agent:{}/{}",
        agent.to_hex(),
        DisclosureDataClass::Names.as_str()
    );
    let whole = format!("agent:{0}/*", agent.to_hex());

    let unset = get_item(&me, CEILING, &dial, json!([]));
    assert_eq!(
        unset["value"],
        Value::Null,
        "with no row there is no dial: {unset}"
    );
    assert_eq!(unset["source"], json!({ "from": "default" }), "{unset}");

    let band = json!(DisclosureBand::Private.as_str());
    set_applied(
        &fx.vault,
        &fx.owner_proof,
        SetSetting {
            key: CEILING.to_owned(),
            item: Some(dial.clone()),
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(band.clone()),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    let set = get_item(&me, CEILING, &dial, json!([]));
    assert_eq!(set["value"], band, "the owner's row is the dial: {set}");
    assert_eq!(
        set["source"],
        json!({ "from": "row", "scope": vault_scope() }),
        "{set}"
    );

    let other = get_item(&me, CEILING, &whole, json!([]));
    assert_eq!(
        other["value"],
        Value::Null,
        "another dial keeps no dial: {other}"
    );
}

#[test]
fn the_notification_rows_read_their_defaults_until_the_owners_row() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let person = EntityId::now();
    let other = EntityId::now();

    let mode = get(&me, NOTIF_MODE, json!([person_scope(person)]));
    assert_eq!(
        mode["value"],
        mode_json(PolicyNotificationMode::Inherit),
        "with no row the mode inherits: {mode}"
    );
    assert_eq!(mode["source"], json!({ "from": "default" }), "{mode}");
    let interval = get(&me, NOTIF_INTERVAL, json!([person_scope(person)]));
    assert_eq!(
        interval["value"],
        Value::Null,
        "with no row the interval is the manifest's: {interval}"
    );
    assert_eq!(
        interval["source"],
        json!({ "from": "default" }),
        "{interval}"
    );

    set_applied(
        &fx.vault,
        &fx.owner_proof,
        SetSetting {
            key: NOTIF_MODE.to_owned(),
            item: None,
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(mode_json(PolicyNotificationMode::PushAll)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    set_applied(
        &fx.vault,
        &fx.owner_proof,
        SetSetting {
            key: NOTIF_INTERVAL.to_owned(),
            item: None,
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!(3600)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    let mode = get(&me, NOTIF_MODE, json!([person_scope(person)]));
    assert_eq!(
        mode["value"],
        mode_json(PolicyNotificationMode::PushAll),
        "the vault's row is every person's: {mode}"
    );
    let interval = get(&me, NOTIF_INTERVAL, json!([person_scope(person)]));
    assert_eq!(
        interval["value"],
        json!(3600),
        "the vault's interval is every person's: {interval}"
    );

    set_applied(
        &fx.vault,
        &fx.owner_proof,
        SetSetting {
            key: NOTIF_MODE.to_owned(),
            item: None,
            scope: SettingScope::Person(person),
            mode: SettingMode::Value,
            value: Some(mode_json(PolicyNotificationMode::Digest)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    let own = get(&me, NOTIF_MODE, json!([person_scope(person)]));
    assert_eq!(
        own["value"],
        mode_json(PolicyNotificationMode::Digest),
        "the person's row is its own: {own}"
    );
    let others = get(&me, NOTIF_MODE, json!([person_scope(other)]));
    assert_eq!(
        others["value"],
        mode_json(PolicyNotificationMode::PushAll),
        "another person keeps the vault's: {others}"
    );
}

#[test]
fn the_old_checks_refuse_what_they_refused() {
    let (_dir, vault) = open_vault();
    let owner = embedded_owner_proof(&vault);

    let zero = set_refused(
        &vault,
        &owner,
        SetSetting {
            key: WAIT.to_owned(),
            item: Some(RetainedWorkQueue::FederationBurst.code().to_owned()),
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!(0)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert!(
        zero.contains("greater than zero"),
        "a zero wait is refused: {zero}"
    );

    let stray_queue = set_refused(
        &vault,
        &owner,
        SetSetting {
            key: WAIT.to_owned(),
            item: Some("bogus".to_owned()),
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!(123)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert!(
        stray_queue.contains("not one of") && stray_queue.contains("retained work queue"),
        "a stray queue is refused: {stray_queue}"
    );

    let walk = set_refused(
        &vault,
        &owner,
        SetSetting {
            key: THRESHOLD.to_owned(),
            item: Some(EngineScan::DependentWalkRows.code().to_owned()),
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!(10)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert!(
        walk.contains("not one of") && walk.contains("engine scan"),
        "the dependent walk keeps its own policy: {walk}"
    );

    for bad in [json!(0), json!(31_536_001)] {
        let refused = set_refused(
            &vault,
            &owner,
            SetSetting {
                key: NOTIF_INTERVAL.to_owned(),
                item: None,
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value: Some(bad),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        );
        assert!(
            refused.contains("1 second to 365 days"),
            "a stray interval is refused: {refused}"
        );
    }

    let stray_dial = set_refused(
        &vault,
        &owner,
        SetSetting {
            key: CEILING.to_owned(),
            item: Some("bogus".to_owned()),
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!(DisclosureBand::Private.as_str())),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    );
    assert!(
        stray_dial.contains("not one of") && stray_dial.contains("model connection and data class"),
        "a stray dial is refused: {stray_dial}"
    );

    assert_eq!(
        vault
            .retained_work_wait_secs(RetainedWorkQueue::FederationBurst)
            .expect("the read"),
        RetainedWorkQueue::FederationBurst.default_wait_secs(),
        "nothing refused was written"
    );
    assert_eq!(
        vault
            .scan_threshold(EngineScan::TypeIndexRows)
            .expect("the read"),
        DEFAULT_SCAN_CHECK_THRESHOLD,
        "nothing refused was written"
    );
}

#[test]
fn a_person_sets_only_their_own_notification_row() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let person = fx.person();
    let proof = fx.person_proof(person);
    let other = fx.person();

    let outcome = fx
        .vault
        .set_setting(
            SettingCaller::Person(&proof),
            SetSetting {
                key: NOTIF_MODE.to_owned(),
                item: None,
                scope: SettingScope::Person(person),
                mode: SettingMode::Value,
                value: Some(mode_json(PolicyNotificationMode::Digest)),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
        .expect("a person sets their own row");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "a person sets their own row: {outcome:?}"
    );
    let own = get(&me, NOTIF_MODE, json!([person_scope(person)]));
    assert_eq!(
        own["value"],
        mode_json(PolicyNotificationMode::Digest),
        "the person's row is what the read returns: {own}"
    );

    let outcome = fx
        .vault
        .set_setting(
            SettingCaller::Person(&proof),
            SetSetting {
                key: NOTIF_INTERVAL.to_owned(),
                item: None,
                scope: SettingScope::Person(person),
                mode: SettingMode::Value,
                value: Some(json!(7200)),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
        .expect("a person sets their own interval");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "a person sets their own interval: {outcome:?}"
    );
    let interval = get(&me, NOTIF_INTERVAL, json!([person_scope(person)]));
    assert_eq!(
        interval["value"],
        json!(7200),
        "the person's interval is what the read returns: {interval}"
    );

    for key in [NOTIF_MODE, NOTIF_INTERVAL] {
        let value = if key == NOTIF_MODE {
            mode_json(PolicyNotificationMode::PushAll)
        } else {
            json!(3600)
        };
        let refused = format!(
            "{:?}",
            fx.vault
                .set_setting(
                    SettingCaller::Person(&proof),
                    SetSetting {
                        key: key.to_owned(),
                        item: None,
                        scope: SettingScope::Person(other),
                        mode: SettingMode::Value,
                        value: Some(value),
                        expected_revision: None,
                        why: None,
                        check_in_ref: None,
                    },
                )
                .expect_err("another person's row is refused")
        );
        assert!(
            refused.contains("a person sets only"),
            "another person's row is refused: {refused}"
        );
    }

    let others = get(&me, NOTIF_MODE, json!([person_scope(other)]));
    assert_eq!(
        others["value"],
        mode_json(PolicyNotificationMode::Inherit),
        "another person keeps the default: {others}"
    );
}

#[test]
fn an_agents_change_of_the_plan_mode_waits_on_a_check_in() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    fx.grant(agent, &[SET, GET]);
    let it = fx.as_agent(agent);

    let asked = call(&it, SET, set(PLAN, vault_scope(), json!("required")));
    assert_eq!(asked["status"], json!("pending"), "{asked}");
    assert_eq!(
        fx.vault.agent_plan_mode(agent).expect("the read"),
        AgentPlanMode::Optional,
        "a waiting change writes nothing"
    );
}
