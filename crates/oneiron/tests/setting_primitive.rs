//! DESIGN 15-setting-primitive, stage 0.1: the Setting primitive through its public verbs.
//! - the owner sets, reads, lists and clears a key: the default reads until a row stands, every
//!   read names the row that decided it, a revision guards a change, an equal value writes
//!   nothing, a family key takes only its items, and the key's hook runs once per change;
//! - every change is one entry on the feeds' `settings` source, with the prior and new values;
//! - a live holder of the key's `engine.controls` class sets it inside the owner's cap, never
//!   replaces the owner's own row, and never pins; a key read by members reads for any agent;
//! - any other agent's change waits on a check-in under its own Grant, and applies once when the
//!   owner approves it; an agent whose Grant does not list the verb is refused;
//! - the owner's pin decides over every value row, and a row that does not decode reads the
//!   key's strictest value, never its default;
//! - a subject tightens its own row and asks to loosen it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_primitive`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::check_in::HolderAnswer;
use oneiron::claim::ScopedReadActorKey;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{EngineControlClass, Scope, ScopeAxis};
use oneiron::feeds::{
    FeedEntryKind, FeedRead, FeedReadRequest, FeedSelector, FeedSource, FeedStart,
    FeedSubscribeRequest,
};
use oneiron::memory::Memory;
use oneiron::setting::SettingScope;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{hooked_changes, plant_undecodable_row};
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
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("open vault");
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
            issuer,
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

    /// The owner's read lane, as a client holds it: a slip the host root mints for the owner.
    fn owner_key(&self) -> ScopedReadActorKey {
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("host root slip");
        let issued_at = self.vault.capability_slip_now().expect("authority clock");
        let mut claims = root.claims.clone();
        claims.slip_id = [0x5e; 32];
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("human".into());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + 3_600;
        claims.ttl_secs = 3_600;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's slip");
        let challenge = b"setting-test";
        let proof = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        let verified = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
            .expect("verified slip");
        ScopedReadActorKey::from_verified_slip(&verified).expect("owner key")
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

fn vault_scope() -> Value {
    json!({ "kind": "vault" })
}

fn project(id: EntityId) -> Value {
    json!({ "kind": "project", "id": id.to_hex() })
}

fn agent_scope(id: EntityId) -> Value {
    json!({ "kind": "agent", "id": id.to_hex() })
}

fn set(key: &str, scope: Value, value: Value) -> Value {
    json!({ "key": key, "scope": scope, "value": value })
}

fn get(memory: &Memory<'_>, key: &str, at: Value) -> Value {
    call(memory, GET, json!({ "key": key, "at": at }))
}

#[test]
fn the_owner_sets_reads_lists_and_clears_a_key() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.owner_number";

    let unset = get(&me, key, json!([]));
    assert_eq!(unset["value"], json!(7), "{unset}");
    assert_eq!(unset["source"], json!({ "from": "default" }));
    assert_eq!(unset["revision"], json!(0));

    let applied = call(&me, SET, set(key, vault_scope(), json!(9)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let revision = applied["revision"].as_u64().expect("a revision");
    assert!(revision > 0);
    assert_eq!(applied["sequence"], json!(revision));
    let read = get(&me, key, json!([]));
    assert_eq!(read["value"], json!(9));
    assert_eq!(
        read["source"],
        json!({ "from": "row", "scope": { "kind": "vault" } })
    );
    assert_eq!(read["revision"], json!(revision));

    let again = call(&me, SET, set(key, vault_scope(), json!(9)));
    assert_eq!(
        again["sequence"],
        Value::Null,
        "an equal value writes nothing"
    );
    assert_eq!(again["revision"], json!(revision));

    let moved = refused(
        &me,
        SET,
        json!({ "key": key, "scope": vault_scope(), "value": 10, "expected_revision": revision + 7 }),
    );
    assert!(moved.contains("revision"), "{moved}");

    let place = EntityId::now();
    call(&me, SET, set(key, project(place), json!(11)));
    assert_eq!(get(&me, key, json!([project(place)]))["value"], json!(11));
    assert_eq!(get(&me, key, json!([]))["value"], json!(9));

    let listed = call(&me, LIST, json!({ "prefix": "test.owner" }));
    let keys = listed["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 1, "{listed}");
    assert_eq!(keys[0]["key"], json!(key));
    assert_eq!(keys[0]["default"], json!(7));
    assert_eq!(keys[0]["set_by"], json!("owner"));
    assert_eq!(keys[0]["rows"].as_array().expect("rows").len(), 2);
    assert_eq!(keys[0]["value"]["value"], json!(9));

    let cleared = call(
        &me,
        SET,
        json!({ "key": key, "scope": vault_scope(), "value": null }),
    );
    assert_eq!(cleared["revision"], json!(0), "{cleared}");
    assert_eq!(
        get(&me, key, json!([]))["source"],
        json!({ "from": "default" })
    );

    assert!(
        refused(&me, SET, set("test.no_such_key", vault_scope(), json!(1)))
            .contains("no setting key")
    );
    refused(&me, SET, set(key, agent_scope(fx.owner), json!(1)));
    call(
        &me,
        SET,
        json!({ "key": "test.channel_wait", "item": "mail", "scope": vault_scope(), "value": 30 }),
    );
    refused(
        &me,
        SET,
        json!({ "key": "test.channel_wait", "item": "sms", "scope": vault_scope(), "value": 30 }),
    );
    let mail = call(
        &me,
        GET,
        json!({ "key": "test.channel_wait", "item": "mail" }),
    );
    assert_eq!(mail["value"], json!(30));
    let chat = call(
        &me,
        GET,
        json!({ "key": "test.channel_wait", "item": "chat" }),
    );
    assert_eq!(chat["value"], json!(0), "another item reads the default");

    let before = hooked_changes();
    call(&me, SET, set("test.hooked", vault_scope(), json!(1)));
    call(&me, SET, set("test.hooked", vault_scope(), json!(1)));
    call(&me, SET, set("test.hooked", vault_scope(), json!(2)));
    assert_eq!(
        hooked_changes() - before,
        2,
        "the hook runs once per change"
    );
}

#[test]
fn every_change_is_one_entry_on_the_settings_feed() {
    let fx = Fixture::rooted();
    let key = fx.owner_key();
    let subscription = fx
        .vault
        .feed_subscribe(
            &fx.vault.scoped_read(key.clone()),
            &FeedSubscribeRequest {
                selector: FeedSelector {
                    sources: vec![FeedSource::Settings],
                    kinds: Vec::new(),
                    entity_types: Vec::new(),
                    predicates: Vec::new(),
                },
                start: FeedStart::Beginning,
            },
        )
        .expect("subscribe")
        .subscription;
    let me = fx.as_owner();
    call(&me, SET, set("test.owner_number", vault_scope(), json!(9)));
    call(&me, SET, set("test.owner_number", vault_scope(), json!(9)));
    call(&me, SET, set("test.owner_number", vault_scope(), json!(12)));

    let read = fx
        .vault
        .feed_read(
            &fx.vault.scoped_read(key),
            &FeedReadRequest {
                subscription,
                limit: None,
            },
        )
        .expect("feed read");
    let FeedRead::Page(page) = read else {
        panic!("a page, not {read:?}");
    };
    let changes: Vec<_> = page
        .entries
        .iter()
        .filter(|entry| entry.kind == FeedEntryKind::Setting)
        .filter_map(|entry| entry.setting.clone())
        .collect();
    assert_eq!(changes.len(), 2, "the equal value wrote no entry: {page:?}");
    assert_eq!(changes[0].key, "test.owner_number");
    assert_eq!(changes[0].scope, SettingScope::Vault);
    assert_eq!(changes[0].prior, Value::Null);
    assert_eq!(changes[0].value, json!(9));
    assert_eq!(changes[1].prior, json!(9));
    assert_eq!(changes[1].value, json!(12));
    assert!(changes[0].sequence < changes[1].sequence);
}

#[test]
fn a_class_holder_sets_inside_the_owners_cap_and_never_replaces_the_owners_row() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let holder = fx.agent();
    fx.grant(holder, &[SET, GET]);
    fx.controls(holder, EngineControlClass::WorkBudget);
    let them = fx.as_agent(holder);
    let key = "test.work_budget";
    let place = EntityId::now();

    let applied = call(&them, SET, set(key, project(place), json!(4)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(get(&them, key, json!([project(place)]))["value"], json!(4));

    call(&me, SET, set(key, vault_scope(), json!(8)));
    let above = call(&them, SET, set(key, project(place), json!(9)));
    assert_eq!(
        above["status"],
        json!("pending"),
        "above the owner's cap: {above}"
    );
    let owners = call(&them, SET, set(key, vault_scope(), json!(5)));
    assert_eq!(
        owners["status"],
        json!("pending"),
        "the owner's own row: {owners}"
    );
    let pin = call(
        &them,
        SET,
        json!({ "key": key, "scope": project(place), "pin": true, "value": 3 }),
    );
    assert_eq!(
        pin["status"],
        json!("pending"),
        "a pin is the owner's: {pin}"
    );

    call(&me, SET, set(key, vault_scope(), json!(2)));
    let capped = get(&them, key, json!([project(place)]));
    assert_eq!(
        capped["value"],
        json!(2),
        "the owner's lower cap decides: {capped}"
    );
    assert_eq!(
        capped["source"],
        json!({ "from": "row", "scope": { "kind": "vault" } })
    );

    let other = fx.agent();
    fx.grant(other, &[SET, GET]);
    let stranger = fx.as_agent(other);
    refused(&stranger, GET, json!({ "key": key }));
    call(
        &me,
        SET,
        set("test.member_banner", vault_scope(), json!("hello")),
    );
    assert_eq!(
        get(&stranger, "test.member_banner", json!([]))["value"],
        json!("hello"),
        "a key read by members reads for any agent"
    );
    let listed = call(&stranger, LIST, json!({ "prefix": "test." }));
    let names: Vec<&str> = listed["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .filter_map(|entry| entry["key"].as_str())
        .collect();
    assert!(names.contains(&"test.member_banner"), "{names:?}");
    assert!(!names.contains(&"test.work_budget"), "{names:?}");
}

#[test]
fn any_other_agent_change_waits_on_a_check_in_and_applies_once_approved() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let asker = fx.agent();
    fx.grant(asker, &[SET, GET]);
    let them = fx.as_agent(asker);
    let key = "test.owner_number";
    let ask = set(key, vault_scope(), json!(21));

    let pending = call(&them, SET, ask.clone());
    assert_eq!(pending["status"], json!("pending"), "{pending}");
    let handle = pending["check_in"].as_str().expect("a handle").to_owned();
    let again = call(&them, SET, ask.clone());
    assert_eq!(
        again["check_in"],
        json!(handle),
        "the same ask finds its check-in"
    );
    assert_eq!(
        get(&me, key, json!([]))["value"],
        json!(7),
        "nothing applied yet"
    );

    let id = EntityId::from_hex(&handle).expect("hex id");
    let row = fx
        .vault
        .pending_check_in(&id)
        .expect("read")
        .expect("the pending check-in");
    oneiron::test_doors::check_in::answer_verified(
        &fx.vault,
        &fx.owner_proof,
        &id,
        &row.effect_digest,
        HolderAnswer::Approve,
    )
    .expect("the owner approves");

    let mut other_value = ask.clone();
    other_value["value"] = json!(22);
    other_value["check_in_ref"] = json!(handle);
    refused(&them, SET, other_value);
    let mut spend = ask;
    spend["check_in_ref"] = json!(handle);
    let applied = call(&them, SET, spend.clone());
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(get(&me, key, json!([]))["value"], json!(21));
    let listed = call(&me, LIST, json!({ "prefix": key }));
    assert_eq!(
        listed["keys"][0]["rows"][0]["setter"],
        json!({ "as": "approved", "check_in": handle })
    );
    spend["value"] = json!(23);
    refused(&them, SET, spend);

    let ungranted = fx.agent();
    fx.grant(ungranted, &[GET]);
    refused(
        &fx.as_agent(ungranted),
        SET,
        set(key, vault_scope(), json!(5)),
    );
}

#[test]
fn the_owners_pin_decides_and_an_unreadable_row_reads_the_strictest_value() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let holder = fx.agent();
    fx.grant(holder, &[SET, GET]);
    fx.controls(holder, EngineControlClass::WorkBudget);
    let place = EntityId::now();
    let key = "test.work_budget";

    call(
        &fx.as_agent(holder),
        SET,
        set(key, project(place), json!(6)),
    );
    call(
        &me,
        SET,
        json!({ "key": key, "scope": vault_scope(), "pin": true, "value": 9 }),
    );
    let pinned = get(&me, key, json!([project(place)]));
    assert_eq!(pinned["value"], json!(9), "{pinned}");
    assert_eq!(
        pinned["source"],
        json!({ "from": "pin", "scope": { "kind": "vault" } })
    );

    plant_undecodable_row(&fx.vault, "test.owner_number", SettingScope::Vault)
        .expect("a damaged row");
    let damaged = get(&me, "test.owner_number", json!([]));
    assert_eq!(
        damaged["value"],
        json!(0),
        "the strictest value, never the default: {damaged}"
    );
    assert_eq!(
        damaged["source"],
        json!({ "from": "unreadable", "scope": { "kind": "vault" } })
    );
    let replaced = call(&me, SET, set("test.owner_number", vault_scope(), json!(7)));
    assert!(
        replaced["sequence"].as_u64().is_some(),
        "a set replaces an unreadable row even with the default's value: {replaced}"
    );
}

#[test]
fn a_subject_tightens_its_own_row_and_asks_to_loosen_it() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    fx.grant(agent, &[SET, GET]);
    let them = fx.as_agent(agent);
    let key = "test.agent_quiet";

    let quiet = call(&them, SET, set(key, agent_scope(agent), json!(true)));
    assert_eq!(quiet["status"], json!("applied"), "{quiet}");
    let own = get(&them, key, json!([agent_scope(agent)]));
    assert_eq!(own["value"], json!(true));
    let loud = call(&them, SET, set(key, agent_scope(agent), json!(false)));
    assert_eq!(loud["status"], json!("pending"), "loosening asks: {loud}");

    let other = fx.agent();
    let theirs = call(&them, SET, set(key, agent_scope(other), json!(true)));
    assert_eq!(
        theirs["status"],
        json!("pending"),
        "another's row asks: {theirs}"
    );
}
