//! DESIGN 15-setting-primitive, stage 6.0: the order of a key and the one rule for every move.
//! - a read meets every value row its scope reaches with the vault's value or the default, and
//!   names the row that holds the result, or `met` when no single row does;
//! - a holder's tightening lands at once and is receipted `tighter`; its loosening waits on a
//!   check-in, and lands receipted `looser` once approved;
//! - clearing a row below the vault drops a bound: a loose move;
//! - a neutral key's moves land for a holder, receipted `neutral`; a key with no order has no safe
//!   move, so an agent holder asks for every move (AUTH-1 = A);
//! - an agent that holds nothing proposes both ways; the subject of a row narrows it at once and
//!   asks to loosen it;
//! - a custom key judges a move by its comparator;
//! - a request is met with the value in force, says when it was clamped, and never reaches a key
//!   with no meet;
//! - an approval spends only over the row it was asked over;
//! - over a row the owner set, a non-owner makes no widening: a person tightens the owner's row
//!   of their own choice and is refused a loosening;
//! - every catalogue key states an order its read can keep, and the list shows it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_order`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::check_in::HolderAnswer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{EngineControlClass, Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::setting::{
    ChangeDirection, Order, Quorum, ScopeKind, SetSetting, SetSettingOutcome, Setter, SettingScope,
    SettingSource, catalogue,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    custom_window_requested, ordered_cap_requested, set_setting_as_person, setting_change,
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

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> String {
    format!(
        "{:?}",
        invoke(memory, verb, input).expect_err("the call is refused")
    )
}

fn vault_scope() -> Value {
    json!({ "kind": "vault" })
}

fn world(id: EntityId) -> Value {
    json!({ "kind": "world", "id": id.to_hex() })
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

fn clear(key: &str, scope: Value) -> Value {
    json!({ "key": key, "scope": scope })
}

fn get(memory: &Memory<'_>, key: &str, at: Value) -> Value {
    call(memory, GET, json!({ "key": key, "at": at }))
}

/// The status of a change's answer.
fn status(outcome: &Value) -> &str {
    outcome["status"].as_str().unwrap_or_default()
}

/// The direction the change of `outcome` recorded.
fn direction(fx: &Fixture, outcome: &Value) -> Option<ChangeDirection> {
    let sequence = outcome["sequence"]
        .as_u64()
        .expect("an applied change's sequence");
    setting_change(&fx.vault, sequence)
        .expect("the change stream reads")
        .expect("the change stands")
        .direction
}

/// The owner approves the check-in `outcome` names.
fn approve(fx: &Fixture, outcome: &Value) -> String {
    let handle = outcome["check_in"].as_str().expect("a handle").to_owned();
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
    handle
}

/// A holder of the work-budget class, as its handle.
fn holder(fx: &Fixture) -> EntityId {
    let agent = fx.agent();
    fx.grant(agent, &[SET, GET]);
    fx.controls(agent, EngineControlClass::WorkBudget);
    agent
}

#[test]
fn a_read_meets_every_row_its_scope_reaches_and_names_the_row_that_holds_the_value() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.ordered_cap";
    let (place, room) = (EntityId::now(), EntityId::now());

    call(&me, SET, set(key, world(place), json!(5)));
    call(&me, SET, set(key, vault_scope(), json!(3)));
    let unbound = get(&me, key, json!([world(place)]));
    assert_eq!(
        unbound["value"],
        json!(3),
        "a world row of 5 under a vault of 3: {unbound}"
    );
    assert_eq!(
        unbound["source"],
        json!({ "from": "row", "scope": vault_scope() })
    );
    call(&me, SET, set(key, world(place), json!(10)));
    call(&me, SET, set(key, vault_scope(), json!(30)));
    let bound = get(&me, key, json!([world(place)]));
    assert_eq!(
        bound["value"],
        json!(10),
        "the world row binds once the vault is looser: {bound}"
    );
    call(&me, SET, set(key, project(room), json!(4)));
    let narrowest = get(&me, key, json!([project(room), world(place)]));
    assert_eq!(narrowest["value"], json!(4));
    assert_eq!(
        narrowest["source"],
        json!({ "from": "row", "scope": project(room) })
    );

    let permits = "test.permit_list";
    call(
        &me,
        SET,
        set(permits, vault_scope(), json!(["read", "send"])),
    );
    call(
        &me,
        SET,
        set(permits, project(room), json!(["send", "share"])),
    );
    let met = get(&me, permits, json!([project(room)]));
    assert_eq!(met["value"], json!(["send"]), "the intersection: {met}");
    assert_eq!(met["source"], json!({ "from": "met" }));

    let bounds = "test.bounds";
    call(
        &me,
        SET,
        set(
            bounds,
            vault_scope(),
            json!({ "max_open": 8, "floor_secs": 20 }),
        ),
    );
    call(
        &me,
        SET,
        set(
            bounds,
            project(room),
            json!({ "max_open": 4, "floor_secs": 5 }),
        ),
    );
    let parts = get(&me, bounds, json!([project(room)]));
    assert_eq!(
        parts["value"],
        json!({ "max_open": 4, "floor_secs": 20 }),
        "part by part: {parts}"
    );
    assert_eq!(parts["source"], json!({ "from": "met" }));
}

#[test]
fn a_holders_tightening_lands_at_once_and_its_loosening_lands_receipted_looser_once_approved() {
    let fx = Fixture::rooted();
    let agent = holder(&fx);
    let them = fx.as_agent(agent);
    let key = "test.ordered_cap";

    let tighter = call(&them, SET, set(key, vault_scope(), json!(6)));
    assert_eq!(status(&tighter), "applied", "{tighter}");
    assert_eq!(direction(&fx, &tighter), Some(ChangeDirection::Tighter));

    let ask = set(key, vault_scope(), json!(9));
    let pending = call(&them, SET, ask.clone());
    assert_eq!(
        status(&pending),
        "pending",
        "a loosening asks the user: {pending}"
    );
    assert_eq!(
        get(&fx.as_owner(), key, json!([]))["value"],
        json!(6),
        "nothing moved yet"
    );
    let handle = approve(&fx, &pending);
    let mut spend = ask;
    spend["check_in_ref"] = json!(handle);
    let looser = call(&them, SET, spend);
    assert_eq!(status(&looser), "applied", "{looser}");
    assert_eq!(direction(&fx, &looser), Some(ChangeDirection::Looser));
    let sequence = looser["sequence"].as_u64().expect("sequence");
    let change = setting_change(&fx.vault, sequence)
        .expect("read")
        .expect("change");
    assert!(
        matches!(change.setter, Setter::Approved { .. }),
        "{change:?}"
    );
    assert_eq!(get(&fx.as_owner(), key, json!([]))["value"], json!(9));

    let owner = call(&fx.as_owner(), SET, set(key, vault_scope(), json!(20)));
    assert_eq!(
        direction(&fx, &owner),
        Some(ChangeDirection::Looser),
        "the owner's widening is receipted"
    );
}

#[test]
fn clearing_a_row_below_the_vault_drops_a_bound_and_is_a_loose_move() {
    let fx = Fixture::rooted();
    let agent = holder(&fx);
    let them = fx.as_agent(agent);
    let key = "test.ordered_cap";
    let room = EntityId::now();

    let added = call(&them, SET, set(key, project(room), json!(4)));
    assert_eq!(status(&added), "applied", "{added}");
    assert_eq!(direction(&fx, &added), Some(ChangeDirection::Tighter));
    let cleared = call(&them, SET, clear(key, project(room)));
    assert_eq!(
        status(&cleared),
        "pending",
        "a clear drops a bound: {cleared}"
    );
    let owners = call(&fx.as_owner(), SET, clear(key, project(room)));
    assert_eq!(status(&owners), "applied", "{owners}");
    assert_eq!(direction(&fx, &owners), Some(ChangeDirection::Looser));
}

#[test]
fn a_neutral_key_moves_at_once_for_a_holder_and_a_key_with_no_order_asks_for_every_move() {
    let fx = Fixture::rooted();
    let agent = holder(&fx);
    let them = fx.as_agent(agent);

    let neutral = call(
        &them,
        SET,
        set("test.neutral_label", vault_scope(), json!("fancy")),
    );
    assert_eq!(status(&neutral), "applied", "{neutral}");
    assert_eq!(direction(&fx, &neutral), Some(ChangeDirection::Neutral));

    let key = "test.class_number";
    let asked = call(&them, SET, set(key, vault_scope(), json!(3)));
    assert_eq!(
        status(&asked),
        "pending",
        "no order, no safe move (AUTH-1 = A): {asked}"
    );
    let owners = call(&fx.as_owner(), SET, set(key, vault_scope(), json!(3)));
    assert_eq!(status(&owners), "applied", "{owners}");
    assert_eq!(direction(&fx, &owners), Some(ChangeDirection::Unordered));
}

#[test]
fn an_agent_that_holds_nothing_proposes_both_ways_and_a_rows_subject_only_narrows_it() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    fx.grant(agent, &[SET, GET]);
    let them = fx.as_agent(agent);

    let tighter = call(&them, SET, set("test.ordered_cap", vault_scope(), json!(2)));
    assert_eq!(
        status(&tighter),
        "pending",
        "a free safe move is only for a holder's row or the actor's own: {tighter}"
    );

    let key = "test.agent_cap";
    let own = call(&them, SET, set(key, agent_scope(agent), json!(4)));
    assert_eq!(
        status(&own),
        "applied",
        "the subject narrows its own row: {own}"
    );
    assert_eq!(direction(&fx, &own), Some(ChangeDirection::Tighter));
    assert_eq!(
        get(&fx.as_owner(), key, json!([agent_scope(agent)]))["value"],
        json!(4)
    );
    let raised = call(&them, SET, set(key, agent_scope(agent), json!(6)));
    assert_eq!(
        status(&raised),
        "pending",
        "and asks to loosen it: {raised}"
    );
    let other = fx.agent();
    let theirs = call(&them, SET, set(key, agent_scope(other), json!(1)));
    assert_eq!(status(&theirs), "pending", "another's row: {theirs}");
}

#[test]
fn a_custom_key_judges_a_move_by_its_comparator_and_has_one_slot() {
    let fx = Fixture::rooted();
    let agent = holder(&fx);
    let them = fx.as_agent(agent);
    let key = "test.custom_window";

    let shorter = call(&them, SET, set(key, vault_scope(), json!(8)));
    assert_eq!(status(&shorter), "applied", "{shorter}");
    assert_eq!(direction(&fx, &shorter), Some(ChangeDirection::Tighter));
    let longer = call(&them, SET, set(key, vault_scope(), json!(12)));
    assert_eq!(status(&longer), "pending", "{longer}");
    let refusal = refused(&them, SET, set(key, project(EntityId::now()), json!(1)));
    assert!(
        refusal.contains("has no rows at a project scope"),
        "{refusal}"
    );
}

#[test]
fn a_request_is_met_with_the_value_in_force_and_says_when_it_was_clamped() {
    let fx = Fixture::rooted();
    call(
        &fx.as_owner(),
        SET,
        set("test.ordered_cap", vault_scope(), json!(6)),
    );

    let over = ordered_cap_requested(&fx.vault, &[], 9).expect("a request");
    assert_eq!((over.value, over.clamped), (6, true), "{over:?}");
    assert_eq!(
        over.in_force.source,
        SettingSource::Row(SettingScope::Vault)
    );
    let under = ordered_cap_requested(&fx.vault, &[], 4).expect("a request");
    assert_eq!((under.value, under.clamped), (4, false), "{under:?}");
    let refusal = custom_window_requested(&fx.vault, 4).expect_err("no meet, no request");
    assert!(
        format!("{refusal:?}").contains("a request cannot narrow it"),
        "{refusal:?}"
    );
}

#[test]
fn an_approval_spends_only_over_the_row_it_was_asked_over() {
    let fx = Fixture::rooted();
    let agent = holder(&fx);
    let them = fx.as_agent(agent);
    let key = "test.ordered_cap";
    call(&fx.as_owner(), SET, set(key, vault_scope(), json!(6)));

    let ask = set(key, vault_scope(), json!(9));
    let pending = call(&them, SET, ask.clone());
    assert_eq!(status(&pending), "pending", "{pending}");
    let handle = approve(&fx, &pending);
    call(&fx.as_owner(), SET, set(key, vault_scope(), json!(7)));
    let mut spend = ask;
    spend["check_in_ref"] = json!(handle);
    let moved = refused(&them, SET, spend);
    assert!(!moved.is_empty());
    assert_eq!(
        get(&fx.as_owner(), key, json!([]))["value"],
        json!(7),
        "the owner's later row stands"
    );
}

#[test]
fn every_catalogue_key_states_an_order_its_read_can_keep_and_the_list_shows_it() {
    for spec in catalogue() {
        assert_eq!(
            spec.quorum,
            Quorum::One,
            "{}: quorum all waits for its count (6d-1)",
            spec.name
        );
        if spec.kind.order() == Order::Custom {
            assert!(
                spec.scopes.iter().all(|kind| *kind == ScopeKind::Vault),
                "{}: a custom key has one slot, at the vault",
                spec.name
            );
        }
    }
    let fx = Fixture::rooted();
    let listed = call(
        &fx.as_owner(),
        LIST,
        json!({ "prefix": "test.ordered_cap" }),
    );
    assert_eq!(listed["keys"][0]["order"], json!("lower"), "{listed}");
    assert_eq!(listed["keys"][0]["quorum"], json!("one"), "{listed}");
}

#[test]
fn over_a_row_the_owner_set_a_person_tightens_it_and_is_refused_a_loosening() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let key = "test.person_quiet";
    let mine = SettingScope::Person(fx.owner);
    let scope = json!({ "kind": "person", "id": fx.owner.to_hex() });
    let row = |value: Value| SetSetting {
        scope: mine.clone(),
        ..SetSetting::vault_value(key, value)
    };

    call(&me, SET, set(key, scope.clone(), json!(false)));
    let tighter = set_setting_as_person(&fx.vault, &fx.owner_proof, row(json!(true)))
        .expect("a person tightens the owner's row of their own choice");
    assert!(
        matches!(tighter, SetSettingOutcome::Applied { .. }),
        "{tighter:?}"
    );
    call(&me, SET, set(key, scope.clone(), json!(true)));
    let refused = set_setting_as_person(&fx.vault, &fx.owner_proof, row(json!(false)))
        .expect_err("over the owner's row a person makes no widening");
    assert!(
        format!("{refused:?}").contains("a person sets only"),
        "{refused:?}"
    );
    assert_eq!(get(&me, key, json!([scope]))["value"], json!(true));
}
