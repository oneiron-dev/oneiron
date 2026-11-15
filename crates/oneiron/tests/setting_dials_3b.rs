//! DESIGN 15-setting-primitive, stage 2, lane SETTING-DIALS PR D3b: four `settings/` rows that
//! need the 0.3 items become catalogue keys.
//! - `recall.non_base_world_claim_fraction`, `snapshot_read.bounds`, `context_board.layout` and
//!   `models.owner_fallback` are in the catalogue and read their old defaults, through the verb
//!   and through each kept reader; the verbs they replace are gone;
//! - the owner sets the fraction, a holder of any `engine.controls` class reads it (a dial), and
//!   a fraction out of 0..=1 is refused;
//! - a holder of `engine.controls.work_budget` lowers the snapshot bounds and raises its own
//!   lowering back up to the defaults, never above; the owner raises them; once the owner's row
//!   stands, the holder's change asks;
//! - an owner's agent override must name an agent the vault holds, the owner route keeps the other
//!   layers, and an erase of the agent takes its override out of the value;
//! - the engine applies the owner's `use_fallback` answer as the setter `engine` naming the ask,
//!   the kept reader returns it, and an item that is no offer's key is refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dials_3b`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::context_board::BoardLayout;
use oneiron::federation::{EngineControlClass, Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::settings::BoardLayoutSettings;
use oneiron::settings::non_base_world_claim_fraction::NonBaseWorldClaimFraction;
use oneiron::settings::snapshot_read::SnapshotReadSettings;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::erase_entity_from_settings;
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
const LIST: &str = "vault.settings.list";
const T0: u64 = 1_790_000_000;

const FRACTION: &str = "recall.non_base_world_claim_fraction";
const BOUNDS: &str = "snapshot_read.bounds";
const BOARD: &str = "context_board.layout";
const FALLBACK: &str = "models.owner_fallback";
/// An offer's key: 64 lowercase hex.
const OFFER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const MODEL: &str = "dials-provider/dials-model@r1";

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
                    "agent_id": format!("dials3b-agent-{}", id.to_hex()),
                    "desc": "setting dials 3b fixture",
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

fn set(key: &str, value: Value) -> Value {
    json!({ "key": key, "scope": { "kind": "vault" }, "value": value })
}

fn set_item(key: &str, item: &str, value: Value) -> Value {
    json!({ "key": key, "item": item, "scope": { "kind": "vault" }, "value": value })
}

fn get(memory: &Memory<'_>, key: &str) -> Value {
    call(memory, GET, json!({ "key": key }))
}

fn json_of<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("the value encodes")
}

/// The stored rows of `key`, as `vault.settings.list` answers them.
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

/// The snapshot bounds with `page_rows` changed.
fn bounds_with_page_rows(page_rows: u32) -> Value {
    json_of(&SnapshotReadSettings {
        page_rows,
        ..SnapshotReadSettings::DEFAULT
    })
}

/// A board layout that gives the tasks section `share_pct` of the cap.
fn tasks_layout(share_pct: u8) -> Value {
    json!({ "sections": { "tasks": { "share_pct": share_pct } } })
}

#[test]
fn the_four_keys_read_their_old_defaults_and_their_verbs_are_gone() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let fraction = get(&me, FRACTION);
    assert_eq!(fraction["value"], json!({ "fraction": 0.5 }), "{fraction}");
    assert_eq!(
        fraction["source"],
        json!({ "from": "default" }),
        "{fraction}"
    );
    assert_eq!(
        fx.vault.non_base_world_claim_fraction().expect("read"),
        NonBaseWorldClaimFraction::DEFAULT
    );

    let bounds = get(&me, BOUNDS);
    assert_eq!(
        bounds["value"],
        json_of(&SnapshotReadSettings::DEFAULT),
        "{bounds}"
    );
    assert_eq!(
        fx.vault.snapshot_read_settings().expect("read"),
        SnapshotReadSettings::DEFAULT
    );

    let board = get(&me, BOARD);
    assert_eq!(
        board["value"],
        json_of(&BoardLayoutSettings::default()),
        "{board}"
    );
    assert_eq!(
        fx.vault.board_layout_settings().expect("read"),
        BoardLayoutSettings::default()
    );

    let fallback = call(&me, GET, json!({ "key": FALLBACK, "item": OFFER }));
    assert_eq!(fallback["value"], Value::Null, "{fallback}");
    assert_eq!(fx.vault.model_fallback(OFFER).expect("read"), None);

    for verb in [
        "vault.settings.non_base_world_claim_fraction",
        "vault.settings.non_base_world_claim_fraction.set",
        "vault.settings.snapshot_read",
        "vault.settings.snapshot_read.replace",
        "vault.settings.snapshot_read.lower",
    ] {
        refused(&me, verb, json!({ "fraction": 0.25 }));
    }
}

#[test]
fn the_owner_sets_the_fraction_and_a_controls_holder_reads_it() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let applied = call(&me, SET, set(FRACTION, json!({ "fraction": 0.25 })));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(
        fx.vault
            .non_base_world_claim_fraction()
            .expect("read")
            .fraction,
        0.25
    );
    for out_of_range in [json!({ "fraction": 1.5 }), json!({ "fraction": -0.1 })] {
        refused(&me, SET, set(FRACTION, out_of_range));
    }
    assert_eq!(get(&me, FRACTION)["value"], json!({ "fraction": 0.25 }));

    let steward = fx.agent();
    fx.grant(steward, &[SET, GET]);
    fx.controls(steward, EngineControlClass::WakeCadence);
    let them = fx.as_agent(steward);
    assert_eq!(get(&them, FRACTION)["value"], json!({ "fraction": 0.25 }));
    let asked = call(&them, SET, set(FRACTION, json!({ "fraction": 1.0 })));
    assert_eq!(
        asked["status"],
        json!("pending"),
        "the owner alone sets it: {asked}"
    );

    let plain = fx.agent();
    fx.grant(plain, &[SET, GET]);
    refused(&fx.as_agent(plain), GET, json!({ "key": FRACTION }));
}

#[test]
fn a_work_budget_holder_tunes_the_snapshot_bounds_inside_the_cap() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let holder = fx.agent();
    fx.grant(holder, &[SET, GET]);
    fx.controls(holder, EngineControlClass::WorkBudget);
    let them = fx.as_agent(holder);

    let lowered = call(&them, SET, set(BOUNDS, bounds_with_page_rows(100)));
    assert_eq!(lowered["status"], json!("applied"), "{lowered}");
    assert_eq!(
        fx.vault.snapshot_read_settings().expect("read").page_rows,
        100
    );
    let back_up = call(&them, SET, set(BOUNDS, bounds_with_page_rows(200)));
    assert_eq!(
        back_up["status"],
        json!("applied"),
        "a holder raises its own lowering back up to the default: {back_up}"
    );
    let above = call(&them, SET, set(BOUNDS, bounds_with_page_rows(300)));
    assert_eq!(
        above["status"],
        json!("pending"),
        "above the default asks: {above}"
    );
    assert_eq!(
        fx.vault.snapshot_read_settings().expect("read").page_rows,
        200
    );

    let raised = call(&me, SET, set(BOUNDS, bounds_with_page_rows(400)));
    assert_eq!(raised["status"], json!("applied"), "{raised}");
    assert_eq!(
        fx.vault.snapshot_read_settings().expect("read").page_rows,
        400
    );
    let under_owner = call(&them, SET, set(BOUNDS, bounds_with_page_rows(300)));
    assert_eq!(
        under_owner["status"],
        json!("pending"),
        "the owner's row stands: only the owner, or an approved ask, replaces it: {under_owner}"
    );
    assert_eq!(get(&them, BOUNDS)["value"], bounds_with_page_rows(400));

    let lifetime_past_most = json_of(&SnapshotReadSettings {
        default_lifetime_secs: 7_200,
        ..SnapshotReadSettings::DEFAULT
    });
    refused(&me, SET, set(BOUNDS, lifetime_past_most));
    refused(&me, SET, set(BOUNDS, bounds_with_page_rows(0)));
}

#[test]
fn an_agent_override_names_a_held_agent_and_its_erase_takes_it_out() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let agent = fx.agent();

    let mut board = json_of(&BoardLayoutSettings::default());
    board["agent_override_layouts"] =
        json!([{ "agent": agent.to_hex(), "layout": tasks_layout(30) }]);
    let applied = call(&me, SET, set(BOARD, board));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let settings = fx.vault.board_layout_settings().expect("read");
    assert_eq!(settings.agent_override_layouts.len(), 1, "{settings:?}");
    assert!(
        settings.override_for(agent).sections.contains_key("tasks"),
        "{settings:?}"
    );

    let stranger = EntityId::now();
    let mut foreign = json_of(&settings);
    foreign["agent_override_layouts"] = json!([
        { "agent": agent.to_hex(), "layout": tasks_layout(30) },
        { "agent": stranger.to_hex(), "layout": tasks_layout(20) },
    ]);
    if stranger < agent {
        foreign["agent_override_layouts"] = json!([
            { "agent": stranger.to_hex(), "layout": tasks_layout(20) },
            { "agent": agent.to_hex(), "layout": tasks_layout(30) },
        ]);
    }
    let refusal = refused(&me, SET, set(BOARD, foreign));
    assert!(refusal.contains("no agent the vault holds"), "{refusal}");

    let capped = fx
        .vault
        .set_board_layout_settings(&fx.owner_proof, Some(Some(5_000)), None, None, None)
        .expect("the owner route sets the cap");
    assert_eq!(capped.cap_tok, Some(5_000));
    assert_eq!(
        capped.agent_override_layouts, settings.agent_override_layouts,
        "the other layers stay"
    );
    let one_more: BoardLayout = serde_json::from_value(tasks_layout(10)).expect("a board layout");
    let refused_route = fx.vault.set_board_layout_settings(
        &fx.owner_proof,
        None,
        None,
        None,
        Some((stranger, Some(one_more))),
    );
    assert!(refused_route.is_err(), "{refused_route:?}");

    erase_entity_from_settings(&fx.vault, agent).expect("the erase scrub runs");
    let erased = fx.vault.board_layout_settings().expect("read");
    assert!(erased.agent_override_layouts.is_empty(), "{erased:?}");
    assert_eq!(erased.cap_tok, Some(5_000), "the other layers stay");
}

#[test]
fn the_engine_applies_the_owners_fallback_answer() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    fx.vault
        .answer_model_fallback(OFFER, T0, MODEL)
        .expect("the engine applies the answer");
    assert_eq!(
        fx.vault.model_fallback(OFFER).expect("read").as_deref(),
        Some(MODEL)
    );
    let read = call(&me, GET, json!({ "key": FALLBACK, "item": OFFER }));
    assert_eq!(read["value"], json!(MODEL), "{read}");
    let stored = rows(&me, FALLBACK);
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(stored[0]["item"], json!(OFFER), "{stored:?}");
    assert_eq!(stored[0]["setter"]["as"], json!("engine"), "{stored:?}");
    assert!(
        stored[0]["setter"]["ask"].is_string(),
        "the change names the answered question: {stored:?}"
    );

    assert!(fx.vault.model_fallback("not-an-offer").is_err());
    refused(&me, GET, json!({ "key": FALLBACK, "item": "not-an-offer" }));
    assert!(
        fx.vault
            .answer_model_fallback("not-an-offer", T0, MODEL)
            .is_err()
    );

    let other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let owner_set = call(&me, SET, set_item(FALLBACK, other, json!(MODEL)));
    assert_eq!(owner_set["status"], json!("applied"), "{owner_set}");
    let asker = fx.agent();
    fx.grant(asker, &[SET, GET]);
    let asked = call(
        &fx.as_agent(asker),
        SET,
        set_item(FALLBACK, OFFER, Value::Null),
    );
    assert_eq!(asked["status"], json!("pending"), "an owner act: {asked}");
    assert_eq!(
        fx.vault.model_fallback(OFFER).expect("read").as_deref(),
        Some(MODEL)
    );
}
