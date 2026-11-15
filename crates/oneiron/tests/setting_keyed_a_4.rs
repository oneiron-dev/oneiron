//! DESIGN 15-setting-primitive, stage 4, lane SETTING-KEYED-A, PR K3b: the owner's graduation
//! threshold rows (ED-05, `EDIT_DISTANCE_GRADUATION_THRESHOLD`) become one setting,
//! `edit_distance.graduation.thresholds`, whose value is the list of rows.
//! - the owner sets the rows whole with `vault.settings.set`; the policy in force for a scope is
//!   the most specific row that governs it, and with no row the compiled catch-all;
//! - a value with a row that governs nothing, or two rows on one pattern, is refused, and the
//!   policy in force stays;
//! - the per-row verbs `vault.consent.graduation.policy.{set,clear}` are gone, and an agent's
//!   change waits on a check-in;
//! - an actor's hard erase takes every row whose pattern names that actor out of the value.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_keyed_a_4`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent_graduation::{DEFAULT_GRADUATION_STREAK_FLOOR, RampScope};
use oneiron::edit_distance::graduation::{
    ThresholdRow, WILDCARD_PATTERN, exact_pattern, graduation_policy_for, graduation_policy_rows,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{DeleteReason, EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const T0: u64 = 1_790_000_000;

const KEY: &str = "edit_distance.graduation.thresholds";
const OP_KIND: &str = "send_email";
const TARGET_CLASS: &str = "client_followup";

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
                    "agent_id": format!("keyed-a-graduation-agent-{}", id.to_hex()),
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

fn set(value: Value) -> Value {
    json!({ "key": KEY, "scope": { "kind": "vault" }, "value": value })
}

fn get(memory: &Memory<'_>) -> Value {
    call(memory, GET, json!({ "key": KEY }))
}

/// One threshold row as the setting's value spells it.
fn row(pattern: &str, streak: u32, guard: f32, backoff: [u64; 2]) -> Value {
    json!({
        "scope_pattern": pattern,
        "required_streak": streak,
        "posterior_guard": guard,
        "snooze_backoff_seconds": backoff,
    })
}

fn scope(actor: &str) -> RampScope {
    RampScope::new(OP_KIND, TARGET_CLASS, actor).expect("a scope")
}

fn patterns(rows: &[ThresholdRow]) -> Vec<&str> {
    rows.iter().map(|row| row.scope_pattern.as_str()).collect()
}

#[test]
fn the_owner_sets_the_threshold_rows_as_one_setting_and_the_policy_follows() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let exact = scope(&EntityId::now().to_hex());
    let sibling = scope(&EntityId::now().to_hex());
    let other_op =
        RampScope::new("archive_thread", TARGET_CLASS, exact.actor.clone()).expect("a scope");

    let fresh = get(&me);
    assert_eq!(fresh["value"], json!([]), "{fresh}");
    assert_eq!(fresh["source"], json!({ "from": "default" }), "{fresh}");
    let compiled = graduation_policy_for(&fx.vault, &exact).expect("policy read");
    assert_eq!(compiled.scope_pattern, WILDCARD_PATTERN);
    assert_eq!(compiled.required_streak, DEFAULT_GRADUATION_STREAK_FLOOR);

    let exact_row = row(&exact_pattern(&exact), 5, 0.25, [0, 0]);
    let op_row = row("send_email/*/*", 7, 0.5, [60, 120]);
    let applied = call(&me, SET, set(json!([exact_row, op_row])));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(
        get(&me)["value"],
        json!([op_row, exact_row]),
        "the value is stored pattern-ordered"
    );
    let rows = graduation_policy_rows(&fx.vault).expect("rows read");
    assert_eq!(
        patterns(&rows),
        vec!["send_email/*/*", exact_pattern(&exact).as_str()]
    );

    let for_exact = graduation_policy_for(&fx.vault, &exact).expect("policy read");
    assert_eq!(
        (
            for_exact.required_streak,
            for_exact.posterior_guard,
            for_exact.snooze_backoff_seconds
        ),
        (5, 0.25, [0, 0]),
        "the exact row governs its scope"
    );
    let for_sibling = graduation_policy_for(&fx.vault, &sibling).expect("policy read");
    assert_eq!(
        (
            for_sibling.scope_pattern.as_str(),
            for_sibling.required_streak,
            for_sibling.snooze_backoff_seconds
        ),
        ("send_email/*/*", 7, [60, 120]),
        "the op-kind row governs every other scope of its op kind"
    );
    assert_eq!(
        graduation_policy_for(&fx.vault, &other_op)
            .expect("policy read")
            .scope_pattern,
        WILDCARD_PATTERN,
        "a scope no row governs falls to the compiled catch-all"
    );

    let cleared = call(&me, SET, set(Value::Null));
    assert_eq!(cleared["status"], json!("applied"), "{cleared}");
    assert!(
        graduation_policy_rows(&fx.vault)
            .expect("rows read")
            .is_empty()
    );
    assert_eq!(
        graduation_policy_for(&fx.vault, &exact)
            .expect("policy read")
            .scope_pattern,
        WILDCARD_PATTERN,
        "a clear hands every scope back to the compiled catch-all"
    );
}

#[test]
fn a_value_with_a_row_that_governs_nothing_is_refused_and_the_policy_stays() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let exact = scope(&EntityId::now().to_hex());
    let kept = row(&exact_pattern(&exact), 5, 0.25, [0, 0]);
    let applied = call(&me, SET, set(json!([kept])));
    assert_eq!(applied["status"], json!("applied"), "{applied}");

    for (what, value, needle) in [
        (
            "a pattern of two axes",
            json!([row("send_email/*", 3, 0.5, [0, 0])]),
            "op_kind/target_class/actor",
        ),
        (
            "a streak of zero",
            json!([row("*/*/*", 0, 0.5, [0, 0])]),
            "zero clean rulings",
        ),
        (
            "a guard above one",
            json!([row("*/*/*", 3, 1.5, [0, 0])]),
            "probability",
        ),
        (
            "two rows on one pattern",
            json!([row("*/*/*", 3, 0.5, [0, 0]), row("*/*/*", 4, 0.5, [0, 0])]),
            "at most one",
        ),
        (
            "a field no row has",
            json!([{
                "scope_pattern": "*/*/*",
                "required_streak": 3,
                "posterior_guard": 0.5,
                "snooze_backoff_seconds": [0, 0],
                "floor": 1,
            }]),
            "floor",
        ),
    ] {
        let refusal = refused(&me, SET, set(value));
        assert!(refusal.contains(needle), "{what}: {refusal}");
    }

    assert_eq!(get(&me)["value"], json!([kept]), "the value in force stays");
    assert_eq!(
        graduation_policy_for(&fx.vault, &exact)
            .expect("policy read")
            .required_streak,
        5,
        "the policy in force stays"
    );
}

#[test]
fn the_per_row_verbs_are_gone_and_an_agents_change_waits_on_a_check_in() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    for (verb, input) in [
        (
            "vault.consent.graduation.policy.set",
            json!({ "policy": row("*/*/*", 3, 0.5, [0, 0]) }),
        ),
        (
            "vault.consent.graduation.policy.clear",
            json!({ "scope_pattern": "*/*/*" }),
        ),
    ] {
        assert!(
            invoke(&me, verb, input).is_err(),
            "{verb} is no longer a verb: the rows are one setting"
        );
    }
    assert!(
        graduation_policy_rows(&fx.vault)
            .expect("rows read")
            .is_empty()
    );

    let agent = fx.granted_agent();
    let them = fx.vault.memory(agent, EdgeActorClass::Agent);
    let pending = call(&them, SET, set(json!([row("*/*/*", 3, 0.5, [0, 0])])));
    assert_eq!(pending["status"], json!("pending"), "{pending}");
    assert_eq!(
        get(&me)["source"],
        json!({ "from": "default" }),
        "nothing applied"
    );
    assert!(
        graduation_policy_rows(&fx.vault)
            .expect("rows read")
            .is_empty(),
        "the agent's rows wait on the owner"
    );
}

#[test]
fn an_actors_erase_takes_its_rows_out_of_the_setting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    let owner = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    let actor = EntityId::now();
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let hex = actor.to_hex();
    let other = EntityId::now().to_hex();
    let rows = json!([
        row(&format!("{OP_KIND}/*/{hex}"), 4, 0.5, [0, 0]),
        row(&exact_pattern(&scope(&hex)), 5, 0.5, [0, 0]),
        row(&format!("{OP_KIND}/*/{other}"), 6, 0.5, [0, 0]),
        row("*/*/*", 9, 0.5, [0, 0]),
    ]);
    let applied = vault
        .set_setting(
            SettingCaller::Owner(&owner),
            SetSetting::vault_value(KEY, rows),
        )
        .expect("the owner sets the rows");
    assert!(
        matches!(applied, SetSettingOutcome::Applied { .. }),
        "{applied:?}"
    );
    assert_eq!(graduation_policy_rows(&vault).expect("rows read").len(), 4);

    // Every delete signs as this install first.
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault
        .delete_entity_with_reason(&actor, DeleteReason::UserHardDelete)
        .expect("the actor is hard-erased");

    let left = graduation_policy_rows(&vault).expect("rows read");
    assert_eq!(
        patterns(&left),
        vec!["*/*/*", format!("{OP_KIND}/*/{other}").as_str()],
        "the rows that named the erased actor are gone, the others stay"
    );
    assert!(
        !format!("{left:?}").contains(&hex),
        "no row names the erased actor"
    );
    assert_eq!(
        graduation_policy_for(&vault, &scope(&hex))
            .expect("policy read")
            .required_streak,
        9,
        "the erased actor's scope falls to the next row that governs it"
    );
}
