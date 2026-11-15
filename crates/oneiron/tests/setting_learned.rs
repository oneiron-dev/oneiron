//! DESIGN 15-setting-primitive, stage 3a: learned keys in the Setting primitive (ARCH-0003
//! `#learning-settings`).
//! - once a cell's fit has runs of its own it decides at its place, before the seed there, and
//!   the read names that cell; the owner's pin decides over it, and the read still shows the fit;
//! - a seed at a narrower place decides over a fit at a wider one; a goal's cell is keyed with
//!   the read's project, and a task type's cell comes first at each place;
//! - a fit with no runs is passed over; one outside the key's range is clamped into it;
//! - a learned key's seed carries a weight in runs and a pin none; a value outside the range, a
//!   weight on a pin, a clear or a key that is not learned are refused; the weight is part of
//!   the row;
//! - the seed a fit starts from is the narrowest seed on the chain, with its weight, never a pin;
//! - every learned key in the catalogue sits only where a fit's cell is keyed, has no item, and
//!   its default lies in its range.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_learned`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::memory::Memory;
use oneiron::setting::{FitCell, LEARNED_SCOPES, SettingScope, catalogue};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{learned_rate_seed, put_setting_fit};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const SET: &str = "vault.settings.set";
const KEY: &str = "test.learned_rate";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
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
        vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            _issuer: issuer,
            owner,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn id(&self) -> EntityId {
        self.vault.new_entity_id().expect("entity id")
    }

    /// Caches the fit `value` from `runs` runs in `cell`.
    fn fit(&self, cell: &FitCell, value: f64, runs: f64) {
        put_setting_fit(&self.vault, KEY, cell, value, runs).expect("the fit is cached");
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, input: Value, says: &str) {
    let error = invoke(memory, SET, input.clone()).expect_err("the change is refused");
    assert!(
        format!("{error:?}").contains(says),
        "{input}: refused for another reason: {error:?}"
    );
}

fn vault_scope() -> Value {
    json!({ "kind": "vault" })
}

fn project(id: EntityId) -> Value {
    json!({ "kind": "project", "id": id.to_hex() })
}

fn goal(id: EntityId) -> Value {
    json!({ "kind": "goal", "id": id.to_hex() })
}

fn task_type(node: &str) -> Value {
    json!({ "kind": "task_type", "id": node })
}

/// The owner's seed of `value` with `weight` runs at `scope`.
fn seed(memory: &Memory<'_>, scope: Value, value: f64, weight: f64) -> Value {
    call(
        memory,
        SET,
        json!({ "key": KEY, "scope": scope, "value": value, "weight_runs": weight }),
    )
}

fn pin(memory: &Memory<'_>, scope: Value, value: f64) -> Value {
    call(
        memory,
        SET,
        json!({ "key": KEY, "scope": scope, "pin": true, "value": value }),
    )
}

fn get(memory: &Memory<'_>, at: Value) -> Value {
    call(memory, GET, json!({ "key": KEY, "at": at }))
}

fn cell(project: Option<EntityId>, goal: Option<EntityId>, task_type: Option<&str>) -> FitCell {
    FitCell {
        project,
        goal,
        task_type: task_type.map(str::to_owned),
    }
}

/// The source a read names for a fit learned in `cell`.
fn fit_source(cell: &FitCell) -> Value {
    json!({ "from": "fit", "scope": cell })
}

/// The catalogue entry of `key`, as the owner lists it.
fn entry(memory: &Memory<'_>, key: &str) -> Value {
    let listed = call(memory, LIST, json!({ "prefix": key }));
    listed["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .find(|entry| entry["key"] == json!(key))
        .cloned()
        .unwrap_or_else(|| panic!("{key} is listed: {listed}"))
}

#[test]
fn a_fit_with_runs_decides_over_the_seed_at_its_place_and_the_owners_pin_over_the_fit() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let read = get(&me, json!([]));
    assert_eq!(read["value"], json!(0.05), "the catalogue seed: {read}");
    assert_eq!(read["source"], json!({ "from": "default" }), "{read}");
    assert!(read.get("fit").is_none(), "no fit yet: {read}");

    seed(&me, vault_scope(), 0.2, 10.0);
    let read = get(&me, json!([]));
    assert_eq!(read["value"], json!(0.2), "the owner's seed: {read}");
    assert_eq!(
        read["source"],
        json!({ "from": "row", "scope": vault_scope() })
    );

    let vault_cell = cell(None, None, None);
    fx.fit(&vault_cell, 0.3, 4.0);
    let read = get(&me, json!([]));
    assert_eq!(
        read["value"],
        json!(0.3),
        "the fit decides over the seed: {read}"
    );
    assert_eq!(read["source"], fit_source(&vault_cell), "{read}");
    assert_eq!(read["revision"], json!(0), "no row decided: {read}");
    assert_eq!(
        read["fit"],
        json!({ "value": 0.3, "runs": 4.0, "cell": vault_cell })
    );

    pin(&me, vault_scope(), 0.9);
    let read = get(&me, json!([]));
    assert_eq!(read["value"], json!(0.9), "the owner's pin decides: {read}");
    assert_eq!(
        read["source"],
        json!({ "from": "pin", "scope": vault_scope() })
    );
    assert_eq!(
        read["fit"],
        json!({ "value": 0.3, "runs": 4.0, "cell": vault_cell }),
        "the fit stays visible beside the pin: {read}"
    );
}

#[test]
fn a_narrower_seed_decides_over_a_wider_fit_and_a_narrower_fit_over_a_wider_seed() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let (place, aim) = (fx.id(), fx.id());
    fx.fit(&cell(None, None, None), 0.3, 4.0);
    seed(&me, project(place), 0.6, 5.0);
    let read = get(&me, json!([project(place)]));
    assert_eq!(read["value"], json!(0.6), "the project's seed: {read}");
    assert_eq!(
        read["source"],
        json!({ "from": "row", "scope": project(place) })
    );
    assert_eq!(
        read["fit"]["cell"],
        json!(cell(None, None, None)),
        "the vault's fit shows: {read}"
    );
    assert_eq!(
        get(&me, json!([]))["value"],
        json!(0.3),
        "the vault reads its fit"
    );

    let project_cell = cell(Some(place), None, None);
    fx.fit(&project_cell, 0.7, 2.0);
    let read = get(&me, json!([project(place)]));
    assert_eq!(read["value"], json!(0.7), "the project's fit: {read}");
    assert_eq!(read["source"], fit_source(&project_cell), "{read}");

    let typed_cell = cell(Some(place), None, Some("node"));
    fx.fit(&typed_cell, 0.8, 2.0);
    let read = get(&me, json!([project(place), task_type("node")]));
    assert_eq!(read["value"], json!(0.8), "the typed cell first: {read}");
    assert_eq!(read["source"], fit_source(&typed_cell), "{read}");
    let read = get(&me, json!([project(place), task_type("other")]));
    assert_eq!(
        read["source"],
        fit_source(&project_cell),
        "another type falls to the project's own cell: {read}"
    );

    let goal_cell = cell(Some(place), Some(aim), None);
    fx.fit(&goal_cell, 0.4, 1.0);
    let read = get(&me, json!([goal(aim), project(place), task_type("node")]));
    assert_eq!(
        read["value"],
        json!(0.4),
        "the goal's cell, keyed with the read's project: {read}"
    );
    assert_eq!(read["source"], fit_source(&goal_cell), "{read}");

    seed(&me, goal(aim), 0.1, 3.0);
    let read = get(&me, json!([goal(aim), project(place)]));
    assert_eq!(
        read["source"],
        fit_source(&goal_cell),
        "the goal's fit decides over the goal's own seed: {read}"
    );
}

#[test]
fn a_fit_with_no_runs_is_passed_over_and_one_outside_the_range_is_clamped() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let vault_cell = cell(None, None, None);
    fx.fit(&vault_cell, 0.3, 0.0);
    let read = get(&me, json!([]));
    assert_eq!(read["value"], json!(0.05), "no runs, no fit: {read}");
    assert_eq!(read["source"], json!({ "from": "default" }), "{read}");
    assert!(read.get("fit").is_none(), "{read}");

    fx.fit(&vault_cell, 1.7, 3.0);
    let read = get(&me, json!([]));
    assert_eq!(read["value"], json!(1.0), "clamped into [0, 1]: {read}");
    assert_eq!(read["source"], fit_source(&vault_cell), "{read}");
}

#[test]
fn a_learned_seed_carries_a_weight_and_a_pin_none() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let says = "carries a weight in runs, finite and above zero";
    refused(
        &me,
        json!({ "key": KEY, "scope": vault_scope(), "value": 0.2 }),
        says,
    );
    for weight in [0.0, -1.0] {
        refused(
            &me,
            json!({ "key": KEY, "scope": vault_scope(), "value": 0.2, "weight_runs": weight }),
            says,
        );
    }
    let only = "only a seed of a learned key carries a weight in runs";
    refused(
        &me,
        json!({ "key": KEY, "scope": vault_scope(), "pin": true, "value": 0.2, "weight_runs": 2.0 }),
        only,
    );
    refused(
        &me,
        json!({ "key": KEY, "scope": vault_scope(), "weight_runs": 2.0 }),
        only,
    );
    refused(
        &me,
        json!({ "key": "test.owner_number", "scope": vault_scope(), "value": 3, "weight_runs": 2.0 }),
        only,
    );
    refused(
        &me,
        json!({ "key": KEY, "scope": vault_scope(), "value": 1.5, "weight_runs": 2.0 }),
        "lies in [0, 1]",
    );

    let first = seed(&me, vault_scope(), 0.2, 10.0);
    assert_eq!(first["status"], json!("applied"), "{first}");
    let rows = entry(&me, KEY)["rows"].clone();
    assert_eq!(
        rows[0]["weight_runs"],
        json!(10.0),
        "the weight is stored: {rows}"
    );
    let same = seed(&me, vault_scope(), 0.2, 10.0);
    assert_eq!(same["sequence"], Value::Null, "nothing to write: {same}");
    let reweighed = seed(&me, vault_scope(), 0.2, 20.0);
    assert!(
        reweighed["sequence"].is_u64(),
        "a new weight is a change of the row: {reweighed}"
    );
    let pinned = pin(&me, vault_scope(), 0.5);
    assert_eq!(
        pinned["status"],
        json!("applied"),
        "a pin takes no weight: {pinned}"
    );
}

#[test]
fn the_seed_a_fit_starts_from_is_the_narrowest_seed_with_its_weight_never_a_pin() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let place = fx.id();
    let at_place = [SettingScope::Project(place)];
    assert_eq!(learned_rate_seed(&fx.vault, &at_place).expect("seed"), None);
    seed(&me, vault_scope(), 0.2, 10.0);
    assert_eq!(
        learned_rate_seed(&fx.vault, &at_place).expect("seed"),
        Some((0.2, 10.0))
    );
    seed(&me, project(place), 0.6, 5.0);
    assert_eq!(
        learned_rate_seed(&fx.vault, &at_place).expect("seed"),
        Some((0.6, 5.0))
    );
    assert_eq!(
        learned_rate_seed(&fx.vault, &[]).expect("seed"),
        Some((0.2, 10.0)),
        "the vault's own seed"
    );
    pin(&me, project(place), 0.9);
    assert_eq!(
        learned_rate_seed(&fx.vault, &at_place).expect("seed"),
        Some((0.6, 5.0)),
        "a pin is no seed"
    );
}

#[test]
fn every_learned_key_sits_where_a_fit_is_keyed_has_no_item_and_a_default_in_its_range() {
    let fx = Fixture::rooted();
    let mut learned = Vec::new();
    for spec in catalogue() {
        let Some(range) = spec.kind.learned_range() else {
            continue;
        };
        learned.push(spec.name);
        assert!(
            spec.item.is_none(),
            "{}: a learned key has no item",
            spec.name
        );
        assert!(
            spec.scopes.iter().all(|kind| LEARNED_SCOPES.contains(kind)),
            "{}: a learned key sits only where a fit's cell is keyed",
            spec.name
        );
        let default = spec
            .kind
            .default_value()
            .expect("default")
            .decode::<f64>()
            .expect("a learned key's default is a number");
        assert!(range.contains(default), "{}: default {default}", spec.name);
    }
    assert!(learned.contains(&KEY), "{learned:?}");
    assert_eq!(
        entry(&fx.as_owner(), KEY)["learned"],
        json!({ "min": 0.0, "max": 1.0 }),
        "the catalogue shows the range"
    );
}
