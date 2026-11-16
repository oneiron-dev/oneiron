//! DESIGN 15-setting-primitive, stage 3 (SETTING-PLAIN PLAIN-4): the 40 learned knobs of
//! `LEARNING_SETTING` are learned Setting keys, and the engine's readers read them through the
//! Setting walk.
//! - each knob is a learned catalogue key at the goal, project, task type and vault places, its
//!   shipped seed inside its range; the 18 undotted names took a dot at their domain word; a
//!   holder of a knob's `engine.controls` class sets it, and every other knob is the owner's;
//! - the engine's reader answers the shipped seed, then the owner's seed, then the owner's pin,
//!   and a clear brings back what stands beneath;
//! - a sourced read cites no row for the shipped seed and the setting change that wrote the
//!   deciding seed or pin;
//! - the learning verbs refuse a knob, which is set with `settings.set`, and keep the owner's
//!   spawn choices.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_plain_4`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::dreamer_runner::maintenance::agent_health::{HEALTH_LOOP_REPEATS, HEALTH_OWNER_COPY};
use oneiron::federation::EngineControlClass;
use oneiron::learning_setting::setting_value;
use oneiron::memory::Memory;
use oneiron::setting::{LEARNED_SCOPES, SetBy, spec_named};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::learning_setting_sourced::setting_value_sourced;
use oneiron::test_doors::setting::setting_change;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const SET: &str = "vault.settings.set";
const LEARNING_PUT: &str = "vault.settings.learning.put";
const LOOP_REPEATS: &str = "health.loop.repeats";

/// Every learned knob, by its catalogue name, with the class whose holder may set it.
const KNOBS: [(&str, Option<EngineControlClass>); 40] = [
    ("attribution.unclear_floor", None),
    (
        "contribution.check_rate",
        Some(EngineControlClass::MaintenanceCadence),
    ),
    ("credit.decay", None),
    ("credit.enabled", None),
    (
        "credit.depth_cap",
        Some(EngineControlClass::MaintenanceCadence),
    ),
    (
        "credit.check_every_hop",
        Some(EngineControlClass::MaintenanceCadence),
    ),
    ("group_commit.window_ms", None),
    ("group_commit.max_writes", None),
    (
        "learning.window_half_life_days",
        Some(EngineControlClass::MaintenanceCadence),
    ),
    (
        "learning.shipped_prior_runs",
        Some(EngineControlClass::MaintenanceCadence),
    ),
    (
        "learning.borrowed_prior_runs",
        Some(EngineControlClass::MaintenanceCadence),
    ),
    ("planner.solo_success_floor", None),
    ("planner.solo_margin", None),
    ("planner.big_plan_width", None),
    ("audit.rate", Some(EngineControlClass::MaintenanceCadence)),
    ("exploration.ask.climb_hours", None),
    ("exploration.ask.lapse_hours", None),
    ("eval_floor.min_families", None),
    ("eval_floor.min_families_per_slice", None),
    ("health.review", Some(EngineControlClass::WakeCadence)),
    ("health.loop.repeats", Some(EngineControlClass::WakeCadence)),
    ("health.check.fails", Some(EngineControlClass::WakeCadence)),
    ("health.wait.share", Some(EngineControlClass::WakeCadence)),
    ("health.wait.minutes", Some(EngineControlClass::WakeCadence)),
    (
        "health.silent.minutes",
        Some(EngineControlClass::WakeCadence),
    ),
    (
        "health.widen.denials",
        Some(EngineControlClass::WakeCadence),
    ),
    ("health.cost.spike", Some(EngineControlClass::WakeCadence)),
    (
        "health.escalate.ttl_hours",
        Some(EngineControlClass::WakeCadence),
    ),
    ("health.card.floor", Some(EngineControlClass::WakeCadence)),
    ("health.dup.min_cost", Some(EngineControlClass::WakeCadence)),
    ("health.card.owner_copy", None),
    (
        "health.review.window_hours",
        Some(EngineControlClass::WakeCadence),
    ),
    (
        "health.cost.min_runs",
        Some(EngineControlClass::WakeCadence),
    ),
    (
        "health.trend.period_days",
        Some(EngineControlClass::WakeCadence),
    ),
    (
        "coach.tradeoff_reminder_hours",
        Some(EngineControlClass::WakeCadence),
    ),
    (
        "coach.attribution_label_receipts",
        Some(EngineControlClass::WakeCadence),
    ),
    ("esign.ask.climb_hours", None),
    (
        "question.call_budget_ms",
        Some(EngineControlClass::WorkBudget),
    ),
    (
        "detector.centroid.min_similarity",
        Some(EngineControlClass::WakeCadence),
    ),
    ("linker.vector.margin", None),
];

/// The names the 18 undotted knobs had before stage 3.
const OLD_NAMES: [&str; 18] = [
    "attribution_unclear_floor",
    "contribution_check_rate",
    "credit_decay",
    "credit_enabled",
    "credit_depth_cap",
    "credit_check_every_hop",
    "group_commit_window_ms",
    "group_commit_max_writes",
    "learning_window_half_life_days",
    "learning_shipped_prior_runs",
    "learning_borrowed_prior_runs",
    "planner_solo_success_floor",
    "planner_solo_margin",
    "planner_big_plan_width",
    "audit_rate",
    "eval_floor_min_families",
    "eval_floor_min_families_per_slice",
    "question_call_budget_ms",
];

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned (as
    /// tests/setting_learned.rs opens it): the writer lease lets the owner's handle call the
    /// owner verbs by name.
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

    /// What the engine's reader of `health.loop.repeats` answers for the whole vault.
    fn loop_repeats(&self) -> f64 {
        setting_value(&self.vault, &HEALTH_LOOP_REPEATS).expect("the knob reads")
    }

    /// The sourced read of `health.loop.repeats`: the value and the rows it stands on.
    fn loop_repeats_sourced(&self) -> (f64, Option<Vec<EntityId>>) {
        setting_value_sourced(&self.vault, &HEALTH_LOOP_REPEATS).expect("the knob reads sourced")
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

/// The sequence of the change a `settings.set` answer recorded.
fn sequence_of(answer: &Value) -> u64 {
    assert_eq!(answer["status"], json!("applied"), "{answer}");
    answer["sequence"]
        .as_u64()
        .unwrap_or_else(|| panic!("an applied change names its sequence: {answer}"))
}

#[test]
fn every_knob_is_a_learned_catalogue_key_with_its_holders_class() {
    for (name, class) in KNOBS {
        let spec = spec_named(name).unwrap_or_else(|error| panic!("{name} is a key: {error:?}"));
        assert!(spec.is_learned(), "{name} is learned");
        assert!(spec.item.is_none(), "{name} has no item");
        assert_eq!(
            spec.scopes,
            &LEARNED_SCOPES[..],
            "{name} sits where a fit is keyed"
        );
        let expected = class.map_or(SetBy::Owner, SetBy::Class);
        assert_eq!(spec.set_by, expected, "{name}'s setter");
    }
    for old in OLD_NAMES {
        assert!(spec_named(old).is_err(), "{old} is no key: it took a dot");
    }
}

#[test]
fn the_reader_answers_the_shipped_seed_then_the_owners_seed_then_the_owners_pin() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    assert_eq!(fx.loop_repeats(), 3.0, "the shipped seed");

    call(
        &me,
        SET,
        json!({ "key": LOOP_REPEATS, "scope": { "kind": "vault" }, "value": 5.0, "weight_runs": 2.0 }),
    );
    assert_eq!(fx.loop_repeats(), 5.0, "the owner's seed");

    call(
        &me,
        SET,
        json!({ "key": LOOP_REPEATS, "scope": { "kind": "vault" }, "pin": true, "value": 7.0 }),
    );
    assert_eq!(
        fx.loop_repeats(),
        7.0,
        "the owner's pin decides over the seed"
    );

    call(
        &me,
        SET,
        json!({ "key": LOOP_REPEATS, "scope": { "kind": "vault" }, "pin": true }),
    );
    assert_eq!(fx.loop_repeats(), 5.0, "a cleared pin leaves the seed");

    call(
        &me,
        SET,
        json!({ "key": LOOP_REPEATS, "scope": { "kind": "vault" } }),
    );
    assert_eq!(
        fx.loop_repeats(),
        3.0,
        "a cleared seed leaves the shipped seed"
    );

    // An owner-only knob reads the same way.
    assert_eq!(
        setting_value(&fx.vault, &HEALTH_OWNER_COPY).expect("the knob reads"),
        0.0
    );
}

#[test]
fn a_sourced_read_cites_the_change_that_wrote_its_row() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    assert_eq!(
        fx.loop_repeats_sourced(),
        (3.0, Some(Vec::new())),
        "the shipped seed stands on no row"
    );

    let answer = call(
        &me,
        SET,
        json!({ "key": LOOP_REPEATS, "scope": { "kind": "vault" }, "value": 4.0, "weight_runs": 1.0 }),
    );
    let change = setting_change(&fx.vault, sequence_of(&answer))
        .expect("the change reads")
        .expect("the change is recorded");
    assert_eq!(change.key, LOOP_REPEATS);
    assert_eq!(
        fx.loop_repeats_sourced(),
        (4.0, Some(vec![change.id])),
        "the owner's seed cites the change that wrote it"
    );
}

#[test]
fn the_learning_verbs_refuse_a_knob_and_keep_the_owners_spawn_choices() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let error = invoke(
        &me,
        LEARNING_PUT,
        json!({ "key": LOOP_REPEATS, "mode": "pin", "why": "fewer repeats" }),
    )
    .expect_err("a knob is no spawn choice");
    assert!(
        format!("{error:?}").contains("a learned knob is a setting"),
        "refused for another reason: {error:?}"
    );
    assert_eq!(fx.loop_repeats(), 3.0, "the knob is untouched");

    let view = call(
        &me,
        LEARNING_PUT,
        json!({ "key": "width", "mode": "pin", "choice": { "width": 3 }, "why": "two reviewers and a writer" }),
    );
    let rows = view["rows"].as_array().expect("rows");
    assert!(
        rows.iter()
            .any(|row| row["key"] == json!("width") && row["choice"] == json!({ "width": 3 })),
        "the spawn width row stands: {view}"
    );
    assert!(view.get("catalog").is_none(), "no knob catalog: {view}");
}
