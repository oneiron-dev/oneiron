//! DESIGN 15-setting-primitive, stage 2 (SETTING-DREAMER D4): the Dreamer's maintenance cadence
//! dials are Setting keys. The consolidation selection, the consolidation strength policy, the
//! curator's rubric and the retune thresholds become six keys; a row a holder moved only in part
//! becomes two.
//! - each key is in the catalogue with its setter and its order: the selection's timing, the
//!   strength policy, the curator's cadence and the retune thresholds are the maintenance cadence
//!   class's, neutral; the selection's scoring and the curator's grading are the owner's;
//! - a new vault reads the shipped policies;
//! - the owner's `Vault::set_setting` is what the readers return, each composed from its keys;
//! - a holder of the maintenance cadence class moves its four keys either way, and not the
//!   owner's two; a holder of another class moves none;
//! - a value the type's check refuses is refused, and the value in force stands;
//! - a secret in a curator question never lands raw (the side-row wall in `set_setting`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dreamer_4`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::dreamer_consolidation::strength::ConsolidationStrengthPolicy;
use oneiron::dreamer_runner::maintenance::{CuratorQuestions, CuratorRubric};
use oneiron::federation::EngineControlClass;
use oneiron::memory::Memory;
use oneiron::setting::{
    Order, Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, ValueKind, spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const TIMING: &str = "dreamer.consolidation.selection.timing";
const SCORING: &str = "dreamer.consolidation.selection.scoring";
const STRENGTH: &str = "dreamer.consolidation.strength.policy";
const CADENCE: &str = "dreamer.curator.cadence";
const GRADING: &str = "dreamer.curator.grading";
const THRESHOLDS: &str = "dreamer.evaluation.retune_thresholds";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned (as
    /// tests/setting_primitive.rs opens it).
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

    /// An enabled, active agent definition the owner creates, holding the `engine.controls`
    /// class `class`.
    fn holder(&self, class: EngineControlClass) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("dreamer-dials-setting-agent-{}", id.to_hex()),
                    "desc": "setting dreamer dials fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        self.vault
            .grant_engine_controls(&self.owner_proof, id, &[class].into_iter().collect())
            .expect("the owner's engine.controls grant");
        id
    }

    fn set(
        &self,
        caller: SettingCaller<'_>,
        key: &str,
        value: Value,
    ) -> oneiron::Result<SetSettingOutcome> {
        self.vault
            .set_setting(caller, SetSetting::vault_value(key, value))
    }

    fn set_as_owner(&self, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.set(SettingCaller::Owner(&self.owner_proof), key, value)
    }

    fn curator_rubric(&self) -> CuratorRubric {
        self.vault
            .curator_rubric_as(&self.owner_proof)
            .expect("the curator's rubric")
    }

    /// The retune thresholds in force, as `vault.settings.get` answers the owner.
    fn thresholds(&self) -> Value {
        let me = self.as_owner();
        let answer = invoke(
            &me,
            "vault.settings.get",
            json!({ "key": THRESHOLDS, "at": [] }),
        )
        .unwrap_or_else(|error| panic!("vault.settings.get answers: {error:?}"));
        answer["value"].clone()
    }
}

fn applied(outcome: SetSettingOutcome) {
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the change applies and is recorded: {outcome:?}"
    );
}

fn not_applied(outcome: &oneiron::Result<SetSettingOutcome>, what: &str) {
    assert!(
        !matches!(outcome, Ok(SetSettingOutcome::Applied { .. })),
        "{what}: the change does not apply: {outcome:?}"
    );
}

/// `config` without its timing: the value of `dreamer.consolidation.selection.scoring`.
fn scoring_json(config: &SelectionConfig) -> Value {
    let mut value = serde_json::to_value(config).expect("a selection config");
    let fields = value.as_object_mut().expect("an object");
    fields.remove("soak_ms");
    fields.remove("recency_window_ms");
    value
}

fn timing_json(soak_ms: u64, recency_window_ms: u64) -> Value {
    json!({ "soak_ms": soak_ms, "recency_window_ms": recency_window_ms })
}

fn strength_json(archive_below: f64, quiet_ms: u64) -> Value {
    json!({ "archive_below": archive_below, "quiet_ms": quiet_ms })
}

fn cadence_json(minimum_age_secs: u64, cadence_secs: u64) -> Value {
    json!({ "minimum_age_secs": minimum_age_secs, "cadence_secs": cadence_secs })
}

fn thresholds_json(prompts: f64, weights: f64, manifest: f64) -> Value {
    json!({
        "prompts_score_regression": prompts,
        "weights_score_regression": weights,
        "manifest_thresholds_score_regression": manifest,
    })
}

/// The shipped curator_defaults.json.
fn shipped_rubric() -> CuratorRubric {
    CuratorRubric {
        minimum_age_secs: 86_400,
        edge_weight_factor: 0.8,
        confidence_factor: 0.8,
        cadence_secs: 86_400,
        questions: CuratorQuestions {
            authorship: "Was this approved, active consolidation generated by this Dreamer, with unambiguous actor and surface provenance?".to_owned(),
            freshness: "Has the consolidation remained old enough to warrant review under the configured minimum age? Age alone is not evidence of falsehood.".to_owned(),
            least_force: "What is the first available demotion rung after the recorded rung, without touching VAD or deleting the claim?".to_owned(),
        },
    }
}

fn grading_json(edge_weight_factor: f32, confidence_factor: f32, authorship: &str) -> Value {
    let shipped = shipped_rubric().questions;
    json!({
        "edge_weight_factor": edge_weight_factor,
        "confidence_factor": confidence_factor,
        "questions": {
            "authorship": authorship,
            "freshness": shipped.freshness,
            "least_force": shipped.least_force,
        },
    })
}

#[test]
fn each_key_is_in_the_catalogue_with_its_setter_and_order() {
    let class = SetBy::Class(EngineControlClass::MaintenanceCadence);
    let rows = [
        (TIMING, class, Order::Neutral),
        (SCORING, SetBy::Owner, Order::None),
        (STRENGTH, class, Order::Neutral),
        (CADENCE, class, Order::Neutral),
        (GRADING, SetBy::Owner, Order::None),
        (THRESHOLDS, class, Order::Neutral),
    ];
    for (name, set_by, order) in rows {
        let spec =
            spec_named(name).unwrap_or_else(|error| panic!("{name} in the catalogue: {error}"));
        assert_eq!(spec.set_by, set_by, "{name}: who sets it");
        assert_eq!(spec.kind.order(), order, "{name}: its order");
        assert_eq!(
            spec.restore,
            Restore::Live,
            "{name}: a restore keeps the live choice"
        );
        assert!(spec.item.is_none(), "{name}: one setting, not a family");
    }
}

#[test]
fn a_new_vault_reads_the_shipped_policies() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    assert_eq!(
        vault.consolidation_selection().unwrap(),
        SelectionConfig::default()
    );
    assert_eq!(
        vault.consolidation_strength_policy().unwrap(),
        ConsolidationStrengthPolicy {
            archive_below: 0.4,
            quiet_ms: 2_592_000_000,
        }
    );
    assert_eq!(fixture.curator_rubric(), shipped_rubric());
}

#[test]
fn the_owners_set_is_what_the_readers_return() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    let mut selection = SelectionConfig::default();
    selection.evidence_minimum = 3;
    selection.cosine_threshold = 0.5;
    selection.extraction_parallelism = 2;
    selection.soak_ms = 1_000;
    selection.recency_window_ms = 3_600_000;
    applied(
        fixture
            .set_as_owner(SCORING, scoring_json(&selection))
            .unwrap(),
    );
    applied(
        fixture
            .set_as_owner(TIMING, timing_json(1_000, 3_600_000))
            .unwrap(),
    );
    assert_eq!(
        vault.consolidation_selection().unwrap(),
        selection,
        "the selection composes the owner's scoring and timing"
    );

    applied(
        fixture
            .set_as_owner(STRENGTH, strength_json(0.25, 86_400_000))
            .unwrap(),
    );
    assert_eq!(
        vault.consolidation_strength_policy().unwrap(),
        ConsolidationStrengthPolicy {
            archive_below: 0.25,
            quiet_ms: 86_400_000,
        }
    );

    applied(
        fixture
            .set_as_owner(CADENCE, cadence_json(3_600, 7_200))
            .unwrap(),
    );
    applied(
        fixture
            .set_as_owner(
                GRADING,
                grading_json(0.5, 0.75, "Did this Dreamer write it?"),
            )
            .unwrap(),
    );
    let mut rubric = shipped_rubric();
    rubric.minimum_age_secs = 3_600;
    rubric.cadence_secs = 7_200;
    rubric.edge_weight_factor = 0.5;
    rubric.confidence_factor = 0.75;
    rubric.questions.authorship = "Did this Dreamer write it?".to_owned();
    assert_eq!(
        fixture.curator_rubric(),
        rubric,
        "the rubric composes the owner's cadence and grading"
    );

    applied(
        fixture
            .set_as_owner(THRESHOLDS, thresholds_json(0.2, 0.3, 0.4))
            .unwrap(),
    );
    assert_eq!(fixture.thresholds(), thresholds_json(0.2, 0.3, 0.4));
}

#[test]
fn a_maintenance_cadence_holder_moves_its_four_keys_either_way_and_not_the_owners_two() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let holder = fixture.holder(EngineControlClass::MaintenanceCadence);
    let as_holder = || SettingCaller::Agent(holder);

    for (soak, window) in [(60_000, 1_000_000), (0, 500)] {
        applied(
            fixture
                .set(as_holder(), TIMING, timing_json(soak, window))
                .unwrap(),
        );
    }
    for (below, quiet) in [(0.6, 1_000), (0.1, 5_000_000_000)] {
        applied(
            fixture
                .set(as_holder(), STRENGTH, strength_json(below, quiet))
                .unwrap(),
        );
    }
    for (age, period) in [(60, 600), (172_800, 259_200)] {
        applied(
            fixture
                .set(as_holder(), CADENCE, cadence_json(age, period))
                .unwrap(),
        );
    }
    for regression in [0.5, 0.01] {
        applied(
            fixture
                .set(
                    as_holder(),
                    THRESHOLDS,
                    thresholds_json(regression, regression, regression),
                )
                .unwrap(),
        );
    }

    let mut selection = SelectionConfig::default();
    selection.soak_ms = 0;
    selection.recency_window_ms = 500;
    assert_eq!(
        vault.consolidation_selection().unwrap(),
        selection,
        "the holder's timing, the shipped scoring"
    );
    assert_eq!(
        vault.consolidation_strength_policy().unwrap(),
        ConsolidationStrengthPolicy {
            archive_below: 0.1,
            quiet_ms: 5_000_000_000,
        }
    );
    let mut rubric = shipped_rubric();
    rubric.minimum_age_secs = 172_800;
    rubric.cadence_secs = 259_200;
    assert_eq!(
        fixture.curator_rubric(),
        rubric,
        "the holder's cadence, the shipped grading"
    );
    assert_eq!(fixture.thresholds(), thresholds_json(0.01, 0.01, 0.01));

    let mut scoring = SelectionConfig::default();
    scoring.evidence_minimum = 9;
    let scoring_change = fixture.set(as_holder(), SCORING, scoring_json(&scoring));
    not_applied(&scoring_change, "the selection's scoring, the owner's");
    let grading_change = fixture.set(
        as_holder(),
        GRADING,
        grading_json(0.5, 0.5, "Is it the Coach's?"),
    );
    not_applied(&grading_change, "the curator's grading, the owner's");
    assert_eq!(vault.consolidation_selection().unwrap(), selection);
    assert_eq!(fixture.curator_rubric(), rubric);

    let other = fixture.holder(EngineControlClass::WorkBudget);
    let timing_change = fixture.set(SettingCaller::Agent(other), TIMING, timing_json(7, 7_000));
    not_applied(&timing_change, "the selection's timing, another class's");
    let cadence_change = fixture.set(SettingCaller::Agent(other), CADENCE, cadence_json(7, 7_000));
    not_applied(&cadence_change, "the curator's cadence, another class's");
    assert_eq!(vault.consolidation_selection().unwrap(), selection);
    assert_eq!(fixture.curator_rubric(), rubric);
}

#[test]
fn a_value_its_check_refuses_is_refused_and_the_value_in_force_stands() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let mut heavy = SelectionConfig::default();
    heavy.weights.type_prior = heavy.weights.frequency;
    let refused = [
        (TIMING, timing_json(1_000, 0), "a zero recency window"),
        (
            SCORING,
            scoring_json(&heavy),
            "a type prior weight below the rest",
        ),
        (
            STRENGTH,
            strength_json(1.5, 1_000),
            "an archive bar above 1",
        ),
        (STRENGTH, strength_json(0.5, 0), "a zero quiet stretch"),
        (CADENCE, cadence_json(60, 0), "a zero curator period"),
        (
            GRADING,
            grading_json(1.0, 0.5, "Who wrote it?"),
            "a factor of 1",
        ),
        (GRADING, grading_json(0.5, 0.5, "   "), "a blank question"),
        (
            THRESHOLDS,
            thresholds_json(0.1, 1.5, 0.1),
            "a regression above 1",
        ),
    ];
    for (key, value, what) in refused {
        let outcome = fixture.set_as_owner(key, value);
        not_applied(&outcome, what);
    }
    assert_eq!(
        vault.consolidation_selection().unwrap(),
        SelectionConfig::default()
    );
    assert_eq!(
        vault.consolidation_strength_policy().unwrap(),
        ConsolidationStrengthPolicy::default()
    );
    assert_eq!(fixture.curator_rubric(), shipped_rubric());
}

#[test]
fn a_secret_in_a_curator_question_never_lands_raw() {
    let fixture = Fixture::rooted();
    let token = "Ask with TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz";
    let outcome = fixture.set_as_owner(GRADING, grading_json(0.5, 0.5, token));
    let authorship = fixture.curator_rubric().questions.authorship;
    assert!(
        !authorship.contains("ghp_0123456789"),
        "the wall lifted the token or refused the change ({outcome:?}): {authorship}"
    );
}
