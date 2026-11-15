//! DESIGN 15-setting-primitive, stages 1 and 2 (SETTING-DREAMER D2a): the Dreamer's action-mode
//! policy and the proactivity digest's cadence and presentation are Setting keys.
//! - each key is in the catalogue: the action-mode policy, the digest's delivery and its
//!   presentation are the owner's; the digest's period is the maintenance cadence class's;
//! - a new vault has no action-mode policy and no digest rows set;
//! - the owner's `Vault::set_setting` is what the readers return, and a cleared policy reads none;
//! - a holder of the maintenance cadence class moves the period and nothing else;
//! - a value the type's check refuses is refused, and the value in force stands.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dreamer_2`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::maintenance::action_mode::ActionModePolicy;
use oneiron::dreamer_runner::maintenance::digest::{
    ProactivityCadence, ProactivityPolicyBasis, ProactivityPresentation,
};
use oneiron::federation::EngineControlClass;
use oneiron::setting::{
    Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope,
    spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const ACTION_MODE: &str = "dreamer.action_mode.policy";
const PERIOD: &str = "dreamer.proactivity.period";
const DELIVERY: &str = "dreamer.proactivity.delivery";
const PRESENTATION: &str = "dreamer.proactivity.presentation";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
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
            owner_proof,
        }
    }

    /// An enabled, active agent definition the owner creates, with no Grant.
    fn agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("dreamer-setting-agent-{}", id.to_hex()),
                    "desc": "setting dreamer fixture",
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

    fn set(
        &self,
        caller: SettingCaller<'_>,
        key: &str,
        value: Value,
    ) -> oneiron::Result<SetSettingOutcome> {
        self.vault.set_setting(
            caller,
            SetSetting {
                key: key.to_owned(),
                item: None,
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value: Some(value),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
    }

    fn set_as_owner(&self, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.set(SettingCaller::Owner(&self.owner_proof), key, value)
    }

    /// The owner's `engine.controls` grant of `class` to `agent`.
    fn controls(&self, agent: EntityId, class: EngineControlClass) {
        self.vault
            .grant_engine_controls(&self.owner_proof, agent, &[class].into_iter().collect())
            .expect("the owner's engine.controls grant");
    }
}

fn policy() -> ActionModePolicy {
    serde_json::from_value(json!({
        "window": {
            "window_secs": 604_800,
            "expected_goal_completions": 5,
            "expected_engaged_days": 4,
        },
        "rules": [
            {"mode": "rest", "min_index": 0.0, "max_index": 0.5},
            {"mode": "push", "min_index": 0.5, "max_index": 1.0},
        ],
    }))
    .expect("an action-mode policy")
}

fn presentation() -> ProactivityPresentation {
    serde_json::from_value(json!({
        "group_aliases": {"dreamer.proactivity": "Ideas"},
        "group_template": "## {group}\n",
        "item_template": "* {summary} ({ref})\n",
        "voice_style": "brief",
        "urgent_groups": ["proposals"],
    }))
    .expect("a presentation")
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

fn unset() -> ProactivityPolicyBasis {
    ProactivityPolicyBasis {
        cadence: None,
        presentation: None,
    }
}

#[test]
fn each_key_is_in_the_catalogue_with_its_setter() {
    let setters = [
        (ACTION_MODE, SetBy::Owner),
        (PERIOD, SetBy::Class(EngineControlClass::MaintenanceCadence)),
        (DELIVERY, SetBy::Owner),
        (PRESENTATION, SetBy::Owner),
    ];
    for (name, set_by) in setters {
        let spec =
            spec_named(name).unwrap_or_else(|error| panic!("{name} in the catalogue: {error}"));
        assert_eq!(spec.set_by, set_by, "{name}: who sets it");
        assert_eq!(
            spec.restore,
            Restore::Live,
            "{name}: a restore keeps the live choice"
        );
        assert!(spec.item.is_none(), "{name}: one setting, not a family");
    }
}

#[test]
fn a_new_vault_has_no_action_mode_policy_and_no_digest_rows_set() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    assert_eq!(vault.action_mode_policy().unwrap(), None);
    assert_eq!(vault.proactivity_policy_basis().unwrap(), unset());
}

#[test]
fn the_owners_set_is_what_the_readers_return_and_a_clear_reads_none() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    applied(
        fixture
            .set_as_owner(ACTION_MODE, serde_json::to_value(policy()).unwrap())
            .unwrap(),
    );
    assert_eq!(vault.action_mode_policy().unwrap(), Some(policy()));
    applied(fixture.set_as_owner(ACTION_MODE, Value::Null).unwrap());
    assert_eq!(
        vault.action_mode_policy().unwrap(),
        None,
        "a null value clears the policy"
    );

    applied(fixture.set_as_owner(PERIOD, json!(3_600)).unwrap());
    assert_eq!(
        vault.proactivity_policy_basis().unwrap().cadence,
        Some(ProactivityCadence {
            period_secs: 3_600,
            group_by_facet: true,
            urgent_breakthrough: true,
        }),
        "the period moved; the delivery is the shipped one"
    );
    applied(
        fixture
            .set_as_owner(
                DELIVERY,
                json!({"group_by_facet": false, "urgent_breakthrough": true}),
            )
            .unwrap(),
    );
    applied(
        fixture
            .set_as_owner(PRESENTATION, serde_json::to_value(presentation()).unwrap())
            .unwrap(),
    );
    assert_eq!(
        vault.proactivity_policy_basis().unwrap(),
        ProactivityPolicyBasis {
            cadence: Some(ProactivityCadence {
                period_secs: 3_600,
                group_by_facet: false,
                urgent_breakthrough: true,
            }),
            presentation: Some(presentation()),
        }
    );
}

#[test]
fn a_holder_of_the_maintenance_cadence_class_moves_the_period_and_nothing_else() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let holder = fixture.agent();
    fixture.controls(holder, EngineControlClass::MaintenanceCadence);

    applied(
        fixture
            .set(SettingCaller::Agent(holder), PERIOD, json!(43_200))
            .unwrap(),
    );
    let attempts = [
        (
            DELIVERY,
            json!({"group_by_facet": false, "urgent_breakthrough": false}),
        ),
        (PRESENTATION, serde_json::to_value(presentation()).unwrap()),
        (ACTION_MODE, serde_json::to_value(policy()).unwrap()),
    ];
    for (key, value) in attempts {
        let outcome = fixture.set(SettingCaller::Agent(holder), key, value);
        assert!(
            !matches!(outcome, Ok(SetSettingOutcome::Applied { .. })),
            "{key}: the class holder does not apply a change: {outcome:?}"
        );
    }
    assert_eq!(
        vault.proactivity_policy_basis().unwrap(),
        ProactivityPolicyBasis {
            cadence: Some(ProactivityCadence {
                period_secs: 43_200,
                group_by_facet: true,
                urgent_breakthrough: true,
            }),
            presentation: None,
        }
    );
    assert_eq!(vault.action_mode_policy().unwrap(), None);
}

#[test]
fn a_value_its_check_refuses_is_refused_and_the_value_in_force_stands() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    assert!(
        fixture.set_as_owner(PERIOD, json!(0)).is_err(),
        "a period of 0 is refused"
    );
    let mut empty = policy();
    empty.rules.clear();
    assert!(
        fixture
            .set_as_owner(ACTION_MODE, serde_json::to_value(empty).unwrap())
            .is_err(),
        "a policy with no band is refused"
    );
    let mut no_group = presentation();
    no_group.group_template = "items\n".to_owned();
    assert!(
        fixture
            .set_as_owner(PRESENTATION, serde_json::to_value(no_group).unwrap())
            .is_err(),
        "a group template without {{group}} is refused"
    );
    assert_eq!(vault.action_mode_policy().unwrap(), None);
    assert_eq!(vault.proactivity_policy_basis().unwrap(), unset());
}
