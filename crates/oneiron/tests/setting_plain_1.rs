//! DESIGN 15-setting-primitive, stage 1 (SETTING-PLAIN PLAIN-1): six skill dials are Setting
//! keys, and the engine's readers read them through the Setting walk.
//! - each key is in the catalogue as an owner key of the vault, kept live through a restore;
//! - on a new vault each reader answers the default it answered from its own table: the advisory
//!   ask on, code auto-install off, the rule fit, N = 5, K = 2 and a floor of 0.25;
//! - the owner's `Vault::set_setting` is what the kept reader returns;
//! - a value its type's check refuses is refused, and the reader keeps the value in force;
//! - an agent with no Grant changes none of them.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_plain_1`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::setting::{
    Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope,
    spec_named,
};
use oneiron::skill_hub::SkillFitSetting;
use oneiron::skill_optimize::{
    DEFAULT_SKILL_EDIT_CYCLE_CAP, DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES, skill_edit_cycle_cap,
    skill_optimize_min_outcomes,
};
use oneiron::skill_reliability::{DEFAULT_SKILL_RELIABILITY_FLOOR, skill_reliability_floor};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{SettingGetRequest, setting_get_embedded};
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const ADVISORY_ASK: &str = "skills.advisory_ask";
const CODE_AUTO_INSTALL: &str = "skills.code_auto_install";
const SKILL_FIT: &str = "skills.fit";
const MIN_OUTCOMES: &str = "skills.optimize.min_outcomes";
const EDIT_CYCLE_CAP: &str = "skills.optimize.edit_cycle_cap";
const RELIABILITY_FLOOR: &str = "skills.reliability_floor";
const KEYS: [&str; 6] = [
    ADVISORY_ASK,
    CODE_AUTO_INSTALL,
    SKILL_FIT,
    MIN_OUTCOMES,
    EDIT_CYCLE_CAP,
    RELIABILITY_FLOOR,
];

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

    /// An enabled, active agent definition the owner creates, with no Grant.
    fn agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("plain-setting-agent-{}", id.to_hex()),
                    "desc": "setting plain fixture",
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

    /// Code auto-install has no public reader: the owner reads it through `vault.settings.get`.
    fn code_auto_install(&self) -> Value {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        setting_get_embedded(
            &memory,
            SettingGetRequest {
                key: CODE_AUTO_INSTALL.to_owned(),
                item: None,
                at: Vec::new(),
            },
        )
        .expect("the owner reads code auto-install")
        .value
    }

    fn assert_defaults(&self) {
        let vault = &self.vault;
        assert!(vault.marketplace_advisory_ask().unwrap());
        assert_eq!(self.code_auto_install(), json!(false));
        assert_eq!(
            vault.marketplace_skill_fit().unwrap(),
            SkillFitSetting::RuleFit
        );
        assert_eq!(
            skill_optimize_min_outcomes(vault).unwrap(),
            DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES
        );
        assert_eq!(
            skill_edit_cycle_cap(vault).unwrap(),
            DEFAULT_SKILL_EDIT_CYCLE_CAP
        );
        assert!(
            (skill_reliability_floor(vault).unwrap() - DEFAULT_SKILL_RELIABILITY_FLOOR).abs()
                < f32::EPSILON
        );
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
        "the owner's change applies and is recorded: {outcome:?}"
    );
}

#[test]
fn each_key_is_an_owner_key_of_the_vault_kept_live() {
    for name in KEYS {
        let spec =
            spec_named(name).unwrap_or_else(|error| panic!("{name} in the catalogue: {error}"));
        assert_eq!(spec.set_by, SetBy::Owner, "{name}: only the owner sets it");
        assert_eq!(
            spec.restore,
            Restore::Live,
            "{name}: a restore keeps the live choice"
        );
        assert!(spec.item.is_none(), "{name}: one setting, not a family");
    }
}

#[test]
fn a_new_vault_reads_the_old_defaults() {
    let fixture = Fixture::rooted();
    fixture.assert_defaults();
    assert_eq!(DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES, 5);
    assert_eq!(DEFAULT_SKILL_EDIT_CYCLE_CAP, 2);
}

#[test]
fn the_owners_set_is_what_each_reader_returns() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    applied(fixture.set_as_owner(ADVISORY_ASK, json!(false)).unwrap());
    assert!(!vault.marketplace_advisory_ask().unwrap());

    applied(
        fixture
            .set_as_owner(CODE_AUTO_INSTALL, json!(true))
            .unwrap(),
    );
    assert_eq!(fixture.code_auto_install(), json!(true));

    applied(
        fixture
            .set_as_owner(SKILL_FIT, json!("owner_asked"))
            .unwrap(),
    );
    assert_eq!(
        vault.marketplace_skill_fit().unwrap(),
        SkillFitSetting::OwnerAsked
    );

    applied(fixture.set_as_owner(MIN_OUTCOMES, json!(9)).unwrap());
    assert_eq!(skill_optimize_min_outcomes(vault).unwrap(), 9);

    applied(fixture.set_as_owner(EDIT_CYCLE_CAP, json!(4)).unwrap());
    assert_eq!(skill_edit_cycle_cap(vault).unwrap(), 4);

    applied(fixture.set_as_owner(RELIABILITY_FLOOR, json!(0.5)).unwrap());
    assert!((skill_reliability_floor(vault).unwrap() - 0.5).abs() < f32::EPSILON);
}

#[test]
fn a_value_its_check_refuses_is_refused_and_the_value_in_force_stands() {
    let fixture = Fixture::rooted();
    for (key, value, why) in [
        (MIN_OUTCOMES, json!(0), "N of zero is refused"),
        (EDIT_CYCLE_CAP, json!(0), "K of zero is refused"),
        (RELIABILITY_FLOOR, json!(1.5), "a floor above 1 is refused"),
        (RELIABILITY_FLOOR, json!(-0.1), "a floor below 0 is refused"),
        (
            SKILL_FIT,
            json!("any_fit"),
            "a fit that is not one of the two is refused",
        ),
        (ADVISORY_ASK, json!("off"), "a switch is a bool"),
    ] {
        assert!(fixture.set_as_owner(key, value).is_err(), "{key}: {why}");
    }
    fixture.assert_defaults();
}

#[test]
fn an_agent_with_no_grant_changes_none_of_them() {
    let fixture = Fixture::rooted();
    let agent = fixture.agent();
    for (key, value) in [
        (ADVISORY_ASK, json!(false)),
        (CODE_AUTO_INSTALL, json!(true)),
        (SKILL_FIT, json!("owner_asked")),
        (MIN_OUTCOMES, json!(9)),
        (EDIT_CYCLE_CAP, json!(4)),
        (RELIABILITY_FLOOR, json!(0.5)),
    ] {
        let outcome = fixture.set(SettingCaller::Agent(agent), key, value);
        assert!(
            !matches!(outcome, Ok(SetSettingOutcome::Applied { .. })),
            "{key}: an agent with no Grant does not apply a change: {outcome:?}"
        );
    }
    fixture.assert_defaults();
}
