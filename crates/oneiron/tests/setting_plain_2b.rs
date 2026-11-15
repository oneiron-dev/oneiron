//! DESIGN 15-setting-primitive, stage 1 (SETTING-PLAIN PLAIN-2b): three owner rows read below
//! the vault are Setting keys, and the engine's readers read them through the Setting walk: the
//! write-door secret scan switch, the per-project history budget and the skill-scan activation
//! risk threshold.
//! - each key is in the catalogue as an owner key of the vault that only holders read, live
//!   through a restore, as its table was; a change of the switch is a security control's act;
//! - on a new vault each reader answers the default it answered from its own table;
//! - the owner's `Vault::set_setting` is what the kept reader returns, and a clear brings the
//!   default back;
//! - the switch's change log is the setting feed: one numbered row per change, with who made it
//!   and the mode before; the same mode again records nothing; switching back on queues the
//!   historical lift run, and switching off does not;
//! - a history budget of zero, and a value of another shape, are refused, and the reader keeps
//!   the value in force;
//! - an agent with no Grant changes none of them.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_plain_2b`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::check_in::ActClass;
use oneiron::consent::AuthenticatedOwner;
use oneiron::policy_model::{LiftTrigger, SecretScanMode};
use oneiron::setting::{
    ReadBy, Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode,
    SettingScope, spec_named,
};
use oneiron::skill_hub::ScanRiskLevel;
use oneiron::skill_scan::skill_scan_activation_risk_threshold;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::workspace_roster::ProjectHistoryPolicy;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const SECRET_SCAN: &str = "secret_scan.mode";
const HISTORY_POLICY: &str = "projects.history_policy";
const ACTIVATION_RISK: &str = "skills.scan_activation_risk_threshold";
const KEYS: [&str; 3] = [SECRET_SCAN, HISTORY_POLICY, ACTIVATION_RISK];

/// What the three readers answer, in key order.
type InForce = (SecretScanMode, ProjectHistoryPolicy, ScanRiskLevel);

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
                    "agent_id": format!("plain-setting-2b-agent-{}", id.to_hex()),
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

    fn change(
        &self,
        caller: SettingCaller<'_>,
        key: &str,
        value: Option<Value>,
    ) -> oneiron::Result<SetSettingOutcome> {
        self.vault.set_setting(
            caller,
            SetSetting {
                key: key.to_owned(),
                item: None,
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value,
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
    }

    fn set_as_owner(&self, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.change(SettingCaller::Owner(&self.owner_proof), key, Some(value))
    }

    fn clear_as_owner(&self, key: &str) -> oneiron::Result<SetSettingOutcome> {
        self.change(SettingCaller::Owner(&self.owner_proof), key, None)
    }
}

/// The sequence of an applied, recorded change.
fn recorded(outcome: SetSettingOutcome) -> u64 {
    match outcome {
        SetSettingOutcome::Applied {
            sequence: Some(sequence),
            ..
        } => sequence,
        other => panic!("the owner's change applies and is recorded: {other:?}"),
    }
}

/// What each reader answers, in one tuple.
fn in_force(fixture: &Fixture) -> InForce {
    let vault = &fixture.vault;
    (
        vault.secret_scan_mode().unwrap(),
        vault.project_history_policy().unwrap(),
        skill_scan_activation_risk_threshold(vault).unwrap(),
    )
}

fn defaults() -> InForce {
    (
        SecretScanMode::On,
        ProjectHistoryPolicy {
            max_revisions: 10_000,
            cycle_worlds_max: 64,
        },
        ScanRiskLevel::High,
    )
}

#[test]
fn each_key_is_an_owner_key_of_the_vault_that_holders_read() {
    for name in KEYS {
        let spec =
            spec_named(name).unwrap_or_else(|error| panic!("{name} in the catalogue: {error}"));
        assert_eq!(spec.set_by, SetBy::Owner, "{name}: only the owner sets it");
        assert_eq!(
            spec.read_by,
            ReadBy::Holders,
            "{name}: only holders read it"
        );
        assert_eq!(
            spec.restore,
            Restore::Live,
            "{name}: live through a restore, as its table was"
        );
        assert!(spec.item.is_none(), "{name}: one setting, not a family");
    }
    assert_eq!(
        spec_named(SECRET_SCAN).unwrap().act,
        ActClass::SecurityControlDisable,
        "a change of the switch is a security control's act"
    );
}

#[test]
fn a_new_vault_reads_the_old_defaults() {
    let fixture = Fixture::rooted();
    assert_eq!(in_force(&fixture), defaults());
    assert!(fixture.vault.secret_scan_change_log().unwrap().is_empty());
}

#[test]
fn the_owners_set_is_what_each_reader_returns_and_a_clear_restores_the_default() {
    let fixture = Fixture::rooted();
    let changes = [
        (SECRET_SCAN, json!("off")),
        (
            HISTORY_POLICY,
            json!({"max_revisions": 3, "cycle_worlds_max": 2}),
        ),
        (ACTIVATION_RISK, json!("medium")),
    ];
    for (key, value) in changes {
        recorded(
            fixture
                .set_as_owner(key, value)
                .unwrap_or_else(|error| panic!("{key}: the owner's change applies: {error}")),
        );
    }
    assert_eq!(
        in_force(&fixture),
        (
            SecretScanMode::Off,
            ProjectHistoryPolicy {
                max_revisions: 3,
                cycle_worlds_max: 2,
            },
            ScanRiskLevel::Medium,
        ),
        "each reader returns the owner's value"
    );

    for key in KEYS {
        fixture
            .clear_as_owner(key)
            .unwrap_or_else(|error| panic!("{key}: the owner's clear applies: {error}"));
    }
    assert_eq!(in_force(&fixture), defaults());
}

#[test]
fn the_switch_logs_each_change_and_switching_back_on_queues_the_lift() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let owner = fixture.owner_proof.actor().to_hex();
    assert!(
        vault.secret_lift_status().unwrap().running.is_none(),
        "a new vault runs no lift"
    );

    recorded(fixture.set_as_owner(SECRET_SCAN, json!("off")).unwrap());
    assert!(
        vault.secret_lift_status().unwrap().running.is_none(),
        "switching off queues no lift"
    );
    recorded(fixture.set_as_owner(SECRET_SCAN, json!("on")).unwrap());
    let running = vault
        .secret_lift_status()
        .unwrap()
        .running
        .expect("switching back on queues the historical lift run");
    assert_eq!(running.trigger, LiftTrigger::Switch);

    let again = fixture.set_as_owner(SECRET_SCAN, json!("on")).unwrap();
    assert!(
        matches!(again, SetSettingOutcome::Applied { sequence: None, .. }),
        "the mode the owner's row already holds records nothing: {again:?}"
    );

    let log = vault.secret_scan_change_log().unwrap();
    let seen: Vec<_> = log
        .iter()
        .map(|receipt| (receipt.revision, receipt.mode, receipt.previous))
        .collect();
    assert_eq!(
        seen,
        vec![
            (1, SecretScanMode::Off, SecretScanMode::On),
            (2, SecretScanMode::On, SecretScanMode::Off),
        ],
        "one numbered row per change, with the mode before it"
    );
    for receipt in &log {
        assert_eq!(receipt.author, owner, "the owner made each change");
        assert_eq!(receipt.receipt_id.len(), 32, "named by the change's id");
    }
    assert_ne!(log[0].receipt_id, log[1].receipt_id);
}

#[test]
fn a_zero_budget_or_a_value_of_another_shape_is_refused_and_the_value_in_force_stands() {
    let fixture = Fixture::rooted();
    let attempts = [
        (SECRET_SCAN, json!("sometimes")),
        (SECRET_SCAN, json!(false)),
        (
            HISTORY_POLICY,
            json!({"max_revisions": 0, "cycle_worlds_max": 64}),
        ),
        (
            HISTORY_POLICY,
            json!({"max_revisions": 10, "cycle_worlds_max": 0}),
        ),
        (
            HISTORY_POLICY,
            json!({"max_revisions": 10, "cycle_worlds_max": 64, "seal": true}),
        ),
        (ACTIVATION_RISK, json!("severe")),
        (ACTIVATION_RISK, json!(3)),
    ];
    for (key, value) in attempts {
        assert!(
            fixture.set_as_owner(key, value.clone()).is_err(),
            "{key}: {value} is refused"
        );
    }
    assert_eq!(in_force(&fixture), defaults());
    assert!(fixture.vault.secret_scan_change_log().unwrap().is_empty());
}

#[test]
fn an_agent_with_no_grant_changes_none_of_them() {
    let fixture = Fixture::rooted();
    let agent = fixture.agent();
    let attempts = [
        (SECRET_SCAN, json!("off")),
        (
            HISTORY_POLICY,
            json!({"max_revisions": 1, "cycle_worlds_max": 1}),
        ),
        (ACTIVATION_RISK, json!("critical")),
    ];
    for (key, value) in attempts {
        let outcome = fixture.change(SettingCaller::Agent(agent), key, Some(value));
        assert!(
            !matches!(outcome, Ok(SetSettingOutcome::Applied { .. })),
            "{key}: an agent with no Grant does not apply a change: {outcome:?}"
        );
    }
    assert_eq!(in_force(&fixture), defaults());
}
