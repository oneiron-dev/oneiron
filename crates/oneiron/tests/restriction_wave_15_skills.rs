//! Restriction wave 15, row C110: the reliability floor's evidence count is the owner key
//! `skills.reliability_floor_min_outcomes`. Default = today: 5 attributed outcomes
//! (`SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES`), so nothing changes until the owner moves it.
//! - the key is in the catalogue as an owner key of the vault, one setting, kept live through a
//!   restore;
//! - on a new vault the value in force is 5;
//! - the owner's set of 3 applies and is the value in force;
//! - a count of 0 is refused, and the value in force stands.
//!
//! The floor check (`check_floor_cells_in_txn`) reads the key through the same Setting walk that
//! `vault.settings.get` answers from, as tests/setting_plain_1.rs reads code auto-install.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restriction_wave_15_skills`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::setting::{
    Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope,
    spec_named,
};
use oneiron::skill_reliability::SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{SettingGetRequest, setting_get_embedded};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const KEY: &str = "skills.reliability_floor_min_outcomes";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned (as
    /// tests/setting_plain_1.rs opens it).
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

    /// The owner's set of `value` on the vault row of the floor's evidence count.
    fn set_as_owner(&self, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.vault.set_setting(
            SettingCaller::Owner(&self.owner_proof),
            SetSetting {
                key: KEY.to_owned(),
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

    /// The floor's evidence count in force, as the owner reads it through `vault.settings.get`.
    fn in_force(&self) -> Value {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        setting_get_embedded(
            &memory,
            SettingGetRequest {
                key: KEY.to_owned(),
                item: None,
                at: Vec::new(),
            },
        )
        .expect("the owner reads the floor's evidence count")
        .value
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
fn the_floor_evidence_count_is_an_owner_key_of_the_vault_kept_live() {
    let spec = spec_named(KEY).unwrap_or_else(|error| panic!("{KEY} in the catalogue: {error}"));
    assert_eq!(spec.set_by, SetBy::Owner, "only the owner sets it");
    assert_eq!(
        spec.restore,
        Restore::Live,
        "a restore keeps the live choice"
    );
    assert!(spec.item.is_none(), "one setting, not a family");
}

#[test]
fn a_new_vault_reads_five_attributed_outcomes() {
    let fixture = Fixture::rooted();
    assert_eq!(SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES, 5);
    assert_eq!(fixture.in_force(), json!(5));
}

#[test]
fn the_owners_count_is_the_value_in_force() {
    let fixture = Fixture::rooted();
    applied(fixture.set_as_owner(json!(3)).unwrap());
    assert_eq!(fixture.in_force(), json!(3));
}

#[test]
fn a_count_of_zero_is_refused_and_the_value_in_force_stands() {
    let fixture = Fixture::rooted();
    let error = fixture
        .set_as_owner(json!(0))
        .expect_err("a count of zero is refused");
    let text = format!("{error:?} {error}");
    assert!(text.contains("at least one attributed outcome"), "{text}");
    assert_eq!(fixture.in_force(), json!(5));
}
