//! DESIGN 15-setting-primitive, stage 1 (SETTING-DREAMER D1): four Dreamer setting tables are
//! Setting keys, and the engine's readers read them through the Setting walk.
//! - each key is in the catalogue as an owner key of the vault, kept live through a restore;
//! - on a new vault each reader answers the default it answered from its own table: the shipped
//!   key rules and recipe policy, an empty exclusion set, a prefilter that drops nothing;
//! - the owner's `Vault::set_setting` is what the kept reader returns;
//! - a value the type's check refuses is refused, and the reader keeps the value in force;
//! - an agent with no Grant changes none of them.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dreamer_1`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::excluded_conversations::DreamerExcludedConversations;
use oneiron::dreamer_consolidation::routing::PredicateKeyRules;
use oneiron::dreamer_prefilter::PrefilterConfig;
use oneiron::dreamer_wake::WakeRecipePolicy;
use oneiron::setting::{Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, spec_named};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const KEY_RULES: &str = "dreamer.consolidation.key_rules";
const EXCLUDED: &str = "dreamer.excluded_conversations";
const PREFILTER: &str = "dreamer.prefilter";
const RECIPE_POLICY: &str = "dreamer.wake.recipe_policy";

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
        self.vault
            .set_setting(caller, SetSetting::vault_value(key, value))
    }

    fn set_as_owner(&self, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.set(SettingCaller::Owner(&self.owner_proof), key, value)
    }
}

fn shipped_key_rules() -> PredicateKeyRules {
    serde_json::from_str(include_str!(
        "../src/dreamer_consolidation/key_defaults.json"
    ))
    .expect("shipped key rules")
}

fn shipped_recipe_policy() -> WakeRecipePolicy {
    serde_json::from_str(include_str!(
        "../src/dreamer_wake/recipe_policy_defaults.json"
    ))
    .expect("shipped recipe policy")
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
    for name in [KEY_RULES, EXCLUDED, PREFILTER, RECIPE_POLICY] {
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
    let vault = &fixture.vault;
    assert_eq!(
        vault.consolidation_key_rules().unwrap(),
        shipped_key_rules()
    );
    assert!(vault.dreamer_excluded_conversations().unwrap().is_empty());
    assert_eq!(
        vault.prefilter_config().unwrap(),
        PrefilterConfig::default()
    );
    assert_eq!(
        vault.dreamer_recipe_policy().unwrap(),
        shipped_recipe_policy()
    );
}

#[test]
fn the_owners_set_is_what_each_reader_returns() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    let rules = json!({"preference.colour": {"normalize_text": true, "topic_field": "topic"}});
    applied(fixture.set_as_owner(KEY_RULES, rules.clone()).unwrap());
    let read = vault.consolidation_key_rules().unwrap();
    assert_eq!(serde_json::to_value(&read).unwrap(), rules);

    let conversation = vault.new_entity_id().unwrap();
    let excluded = DreamerExcludedConversations::new([conversation]);
    applied(
        fixture
            .set_as_owner(EXCLUDED, serde_json::to_value(&excluded).unwrap())
            .unwrap(),
    );
    assert_eq!(vault.dreamer_excluded_conversations().unwrap(), excluded);

    let prefilter = PrefilterConfig {
        threshold: 0.4,
        ..PrefilterConfig::default()
    };
    applied(
        fixture
            .set_as_owner(PREFILTER, serde_json::to_value(prefilter).unwrap())
            .unwrap(),
    );
    assert_eq!(vault.prefilter_config().unwrap(), prefilter);

    let mut recipe = shipped_recipe_policy();
    recipe.nightly_spans += 1;
    applied(
        fixture
            .set_as_owner(RECIPE_POLICY, serde_json::to_value(&recipe).unwrap())
            .unwrap(),
    );
    assert_eq!(vault.dreamer_recipe_policy().unwrap(), recipe);
}

#[test]
fn a_value_its_check_refuses_is_refused_and_the_value_in_force_stands() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    let out_of_range = PrefilterConfig {
        threshold: 2.0,
        ..PrefilterConfig::default()
    };
    assert!(
        fixture
            .set_as_owner(PREFILTER, serde_json::to_value(out_of_range).unwrap())
            .is_err(),
        "a threshold outside [0, 1] is refused"
    );
    assert_eq!(
        vault.prefilter_config().unwrap(),
        PrefilterConfig::default()
    );

    let mut recipe = shipped_recipe_policy();
    recipe.continuous_rung_spans = 0;
    assert!(
        fixture
            .set_as_owner(RECIPE_POLICY, serde_json::to_value(&recipe).unwrap())
            .is_err(),
        "a recipe policy with no continuous spans is refused"
    );
    assert_eq!(
        vault.dreamer_recipe_policy().unwrap(),
        shipped_recipe_policy()
    );

    let wrong_version = json!({"version": 2, "conversations": []});
    assert!(
        fixture.set_as_owner(EXCLUDED, wrong_version).is_err(),
        "an exclusion set of another version is refused"
    );
}

#[test]
fn an_agent_with_no_grant_changes_none_of_them() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let agent = fixture.agent();
    let prefilter = PrefilterConfig {
        threshold: 0.4,
        ..PrefilterConfig::default()
    };
    let attempts = [
        (KEY_RULES, json!({})),
        (
            EXCLUDED,
            serde_json::to_value(DreamerExcludedConversations::new([agent])).unwrap(),
        ),
        (PREFILTER, serde_json::to_value(prefilter).unwrap()),
    ];
    for (key, value) in attempts {
        let outcome = fixture.set(SettingCaller::Agent(agent), key, value);
        assert!(
            !matches!(outcome, Ok(SetSettingOutcome::Applied { .. })),
            "{key}: an agent with no Grant does not apply a change: {outcome:?}"
        );
    }
    assert_eq!(
        vault.consolidation_key_rules().unwrap(),
        shipped_key_rules()
    );
    assert!(vault.dreamer_excluded_conversations().unwrap().is_empty());
    assert_eq!(
        vault.prefilter_config().unwrap(),
        PrefilterConfig::default()
    );
}
