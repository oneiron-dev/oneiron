//! DESIGN 15-setting-primitive, stage 1 (SETTING-PLAIN PLAIN-3): the owner's commitment reminder
//! route and the web connector switch are Setting keys, and the engine's readers read them
//! through the Setting walk.
//! - each key is in the catalogue as an owner key of the vault that only holders read; the
//!   reminder route stays live through a restore, the web switch travels with the records;
//! - on a new vault each reader answers the default it answered from its own table: no route,
//!   and Tavily on the deploy's backend key;
//! - the owner's `Vault::set_setting` is what the kept reader returns, and a clear brings the
//!   default back;
//! - a value the old setter's check refused is refused, and the reader keeps the value in force;
//! - an agent with no Grant changes neither.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_plain_3`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::commitment_wake::CommitmentReminderRoute;
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{
    ReadBy, Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode,
    SettingScope, spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::web_connector::{WebConnectorSetting, WebProvider, WebProviderKey};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const REMINDER_ROUTE: &str = "commitments.reminder_route";
const WEB_CONNECTOR: &str = "connectors.web";

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

fn route() -> CommitmentReminderRoute {
    CommitmentReminderRoute {
        channel: "native".to_owned(),
        verb: "send".to_owned(),
        target: "owen".to_owned(),
        utc_offset_minutes: Some(-300),
        iana_timezone: Some("America/New_York".to_owned()),
        voice: None,
    }
}

fn own_key_exa() -> WebConnectorSetting {
    WebConnectorSetting {
        provider: WebProvider::Exa,
        key: WebProviderKey::Secret {
            name: "exa-api".to_owned(),
        },
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
fn each_key_is_an_owner_key_of_the_vault_that_holders_read() {
    for (name, restore) in [
        (REMINDER_ROUTE, Restore::Live),
        (WEB_CONNECTOR, Restore::Content),
    ] {
        let spec =
            spec_named(name).unwrap_or_else(|error| panic!("{name} in the catalogue: {error}"));
        assert_eq!(spec.set_by, SetBy::Owner, "{name}: only the owner sets it");
        assert_eq!(
            spec.read_by,
            ReadBy::Holders,
            "{name}: only holders read it"
        );
        assert_eq!(
            spec.restore, restore,
            "{name}: the restore class its table had"
        );
        assert!(spec.item.is_none(), "{name}: one setting, not a family");
    }
}

#[test]
fn a_new_vault_reads_the_old_defaults() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    assert_eq!(vault.commitment_reminder_route().unwrap(), None);
    assert_eq!(
        vault.web_connector_setting().unwrap(),
        WebConnectorSetting::default()
    );
}

#[test]
fn the_owners_set_is_what_each_reader_returns_and_a_clear_restores_the_default() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    applied(
        fixture
            .set_as_owner(REMINDER_ROUTE, serde_json::to_value(route()).unwrap())
            .unwrap(),
    );
    assert_eq!(vault.commitment_reminder_route().unwrap(), Some(route()));

    applied(
        fixture
            .set_as_owner(WEB_CONNECTOR, serde_json::to_value(own_key_exa()).unwrap())
            .unwrap(),
    );
    assert_eq!(vault.web_connector_setting().unwrap(), own_key_exa());

    applied(fixture.clear_as_owner(REMINDER_ROUTE).unwrap());
    assert_eq!(vault.commitment_reminder_route().unwrap(), None);
    applied(fixture.clear_as_owner(WEB_CONNECTOR).unwrap());
    assert_eq!(
        vault.web_connector_setting().unwrap(),
        WebConnectorSetting::default()
    );
}

#[test]
fn a_value_the_old_check_refused_is_refused_and_the_value_in_force_stands() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    let mut far_offset = route();
    far_offset.utc_offset_minutes = Some(900);
    assert!(
        fixture
            .set_as_owner(REMINDER_ROUTE, serde_json::to_value(far_offset).unwrap())
            .is_err(),
        "a UTC offset outside -840..=840 is refused"
    );
    let mut no_channel = route();
    no_channel.channel = String::new();
    assert!(
        fixture
            .set_as_owner(REMINDER_ROUTE, serde_json::to_value(no_channel).unwrap())
            .is_err(),
        "a route with no channel is refused"
    );
    assert_eq!(vault.commitment_reminder_route().unwrap(), None);

    let exa_on_backend = WebConnectorSetting {
        provider: WebProvider::Exa,
        key: WebProviderKey::Backend,
    };
    assert!(
        fixture
            .set_as_owner(WEB_CONNECTOR, serde_json::to_value(exa_on_backend).unwrap())
            .is_err(),
        "a provider whose terms keep it on the user's key is refused the backend key"
    );
    let blank_secret = WebConnectorSetting {
        provider: WebProvider::Exa,
        key: WebProviderKey::Secret {
            name: " ".to_owned(),
        },
    };
    assert!(
        fixture
            .set_as_owner(WEB_CONNECTOR, serde_json::to_value(blank_secret).unwrap())
            .is_err(),
        "a secret key that names no custody record is refused"
    );
    assert_eq!(
        vault.web_connector_setting().unwrap(),
        WebConnectorSetting::default()
    );
}

#[test]
fn an_agent_with_no_grant_changes_neither() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;
    let agent = fixture.agent();
    let attempts = [
        (REMINDER_ROUTE, serde_json::to_value(route()).unwrap()),
        (WEB_CONNECTOR, serde_json::to_value(own_key_exa()).unwrap()),
    ];
    for (key, value) in attempts {
        let outcome = fixture.change(SettingCaller::Agent(agent), key, Some(value));
        assert!(
            !matches!(outcome, Ok(SetSettingOutcome::Applied { .. })),
            "{key}: an agent with no Grant does not apply a change: {outcome:?}"
        );
    }
    assert_eq!(vault.commitment_reminder_route().unwrap(), None);
    assert_eq!(
        vault.web_connector_setting().unwrap(),
        WebConnectorSetting::default()
    );
}
