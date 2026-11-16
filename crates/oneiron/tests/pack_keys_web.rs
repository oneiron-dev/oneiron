//! PACK-SETTINGS-ALL = B, wave W2 (M14, M15): the web connector's two result caps are Setting
//! keys, `connectors.web.snippet_max_chars` and `connectors.web.fetch_max_chars`.
//! - each cap is in the catalogue as an owner key of the vault that holders read, live through a
//!   restore;
//! - on a new vault the caps are the shipped ones (300 and 50,000 characters), and they cut a
//!   search hit's snippet and a fetched page as the server cut them before;
//! - the owner's value is the cap the server's reply cuts to, and a clear brings the shipped cap
//!   back;
//! - a cap below one character is refused, and the cap in force stands;
//! - an agent with no Grant changes neither.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test pack_keys_web`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{
    ReadBy, Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode,
    SettingScope, spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::web_connector::{
    FETCH_CONTENT_MAX_CHARS, SNIPPET_MAX_CHARS, WebResultLimits, WebSearchHit,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const SNIPPET_KEY: &str = "connectors.web.snippet_max_chars";
const FETCH_KEY: &str = "connectors.web.fetch_max_chars";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned (as
    /// tests/setting_plain_3.rs opens it).
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
                    "agent_id": format!("pack-keys-web-agent-{}", id.to_hex()),
                    "desc": "pack keys web fixture",
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

fn hit(snippet: &str) -> WebSearchHit {
    WebSearchHit {
        title: "A title".to_owned(),
        url: "https://example.com/page".to_owned(),
        snippet: snippet.to_owned(),
    }
}

#[test]
fn each_cap_is_an_owner_key_of_the_vault_that_holders_read() {
    for name in [SNIPPET_KEY, FETCH_KEY] {
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
            "{name}: the cap in force stays through a restore"
        );
        assert!(spec.item.is_none(), "{name}: one setting, not a family");
    }
}

#[test]
fn a_new_vault_reads_the_shipped_caps_and_they_cut_as_before() {
    let fixture = Fixture::rooted();
    let limits = fixture.vault.web_result_limits().unwrap();
    assert_eq!(limits, WebResultLimits::SHIPPED);
    assert_eq!(limits.snippet_max_chars, 300);
    assert_eq!(limits.fetch_max_chars, 50_000);

    let long_snippet = "é".repeat(SNIPPET_MAX_CHARS + 1);
    let cut = limits.cut_hit(hit(&long_snippet));
    assert_eq!(cut.snippet.chars().count(), SNIPPET_MAX_CHARS);
    assert_eq!(cut.title, "A title", "the title is not cut");
    assert_eq!(cut.url, "https://example.com/page", "the URL is not cut");
    let short = limits.cut_hit(hit("short"));
    assert_eq!(short.snippet, "short", "a snippet under the cap stands");

    let long_page = "x".repeat(FETCH_CONTENT_MAX_CHARS + 1);
    assert_eq!(
        limits.cut_page(&long_page).chars().count(),
        FETCH_CONTENT_MAX_CHARS
    );
}

#[test]
fn the_owners_caps_cut_each_result_and_a_clear_restores_the_shipped_caps() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    applied(fixture.set_as_owner(SNIPPET_KEY, json!(5)).unwrap());
    applied(fixture.set_as_owner(FETCH_KEY, json!(7)).unwrap());
    let limits = vault.web_result_limits().unwrap();
    assert_eq!(
        limits,
        WebResultLimits {
            snippet_max_chars: 5,
            fetch_max_chars: 7,
        }
    );
    assert_eq!(limits.cut_hit(hit("abcdefgh")).snippet, "abcde");
    assert_eq!(limits.cut_page("0123456789"), "0123456");

    applied(fixture.set_as_owner(SNIPPET_KEY, json!(1_000)).unwrap());
    let raised = vault.web_result_limits().unwrap();
    let long_snippet = "y".repeat(SNIPPET_MAX_CHARS + 200);
    assert_eq!(
        raised.cut_hit(hit(&long_snippet)).snippet.chars().count(),
        SNIPPET_MAX_CHARS + 200,
        "a cap above the shipped one keeps the longer snippet"
    );

    applied(fixture.clear_as_owner(SNIPPET_KEY).unwrap());
    applied(fixture.clear_as_owner(FETCH_KEY).unwrap());
    assert_eq!(vault.web_result_limits().unwrap(), WebResultLimits::SHIPPED);
}

#[test]
fn a_cap_below_one_character_is_refused_and_the_cap_in_force_stands() {
    let fixture = Fixture::rooted();
    let vault = &fixture.vault;

    applied(fixture.set_as_owner(SNIPPET_KEY, json!(40)).unwrap());
    for key in [SNIPPET_KEY, FETCH_KEY] {
        for value in [json!(0), json!(-1)] {
            assert!(
                fixture.set_as_owner(key, value.clone()).is_err(),
                "{key}: {value} is refused"
            );
        }
    }
    assert_eq!(
        vault.web_result_limits().unwrap(),
        WebResultLimits {
            snippet_max_chars: 40,
            fetch_max_chars: FETCH_CONTENT_MAX_CHARS,
        }
    );
}

#[test]
fn an_agent_with_no_grant_changes_neither() {
    let fixture = Fixture::rooted();
    let agent = fixture.agent();
    for key in [SNIPPET_KEY, FETCH_KEY] {
        let outcome = fixture.change(SettingCaller::Agent(agent), key, Some(json!(5)));
        assert!(
            !matches!(outcome, Ok(SetSettingOutcome::Applied { .. })),
            "{key}: an agent with no Grant does not apply a change: {outcome:?}"
        );
    }
    assert_eq!(
        fixture.vault.web_result_limits().unwrap(),
        WebResultLimits::SHIPPED
    );
}
