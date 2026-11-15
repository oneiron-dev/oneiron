//! DESIGN 15-setting-primitive, stage 1 (SETTING-PLAIN PLAIN-2): five owner rows with no verb
//! are Setting keys, and the engine's readers read them through the Setting walk: the clipboard
//! retention arms, the disclosure offer mode, the inbox review dial, the cleanup posture and the
//! completed-task retention.
//! - each key is in the catalogue as an owner key of the vault that only holders read, live
//!   through a restore, as its table was;
//! - on a new vault each reader answers the default it answered from its own table;
//! - the owner's `Vault::set_setting` is what the kept reader returns, and a clear brings the
//!   default back;
//! - the automatic cleanup posture stays refused while its rollout blockers are open, and the
//!   refused change takes no place in the change feed;
//! - a value of another shape is refused, and the reader keeps the value in force;
//! - an agent with no Grant changes none of them.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_plain_2`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::clipboard::ClipboardRetention;
use oneiron::consent::{AuthenticatedOwner, DisclosureOfferMode};
use oneiron::inbox::InboxReviewDial;
use oneiron::setting::{
    ReadBy, Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode,
    SettingScope, spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{CleanupPosture, EntityId, ErrorKind, Vault, VaultConfig, cleanup_posture};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const CLIPBOARD_RETENTION: &str = "clipboard.retention";
const OFFER_MODE: &str = "disclosure.offer_mode";
const REVIEW_DIAL: &str = "inbox.review_dial";
const POSTURE: &str = "cleanup.posture";
const TASK_RETENTION_DAYS: &str = "cleanup.task_retention_days";
const KEYS: [&str; 5] = [
    CLIPBOARD_RETENTION,
    OFFER_MODE,
    REVIEW_DIAL,
    POSTURE,
    TASK_RETENTION_DAYS,
];

/// What the five readers answer, in key order.
type InForce = (
    ClipboardRetention,
    DisclosureOfferMode,
    InboxReviewDial,
    CleanupPosture,
    u64,
);

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
        vault
            .clipboard_retention_as_owner(&fixture.owner_proof)
            .unwrap(),
        vault.disclosure_offer_mode().unwrap(),
        vault.inbox_review_dial().unwrap(),
        cleanup_posture(vault).unwrap(),
        vault.task_retention_days().unwrap(),
    )
}

fn defaults() -> InForce {
    (
        ClipboardRetention {
            max_text_bytes: None,
            low_disk: true,
            older_than_days: None,
        },
        DisclosureOfferMode::Auto,
        InboxReviewDial::ExceptionsOnly,
        CleanupPosture::ProposeFirst,
        90,
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
}

#[test]
fn a_new_vault_reads_the_old_defaults() {
    let fixture = Fixture::rooted();
    assert_eq!(in_force(&fixture), defaults());
}

#[test]
fn the_owners_set_is_what_each_reader_returns_and_a_clear_restores_the_default() {
    let fixture = Fixture::rooted();
    let changes = [
        (
            CLIPBOARD_RETENTION,
            json!({"max_text_bytes": 4096, "low_disk": false, "older_than_days": 0}),
        ),
        (OFFER_MODE, json!("always_ask")),
        (REVIEW_DIAL, json!("review_everything")),
        (POSTURE, json!("propose_first")),
        (TASK_RETENTION_DAYS, json!(0)),
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
            ClipboardRetention {
                max_text_bytes: Some(4096),
                low_disk: false,
                older_than_days: Some(0),
            },
            DisclosureOfferMode::AlwaysAsk,
            InboxReviewDial::ReviewEverything,
            CleanupPosture::ProposeFirst,
            0,
        ),
        "each reader returns the owner's value; zero days turns the task arm off"
    );

    for key in KEYS {
        fixture
            .clear_as_owner(key)
            .unwrap_or_else(|error| panic!("{key}: the owner's clear applies: {error}"));
    }
    assert_eq!(in_force(&fixture), defaults());
}

#[test]
fn the_automatic_posture_is_refused_while_its_blockers_are_open() {
    let fixture = Fixture::rooted();
    let before = recorded(
        fixture
            .set_as_owner(REVIEW_DIAL, json!("approve_all"))
            .unwrap(),
    );
    let error = fixture
        .set_as_owner(POSTURE, json!("auto_with_digest"))
        .expect_err("the automatic posture is refused while its rollout blockers are open");
    assert_eq!(
        error.kind(),
        ErrorKind::InvariantViolation,
        "the refusal the owner's cleanup door maps to its propose-first answer: {error}"
    );
    assert_eq!(
        cleanup_posture(&fixture.vault).unwrap(),
        CleanupPosture::ProposeFirst
    );
    let after = recorded(fixture.clear_as_owner(REVIEW_DIAL).unwrap());
    assert_eq!(
        after,
        before + 1,
        "the refused change took no place in the change feed"
    );
}

#[test]
fn a_value_of_another_shape_is_refused_and_the_value_in_force_stands() {
    let fixture = Fixture::rooted();
    let attempts = [
        (CLIPBOARD_RETENTION, json!({"low_disk": "yes"})),
        (OFFER_MODE, json!("sometimes")),
        (REVIEW_DIAL, json!("approve_some")),
        (POSTURE, json!("archive_everything")),
        (TASK_RETENTION_DAYS, json!(-1)),
        (TASK_RETENTION_DAYS, json!("ninety")),
    ];
    for (key, value) in attempts {
        assert!(
            fixture.set_as_owner(key, value.clone()).is_err(),
            "{key}: {value} is not of the key's type"
        );
    }
    assert_eq!(in_force(&fixture), defaults());
}

#[test]
fn an_agent_with_no_grant_changes_none_of_them() {
    let fixture = Fixture::rooted();
    let agent = fixture.agent();
    let attempts = [
        (
            CLIPBOARD_RETENTION,
            json!({"max_text_bytes": 1, "low_disk": false, "older_than_days": 1}),
        ),
        (OFFER_MODE, json!("always_yes")),
        (REVIEW_DIAL, json!("approve_all")),
        (POSTURE, json!("propose_first")),
        (TASK_RETENTION_DAYS, json!(1)),
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
