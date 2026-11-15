//! DESIGN 15-setting-primitive, stage 1 (SETTING-PLAIN PLAIN-3b): the owner's drafter policy is
//! the Setting key `drafter.policy`, and the drafter's readers read it through the Setting walk.
//! - the key is in the catalogue as an owner key of the vault that only holders read, live
//!   through a restore, as its table was;
//! - on a new vault the status reads the shipped default: on, no world excluded, no recipe, at
//!   revision 0, set by no one;
//! - the owner's `Vault::set_setting` is what the status reads, at the revision of the change
//!   that wrote it, with the owner as its setter and the change's time; the change row is the
//!   record of the set, so a set that moves no binding writes no drafter event;
//! - the serving host is told once per applied change, after the write commits; the same value
//!   again records nothing and tells no one;
//! - a set at a revision that moved since is refused; a value of another shape is refused; a
//!   clear brings the default back;
//! - an agent with no Grant changes nothing.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_plain_3b`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::authority::MachineRole;
use oneiron::check_in::ActClass;
use oneiron::consent::AuthenticatedOwner;
use oneiron::drafter::{
    DrafterActor, DrafterPolicy, DrafterServedView, DrafterServingRuntime, DrafterStatus,
    DrafterStatusRequest, drafter_status_as_owner,
};
use oneiron::setting::{
    ReadBy, Restore, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode,
    SettingScope, spec_named,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const DRAFTER_POLICY: &str = "drafter.policy";

/// A serving host that counts how often it is told a binding or the policy moved.
#[derive(Default)]
struct CountingHost {
    moved: AtomicUsize,
}

impl CountingHost {
    fn told(&self) -> usize {
        self.moved.load(Ordering::SeqCst)
    }
}

impl DrafterServingRuntime for CountingHost {
    fn bindings_moved(&self) {
        self.moved.fetch_add(1, Ordering::SeqCst);
    }

    fn vault_locking(&self) {}

    fn served(&self) -> Vec<DrafterServedView> {
        Vec::new()
    }
}

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    host: Arc<CountingHost>,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned (as
    /// tests/setting_primitive.rs opens it), with a counting serving host attached.
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
        let host = Arc::new(CountingHost::default());
        vault.attach_drafter_serving(Arc::clone(&host) as Arc<dyn DrafterServingRuntime>);
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner_proof,
            host,
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
                    "agent_id": format!("plain-setting-3b-agent-{}", id.to_hex()),
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
        value: Option<Value>,
        expected_revision: Option<u64>,
    ) -> oneiron::Result<SetSettingOutcome> {
        self.vault.set_setting(
            caller,
            SetSetting {
                key: DRAFTER_POLICY.to_owned(),
                item: None,
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value,
                expected_revision,
                why: None,
                check_in_ref: None,
            },
        )
    }

    fn set_as_owner(&self, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.change(SettingCaller::Owner(&self.owner_proof), Some(value), None)
    }

    fn status(&self) -> DrafterStatus {
        drafter_status_as_owner(
            &self.vault,
            &self.owner_proof,
            &DrafterStatusRequest { events_after: None },
        )
        .expect("the owner reads the drafter status")
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

#[test]
fn the_policy_is_an_owner_key_of_the_vault_that_holders_read() {
    let spec = spec_named(DRAFTER_POLICY)
        .unwrap_or_else(|error| panic!("{DRAFTER_POLICY} in the catalogue: {error}"));
    assert_eq!(spec.set_by, SetBy::Owner, "only the owner sets it");
    assert_eq!(spec.read_by, ReadBy::Holders, "only holders read it");
    assert_eq!(
        spec.restore,
        Restore::Live,
        "live through a restore, as its table was"
    );
    assert_eq!(spec.act, ActClass::ReversibleWork);
    assert!(spec.item.is_none(), "one setting, not a family");
    assert!(spec.on_change.is_some(), "a change moves the bindings");
    assert!(
        spec.after_commit.is_some(),
        "a change tells the serving host"
    );
}

#[test]
fn a_new_vault_reads_the_shipped_default() {
    let fixture = Fixture::rooted();
    let status = fixture.status();
    assert_eq!(status.policy, DrafterPolicy::default());
    assert!(status.policy.enabled, "on by default (I5-DRAFTER = A)");
    assert_eq!(status.policy.revision, 0);
    assert!(status.policy.set_by.is_none());
    assert_eq!(fixture.host.told(), 0);
}

#[test]
fn the_owners_set_is_what_the_status_reads_and_the_host_is_told_after_commit() {
    let fixture = Fixture::rooted();
    let owner = fixture.owner_proof.actor();
    let world = fixture.vault.new_entity_id().expect("world id");

    let value = json!({"enabled": false, "excluded_worlds": [world.to_hex()]});
    let sequence = recorded(
        fixture
            .set_as_owner(value.clone())
            .expect("the owner's change applies"),
    );
    let status = fixture.status();
    assert!(!status.policy.enabled, "the owner switched it off");
    assert_eq!(
        status.policy.excluded_worlds.iter().copied().collect::<Vec<_>>(),
        vec![world]
    );
    assert!(status.policy.recipe.is_none());
    assert_eq!(
        status.policy.revision, sequence,
        "the revision is the change that wrote the row"
    );
    assert_eq!(status.policy.set_by, Some(DrafterActor::Owner(owner)));
    assert!(status.policy.set_at.is_some(), "the change's time");
    assert!(
        status.events.is_empty(),
        "a set that moves no binding writes no drafter event: {:?}",
        status.events
    );
    assert_eq!(fixture.host.told(), 1, "told once, after the commit");

    let again = fixture.set_as_owner(value).unwrap();
    assert!(
        matches!(again, SetSettingOutcome::Applied { sequence: None, .. }),
        "the value the row already holds records nothing: {again:?}"
    );
    assert_eq!(fixture.status().policy.revision, sequence);
    assert_eq!(fixture.host.told(), 1, "an equal value tells no one");
}

#[test]
fn a_set_at_a_moved_revision_is_refused_and_a_clear_restores_the_default() {
    let fixture = Fixture::rooted();
    let owner = SettingCaller::Owner(&fixture.owner_proof);
    let first = recorded(
        fixture
            .change(owner, Some(json!({"enabled": false})), Some(0))
            .expect("a set at the revision the owner read applies"),
    );
    assert!(
        fixture
            .change(owner, Some(json!({"enabled": true})), Some(0))
            .is_err(),
        "a set at a revision that moved since is refused"
    );
    assert!(!fixture.status().policy.enabled);
    assert_eq!(fixture.host.told(), 1);

    let second = recorded(
        fixture
            .change(owner, Some(json!({"enabled": true})), Some(first))
            .expect("a set at the revision in force applies"),
    );
    assert!(second > first);
    assert!(fixture.status().policy.enabled);
    assert_eq!(fixture.host.told(), 2);

    fixture
        .change(owner, None, None)
        .expect("the owner's clear applies");
    assert_eq!(fixture.status().policy, DrafterPolicy::default());
    assert_eq!(fixture.host.told(), 3);
}

#[test]
fn a_value_of_another_shape_is_refused_and_the_default_stands() {
    let fixture = Fixture::rooted();
    let attempts = [
        json!(false),
        json!({"enabled": "no"}),
        json!({"enabled": true, "seal": 1}),
        json!({"enabled": true, "excluded_worlds": ["not-an-id"]}),
        json!({"enabled": true, "revision": 4}),
    ];
    for value in attempts {
        assert!(
            fixture.set_as_owner(value.clone()).is_err(),
            "{value} is refused"
        );
    }
    assert_eq!(fixture.status().policy, DrafterPolicy::default());
    assert_eq!(fixture.host.told(), 0);
}

#[test]
fn an_agent_with_no_grant_changes_nothing() {
    let fixture = Fixture::rooted();
    let agent = fixture.agent();
    let outcome = fixture.change(
        SettingCaller::Agent(agent),
        Some(json!({"enabled": false})),
        None,
    );
    assert!(
        !matches!(outcome, Ok(SetSettingOutcome::Applied { .. })),
        "an agent with no Grant does not apply a change: {outcome:?}"
    );
    assert_eq!(fixture.status().policy, DrafterPolicy::default());
    assert_eq!(fixture.host.told(), 0);
}
