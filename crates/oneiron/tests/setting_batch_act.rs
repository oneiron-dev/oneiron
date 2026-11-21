//! DESIGN 15-setting-primitive, stage 7a-3 "a batch is one act" (section 1.6 "What travels",
//! a vault with no authority root):
//! - another machine's batch lands each row in its own slot, and both values project, credited to
//!   the one act; a later act on one row replaces the batch there and leaves it on the other;
//! - a batch whose second row names a wrong `seen` lands no row;
//! - the rows the owner set before the vault was rooted travel as ONE batch act once this install
//!   can carry it, and an install that holds the log and none of the rows writes them from it;
//! - the publish leaves a slot an act already names, an engine row and an install key's row;
//! - it runs once per vault;
//! - a rooted vault with no carrier publishes nothing, and publishes once its profile lands.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_batch_act`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{
    SetSetting, SetSettingOutcome, Setter, SettingCaller, SettingChange, SettingMode, SettingScope,
    SettingSource, SettingStanding,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::setting::{
    EnrolledMachine, SlotName, enroll_machine_with_key, forget_projected_setting_rows,
    land_setting_batch_from, ordered_cap_read, owner_number_read_both_ways, set_setting_as_engine,
    setting_change, setting_frontier_of, settings_published,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_authority::authority::{
    AuthorityEntryHash, AuthorityOp, PolicySettingSet, authority_log_entity_id_from_hash,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

const NUMBER: &str = "test.owner_number";
const CAP: &str = "test.ordered_cap";
const DIAL: &str = "test.dial_number";
const INSTALL_MODE: &str = "test.install_mode";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    issuer: Option<HostSlipIssuer>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A vault with no authority root: one machine.
    fn unrooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            issuer: None,
            owner,
            owner_proof,
        }
    }

    /// A vault rooted when it opened, whose install carries the owner's acts.
    fn rooted() -> Self {
        let mut fx = Self::unrooted();
        fx.root();
        fx.carry();
        fx
    }

    /// Roots the vault, with no machine profile of this install yet.
    fn root(&mut self) {
        let issuer = self
            .vault
            .bootstrap_host_slip_issuer()
            .expect("host issuer");
        self.vault
            .ensure_host_root_slip(&issuer)
            .expect("host root");
        self.vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        self.issuer = Some(issuer);
    }

    /// Enrols this install's machine profile: it can carry the owner's acts from now on.
    fn carry(&self) {
        self.vault
            .ensure_serving_install_profile(
                self.issuer.as_ref().expect("a rooted vault's issuer"),
                MachineRole::Unanswered,
            )
            .expect("serving install profile");
    }

    fn owner_sets(&self, request: SetSetting) -> SetSettingOutcome {
        self.vault
            .set_setting(SettingCaller::Owner(&self.owner_proof), request)
            .expect("the owner's change")
    }

    /// The change row an applied outcome names.
    fn change_of(&self, outcome: &SetSettingOutcome) -> SettingChange {
        let SetSettingOutcome::Applied {
            sequence: Some(sequence),
            ..
        } = outcome
        else {
            panic!("an applied change that wrote a row: {outcome:?}");
        };
        self.change_at(*sequence)
    }

    fn change_at(&self, sequence: u64) -> SettingChange {
        setting_change(&self.vault, sequence)
            .expect("the change stream")
            .expect("the change row")
    }

    /// The setting act `signed` names, as the log holds it.
    fn act(&self, signed: Option<AuthorityEntryHash>) -> PolicySettingSet {
        let hash = signed.expect("the change names its act");
        let entry = self
            .vault
            .get_authority_log_entry(&authority_log_entity_id_from_hash(&hash).expect("id"))
            .expect("the log")
            .expect("the entry");
        let AuthorityOp::PolicySettingSet(set) = entry.op else {
            panic!("a setting act: {:?}", entry.op);
        };
        set
    }

    /// `test.owner_number` at the vault: value, source, revision and standing.
    fn number(&self) -> (u64, SettingSource, u64, SettingStanding) {
        let (read, _) = owner_number_read_both_ways(&self.vault, &[]).expect("the read");
        (read.value, read.source, read.revision, read.standing)
    }

    /// `test.ordered_cap` at the vault: value and revision.
    fn cap(&self) -> (u64, u64) {
        let read = ordered_cap_read(&self.vault, &[]).expect("the read");
        (read.value, read.revision)
    }

    fn second_machine(&self, seed: u8) -> EnrolledMachine {
        enroll_machine_with_key(&self.vault, &self.owner_proof, seed).expect("enrolled")
    }

    fn published(&self) -> bool {
        settings_published(&self.vault).expect("the publish marker")
    }
}

/// `key`'s vault value row with no item.
fn vault_row(key: &str) -> SlotName<'_> {
    (key, None, SettingMode::Value, SettingScope::Vault)
}

/// The keys an act names: its own row's and each further row's.
fn keys_named(act: &PolicySettingSet) -> Vec<String> {
    let mut keys: Vec<String> = std::iter::once(act.setting.clone())
        .chain(act.more.iter().map(|row| row.setting.clone()))
        .collect();
    keys.sort();
    keys
}

#[test]
fn a_batch_from_another_machine_lands_each_row_in_its_own_slot() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x51);
    let frontier =
        setting_frontier_of(&fx.vault, &[vault_row(NUMBER), vault_row(CAP)]).expect("frontier");
    let counted = land_setting_batch_from(
        &fx.vault,
        &other,
        fx.owner,
        &frontier,
        &[
            (vault_row(NUMBER), Some(json!(4))),
            (vault_row(CAP), Some(json!(3))),
        ],
        T0,
    )
    .expect("the batch lands");
    assert!(counted, "the fold counts the batch");

    let (number, source, number_revision, standing) = fx.number();
    assert_eq!(
        (number, source, standing),
        (
            4,
            SettingSource::Row(SettingScope::Vault),
            SettingStanding::Settled
        )
    );
    let (cap, cap_revision) = fx.cap();
    assert_eq!(cap, 3);
    let batch = fx.change_at(number_revision).signed;
    assert_eq!(
        fx.change_at(cap_revision).signed,
        batch,
        "both rows are credited to the one act"
    );
    assert_eq!(fx.act(batch).more.len(), 1, "one entry, two rows");

    fx.owner_sets(SetSetting::vault_value(NUMBER, json!(8)));
    assert_eq!(
        fx.number().0,
        8,
        "an act on one row replaces the batch there"
    );
    let (cap, cap_revision) = fx.cap();
    assert_eq!(cap, 3, "and leaves it in force on the other");
    assert_eq!(fx.change_at(cap_revision).signed, batch);
}

#[test]
fn a_batch_whose_second_row_names_a_wrong_seen_lands_no_row() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x52);
    fx.owner_sets(SetSetting::vault_value(CAP, json!(9)));
    // The frontier read NUMBER's acts and not CAP's: the batch names CAP's `seen` as zero, while
    // the owner's act on CAP is among its parents.
    let frontier = setting_frontier_of(&fx.vault, &[vault_row(NUMBER)]).expect("frontier");
    let landed = land_setting_batch_from(
        &fx.vault,
        &other,
        fx.owner,
        &frontier,
        &[
            (vault_row(NUMBER), Some(json!(4))),
            (vault_row(CAP), Some(json!(3))),
        ],
        T0,
    );
    assert!(
        !matches!(landed, Ok(true)),
        "the fold does not count it: {landed:?}"
    );
    let (number, source, _, _) = fx.number();
    assert_eq!(
        (number, source),
        (7, SettingSource::Default),
        "no row on the first slot either"
    );
    assert_eq!(fx.cap().0, 9, "the owner's act stays in force");
}

#[test]
fn rows_the_owner_set_before_the_vault_was_rooted_travel_as_one_batch_act() {
    let mut fx = Fixture::unrooted();
    let number = fx.change_of(&fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5))));
    let cap = fx.change_of(&fx.owner_sets(SetSetting::vault_value(CAP, json!(6))));
    assert_eq!(
        (number.signed, cap.signed),
        (None, None),
        "one machine: the rows alone"
    );
    fx.root();
    fx.carry();
    fx.vault.project_settings().expect("the pass");

    let batch = fx.change_at(number.sequence).signed;
    assert!(batch.is_some(), "the row's change names the act");
    assert_eq!(
        fx.change_at(cap.sequence).signed,
        batch,
        "one act names both rows"
    );
    let act = fx.act(batch);
    assert_eq!(keys_named(&act), [CAP, NUMBER]);
    assert_eq!(act.act.seen, [0; 32], "no act named the slot");
    assert_eq!(act.act.owner, fx.owner);

    // An install that holds the log and none of the rows writes both from the act.
    assert_eq!(forget_projected_setting_rows(&fx.vault).expect("forget"), 2);
    assert_eq!(fx.number().1, SettingSource::Default, "the rows are gone");
    fx.vault.project_settings().expect("the pass");
    let (value, _, revision, standing) = fx.number();
    assert_eq!((value, standing), (5, SettingStanding::Settled));
    let written = fx.change_at(revision);
    assert_eq!(
        (written.signed, written.setter, written.by),
        (batch, Setter::Owner, Some(fx.owner))
    );
    assert_eq!(fx.cap().0, 6);
}

#[test]
fn the_publish_leaves_a_slot_an_act_names_an_engine_row_and_an_install_keys_row() {
    let mut fx = Fixture::unrooted();
    let number = fx.change_of(&fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5))));
    fx.owner_sets(SetSetting::vault_value(CAP, json!(6)));
    fx.owner_sets(SetSetting::vault_value(INSTALL_MODE, json!(3)));
    set_setting_as_engine(&fx.vault, None, SetSetting::vault_value(DIAL, json!(2)))
        .expect("the engine's own change");
    fx.root();
    fx.carry();
    // The owner's act on CAP lands before any pass publishes.
    let on_cap = fx.change_of(&fx.owner_sets(SetSetting::vault_value(CAP, json!(4))));
    assert!(on_cap.signed.is_some(), "the door's own act");
    fx.vault.project_settings().expect("the pass");

    let batch = fx.change_at(number.sequence).signed;
    assert!(
        batch.is_some(),
        "the owner's row no act backed is published"
    );
    assert_ne!(batch, on_cap.signed);
    assert_eq!(
        keys_named(&fx.act(batch)),
        [NUMBER],
        "not CAP, whose act decides it; not the engine's row; not the install key's"
    );
    assert_eq!(fx.cap().0, 4);
    assert!(fx.published());
}

#[test]
fn the_publish_runs_once() {
    let mut fx = Fixture::unrooted();
    let number = fx.change_of(&fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5))));
    fx.root();
    fx.carry();
    fx.vault.project_settings().expect("the pass");
    let batch = fx.change_at(number.sequence).signed;
    assert!(batch.is_some());
    assert!(fx.published(), "the marker is set");

    assert_eq!(
        fx.vault.publish_settings().expect("a second publish"),
        None,
        "a second pass does nothing"
    );
    fx.vault.project_settings().expect("the pass");
    assert_eq!(fx.change_at(number.sequence).signed, batch, "no new act");
}

#[test]
fn a_rooted_vault_without_a_carrier_publishes_once_its_profile_lands() {
    let mut fx = Fixture::unrooted();
    let number = fx.change_of(&fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5))));
    fx.root();
    fx.vault.project_settings().expect("the pass");
    assert_eq!(
        fx.change_at(number.sequence).signed,
        None,
        "no carrier: nothing published"
    );
    assert!(
        !fx.published(),
        "and no marker, so a later pass tries again"
    );

    fx.carry();
    fx.vault.project_settings().expect("the pass");
    assert!(fx.change_at(number.sequence).signed.is_some());
    assert!(fx.published());
    assert_eq!(fx.number().0, 5);
}
