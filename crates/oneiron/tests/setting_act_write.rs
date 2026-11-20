//! DESIGN 15-setting-primitive, stage 7a-2 "the act is the write" (section 1.6; RULING
//! SETTING-7A-2-DECIDERS = A). In a vault with an authority root:
//! - an owner's change of a row that travels appends its act in the same write, naming no slot
//!   for the vault value row and carrying the value inline, from this install when it names no
//!   surface; the change row names the act;
//! - a pin names its slot, on a target of its own;
//! - another machine's act writes the row here, credited to the owner and to that act;
//! - two concurrent acts on a key with no order conflict: the last value both descend from stays,
//!   until an act that saw both replaces them;
//! - two concurrent acts on a key whose order has a meet read their meet;
//! - an act whose value this build cannot decode reads the key's strictest value, quarantined;
//! - a machine that cannot carry the act is refused, and nothing is written;
//! - an equal value over the engine's row writes, and the row becomes the owner's;
//! - a key that does not travel keeps stage 7a-1's acts: digest only, and only with a surface.
//!
//! Without an authority root, the owner's change writes the row alone.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_act_write`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::policy_setting_doors::policy_setting_target;
use oneiron::receipt::AuthorityAuditQuery;
use oneiron::setting::{
    SetSetting, SetSettingOutcome, Setter, SettingCaller, SettingChange, SettingMode, SettingScope,
    SettingSource, SettingStanding,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::setting::{
    EnrolledMachine, enroll_machine_with_key, land_setting_act_from, ordered_cap_read,
    owner_number_read_both_ways, set_setting_as_engine, setting_change, setting_frontier,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_authority::authority::{
    AuthorityEntryHash, AuthorityOp, PolicySettingSet, authority_log_entity_id_from_hash,
    setting_slot_target,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_setting_contract::RowKey;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

const NUMBER: &str = "test.owner_number";
const CAP: &str = "test.ordered_cap";
const BANNER: &str = "test.member_banner";
const INSTALL_MODE: &str = "test.install_mode";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: Option<HostSlipIssuer>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// How far a fixture's vault is set up.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Install {
    /// No authority root: one machine.
    Unrooted,
    /// A root, and no live machine profile of this install to carry an act.
    RootedWithoutCarrier,
    /// A root, and this install carries the owner's acts.
    Rooted,
}

impl Fixture {
    fn open(install: Install) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = (install != Install::Unrooted).then(|| {
            let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
            vault.ensure_host_root_slip(&issuer).expect("host root");
            vault
                .provision_engine_machine_identities(&issuer)
                .expect("engine machine identities");
            issuer
        });
        if install == Install::Rooted {
            vault
                .ensure_serving_install_profile(
                    issuer.as_ref().expect("a rooted vault's issuer"),
                    MachineRole::Unanswered,
                )
                .expect("serving install profile");
        }
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            _issuer: issuer,
            owner,
            owner_proof,
        }
    }

    fn rooted() -> Self {
        Self::open(Install::Rooted)
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

    /// The owner's setting acts on the main log, as the owner's audit lists them.
    fn setting_act_count(&self) -> usize {
        self.vault
            .authority_audit(
                &self.owner_proof,
                &AuthorityAuditQuery {
                    limit: Some(500),
                    ..AuthorityAuditQuery::default()
                },
            )
            .expect("the owner's audit")
            .rows
            .iter()
            .filter(|row| row.source_op == "policy_setting")
            .count()
    }

    /// `test.owner_number` at the vault: value, source, revision and standing.
    fn number(&self) -> (u64, SettingSource, u64, SettingStanding) {
        let (read, _) = owner_number_read_both_ways(&self.vault, &[]).expect("the read");
        (read.value, read.source, read.revision, read.standing)
    }

    fn second_machine(&self, seed: u8) -> EnrolledMachine {
        enroll_machine_with_key(&self.vault, &self.owner_proof, seed).expect("enrolled")
    }

    /// `machine`'s act on `key`'s vault value row, on the row's acts as they stood at `at`.
    fn lands_from(
        &self,
        machine: &EnrolledMachine,
        at: &oneiron::test_doors::setting::SettingFrontier,
        key: &str,
        value: serde_json::Value,
    ) {
        land_setting_act_from(
            &self.vault,
            machine,
            self.owner,
            at,
            (key, None, SettingMode::Value, SettingScope::Vault),
            Some(value),
            T0,
        )
        .expect("the act lands");
    }

    fn frontier(&self, key: &str) -> oneiron::test_doors::setting::SettingFrontier {
        setting_frontier(
            &self.vault,
            key,
            None,
            SettingMode::Value,
            SettingScope::Vault,
        )
        .expect("frontier")
    }
}

#[test]
fn an_owners_change_of_a_row_that_travels_appends_its_act_with_the_value_inline() {
    let fx = Fixture::rooted();
    let change = fx.change_of(&fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5))));
    assert_eq!(
        change.surface,
        Some(ActSurface::ThisInstall),
        "no surface named: from this install"
    );
    let act = fx.act(change.signed);
    assert_eq!(act.setting, NUMBER);
    assert_eq!(act.slot, None, "the vault value row names no slot");
    assert_eq!(act.inline.as_deref(), Some(&b"5"[..]));
    assert_eq!(act.value, Some(*blake3::hash(b"5").as_bytes()));
    assert_eq!(
        act.act.target,
        policy_setting_target(NUMBER).expect("target"),
        "the key's target, as stage 7a-1's acts name it"
    );
    let (value, source, revision, standing) = fx.number();
    assert_eq!(value, 5);
    assert_eq!(source, SettingSource::Row(SettingScope::Vault));
    assert_eq!(
        revision, change.sequence,
        "the door's row stands as the fold gives it"
    );
    assert_eq!(standing, SettingStanding::Settled);
}

#[test]
fn a_pin_names_its_slot_on_a_target_of_its_own() {
    let fx = Fixture::rooted();
    let change = fx.change_of(&fx.owner_sets(SetSetting {
        mode: SettingMode::Pin,
        ..SetSetting::vault_value(NUMBER, json!(3))
    }));
    let act = fx.act(change.signed);
    let slot = RowKey {
        name: NUMBER.to_owned(),
        item: None,
        mode: SettingMode::Pin,
        scope: SettingScope::Vault,
    };
    assert_eq!(act.slot.as_ref(), Some(&slot));
    assert_eq!(act.act.target, setting_slot_target(&slot).expect("target"));
    assert_ne!(
        act.act.target,
        policy_setting_target(NUMBER).expect("target")
    );
    assert_eq!(fx.number().1, SettingSource::Pin(SettingScope::Vault));
}

#[test]
fn another_machines_act_writes_the_row_here() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x42);
    let before = fx.frontier(NUMBER);
    fx.lands_from(&other, &before, NUMBER, json!(4));

    let (value, source, revision, standing) = fx.number();
    assert_eq!(
        value, 4,
        "the projection wrote the row from the other machine's act"
    );
    assert_eq!(source, SettingSource::Row(SettingScope::Vault));
    assert_eq!(standing, SettingStanding::Settled);
    let change = fx.change_at(revision);
    assert_eq!(change.by, Some(fx.owner));
    assert_eq!(change.setter, Setter::Owner);
    let act = fx.act(change.signed);
    assert_eq!(act.inline.as_deref(), Some(&b"4"[..]));
}

#[test]
fn concurrent_acts_on_a_key_with_no_order_conflict_until_an_act_that_saw_both() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x43);
    fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5)));
    let agreed = fx.frontier(NUMBER);
    fx.owner_sets(SetSetting::vault_value(NUMBER, json!(6)));
    fx.lands_from(&other, &agreed, NUMBER, json!(3));

    let (value, _, _, standing) = fx.number();
    assert_eq!(value, 5, "the last value both heads descend from stays");
    assert_eq!(standing, SettingStanding::Conflict);

    fx.owner_sets(SetSetting::vault_value(NUMBER, json!(8)));
    let (value, _, _, standing) = fx.number();
    assert_eq!(value, 8, "an act that saw both heads replaces them");
    assert_eq!(standing, SettingStanding::Settled);
}

#[test]
fn concurrent_acts_on_a_key_whose_order_has_a_meet_read_their_meet() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x44);
    let before = fx.frontier(CAP);
    fx.owner_sets(SetSetting::vault_value(CAP, json!(7)));
    fx.lands_from(&other, &before, CAP, json!(4));

    let read = ordered_cap_read(&fx.vault, &[]).expect("the read");
    assert_eq!(read.value, 4, "lower is stricter: the meet of 7 and 4");
    assert_eq!(read.standing, SettingStanding::Settled);
}

#[test]
fn an_act_whose_value_does_not_decode_reads_the_strictest_value() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x45);
    let before = fx.frontier(NUMBER);
    fx.lands_from(&other, &before, NUMBER, json!("five"));

    let (value, source, _, standing) = fx.number();
    assert_eq!(value, 0, "the key's strictest value");
    assert_eq!(source, SettingSource::Unreadable(SettingScope::Vault));
    assert_eq!(standing, SettingStanding::Quarantined);
}

#[test]
fn a_machine_that_cannot_carry_the_act_is_refused_and_nothing_is_written() {
    let fx = Fixture::open(Install::RootedWithoutCarrier);
    let acts = fx.setting_act_count();
    let refused = fx.vault.set_setting(
        SettingCaller::Owner(&fx.owner_proof),
        SetSetting::vault_value(NUMBER, json!(5)),
    );
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(fx.setting_act_count(), acts, "no act");
    let (value, source, revision, _) = fx.number();
    assert_eq!(
        (value, source, revision),
        (7, SettingSource::Default, 0),
        "no row"
    );
}

#[test]
fn without_an_authority_root_the_owners_change_writes_the_row_alone() {
    let fx = Fixture::open(Install::Unrooted);
    let change = fx.change_of(&fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5))));
    assert_eq!(change.signed, None);
    assert_eq!(change.surface, None);
    assert_eq!(fx.setting_act_count(), 0);
    let (value, _, _, standing) = fx.number();
    assert_eq!(value, 5);
    assert_eq!(standing, SettingStanding::Settled);
}

#[test]
fn an_equal_value_over_the_engines_row_writes_and_the_row_becomes_the_owners() {
    let fx = Fixture::rooted();
    set_setting_as_engine(&fx.vault, None, SetSetting::vault_value(NUMBER, json!(5)))
        .expect("the engine's own change");
    let over_engine = fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5)));
    let change = fx.change_of(&over_engine);
    assert_eq!(change.setter, Setter::Owner);
    assert_eq!(
        change.prior, change.value,
        "prior equals value: the row became the owner's"
    );
    assert!(change.signed.is_some(), "the owner's act travels");

    let again = fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5)));
    assert!(
        matches!(again, SetSettingOutcome::Applied { sequence: None, .. }),
        "over the owner's own row an equal value writes nothing: {again:?}"
    );
}

#[test]
fn a_key_that_does_not_travel_keeps_the_digest_only_act() {
    let fx = Fixture::rooted();
    let text = fx.change_of(&fx.owner_sets(SetSetting {
        surface: Some(ActSurface::ThisInstall),
        ..SetSetting::vault_value(BANNER, json!("hello"))
    }));
    let act = fx.act(text.signed);
    assert_eq!(act.inline, None, "free text never goes on the log");
    assert_eq!(act.slot, None);

    let acts = fx.setting_act_count();
    for (key, value) in [(BANNER, json!("again")), (INSTALL_MODE, json!(3))] {
        let change = fx.change_of(&fx.owner_sets(SetSetting::vault_value(key, value)));
        assert_eq!(change.signed, None, "{key}: no surface, no act");
    }
    assert_eq!(fx.setting_act_count(), acts);
}
