//! DESIGN 15-setting-primitive, stage 7b-2 "what a head counts for" (section 1.6, "What an act
//! counts for" and "The read of one slot"). A setting act whose decider is proved counts in full
//! where this install counts its entry in full. Where its entry is in doubt here, it counts as a
//! safe move. Here the doubt is a removal race: the owner removed the carrying machine, and no
//! removal saw the act. Such an act
//! - on a key whose order has a meet gives the stricter of its value and what it replaced: a
//!   widening gives what it replaced, and a tightening lands;
//! - beside a counted widening of the owner's that it did not see, meets it with what it
//!   replaced;
//! - as the first act on the vault value row narrows the accepted default and never widens it;
//! - over a value wider than the default is judged against that value, not the default;
//! - on a key with no order changes nothing: what it replaced stays in force.
//!
//! An act that a removal saw keeps its full count, and so does a lone owner act wider than the
//! default.
//!
//! Red at 7a-4 (`7879603777ea`, whose projection read every live head as if it counted in
//! full): the four widening tests and the no-order test fail there. Green at the 7b-2 head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_counts`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope, SettingStanding,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::setting::{
    EnrolledMachine, SettingFrontier, enroll_machine_with_key, land_setting_act_from,
    ordered_cap_read, owner_number_read_both_ways, setting_frontier,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

/// A number only the owner sets; it has no order.
const NUMBER: &str = "test.owner_number";
/// A cap whose rows meet: lower is stricter, and its default is 10.
const CAP: &str = "test.ordered_cap";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// Another machine of the owner's, with its MACHINE id.
struct Other {
    signer: EnrolledMachine,
    machine: EntityId,
}

impl Fixture {
    /// A vault with an authority root whose serving install carries the owner's acts.
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
            _issuer: issuer,
            owner,
            owner_proof,
        }
    }

    fn machines(&self) -> BTreeSet<EntityId> {
        self.vault
            .authority_fold()
            .expect("the fold")
            .machines
            .keys()
            .copied()
            .collect()
    }

    /// Enrols another machine of the owner's, whose install key is derived from `seed`.
    fn other_machine(&self, seed: u8) -> Other {
        let before = self.machines();
        let signer =
            enroll_machine_with_key(&self.vault, &self.owner_proof, seed).expect("enrolled");
        let added: Vec<EntityId> = self.machines().difference(&before).copied().collect();
        let [machine] = added.as_slice() else {
            panic!("one machine enrolled: {added:?}");
        };
        Other {
            signer,
            machine: *machine,
        }
    }

    /// The owner removes `other` on this install.
    fn removes(&self, other: &Other) {
        self.vault
            .set_machine_role(
                &self.owner_proof,
                ActSurface::ThisInstall,
                other.machine,
                MachineRole::Removed,
                None,
            )
            .expect("the owner removes the machine");
    }

    fn owner_sets(&self, key: &str, value: serde_json::Value) {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting::vault_value(key, value),
            )
            .expect("the owner's change");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change applied: {outcome:?}"
        );
    }

    /// Where the acts on `key`'s vault value row stand now.
    fn frontier(&self, key: &str) -> SettingFrontier {
        setting_frontier(
            &self.vault,
            key,
            None,
            SettingMode::Value,
            SettingScope::Vault,
        )
        .expect("frontier")
    }

    /// `other`'s act for the owner on `key`'s vault value row, signed on the row's acts as they
    /// stood at `at`, landed here as a peer's entry lands.
    fn lands_from(&self, other: &Other, at: &SettingFrontier, key: &str, value: serde_json::Value) {
        land_setting_act_from(
            &self.vault,
            &other.signer,
            self.owner,
            at,
            (key, None, SettingMode::Value, SettingScope::Vault),
            Some(value),
            T0,
        )
        .expect("the act is stored");
    }

    /// `test.ordered_cap` at the vault: value and standing.
    fn cap(&self) -> (u64, SettingStanding) {
        let read = ordered_cap_read(&self.vault, &[]).expect("the read");
        (read.value, read.standing)
    }

    /// `test.owner_number` at the vault.
    fn number(&self) -> u64 {
        owner_number_read_both_ways(&self.vault, &[])
            .expect("the read")
            .0
            .value
    }
}

#[test]
fn a_widening_its_carrier_signed_after_its_removal_gives_what_it_replaced() {
    let fx = Fixture::rooted();
    let other = fx.other_machine(0x61);
    fx.owner_sets(CAP, json!(6));
    let before_removal = fx.frontier(CAP);
    fx.removes(&other);
    fx.lands_from(&other, &before_removal, CAP, json!(9));

    assert_eq!(
        fx.cap(),
        (6, SettingStanding::Settled),
        "no removal saw the act, so it is a safe move: 9 over the 6 it replaced reads 6"
    );
}

#[test]
fn a_tightening_its_carrier_signed_after_its_removal_lands() {
    let fx = Fixture::rooted();
    let other = fx.other_machine(0x62);
    fx.owner_sets(CAP, json!(6));
    let before_removal = fx.frontier(CAP);
    fx.removes(&other);
    fx.lands_from(&other, &before_removal, CAP, json!(3));

    assert_eq!(
        fx.cap(),
        (3, SettingStanding::Settled),
        "a safe move narrows: 3 over 6 reads 3"
    );
}

#[test]
fn a_raced_widening_beside_the_owners_counted_widening_meets_what_it_replaced() {
    let fx = Fixture::rooted();
    let other = fx.other_machine(0x63);
    fx.owner_sets(CAP, json!(6));
    let before_both = fx.frontier(CAP);
    fx.owner_sets(CAP, json!(8));
    fx.removes(&other);
    fx.lands_from(&other, &before_both, CAP, json!(9));

    assert_eq!(
        fx.cap(),
        (6, SettingStanding::Settled),
        "the owner's 8 counts in full; the raced 9 gives the 6 it replaced; their meet is 6"
    );

    fx.owner_sets(CAP, json!(8));
    assert_eq!(
        fx.cap(),
        (8, SettingStanding::Settled),
        "an act that saw both heads replaces them"
    );
}

#[test]
fn a_raced_first_act_on_the_vault_row_narrows_the_default_and_never_widens_it() {
    let fx = Fixture::rooted();
    let other = fx.other_machine(0x64);
    let empty = fx.frontier(CAP);
    fx.removes(&other);
    fx.lands_from(&other, &empty, CAP, json!(12));

    assert_eq!(
        fx.cap(),
        (10, SettingStanding::Settled),
        "the act replaced the empty slot, which gives the default 10: 12 over it reads 10"
    );

    let other = fx.other_machine(0x65);
    let now = fx.frontier(CAP);
    fx.removes(&other);
    fx.lands_from(&other, &now, CAP, json!(4));
    assert_eq!(
        fx.cap(),
        (4, SettingStanding::Settled),
        "a raced 4 over the row's 10 narrows it"
    );
}

#[test]
fn on_a_key_with_no_order_an_act_its_carrier_signed_after_its_removal_changes_nothing() {
    let fx = Fixture::rooted();
    let other = fx.other_machine(0x66);
    fx.owner_sets(NUMBER, json!(5));
    let before_removal = fx.frontier(NUMBER);
    fx.removes(&other);
    fx.lands_from(&other, &before_removal, NUMBER, json!(8));

    assert_eq!(
        fx.number(),
        5,
        "nothing is safer than anything else on a key with no order: the 5 it replaced stays"
    );
}

#[test]
fn an_act_a_removal_saw_keeps_its_full_count() {
    let fx = Fixture::rooted();
    let other = fx.other_machine(0x67);
    fx.owner_sets(CAP, json!(6));
    let live = fx.frontier(CAP);
    fx.lands_from(&other, &live, CAP, json!(9));
    assert_eq!(
        fx.cap(),
        (9, SettingStanding::Settled),
        "a live machine's act counts in full"
    );

    fx.removes(&other);
    assert_eq!(
        fx.cap(),
        (9, SettingStanding::Settled),
        "the removal saw the act, so it keeps its full count"
    );
}

#[test]
fn an_owners_act_wider_than_the_default_counts_in_full() {
    let fx = Fixture::rooted();
    fx.owner_sets(CAP, json!(20));

    assert_eq!(
        fx.cap(),
        (20, SettingStanding::Settled),
        "the owner's lone act counts in full: the vault row replaces the default 10"
    );
}

#[test]
fn a_raced_act_is_judged_against_the_value_it_replaced_not_the_default() {
    let fx = Fixture::rooted();
    let other = fx.other_machine(0x68);
    fx.owner_sets(CAP, json!(20));
    let before_removal = fx.frontier(CAP);
    fx.removes(&other);
    fx.lands_from(&other, &before_removal, CAP, json!(30));

    assert_eq!(
        fx.cap(),
        (20, SettingStanding::Settled),
        "a raced 30 over the owner's 20 gives the 20 it replaced, not the default 10"
    );

    let other = fx.other_machine(0x69);
    let now = fx.frontier(CAP);
    fx.removes(&other);
    fx.lands_from(&other, &now, CAP, json!(15));
    assert_eq!(
        fx.cap(),
        (15, SettingStanding::Settled),
        "a raced 15 over that row narrows it to 15"
    );
}
