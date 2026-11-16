//! DESIGN 15-setting-primitive, stage 7b-3 "the read on proofs" (section 1.6, "The read of one
//! slot", "Fold states, and the read's `source`" and "Receipts"). The projection reads each head
//! of a row by what it counts for here:
//! - two concurrent heads that count in full meet, and the change row names the heads the value
//!   came from (`with`) and how they stood (`standing`); a raced tightening below a wider head
//!   narrows, and its change says so;
//! - a pin that counts as a safe move is read as a value row at its scope: it narrows and
//!   releases nothing;
//! - the first raced act on an item's vault value row is met with the accepted default, as on
//!   the item-less row;
//! - a key judged by its own comparator takes a raced act only where it is no wider than what
//!   it replaced, and of concurrent heads the one no wider than every other;
//! - a head this install's own counting holds back (its signer's sequence floor) reads `Held`;
//! - an owner act a machine that is not his carried without his key's proof changes nothing and
//!   reads `Pending`, until his own act from an install that holds his key;
//! - the door of an install that cannot prove the owner's act refuses it, and nothing changes.
//!
//! Red at 7b-2 (`88379fbb6fe9`): the change rows there name no `with` and no `standing`, a raced
//! pin releases the vault row, an item's raced first act widens past the default, the
//! comparator key reads as a key with no order, no row reads `Held` or `Pending`, and the door
//! applies the change on its own install. The guard assertions inside these tests hold there
//! too. Green at the 7b-3 head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! setting_read_on_proofs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActAuthority, ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::test_doors::setting::{
    EnrolledMachine, SettingFrontier, SlotName, enroll_machine_with_key, land_setting_act_from,
    land_signed_setting_act, ordered_cap_read, setting_change, setting_frontier,
    setting_slot_heads, sign_setting_act_ahead,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

/// A cap whose rows meet: lower is stricter, its default is 10.
const CAP: &str = "test.ordered_cap";
/// A cap per channel whose rows meet: lower is stricter, its default is 10.
const CHANNEL_CAP: &str = "test.channel_cap";
/// A window judged by its own comparator (no longer is no wider); its default is 10.
const WINDOW: &str = "test.custom_window";
/// A number only the owner sets; it has no order.
const NUMBER: &str = "test.owner_number";
const GET: &str = "vault.settings.get";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// Another machine of the vault, with its MACHINE id.
struct Other {
    signer: EnrolledMachine,
    machine: EntityId,
}

fn vault_row(key: &str) -> SlotName<'_> {
    (key, None, SettingMode::Value, SettingScope::Vault)
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
            issuer,
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

    /// The owner answers `other`'s role on this install.
    fn answers_role(&self, other: &Other, role: MachineRole) {
        self.vault
            .set_machine_role(
                &self.owner_proof,
                ActSurface::ThisInstall,
                other.machine,
                role,
                None,
            )
            .expect("the owner answers the machine's role");
    }

    /// The owner removes `other` on this install.
    fn removes(&self, other: &Other) {
        self.answers_role(other, MachineRole::Removed);
    }

    /// The owner enrols this install's owner signing key: from then on the vault holds a key that
    /// proves his acts, and a machine that is not his needs its proof.
    fn enrols_owner_key(&self) {
        self.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(self.owner_proof.clone(), ActSurface::ThisInstall),
                &self.issuer,
            )
            .expect("the owner key is enrolled");
    }

    fn owner_sets(&self, key: &str, value: Value) {
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

    /// Where the acts on the row `slot` stand now.
    fn frontier_of(&self, (key, item, mode, scope): SlotName<'_>) -> SettingFrontier {
        setting_frontier(&self.vault, key, item, mode, scope).expect("frontier")
    }

    /// `other`'s act for the owner on the row `slot`, signed on its acts as they stood at `at`,
    /// landed here as a peer's entry lands.
    fn lands_from(&self, other: &Other, at: &SettingFrontier, slot: SlotName<'_>, value: Value) {
        land_setting_act_from(
            &self.vault,
            &other.signer,
            self.owner,
            at,
            slot,
            Some(value),
            T0,
        )
        .expect("the act is stored");
    }

    /// `test.ordered_cap` where the reader knows `known`: its value, the standing's name and the
    /// deciding row's revision.
    fn cap_at(&self, known: &[SettingScope]) -> (u64, String, u64) {
        let read = ordered_cap_read(&self.vault, known).expect("the read");
        (read.value, format!("{:?}", read.standing), read.revision)
    }

    fn cap(&self) -> (u64, String) {
        let (value, standing, _) = self.cap_at(&[]);
        (value, standing)
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// `key`'s value in force at the vault, for `item`, as `vault.settings.get` answers it.
    fn value_of(&self, key: &str, item: Option<&str>) -> Value {
        let input = match item {
            Some(item) => json!({ "key": key, "item": item }),
            None => json!({ "key": key }),
        };
        invoke(&self.as_owner(), GET, input)
            .unwrap_or_else(|error| panic!("{GET} answers: {error:?}"))["value"]
            .clone()
    }

    /// The change row of sequence `sequence`, as JSON.
    fn change(&self, sequence: u64) -> Value {
        let change = setting_change(&self.vault, sequence)
            .expect("the change stream reads")
            .expect("the change stands");
        serde_json::to_value(change).expect("a change row is JSON")
    }

    /// The live acts on `key`'s vault value row, as JSON.
    fn heads(&self, key: &str) -> BTreeSet<String> {
        setting_slot_heads(&self.vault, vault_row(key))
            .expect("the heads")
            .iter()
            .map(|head| {
                serde_json::to_value(head)
                    .expect("a hash is JSON")
                    .to_string()
            })
            .collect()
    }

    fn waiting_owner_choices(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("the fold")
            .waiting_owner_choices()
            .len()
    }
}

/// The acts a change row names: the one it is credited to and the heads it was met with.
fn named_acts(change: &Value) -> BTreeSet<String> {
    let mut named: BTreeSet<String> = change["with"]
        .as_array()
        .map(|with| with.iter().map(Value::to_string).collect())
        .unwrap_or_default();
    named.insert(change["signed"].to_string());
    named
}

#[test]
fn two_concurrent_heads_that_count_in_full_meet_and_the_change_names_both() {
    let fx = Fixture::rooted();
    fx.owner_sets(CAP, json!(6));
    let before_both = fx.frontier_of(vault_row(CAP));
    fx.owner_sets(CAP, json!(8));
    let other = fx.other_machine(0x71);
    fx.lands_from(&other, &before_both, vault_row(CAP), json!(5));

    let (value, standing, revision) = fx.cap_at(&[]);
    assert_eq!(
        (value, standing.as_str()),
        (5, "Settled"),
        "the owner's 8 and the other machine's 5 both count in full: their meet is 5"
    );
    let change = fx.change(revision);
    assert_eq!(fx.heads(CAP).len(), 2, "two live heads");
    assert_eq!(
        named_acts(&change),
        fx.heads(CAP),
        "the change that wrote 5 names both heads: {change}"
    );
    assert_eq!(change["standing"], json!("full"), "{change}");
}

#[test]
fn a_raced_tightening_below_a_wider_head_narrows_and_its_change_says_so() {
    let fx = Fixture::rooted();
    let other = fx.other_machine(0x72);
    fx.owner_sets(CAP, json!(6));
    let before_both = fx.frontier_of(vault_row(CAP));
    fx.owner_sets(CAP, json!(8));
    fx.removes(&other);
    fx.lands_from(&other, &before_both, vault_row(CAP), json!(3));

    let (value, standing, revision) = fx.cap_at(&[]);
    assert_eq!(
        (value, standing.as_str()),
        (3, "Settled"),
        "the raced 3 is a safe move over the 6 it replaced, met with the owner's 8"
    );
    let change = fx.change(revision);
    assert_eq!(named_acts(&change), fx.heads(CAP), "{change}");
    assert_eq!(change["standing"], json!("narrowed"), "{change}");
}

#[test]
fn a_pin_that_counts_as_a_safe_move_narrows_and_releases_nothing() {
    let fx = Fixture::rooted();
    fx.owner_sets(CAP, json!(6));
    let raced = EntityId::now();
    let raced_pin = (CAP, None, SettingMode::Pin, SettingScope::Project(raced));
    let other = fx.other_machine(0x73);
    let empty = fx.frontier_of(raced_pin.clone());
    fx.removes(&other);
    fx.lands_from(&other, &empty, raced_pin, json!(9));

    assert_eq!(
        fx.cap_at(&[SettingScope::Project(raced)]).0,
        6,
        "the raced pin of 9 is read as a value row: it meets the vault's 6 and releases nothing"
    );

    let tight = EntityId::now();
    let tight_pin = (CAP, None, SettingMode::Pin, SettingScope::Project(tight));
    let other = fx.other_machine(0x74);
    let empty = fx.frontier_of(tight_pin.clone());
    fx.removes(&other);
    fx.lands_from(&other, &empty, tight_pin, json!(3));
    assert_eq!(
        fx.cap_at(&[SettingScope::Project(tight)]).0,
        3,
        "a raced pin of 3 narrows the project"
    );

    let counted = EntityId::now();
    let counted_pin = (CAP, None, SettingMode::Pin, SettingScope::Project(counted));
    let live = fx.other_machine(0x75);
    let empty = fx.frontier_of(counted_pin.clone());
    fx.lands_from(&live, &empty, counted_pin, json!(9));
    assert_eq!(
        fx.cap_at(&[SettingScope::Project(counted)]).0,
        9,
        "a pin that counts in full releases the vault's 6"
    );
}

#[test]
fn the_first_raced_act_on_an_items_vault_row_narrows_the_default_and_never_widens_it() {
    let fx = Fixture::rooted();
    let mail = (
        CHANNEL_CAP,
        Some("mail"),
        SettingMode::Value,
        SettingScope::Vault,
    );
    let other = fx.other_machine(0x76);
    let empty = fx.frontier_of(mail.clone());
    fx.removes(&other);
    fx.lands_from(&other, &empty, mail.clone(), json!(12));

    assert_eq!(
        fx.value_of(CHANNEL_CAP, Some("mail")),
        json!(10),
        "the item's row replaced the empty slot, which gives the default 10: 12 over it reads 10"
    );

    let other = fx.other_machine(0x77);
    let now = fx.frontier_of(mail.clone());
    fx.removes(&other);
    fx.lands_from(&other, &now, mail, json!(4));
    assert_eq!(
        fx.value_of(CHANNEL_CAP, Some("mail")),
        json!(4),
        "a raced 4 narrows the item's row"
    );
}

#[test]
fn on_a_key_judged_by_its_own_comparator_a_raced_act_lands_only_where_it_is_no_wider() {
    let fx = Fixture::rooted();
    fx.owner_sets(WINDOW, json!(6));
    let other = fx.other_machine(0x78);
    let before_removal = fx.frontier_of(vault_row(WINDOW));
    fx.removes(&other);
    fx.lands_from(&other, &before_removal, vault_row(WINDOW), json!(3));

    assert_eq!(
        fx.value_of(WINDOW, None),
        json!(3),
        "the comparator says 3 is no wider than the 6 it replaced: the safe move lands"
    );

    let other = fx.other_machine(0x79);
    let now = fx.frontier_of(vault_row(WINDOW));
    fx.removes(&other);
    fx.lands_from(&other, &now, vault_row(WINDOW), json!(9));
    assert_eq!(
        fx.value_of(WINDOW, None),
        json!(3),
        "a raced 9 is wider than the 3 it replaced: it gives the 3"
    );
}

#[test]
fn concurrent_heads_on_a_comparator_key_read_the_one_no_wider_than_every_other() {
    let fx = Fixture::rooted();
    fx.owner_sets(WINDOW, json!(6));
    let before_both = fx.frontier_of(vault_row(WINDOW));
    fx.owner_sets(WINDOW, json!(8));
    let other = fx.other_machine(0x7a);
    fx.lands_from(&other, &before_both, vault_row(WINDOW), json!(5));

    assert_eq!(
        fx.value_of(WINDOW, None),
        json!(5),
        "of the owner's 8 and the other machine's 5, 5 is no wider than every other head"
    );
}

#[test]
fn a_head_this_installs_own_counting_holds_back_reads_held() {
    let fx = Fixture::rooted();
    fx.owner_sets(CAP, json!(6));
    let cap_now = fx.frontier_of(vault_row(CAP));
    let number_now = fx.frontier_of(vault_row(NUMBER));
    let other = fx.other_machine(0x7b);
    let late = sign_setting_act_ahead(
        &fx.vault,
        (&other.signer, fx.owner),
        &cap_now,
        (vault_row(CAP), Some(json!(3))),
        (T0, 0),
    )
    .expect("the act at the machine's next sequence");
    let first = sign_setting_act_ahead(
        &fx.vault,
        (&other.signer, fx.owner),
        &number_now,
        (vault_row(NUMBER), Some(json!(5))),
        (T0, 1),
    )
    .expect("the act one sequence past it");
    land_signed_setting_act(&fx.vault, &first, T0).expect("the later act lands first");
    land_signed_setting_act(&fx.vault, &late, T0).expect("the earlier act lands past the floor");

    assert_eq!(
        fx.cap(),
        (3, "Held".to_owned()),
        "the act arrived past its signer's sequence floor here: a safe move on this machine only"
    );
}

#[test]
fn an_owner_act_a_machine_not_his_carried_without_proof_changes_nothing_and_reads_pending() {
    let fx = Fixture::rooted();
    fx.owner_sets(CAP, json!(6));
    let other = fx.other_machine(0x7c);
    fx.answers_role(&other, MachineRole::Owned(MachineOwnership::WorkSchool));
    fx.enrols_owner_key();
    let now = fx.frontier_of(vault_row(CAP));
    fx.lands_from(&other, &now, vault_row(CAP), json!(3));

    assert_eq!(fx.waiting_owner_choices(), 1, "the act waits for his proof");
    assert_eq!(
        fx.cap(),
        (6, "Pending".to_owned()),
        "a proposal changes nothing, and the row says one waits"
    );

    fx.owner_sets(CAP, json!(3));
    assert_eq!(
        fx.cap(),
        (3, "Settled".to_owned()),
        "his own act from an install that holds his key lands and ends the ask"
    );
    assert_eq!(fx.waiting_owner_choices(), 0);
}

#[test]
fn the_door_of_an_install_that_cannot_prove_the_owners_act_refuses_it() {
    let fx = Fixture::rooted();
    fx.owner_sets(CAP, json!(6));
    fx.enrols_owner_key();
    release_owner_keys(&fx.vault);

    let refused = fx.vault.set_setting(
        SettingCaller::Owner(&fx.owner_proof),
        SetSetting::vault_value(CAP, json!(3)),
    );
    assert!(
        format!("{refused:?}").contains("OwnerKeyRequired"),
        "an act this install cannot prove would change nothing anywhere: {refused:?}"
    );
    assert_eq!(
        fx.cap(),
        (6, "Settled".to_owned()),
        "nothing of the refused change is stored"
    );
}
