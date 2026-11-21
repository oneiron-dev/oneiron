//! DESIGN 15-setting-primitive, stage 7c-1 "values beside their acts" (section 1.6, "What
//! travels": inline or beside; "Fold states"). In a vault with an authority root:
//! - the owner's change of a free-text key travels as its act: the act keeps only the value's
//!   digest, and the same write stores the value beside it, in a row addressed by that digest;
//! - a value longer than an act carries travels beside it whole;
//! - another machine's act whose value is beside it writes the row here once both are here, in
//!   either order;
//! - an act whose value has not arrived leaves the row as it was, `Pending`; the value's arrival
//!   alone moves the row to it;
//! - a value beside an act that does not match its digest, or was erased here, reads the key's
//!   strictest value, `Quarantined`, also when that happens after the row read it, and also
//!   while a later act waits for its own value; a put at that value's row with no value tag is
//!   read at once; on a key that names no strictest value the row reads the key's default;
//! - each act's value has a row of its own: the owner sets again a value whose row was erased;
//! - a row a key's hook refuses on this install keeps no other row of the pass from landing,
//!   and the owner's resident route lands on an install with no model manifest;
//! - review round 2: an erase of a value the row read has it read again before the erase
//!   returns, takes the value out of the setting history, and reaches a value a quarantine kept;
//!   a value that arrives after an erase names no erased entity; a pass on a thread that holds
//!   the calendar admission turn leaves a feed for the pass after the turn; seat installs that
//!   meet with no common act leave no seat; a seat taken out of service keeps its system from
//!   an ICS feed;
//! - an act on a key this build does not know is read once, whether it carries its value or
//!   keeps only a digest, also when its value comes beside it later: a pass reads it again only
//!   once its acts move or a build knows the key;
//! - the rows the owner set before the vault was rooted publish their free text beside the batch
//!   act, and an install that holds the log and none of the rows writes them from it;
//! - `vault.settings.list` shows how each key travels: inline, beside, or local.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_beside`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteEntityOptions;
use oneiron::memory::Memory;
use oneiron::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingChange, SettingMode, SettingScope,
    SettingStanding,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    EnrolledMachine, SignedSettingAct, SlotName, enroll_machine_with_key,
    forget_projected_setting_rows, hold_setting_write_turn, land_setting_batch_from,
    land_setting_beside_act_from, land_setting_beside_untagged, land_setting_beside_value,
    land_setting_beside_value_before, land_setting_beside_value_holding, land_signed_setting_act,
    member_banner_read, permit_list_read, setting_beside_row, setting_beside_value_here,
    setting_change, setting_changes, setting_frontier_of, sign_setting_beside_act_from,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_authority::authority::{
    AuthorityEntryHash, AuthorityOp, PolicySettingSet, authority_log_entity_id_from_hash,
    setting_value_digest,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const BANNER: &str = "test.member_banner";
const PERMITS: &str = "test.permit_list";
const NUMBER: &str = "test.owner_number";
const INSTALL_MODE: &str = "test.install_mode";
const LEARNED: &str = "test.learned_rate";
/// A key no build of this crate knows.
const UNKNOWN: &str = "test.not_in_this_build";
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
    /// A vault with no authority root: one machine. Opened owned: the writer lease is what lets
    /// the owner's handle call the owner verbs by name.
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

    /// A rooted vault whose install carries the owner's acts.
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

    /// Enrols this install's machine profile: it carries the owner's acts from now on.
    fn carry(&self) {
        self.vault
            .ensure_serving_install_profile(
                self.issuer.as_ref().expect("a rooted vault's issuer"),
                MachineRole::Unanswered,
            )
            .expect("serving install profile");
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
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

    fn second_machine(&self, seed: u8) -> EnrolledMachine {
        enroll_machine_with_key(&self.vault, &self.owner_proof, seed).expect("enrolled")
    }

    /// `machine`'s act on `key`'s vault value row to `value`, its value beside the act, on the
    /// row's acts as they stand now; the row that holds the value is not landed.
    fn beside_act_from(&self, machine: &EnrolledMachine, key: &str, value: &Value) {
        let frontier = setting_frontier_of(&self.vault, &[vault_row(key)]).expect("frontier");
        let counted = land_setting_beside_act_from(
            &self.vault,
            (machine, self.owner),
            &frontier,
            vault_row(key),
            value,
            T0,
        )
        .expect("the act lands");
        assert!(counted, "the fold here counts the act");
    }

    /// `machine`'s act on `key`'s vault value row to `value`, its value beside the act, signed on
    /// the row's acts as they stand now and not landed: a test lands its value's row first.
    fn sign_beside_act_from(
        &self,
        machine: &EnrolledMachine,
        key: &str,
        value: &Value,
    ) -> SignedSettingAct {
        let frontier = setting_frontier_of(&self.vault, &[vault_row(key)]).expect("frontier");
        sign_setting_beside_act_from(
            &self.vault,
            (machine, self.owner),
            &frontier,
            vault_row(key),
            value,
            T0,
        )
        .expect("the act signs")
    }

    /// Lands `act` as a peer's entry lands; its commit runs the pass.
    fn land(&self, act: &SignedSettingAct) {
        land_signed_setting_act(&self.vault, act, T0).expect("the act lands");
    }

    /// `test.permit_list` at the vault: value and standing.
    fn permits(&self) -> (Vec<String>, SettingStanding) {
        let read = permit_list_read(&self.vault).expect("the read");
        (read.value, read.standing)
    }

    /// `test.member_banner` at the vault: value and standing.
    fn banner(&self) -> (String, SettingStanding) {
        let read = member_banner_read(&self.vault).expect("the read");
        (read.value, read.standing)
    }
}

/// `key`'s vault value row with no item.
fn vault_row(key: &str) -> SlotName<'_> {
    (key, None, SettingMode::Value, SettingScope::Vault)
}

/// The digest an act keeps of `value`: BLAKE3 over its JSON bytes.
fn digest_of(value: &Value) -> [u8; 32] {
    setting_value_digest(&serde_json::to_vec(value).expect("JSON"))
}

#[test]
fn the_owners_free_text_travels_beside_its_act() {
    let fx = Fixture::rooted();
    let hello = json!("hello");
    let change = fx.change_of(&fx.owner_sets(SetSetting::vault_value(BANNER, hello.clone())));
    let act = fx.act(change.signed);
    assert_eq!(act.inline, None, "free text never goes on the log");
    assert_eq!(
        act.value,
        Some(digest_of(&hello)),
        "the act keeps its digest"
    );
    assert_eq!(act.slot, None, "the vault value row");
    assert_eq!(
        setting_beside_value_here(&fx.vault, vault_row(BANNER), &hello).expect("the row"),
        Some(hello),
        "the same write stored the value beside the act"
    );
    assert_eq!(fx.banner(), ("hello".to_owned(), SettingStanding::Settled));
}

#[test]
fn a_value_longer_than_an_act_carries_travels_beside_it_whole() {
    let fx = Fixture::rooted();
    let long = "a long banner ".repeat(400);
    assert!(long.len() > 4096, "longer than an act carries inline");
    let value = json!(long);
    let change = fx.change_of(&fx.owner_sets(SetSetting::vault_value(BANNER, value.clone())));
    let act = fx.act(change.signed);
    assert_eq!(act.inline, None);
    assert_eq!(act.value, Some(digest_of(&value)));
    assert_eq!(
        setting_beside_value_here(&fx.vault, vault_row(BANNER), &value).expect("the row"),
        Some(value)
    );
    assert_eq!(fx.banner(), (long, SettingStanding::Settled));
}

#[test]
fn another_machines_act_with_its_value_beside_it_writes_the_row_here() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let value = json!("from the other machine");
    let act = fx.sign_beside_act_from(&machine, BANNER, &value);
    land_setting_beside_value_before(&fx.vault, vault_row(BANNER), (&value, &value), &act)
        .expect("the value lands before its act");
    fx.land(&act);
    assert_eq!(
        fx.banner(),
        (
            "from the other machine".to_owned(),
            SettingStanding::Settled
        )
    );
}

#[test]
fn an_act_whose_value_has_not_arrived_reads_pending_until_it_does() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let before = fx.permits();
    assert_eq!(before.1, SettingStanding::Settled);

    let read_only = json!(["read"]);
    fx.beside_act_from(&machine, PERMITS, &read_only);
    assert_eq!(
        fx.permits(),
        (before.0.clone(), SettingStanding::Pending),
        "the row reads as it did before the act"
    );

    // The value's arrival alone moves the row: its commit runs the projection.
    land_setting_beside_value(&fx.vault, vault_row(PERMITS), &read_only).expect("the value lands");
    assert_eq!(
        fx.permits(),
        (vec!["read".to_owned()], SettingStanding::Settled)
    );
}

#[test]
fn a_value_that_does_not_match_its_digest_reads_the_strictest_value() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let read_only = json!(["read"]);
    let act = fx.sign_beside_act_from(&machine, PERMITS, &read_only);
    land_setting_beside_value_before(
        &fx.vault,
        vault_row(PERMITS),
        (&read_only, &json!(["send"])),
        &act,
    )
    .expect("a row that does not match its digest");
    fx.land(&act);
    assert_eq!(
        fx.permits(),
        (Vec::new(), SettingStanding::Quarantined),
        "the key's strictest value"
    );
}

#[test]
fn a_value_erased_here_reads_the_strictest_value() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let read_only = json!(["read"]);
    let act = fx.sign_beside_act_from(&machine, PERMITS, &read_only);
    let row = land_setting_beside_value_before(
        &fx.vault,
        vault_row(PERMITS),
        (&read_only, &read_only),
        &act,
    )
    .expect("the value lands before its act");
    assert!(
        fx.vault
            .delete_entity_with_options(&row, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );

    fx.land(&act);
    assert_eq!(
        setting_beside_value_here(&fx.vault, vault_row(PERMITS), &read_only).expect("the read"),
        None,
        "the erase reached the value"
    );
    assert_eq!(
        fx.permits(),
        (Vec::new(), SettingStanding::Quarantined),
        "the key's strictest value"
    );
}

#[test]
fn a_value_erased_after_the_row_read_it_reads_the_strictest_value() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let read_only = json!(["read"]);
    let act = fx.sign_beside_act_from(&machine, PERMITS, &read_only);
    land_setting_beside_value_before(
        &fx.vault,
        vault_row(PERMITS),
        (&read_only, &read_only),
        &act,
    )
    .expect("the value lands before its act");
    fx.land(&act);
    assert_eq!(
        fx.permits(),
        (vec!["read".to_owned()], SettingStanding::Settled)
    );

    let row = setting_beside_row(&fx.vault, vault_row(PERMITS), &read_only).expect("the row's id");
    assert!(
        fx.vault
            .delete_entity_with_options(&row, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );
    // The erase moves no act: the next pass reads the row again because its value is gone.
    fx.vault.project_settings().expect("the pass");
    assert_eq!(
        fx.permits(),
        (Vec::new(), SettingStanding::Quarantined),
        "the key's strictest value"
    );
}

#[test]
fn a_value_replaced_after_the_row_read_it_reads_the_strictest_value() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let read_only = json!(["read"]);
    let act = fx.sign_beside_act_from(&machine, PERMITS, &read_only);
    land_setting_beside_value_before(
        &fx.vault,
        vault_row(PERMITS),
        (&read_only, &read_only),
        &act,
    )
    .expect("the value lands before its act");
    fx.land(&act);
    assert_eq!(
        fx.permits(),
        (vec!["read".to_owned()], SettingStanding::Settled)
    );

    // Its commit runs the pass, which reads the row again: it no longer holds the act's value.
    land_setting_beside_value_holding(&fx.vault, vault_row(PERMITS), &read_only, &json!(["send"]))
        .expect("a row that no longer matches its digest");
    assert_eq!(
        fx.permits(),
        (Vec::new(), SettingStanding::Quarantined),
        "the key's strictest value"
    );
}

#[test]
fn an_act_on_a_key_this_build_does_not_know_that_keeps_only_a_digest_is_read_once() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    fx.beside_act_from(&machine, UNKNOWN, &json!("another build's value"));
    // The act's commit ran the pass. No value beside it is here, and a signed record never
    // brings one: a later pass leaves the target alone.
    assert_eq!(
        fx.vault.project_settings().expect("the pass").moved,
        0,
        "no pass reads the act again until a build knows its key"
    );
}

#[test]
fn a_value_that_comes_beside_an_act_on_a_key_this_build_does_not_know_moves_no_pass() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let value = json!("another build's value");
    fx.beside_act_from(&machine, UNKNOWN, &value);
    // Its commit runs the pass: the value changes nothing a build that does not know the key
    // reads, so a later pass leaves the target alone too.
    land_setting_beside_value(&fx.vault, vault_row(UNKNOWN), &value).expect("the value lands");
    assert_eq!(
        setting_beside_value_here(&fx.vault, vault_row(UNKNOWN), &value).expect("the row"),
        Some(value),
        "the value is here"
    );
    assert_eq!(
        fx.vault.project_settings().expect("the pass").moved,
        0,
        "no pass reads the act again until a build knows its key"
    );
}

#[test]
fn an_act_on_a_key_this_build_does_not_know_that_carries_its_value_is_read_once() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let frontier = setting_frontier_of(&fx.vault, &[vault_row(UNKNOWN)]).expect("frontier");
    let counted = land_setting_batch_from(
        &fx.vault,
        &machine,
        fx.owner,
        &frontier,
        &[(vault_row(UNKNOWN), Some(json!(7)))],
        T0,
    )
    .expect("the act lands");
    assert!(counted, "the fold here counts the act");
    // The act's commit ran the pass.
    assert_eq!(
        fx.vault.project_settings().expect("the pass").moved,
        0,
        "no pass reads the act again until a build knows its key"
    );
}

#[test]
fn free_text_set_before_the_root_publishes_beside_the_batch_act() {
    let mut fx = Fixture::unrooted();
    let early = json!("set before the root");
    let change = fx.change_of(&fx.owner_sets(SetSetting::vault_value(BANNER, early.clone())));
    assert_eq!(change.signed, None, "one machine: the row alone");
    fx.root();
    fx.carry();
    fx.vault.project_settings().expect("the pass");

    let act = fx.act(fx.change_at(change.sequence).signed);
    assert_eq!(act.setting, BANNER);
    assert_eq!(act.inline, None, "free text never goes on the log");
    assert_eq!(act.value, Some(digest_of(&early)));
    assert_eq!(
        setting_beside_value_here(&fx.vault, vault_row(BANNER), &early).expect("the row"),
        Some(early)
    );

    // An install that holds the log and the value beside it, and not the row, writes the row.
    assert!(forget_projected_setting_rows(&fx.vault).expect("forget") >= 1);
    assert_eq!(fx.banner().0, "", "the row is gone");
    fx.vault.project_settings().expect("the pass");
    assert_eq!(
        fx.banner(),
        ("set before the root".to_owned(), SettingStanding::Settled)
    );
}

#[test]
fn the_list_shows_how_each_key_travels() {
    let fx = Fixture::rooted();
    let listed = invoke(
        &fx.as_owner(),
        "vault.settings.list",
        json!({ "prefix": "test." }),
    )
    .expect("the owner lists the test keys");
    let travel = |key: &str| -> Value {
        listed["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .find(|entry| entry["key"] == key)
            .unwrap_or_else(|| panic!("{key} is listed"))["travel"]
            .clone()
    };
    assert_eq!(travel(NUMBER), json!("inline"), "a closed value");
    assert_eq!(travel(BANNER), json!("beside"), "free text");
    assert_eq!(travel(PERMITS), json!("beside"), "a list of text");
    assert_eq!(travel(INSTALL_MODE), json!("local"), "stays on its install");
    assert_eq!(travel(LEARNED), json!("local"), "a learned key");
}

#[test]
fn the_owner_sets_again_a_value_whose_row_was_erased() {
    let fx = Fixture::rooted();
    let hello = json!("hello");
    fx.owner_sets(SetSetting::vault_value(BANNER, hello.clone()));
    let erased = setting_beside_row(&fx.vault, vault_row(BANNER), &hello).expect("the row");
    fx.owner_sets(SetSetting::vault_value(BANNER, json!("another banner")));
    assert!(
        fx.vault
            .delete_entity_with_options(&erased, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );

    // The same value again is a new act, with a row of its own: the erase does not refuse it.
    fx.owner_sets(SetSetting::vault_value(BANNER, hello.clone()));
    assert_ne!(
        setting_beside_row(&fx.vault, vault_row(BANNER), &hello).expect("the new row"),
        erased
    );
    assert_eq!(
        setting_beside_value_here(&fx.vault, vault_row(BANNER), &hello).expect("the read"),
        Some(hello)
    );
    assert_eq!(fx.banner(), ("hello".to_owned(), SettingStanding::Settled));
}

#[test]
fn a_row_with_no_value_tag_after_its_act_is_read_at_once() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let read_only = json!(["read"]);
    let before = fx.permits();
    fx.beside_act_from(&machine, PERMITS, &read_only);
    assert_eq!(fx.permits(), (before.0, SettingStanding::Pending));

    // Its put runs the pass, whatever its body: the row holds no value of the act.
    land_setting_beside_untagged(
        &fx.vault,
        vault_row(PERMITS),
        &read_only,
        b"not a setting value",
    )
    .expect("the row lands");
    assert_eq!(
        fx.permits(),
        (Vec::new(), SettingStanding::Quarantined),
        "the key's strictest value"
    );
}

#[test]
fn a_kept_value_erased_while_a_later_act_waits_reads_the_strictest_value() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let read_only = json!(["read"]);
    fx.beside_act_from(&machine, PERMITS, &read_only);
    land_setting_beside_value(&fx.vault, vault_row(PERMITS), &read_only).expect("the value lands");
    assert_eq!(
        fx.permits(),
        (vec!["read".to_owned()], SettingStanding::Settled)
    );
    let kept = setting_beside_row(&fx.vault, vault_row(PERMITS), &read_only).expect("the row");

    // A later act whose value has not arrived: the row keeps its value, `Pending`.
    fx.beside_act_from(&machine, PERMITS, &json!(["read", "send"]));
    assert_eq!(
        fx.permits(),
        (vec!["read".to_owned()], SettingStanding::Pending)
    );

    // The value the row keeps is erased here while the later act still waits.
    assert!(
        fx.vault
            .delete_entity_with_options(&kept, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );
    fx.vault.project_settings().expect("the pass");
    assert_eq!(
        fx.permits(),
        (Vec::new(), SettingStanding::Quarantined),
        "the key's strictest value"
    );
}

#[test]
fn an_erased_value_on_a_key_with_no_strictest_value_reads_the_default() {
    let fx = Fixture::rooted();
    let hello = json!("hello");
    fx.owner_sets(SetSetting::vault_value(BANNER, hello.clone()));
    assert_eq!(fx.banner(), ("hello".to_owned(), SettingStanding::Settled));
    let row = setting_beside_row(&fx.vault, vault_row(BANNER), &hello).expect("the row");
    assert!(
        fx.vault
            .delete_entity_with_options(&row, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );

    // `test.member_banner` names no strictest value: no read takes the erased value.
    fx.vault.project_settings().expect("the pass");
    assert_eq!(
        fx.banner(),
        (String::new(), SettingStanding::Quarantined),
        "the key's default"
    );
}

#[test]
fn a_row_a_keys_hook_refuses_here_keeps_no_other_row_of_the_pass_from_landing() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let floor = || vault_row("booking.emergency.min_proposals");
    // A floor above this install's count of proposals: the key's hook refuses the row here.
    let frontier = setting_frontier_of(&fx.vault, &[floor()]).expect("frontier");
    assert!(
        land_setting_batch_from(
            &fx.vault,
            &machine,
            fx.owner,
            &frontier,
            &[(floor(), Some(json!(9)))],
            T0
        )
        .expect("the act lands"),
        "the fold here counts the act"
    );

    // The next act's pass reads both rows: the refused one stays as it was, and the other lands.
    let value = json!("from the other machine");
    let act = fx.sign_beside_act_from(&machine, BANNER, &value);
    land_setting_beside_value_before(&fx.vault, vault_row(BANNER), (&value, &value), &act)
        .expect("the value lands before its act");
    fx.land(&act);
    assert_eq!(
        fx.banner(),
        (
            "from the other machine".to_owned(),
            SettingStanding::Settled
        )
    );
    let read = invoke(
        &fx.as_owner(),
        "vault.settings.get",
        json!({ "key": "booking.emergency.min_proposals" }),
    )
    .expect("the owner reads the floor");
    assert_ne!(read["value"], json!(9), "the refused row stays as it was");
}

#[test]
fn the_owners_resident_route_lands_on_an_install_with_no_model_manifest() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let route = || {
        (
            "models.resident_route",
            Some("llm"),
            SettingMode::Value,
            SettingScope::Vault,
        )
    };
    let frontier = setting_frontier_of(&fx.vault, &[route()]).expect("frontier");
    assert!(
        land_setting_batch_from(
            &fx.vault,
            &machine,
            fx.owner,
            &frontier,
            &[(route(), Some(json!("on_device")))],
            T0
        )
        .expect("the act lands"),
        "the fold here counts the act"
    );
    // His machine checked the route under its manifest; this install's reader takes a route its
    // own manifest does not admit as the slot's pin.
    let read = invoke(
        &fx.as_owner(),
        "vault.settings.get",
        json!({ "key": "models.resident_route", "item": "llm" }),
    )
    .expect("the owner reads the route");
    assert_eq!(read["value"], json!("on_device"));
}

const MENTIONED: &str = "test.mentioned_ids";
const SEAT: &str = "calendar.connector_seat";
const FEED: &str = "calendar.ics_feed";

/// `key`'s vault value row of `item`.
fn item_row<'a>(key: &'a str, item: &'a str) -> SlotName<'a> {
    (key, Some(item), SettingMode::Value, SettingScope::Vault)
}

/// The setup of the CalDAV seat `work`, which imports under the system `caldav-work`, of the
/// calendar `calendar_ref`.
fn seat_setup(calendar_ref: &str) -> Value {
    json!({
        "config": {
            "seat_ref": "work",
            "secret_ref": "caldav-work",
            "system": "caldav-work",
            "calendar_ref": calendar_ref,
            "cadence_jitter_min_seconds": 300,
            "cadence_jitter_max_seconds": 900,
        },
        "endpoint": "https://dav.example.test/",
    })
}

/// The configuration of an ICS feed that imports under `system`.
fn feed(system: &str) -> Value {
    json!({
        "secret_ref": "ics-feed:work",
        "system": system,
        "cadence_min_seconds": 600,
        "cadence_max_seconds": 1200,
    })
}

/// The owner's `vault.settings.get` of `key` at `item`: the value it answers.
fn owner_reads(fx: &Fixture, key: &str, item: Option<&str>) -> Value {
    let input = match item {
        Some(item) => json!({ "key": key, "item": item }),
        None => json!({ "key": key }),
    };
    invoke(&fx.as_owner(), "vault.settings.get", input).expect("the owner reads the key")["value"]
        .clone()
}

/// The owner's `vault.settings.set` of `key`'s vault value row of `item` to `value`: its answer,
/// or its refusal as the error prints it.
fn owner_sets_item(fx: &Fixture, key: &str, item: &str, value: Value) -> Result<Value, String> {
    invoke(
        &fx.as_owner(),
        "vault.settings.set",
        json!({ "key": key, "item": item, "scope": { "kind": "vault" }, "value": value }),
    )
    .map_err(|error| format!("{error:?}"))
}

#[test]
fn a_value_erased_after_the_row_read_it_reads_the_strictest_value_once_the_erase_returns() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let read_only = json!(["read"]);
    let act = fx.sign_beside_act_from(&machine, PERMITS, &read_only);
    land_setting_beside_value_before(
        &fx.vault,
        vault_row(PERMITS),
        (&read_only, &read_only),
        &act,
    )
    .expect("the value lands before its act");
    fx.land(&act);
    assert_eq!(
        fx.permits(),
        (vec!["read".to_owned()], SettingStanding::Settled)
    );

    let row = setting_beside_row(&fx.vault, vault_row(PERMITS), &read_only).expect("the row's id");
    assert!(
        fx.vault
            .delete_entity_with_options(&row, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );
    // No other commit and no pass: the erase itself has the row read again.
    assert_eq!(
        fx.permits(),
        (Vec::new(), SettingStanding::Quarantined),
        "the key's strictest value"
    );
}

#[test]
fn an_erased_value_leaves_the_setting_history() {
    let fx = Fixture::rooted();
    let label = "the owner's own label 4f1c";
    let set = fx.change_of(&fx.owner_sets(SetSetting::vault_value(BANNER, json!(label))));
    assert!(
        set.value
            .as_ref()
            .is_some_and(|value| value.0.windows(label.len()).any(|w| w == label.as_bytes())),
        "the change row holds the value before the erase"
    );
    let row = setting_beside_row(&fx.vault, vault_row(BANNER), &json!(label)).expect("the row");
    assert!(
        fx.vault
            .delete_entity_with_options(&row, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );
    fx.vault.project_settings().expect("the pass");
    assert_eq!(fx.banner(), (String::new(), SettingStanding::Quarantined));

    let holds = |value: Option<&oneiron::setting::EncodedValue>| {
        value.is_some_and(|value| value.0.windows(label.len()).any(|w| w == label.as_bytes()))
    };
    for change in setting_changes(&fx.vault).expect("the change stream") {
        assert!(
            !holds(change.value.as_ref()) && !holds(change.prior.as_ref()),
            "no change row keeps the erased value: {change:?}"
        );
    }
}

#[test]
fn an_erased_value_a_quarantine_kept_reads_the_default() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let hello = json!("hello");
    fx.owner_sets(SetSetting::vault_value(BANNER, hello.clone()));
    let kept = setting_beside_row(&fx.vault, vault_row(BANNER), &hello).expect("the row");

    // A later act whose value is here and matches its digest, but is no banner: the row is
    // quarantined, and `test.member_banner` names no strictest value, so it keeps "hello".
    let no_banner = json!(42);
    let act = fx.sign_beside_act_from(&machine, BANNER, &no_banner);
    land_setting_beside_value_before(&fx.vault, vault_row(BANNER), (&no_banner, &no_banner), &act)
        .expect("the value lands before its act");
    fx.land(&act);
    assert_eq!(
        fx.banner(),
        ("hello".to_owned(), SettingStanding::Quarantined)
    );

    // The value the quarantine kept is erased here: no read takes it.
    assert!(
        fx.vault
            .delete_entity_with_options(&kept, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );
    fx.vault.project_settings().expect("the pass");
    assert_eq!(
        fx.banner(),
        (String::new(), SettingStanding::Quarantined),
        "the key's default"
    );
}

#[test]
fn a_value_that_arrives_after_an_erase_names_no_erased_entity() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    // An entity erased here: the row of the owner's banner value, hard-deleted.
    let hello = json!("hello");
    fx.owner_sets(SetSetting::vault_value(BANNER, hello.clone()));
    let erased = setting_beside_row(&fx.vault, vault_row(BANNER), &hello).expect("the row");
    assert!(
        fx.vault
            .delete_entity_with_options(&erased, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );

    // Another machine's value names it, and reaches this install after the erase.
    let other = EntityId::now();
    let ids = json!([erased.to_hex(), other.to_hex()]);
    let act = fx.sign_beside_act_from(&machine, MENTIONED, &ids);
    fx.land(&act);
    land_setting_beside_value(&fx.vault, vault_row(MENTIONED), &ids).expect("the value lands");
    assert_eq!(
        owner_reads(&fx, MENTIONED, None),
        json!([other.to_hex()]),
        "the erased entity is out of the value"
    );
}

#[test]
fn a_pass_on_a_thread_that_holds_the_calendar_turn_leaves_a_feed_until_the_turn_is_released() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let config = feed("work-ics");
    let frontier = setting_frontier_of(&fx.vault, &[item_row(FEED, "work-ics")]).expect("frontier");
    let act = sign_setting_beside_act_from(
        &fx.vault,
        (&machine, fx.owner),
        &frontier,
        item_row(FEED, "work-ics"),
        &config,
        T0,
    )
    .expect("the act signs");
    land_setting_beside_value_before(
        &fx.vault,
        item_row(FEED, "work-ics"),
        (&config, &config),
        &act,
    )
    .expect("the value lands before its act");

    // A running calendar admission holds the turn: the pass the act's commit runs on its thread
    // leaves the feed as it is.
    let turn = hold_setting_write_turn(&fx.vault, FEED).expect("the turn");
    fx.land(&act);
    assert_eq!(owner_reads(&fx, FEED, Some("work-ics")), Value::Null);
    drop(turn);

    fx.vault.project_settings().expect("the pass");
    assert_eq!(owner_reads(&fx, FEED, Some("work-ics")), config);
}

#[test]
fn seat_installs_that_meet_with_no_common_act_leave_no_seat_and_keep_its_system() {
    let fx = Fixture::rooted();
    let machine = fx.second_machine(7);
    let before = setting_frontier_of(&fx.vault, &[item_row(SEAT, "work")]).expect("frontier");
    let ours = seat_setup("calendars/ours");
    owner_sets_item(&fx, SEAT, "work", ours.clone()).expect("the owner installs the seat");
    assert_eq!(owner_reads(&fx, SEAT, Some("work")), ours);

    // His other device installed another calendar at the same seat ref, on the acts as they
    // stood before: the two installs meet with no act both descend from.
    let theirs = seat_setup("calendars/theirs");
    assert!(
        land_setting_beside_act_from(
            &fx.vault,
            (&machine, fx.owner),
            &before,
            item_row(SEAT, "work"),
            &theirs,
            T0,
        )
        .expect("the act lands"),
        "the fold here counts the act"
    );
    land_setting_beside_value(&fx.vault, item_row(SEAT, "work"), &theirs).expect("the value");
    assert_eq!(
        owner_reads(&fx, SEAT, Some("work")),
        Value::Null,
        "no machine serves either seat"
    );

    // The seat's imported events keep their passports: no ICS feed takes its system.
    let refused =
        owner_sets_item(&fx, FEED, "caldav-work", feed("caldav-work")).expect_err("refused");
    assert!(refused.contains("CalDAV seat"), "{refused}");
}

#[test]
fn a_seat_taken_out_of_service_keeps_its_system_from_an_ics_feed() {
    let fx = Fixture::rooted();
    let ours = seat_setup("calendars/ours");
    owner_sets_item(&fx, SEAT, "work", ours.clone()).expect("the owner installs the seat");
    let row = setting_beside_row(&fx.vault, item_row(SEAT, "work"), &ours).expect("the row");
    assert!(
        fx.vault
            .delete_entity_with_options(&row, DeleteEntityOptions { purge: true })
            .expect("the erase"),
        "the row was here"
    );
    fx.vault.project_settings().expect("the pass");
    assert_eq!(
        owner_reads(&fx, SEAT, Some("work")),
        Value::Null,
        "the seat is out of service"
    );

    let refused =
        owner_sets_item(&fx, FEED, "caldav-work", feed("caldav-work")).expect_err("refused");
    assert!(refused.contains("CalDAV seat"), "{refused}");
}
