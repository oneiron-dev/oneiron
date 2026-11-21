//! Row SETTING-PROJECTED-ROW-REFUSING-HOOKS (Engine ANSWER 21 Nov 13:08): every refused
//! projection of a signed setting act raises an owner-visible notice on every machine, which
//! names both acts and offers a one-step fix. The generic path, with test keys:
//! - two machines each sign one side of a pair whose hook refuses the floor above the count: this
//!   install refuses the other machine's act and raises one notice that names both acts, their
//!   values and the machines that signed them, with one tap; a later pass adds nothing;
//! - the other machine refuses the other side of the same pair, and finds the same notice;
//! - the owner's tap, an equal value of the row this install holds, signs an act that replaces
//!   the refused one, the row settles, and the notice offers no tap any more;
//! - a key whose hook reads no other row names the refused act alone, with the hook's reason;
//! - the tap is one owner act over the refused row and the rows its key's hook meets it with, each
//!   prefilled with the value this install holds and editable (PR 2 of the row);
//! - the owner's change of several rows puts every row before any key's hook runs, signs one act,
//!   and is all or none;
//! - another machine's act of several rows lands here whichever row the pass reads first;
//! - a refused further row of a batch act offers its tap (REVIEW-10294 P1-2);
//! - the owner's equal value over acts no pass has read here signs nothing: only a refusal this
//!   install's pass recorded of the acts as they stand lets an equal value sign (REVIEW-10294
//!   P1-3);
//! - the installed ICS feed's configuration set again is a no-op of its hook, so a keep-value tap
//!   of it can sign (REVIEW-10294 P1-4).
//!
//! Review round 2 (REVIEW-10294, P1=5):
//! - the booking pair's refusal names the other row's act too, so both machines raise one notice;
//! - a refusal of the value that differing heads keep names the act that value came from;
//! - the installed CalDAV seat's setup set again is a no-op of its hook;
//! - a seat refused here offers no tap that leaves the seat with no value, which the machine that
//!   holds it in service refuses (PR 4: no tap that clears it alone);
//! - another machine's copy of the same notice, which holds no marks, keeps the owner's
//!   acknowledgement here.
//!
//! Review round 2 of PR 2 (REVIEW-10306, P1=4):
//! - the owner's tap as offered signs the row the refused row meets into its act, though this
//!   install's row holds its value already;
//! - the booking pair's refusal names the pin that decides the other row, and its tap edits it;
//! - a feed refused here names the seat of its system, and a seat refused here names the feed of
//!   its system;
//! - two rows of one act, each refused against its own row, raise a notice each.
//!
//! PR 3 of the row, the booking pair (SETTING-PROJECTED-EMERGENCY-PAIR = A: signed values land
//! everywhere, a fresh plan refuses and names the cause, and the notice offers both values):
//! - the other machine's count lands here though this install's hook refuses it against the
//!   floor, a fresh plan refuses and names the floor above the count, and the notice leads with
//!   the owner's words and offers both values in one tap; a later pass lands nothing again;
//! - the other machine lands the floor the same way and finds the same notice;
//! - the owner's tap, edited, settles the pair in one act, and a plan goes out again;
//! - an ordinary change that ends the conflict ends the notice's tap, though the refused act
//!   stands as it was.
//!
//! Review round 1 of PR 3 (REVIEW-10343, P1=2):
//! - the other machine's later act of the same count, which this install's row holds already, is
//!   refused here as the act it replaces was, while the pair conflicts: its notice offers the tap;
//! - two machines' acts on the pair read in one pass land both, and the notice names the pair the
//!   pass leaves.
//!
//! Review round 2 of PR 3 (REVIEW-10343, P1=2):
//! - a floor pin read as a value row since the last pass, whose row holds its value, is refused
//!   against the count under the reading the pass records;
//! - the booking pair's tap edits the floor pin read as a value row, not an absent value row.
//!
//! PR 4 of the row, the calendar pair (SETTING-PROJECTED-CALENDAR-SYSTEM-CLAIM = A: the refusing
//! machine quarantines the act, reads the strictest value and stops retrying; both machines show
//! "Your 'work' calendar has two complete sources (...). Pick one"; the pick is one owner act that
//! settles it on every machine):
//! - a seat refused here is quarantined, and no later pass reads it again; the notice leads with
//!   the owner's words of the choice;
//! - a feed refused here is quarantined the same way, and its notice words the same choice, with
//!   a tap for each source;
//! - the owner's pick of the feed settles it where the seat ran: the seat leaves service and its
//!   system goes to the feed;
//! - the owner's pick of the seat settles it where the feed ran;
//! - a quarantined seat is read again once the feed it met is cleared;
//! - a clear of a seat in service signed elsewhere takes it out of service here (REVIEW-10294
//!   round 2 P1-4), and its system stays its own;
//! - a seat refused here offers no tap that clears it alone.
//!
//! Review round 1 of PR 4 (REVIEW-10357, P1=3):
//! - a pick from one calendar's notice names no row of another calendar, though one act set both
//!   calendars' seats;
//! - the pick of the feed clears every seat that holds its system;
//! - the owner's pick of another calendar's seat takes the seat installed here out of service.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_refusal_notice`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{
    ChangeStanding, SetSetting, SetSettingOutcome, SettingCaller, SettingChange, SettingMode,
    SettingScope,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
#[cfg(feature = "sync")]
use oneiron::test_doors::setting::land_notification_copy_without_receipts;
use oneiron::test_doors::setting::{
    EnrolledMachine, SettingFrontier, SlotName, emergency_plan_admission, enroll_machine_with_key,
    forget_projected_setting_rows, forget_setting_projection_records, land_setting_act_from,
    land_setting_batch_from, land_signed_setting_acts, set_setting_as_engine, setting_changes,
    setting_frontier_of, setting_slot_heads, sign_setting_act_ahead,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_authority::authority::{AuthorityEntryHash, authority_log_entity_id_from_hash};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const COUNT: &str = "test.pair_count";
const FLOOR: &str = "test.pair_floor";
const CAPPED: &str = "test.capped_number";
const MAX_PROPOSALS: &str = "booking.emergency.max_proposals";
const MIN_PROPOSALS: &str = "booking.emergency.min_proposals";
const SEARCH_SPAN: &str = "booking.emergency.search_span_secs";
const SEAT: &str = "calendar.connector_seat";
const FEED: &str = "calendar.ics_feed";
const PRODUCER: &str = "setting.projection";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    /// The other machine of the owner's, named "Desktop"; this install is "Laptop".
    desktop: EnrolledMachine,
}

impl Fixture {
    /// A rooted vault whose install carries the owner's acts, and a second machine of the
    /// owner's. The owner names both. Opened owned: the writer lease is what lets the owner's
    /// handle call the owner verbs by name.
    fn rooted() -> Self {
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
        let issuer: HostSlipIssuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let desktop = enroll_machine_with_key(&vault, &owner_proof, 7).expect("enrolled");
        let laptop = vault
            .machine_list(&owner_proof)
            .expect("the machine list")
            .into_iter()
            .find(|listing| listing.this_install)
            .expect("this install is listed")
            .machine;
        for (machine, name) in [(laptop, "Laptop"), (desktop.machine(), "Desktop")] {
            vault
                .set_machine_owner_name(&owner_proof, machine, Some(name))
                .expect("the owner names the machine");
        }
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner,
            owner_proof,
            desktop,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner's change on this install, through the door.
    fn owner_sets(&self, key: &str, value: Value) -> SetSettingOutcome {
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting::vault_value(key, value),
            )
            .expect("the owner's change")
    }

    /// The other machine's act on `key`'s vault value row to `value`, signed on `frontier`,
    /// landed here as a peer's entry lands: its commit runs the pass.
    fn desktop_sets(&self, frontier: &SettingFrontier, key: &str, value: Value) {
        land_setting_act_from(
            &self.vault,
            &self.desktop,
            self.owner,
            frontier,
            vault_row(key),
            Some(value),
            T0,
        )
        .expect("the act lands");
    }

    /// The owner's read of `key` at the vault.
    fn reads(&self, key: &str) -> Value {
        invoke(
            &self.as_owner(),
            "vault.settings.get",
            json!({ "key": key }),
        )
        .expect("the owner reads the key")["value"]
            .clone()
    }

    /// The owner's notices of refused projections, as `self.inbox.list` pages them.
    fn refusal_notices(&self) -> Vec<Value> {
        let page = invoke(&self.as_owner(), "self.inbox.list", json!({}))
            .expect("the owner lists his inbox");
        page["rows"]
            .as_array()
            .expect("list rows")
            .iter()
            .filter(|row| row["source"]["producer"] == PRODUCER)
            .cloned()
            .collect()
    }

    /// The one notice of a refused projection.
    fn the_notice(&self) -> Value {
        let notices = self.refusal_notices();
        assert_eq!(notices.len(), 1, "one notice: {notices:#?}");
        notices.into_iter().next().expect("the notice")
    }

    /// The last change row of `key`.
    fn last_change(&self, key: &str) -> SettingChange {
        setting_changes(&self.vault)
            .expect("the change stream")
            .into_iter()
            .rev()
            .find(|change| change.key == key)
            .expect("a change of the key")
    }
}

/// `key`'s vault value row with no item.
fn vault_row(key: &str) -> SlotName<'_> {
    (key, None, SettingMode::Value, SettingScope::Vault)
}

/// The log entry id of the act `hash`, as a notice's `subject_refs` names it.
fn entry_of(hash: AuthorityEntryHash) -> String {
    authority_log_entity_id_from_hash(&hash)
        .expect("the entry id")
        .to_hex()
}

/// The notice's `subject_refs`, sorted.
fn named_refs(notice: &Value) -> Vec<String> {
    let mut refs: Vec<String> = notice["subject_refs"]
        .as_array()
        .expect("subject refs")
        .iter()
        .map(|id| id.as_str().expect("an id").to_owned())
        .collect();
    refs.sort();
    refs
}

/// The owner's words of `notice`.
fn words_of(notice: &Value) -> String {
    notice["source"]["detail"]
        .as_str()
        .expect("the owner's words")
        .to_owned()
}

/// A CalDAV seat's setup at `seat_ref`, importing under `system`.
fn seat_setup(seat_ref: &str, system: &str) -> Value {
    json!({
        "config": {
            "seat_ref": seat_ref,
            "secret_ref": format!("caldav:{seat_ref}"),
            "system": system,
            "calendar_ref": "personal",
            "cadence_jitter_min_seconds": 300,
            "cadence_jitter_max_seconds": 900,
        },
        "endpoint": "https://dav.example.test/",
    })
}

/// The change of the row of `key` for the item `item` to `value`.
fn item_row(key: &str, item: &str, value: Value) -> SetSetting {
    SetSetting {
        item: Some(item.to_owned()),
        ..SetSetting::vault_value(key, value)
    }
}

/// An ICS feed's configuration for `system`.
fn feed_config(system: &str) -> Value {
    json!({
        "secret_ref": format!("ics-feed:{system}"),
        "system": system,
        "cadence_min_seconds": 600,
        "cadence_max_seconds": 1200,
    })
}

/// The row of `key` for the item `item`, as a test names it.
fn item_slot<'a>(key: &'a str, item: &'a str) -> SlotName<'a> {
    (key, Some(item), SettingMode::Value, SettingScope::Vault)
}

/// The one act that heads the row `slot`.
fn the_head(fx: &Fixture, slot: SlotName<'_>) -> AuthorityEntryHash {
    let [act] = setting_slot_heads(&fx.vault, slot).expect("the row's heads")[..] else {
        panic!("one act heads the row");
    };
    act
}

/// The refused pair: the owner sets the count to 3 on this install, the other machine reads it
/// and sets the count to 2, and the owner sets the floor to 3 here before that act arrives. This
/// install's hook refuses the other machine's count: 3 above 2. The owner's floor act.
fn refused_pair(fx: &Fixture) -> AuthorityEntryHash {
    fx.owner_sets(COUNT, json!(3));
    let frontier = setting_frontier_of(&fx.vault, &[vault_row(COUNT)]).expect("frontier");
    fx.owner_sets(FLOOR, json!(3));
    let [floor_act] =
        setting_slot_heads(&fx.vault, vault_row(FLOOR)).expect("the floor's heads")[..]
    else {
        panic!("one act heads the floor");
    };
    fx.desktop_sets(&frontier, COUNT, json!(2));
    floor_act
}

#[test]
fn a_peers_act_this_installs_hook_refuses_raises_one_notice_naming_both_acts() {
    let fx = Fixture::rooted();
    let floor_act = refused_pair(&fx);
    let [count_act] =
        setting_slot_heads(&fx.vault, vault_row(COUNT)).expect("the count's heads")[..]
    else {
        panic!("the other machine's act heads the count");
    };
    assert_eq!(fx.reads(COUNT), json!(3), "the refused row stays as it was");

    let notice = fx.the_notice();
    assert_eq!(notice["kind"], "ask");
    let detail = notice["source"]["detail"]
        .as_str()
        .expect("the owner's words");
    for words in [
        "Laptop did not apply your `test.pair_count` = 2, set on Desktop",
        "test.pair_floor (3) must not exceed test.pair_count (2)",
        "It meets your `test.pair_floor` = 3, set on Laptop",
    ] {
        assert!(detail.contains(words), "{words:?} in {detail:?}");
    }
    let mut named = vec![entry_of(count_act), entry_of(floor_act)];
    named.sort();
    let mut refs: Vec<String> = notice["subject_refs"]
        .as_array()
        .expect("subject refs")
        .iter()
        .map(|id| id.as_str().expect("an id").to_owned())
        .collect();
    refs.sort();
    assert_eq!(refs, named, "the notice names both acts");
    assert_eq!(
        notice["actions"],
        json!([{
            "verb": "vault.settings.set",
            "args": {
                "key": COUNT,
                "item": null,
                "scope": { "kind": "vault" },
                "pin": false,
                "value": 3,
                "further": [{
                    "key": FLOOR,
                    "item": null,
                    "scope": { "kind": "vault" },
                    "pin": false,
                    "value": 3,
                }],
            },
        }]),
        "one tap: the count this install holds and the floor it meets, which the owner may edit"
    );

    // A later pass reads the refused row again, refuses it again, and adds no notice.
    fx.vault.project_settings().expect("the pass");
    assert_eq!(fx.the_notice()["id"], notice["id"]);
}

#[test]
fn the_other_machines_refusal_of_the_pair_finds_the_same_notice() {
    let fx = Fixture::rooted();
    refused_pair(&fx);
    let notice = fx.the_notice();

    // This install as the other machine holds the pair: its own count of 2 landed, and the
    // owner's floor of 3 arrives from the log. Its hook refuses the floor this time.
    forget_projected_setting_rows(&fx.vault).expect("the rows forgotten");
    set_setting_as_engine(&fx.vault, None, SetSetting::vault_value(COUNT, json!(2)))
        .expect("the count as the other machine holds it");
    fx.vault.project_settings().expect("the pass");
    assert_eq!(fx.reads(COUNT), json!(2));
    assert_eq!(fx.reads(FLOOR), json!(2), "the floor of 3 is refused here");

    let same = fx.the_notice();
    assert_eq!(
        same["id"], notice["id"],
        "one notice for the pair on every machine"
    );
    assert_eq!(
        same["actions"][0]["args"]["key"], FLOOR,
        "the tap here names the row this install refuses"
    );
    assert_eq!(same["actions"][0]["args"]["value"], json!(2));
}

#[test]
fn the_owners_tap_replaces_the_refused_act_and_the_notice_offers_no_tap() {
    let fx = Fixture::rooted();
    refused_pair(&fx);
    let tap = fx.the_notice()["actions"][0].clone();

    // The row here already holds 3: the owner's equal value signs an act all the same.
    invoke(
        &fx.as_owner(),
        tap["verb"].as_str().expect("the verb"),
        tap["args"].clone(),
    )
    .expect("the owner's tap");
    let change = fx.last_change(COUNT);
    assert_eq!(change.value, change.prior, "an equal value");
    let act = change.signed.expect("the equal value signs its act");
    assert_eq!(
        setting_slot_heads(&fx.vault, vault_row(COUNT)).expect("the count's heads"),
        vec![act],
        "the owner's act replaces the refused one"
    );

    fx.vault.project_settings().expect("the pass");
    assert_eq!(fx.reads(COUNT), json!(3));
    assert_eq!(
        fx.the_notice()["actions"],
        Value::Null,
        "a refusal that no longer stands offers no tap"
    );
}

#[test]
fn a_refused_act_of_a_key_whose_hook_reads_no_other_row_is_named_alone_with_the_reason() {
    let fx = Fixture::rooted();
    let frontier = setting_frontier_of(&fx.vault, &[vault_row(CAPPED)]).expect("frontier");
    fx.desktop_sets(&frontier, CAPPED, json!(9));
    assert_eq!(
        fx.reads(CAPPED),
        json!(0),
        "the refused row stays as it was"
    );

    let notice = fx.the_notice();
    let detail = notice["source"]["detail"]
        .as_str()
        .expect("the owner's words");
    assert!(
        detail.starts_with(
            "Laptop did not apply your `test.capped_number` = 9, set on Desktop: \
             test.capped_number takes at most 5, not 9."
        ),
        "{detail:?}"
    );
    assert!(!detail.contains("It meets"), "{detail:?}");
    assert_eq!(notice["subject_refs"].as_array().map(Vec::len), Some(1));
    assert_eq!(notice["actions"][0]["args"]["value"], json!(0));
}

#[test]
fn the_owners_tap_signs_one_act_over_the_refused_row_and_the_row_it_meets() {
    let fx = Fixture::rooted();
    refused_pair(&fx);
    let tap = fx.the_notice()["actions"][0].clone();

    // The owner edits both values in the notice: the count up to 4, the floor down to 2.
    let mut args = tap["args"].clone();
    args["value"] = json!(4);
    args["further"][0]["value"] = json!(2);
    invoke(
        &fx.as_owner(),
        tap["verb"].as_str().expect("the verb"),
        args,
    )
    .expect("the owner's tap");
    let act = fx
        .last_change(COUNT)
        .signed
        .expect("the count's change is signed");
    assert_eq!(
        fx.last_change(FLOOR).signed,
        Some(act),
        "one act signs both rows"
    );
    for key in [COUNT, FLOOR] {
        assert_eq!(
            setting_slot_heads(&fx.vault, vault_row(key)).expect("the row's heads"),
            vec![act],
            "the owner's act heads {key}"
        );
    }

    fx.vault.project_settings().expect("the pass");
    assert_eq!(fx.reads(COUNT), json!(4));
    assert_eq!(fx.reads(FLOOR), json!(2));
    assert_eq!(
        fx.the_notice()["actions"],
        Value::Null,
        "a refusal that no longer stands offers no tap"
    );
}

#[test]
fn an_owners_change_of_several_rows_puts_every_row_before_any_hook_and_is_all_or_none() {
    let fx = Fixture::rooted();
    let pair = |floor: u64, count: u64| {
        json!({
            "key": FLOOR,
            "scope": { "kind": "vault" },
            "value": floor,
            "further": [{ "key": COUNT, "scope": { "kind": "vault" }, "value": count }],
        })
    };

    // The pair reads a floor of 2 and a count of 3: a floor of 5 alone is above the count.
    fx.vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            SetSetting::vault_value(FLOOR, json!(5)),
        )
        .expect_err("a floor above the count is refused");
    // With a count of 6 in the same change, each hook reads both rows as the change leaves them.
    let outcome = invoke(&fx.as_owner(), "vault.settings.set", pair(5, 6))
        .expect("the owner's change of both rows");
    assert_eq!(outcome["status"], "applied");
    assert_eq!(outcome["value"], json!(5), "the first row's outcome");
    assert_eq!(fx.reads(FLOOR), json!(5));
    assert_eq!(fx.reads(COUNT), json!(6));
    let act = fx
        .last_change(FLOOR)
        .signed
        .expect("the floor's change is signed");
    assert_eq!(fx.last_change(COUNT).signed, Some(act), "one act");

    // A change whose rows the hook refuses together writes none of them.
    invoke(&fx.as_owner(), "vault.settings.set", pair(8, 7))
        .expect_err("a floor of 8 above a count of 7 is refused");
    assert_eq!(fx.reads(FLOOR), json!(5));
    assert_eq!(fx.reads(COUNT), json!(6));
    assert_eq!(fx.last_change(COUNT).signed, Some(act), "no act was signed");
    assert!(fx.refusal_notices().is_empty());
}

#[test]
fn another_machines_act_of_several_rows_lands_whichever_row_the_pass_reads_first() {
    let fx = Fixture::rooted();
    // Up from the defaults (a floor of 2, a count of 3), then down: a pass that reads the floor
    // first meets the old count in the first act, and one that reads the count first meets the
    // old floor in the second. Each row lands once the other did.
    for (floor, count) in [(5, 6), (1, 1)] {
        let frontier = setting_frontier_of(&fx.vault, &[vault_row(COUNT), vault_row(FLOOR)])
            .expect("frontier");
        let counted = land_setting_batch_from(
            &fx.vault,
            &fx.desktop,
            fx.owner,
            &frontier,
            &[
                (vault_row(FLOOR), Some(json!(floor))),
                (vault_row(COUNT), Some(json!(count))),
            ],
            T0,
        )
        .expect("the act lands");
        assert!(counted, "the fold counts the act");
        assert_eq!(fx.reads(FLOOR), json!(floor), "the floor of {floor}");
        assert_eq!(fx.reads(COUNT), json!(count), "the count of {count}");
        assert!(
            fx.refusal_notices().is_empty(),
            "no refusal stands: {:#?}",
            fx.refusal_notices()
        );
    }
}

#[test]
fn a_refused_further_row_of_a_batch_act_offers_its_tap() {
    let fx = Fixture::rooted();
    let frontier =
        setting_frontier_of(&fx.vault, &[vault_row(COUNT), vault_row(CAPPED)]).expect("frontier");
    land_setting_batch_from(
        &fx.vault,
        &fx.desktop,
        fx.owner,
        &frontier,
        &[
            (vault_row(COUNT), Some(json!(4))),
            (vault_row(CAPPED), Some(json!(9))),
        ],
        T0,
    )
    .expect("the batch lands");
    assert_eq!(fx.reads(COUNT), json!(4), "the batch's first row lands");
    assert_eq!(
        fx.reads(CAPPED),
        json!(0),
        "its further row is refused here"
    );

    assert_eq!(
        fx.the_notice()["actions"],
        json!([{
            "verb": "vault.settings.set",
            "args": {
                "key": CAPPED,
                "item": null,
                "scope": { "kind": "vault" },
                "pin": false,
                "value": 0,
            },
        }]),
        "the tap names the refused further row, not the batch's first row"
    );
}

#[test]
fn the_owners_equal_value_over_acts_no_pass_has_read_signs_nothing() {
    let fx = Fixture::rooted();
    fx.owner_sets(CAPPED, json!(4));
    let heads = setting_slot_heads(&fx.vault, vault_row(CAPPED)).expect("the heads");

    // The row holds 4 and its acts read as moved, as once a peer's act arrived and before the
    // pass read it: no pass refused them here.
    assert!(
        forget_setting_projection_records(&fx.vault).expect("the records forgotten") > 0,
        "the owner's act was projected"
    );
    fx.owner_sets(CAPPED, json!(4));
    assert_eq!(
        setting_slot_heads(&fx.vault, vault_row(CAPPED)).expect("the heads"),
        heads,
        "an equal value signs no act over acts this install never refused"
    );
    assert!(fx.refusal_notices().is_empty());
}

#[test]
fn the_installed_feeds_configuration_set_again_is_a_no_op_of_its_hook() {
    let fx = Fixture::rooted();
    let feed = json!({
        "secret_ref": "ics-feed:work",
        "system": "work-ics",
        "cadence_min_seconds": 600,
        "cadence_max_seconds": 1200,
    });
    let row = |value: Value| SetSetting {
        item: Some("work-ics".to_owned()),
        ..SetSetting::vault_value("calendar.ics_feed", value)
    };
    set_setting_as_engine(&fx.vault, None, row(feed.clone())).expect("the engine installs it");

    // The owner's equal value over the engine's row writes (the row becomes his), so the hook
    // runs with the installed configuration on both sides.
    let outcome = fx
        .vault
        .set_setting(SettingCaller::Owner(&fx.owner_proof), row(feed.clone()))
        .expect("the same configuration again is no change to the installed feed");
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the owner's row is written: {outcome:?}"
    );

    let mut other = feed;
    other["cadence_max_seconds"] = json!(1800);
    let refused = fx
        .vault
        .set_setting(SettingCaller::Owner(&fx.owner_proof), row(other))
        .expect_err("a change to the installed feed is still refused");
    assert!(refused.to_string().contains("immutable"), "{refused}");
}

#[test]
fn the_booking_pairs_refusal_names_the_other_rows_act_too() {
    let fx = Fixture::rooted();
    fx.owner_sets(MAX_PROPOSALS, json!(3));
    let frontier = setting_frontier_of(&fx.vault, &[vault_row(MAX_PROPOSALS)]).expect("frontier");
    fx.owner_sets(MIN_PROPOSALS, json!(3));
    let [floor_act] =
        setting_slot_heads(&fx.vault, vault_row(MIN_PROPOSALS)).expect("the floor's heads")[..]
    else {
        panic!("one act heads the floor");
    };
    // The other machine lowers the count to 2 while this install raised the floor to 3: this
    // install's hook refuses its count, and the other machine's refuses the floor.
    fx.desktop_sets(&frontier, MAX_PROPOSALS, json!(2));
    let [count_act] =
        setting_slot_heads(&fx.vault, vault_row(MAX_PROPOSALS)).expect("the count's heads")[..]
    else {
        panic!("the other machine's act heads the count");
    };

    let notice = fx.the_notice();
    let mut named = vec![entry_of(count_act), entry_of(floor_act)];
    named.sort();
    assert_eq!(
        named_refs(&notice),
        named,
        "the notice names both acts of the pair, as the other machine's does"
    );
    let words = words_of(&notice);
    assert!(
        words.contains("It meets your `booking.emergency.min_proposals`"),
        "{words:?}"
    );
}

#[test]
fn a_refusal_of_the_value_differing_heads_keep_names_the_act_it_came_from() {
    let fx = Fixture::rooted();
    fx.owner_sets(COUNT, json!(2));
    let [agreed] = setting_slot_heads(&fx.vault, vault_row(COUNT)).expect("the count's heads")[..]
    else {
        panic!("one act heads the count");
    };
    let frontier = setting_frontier_of(&fx.vault, &[vault_row(COUNT)]).expect("frontier");
    fx.owner_sets(COUNT, json!(4));
    fx.owner_sets(FLOOR, json!(3));
    // The other machine sets the count to 5 over the count of 2, while this install set it to 4:
    // the heads differ, the count has no order, so the row takes the value both come from, 2,
    // which this install's hook refuses below the floor of 3.
    fx.desktop_sets(&frontier, COUNT, json!(5));
    assert_eq!(
        setting_slot_heads(&fx.vault, vault_row(COUNT))
            .expect("the count's heads")
            .len(),
        2,
        "the count's heads differ"
    );
    assert_eq!(fx.reads(COUNT), json!(4), "the refused row stays as it was");

    let notice = fx.the_notice();
    assert_eq!(
        notice["source"]["result"],
        json!(entry_of(agreed)),
        "the refused act is the one the refused value came from"
    );
    assert!(
        named_refs(&notice).contains(&entry_of(agreed)),
        "the notice names it: {notice:#?}"
    );
    let words = words_of(&notice);
    assert!(
        words.contains("Laptop did not apply your `test.pair_count` = 2, set on Laptop"),
        "{words:?}"
    );
    assert_eq!(
        notice["actions"][0]["args"]["key"], COUNT,
        "the tap still sets the count over its live heads"
    );
}

#[test]
fn the_installed_seats_setup_set_again_is_a_no_op_of_its_hook() {
    let fx = Fixture::rooted();
    let setup = seat_setup("work", "work-dav");
    set_setting_as_engine(&fx.vault, None, item_row(SEAT, "work", setup.clone()))
        .expect("the engine installs the seat");

    // The owner's equal value over the engine's row writes (the row becomes his), so the hook
    // runs with the installed setup on both sides.
    let outcome = fx
        .vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            item_row(SEAT, "work", setup.clone()),
        )
        .expect("the same setup again is no change to the installed seat");
    assert!(
        matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ),
        "the owner's row is written: {outcome:?}"
    );

    let mut other = setup;
    other["config"]["cadence_jitter_max_seconds"] = json!(1800);
    let refused = fx
        .vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            item_row(SEAT, "work", other),
        )
        .expect_err("a change to the installed seat is still refused");
    assert!(refused.to_string().contains("immutable"), "{refused}");
}

#[test]
fn a_seat_refused_here_offers_no_tap_that_clears_it_alone() {
    let fx = Fixture::rooted();
    fx.vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            item_row(SEAT, "work", seat_setup("work", "work-cal")),
        )
        .expect("the owner installs the seat");

    // This install as another machine: it holds the log, no seat row, and an ICS feed on the
    // seat's system. Its hook refuses the seat, and the notice offers the pick of the two
    // sources: a tap that clears the seat keeps the feed in the same act, which is what the
    // machine that holds the seat in service takes it out of service for.
    forget_projected_setting_rows(&fx.vault).expect("the rows forgotten");
    set_setting_as_engine(
        &fx.vault,
        None,
        item_row(FEED, "work-cal", feed_config("work-cal")),
    )
    .expect("the feed on the seat's system");
    fx.vault.project_settings().expect("the pass");

    let notice = fx.the_notice();
    let taps = taps_of(&notice);
    assert_eq!(taps.len(), 2, "a tap for each source: {notice:#?}");
    for tap in &taps {
        let rows = rows_of(tap);
        if rows.get(SEAT).is_some_and(Value::is_null) {
            assert!(
                rows.get(FEED).is_some_and(|feed| !feed.is_null()),
                "a tap that clears the seat keeps the feed: {tap:#?}"
            );
        }
    }
}

#[cfg(feature = "sync")]
#[test]
fn another_machines_copy_of_the_notice_keeps_the_owners_acknowledgement() {
    let fx = Fixture::rooted();
    refused_pair(&fx);
    let notice = fx.the_notice();
    invoke(
        &fx.as_owner(),
        "self.inbox.mark",
        json!({ "notification_ref": notice["id"], "mark": "acked" }),
    )
    .expect("the owner acknowledges the notice");
    assert_eq!(fx.the_notice()["acked"], true);

    // The other machine raised the same notice alone and never read this install's: its copy
    // holds no marks, and its window carries it here.
    let id = EntityId::from_hex(notice["id"].as_str().expect("the notice id")).expect("an id");
    land_notification_copy_without_receipts(&fx.vault, id).expect("the copy lands");
    let after = fx.the_notice();
    assert_eq!(
        after["acked"], true,
        "the acknowledgement stays: {after:#?}"
    );
    assert_eq!(after["seen"], true);
}

#[test]
fn the_owners_tap_as_offered_signs_the_row_it_meets_into_its_act_too() {
    let fx = Fixture::rooted();
    refused_pair(&fx);
    let tap = fx.the_notice()["actions"][0].clone();
    assert_eq!(
        tap["args"]["further"][0]["key"],
        json!(FLOOR),
        "the tap names the floor: {tap:#?}"
    );

    // Both rows here hold the values the tap offers: the refused count, and the floor the owner
    // set here, whose act the other machine refused. The owner's act heads the floor too, so
    // that machine takes the floor from it with the count.
    invoke(
        &fx.as_owner(),
        tap["verb"].as_str().expect("the verb"),
        tap["args"].clone(),
    )
    .expect("the owner's tap");
    let act = fx
        .last_change(COUNT)
        .signed
        .expect("the count's change is signed");
    assert_eq!(
        fx.last_change(FLOOR).signed,
        Some(act),
        "one act signs both rows"
    );
    for key in [COUNT, FLOOR] {
        assert_eq!(
            setting_slot_heads(&fx.vault, vault_row(key)).expect("the row's heads"),
            vec![act],
            "the owner's act heads {key}"
        );
    }
    fx.vault.project_settings().expect("the pass");
    assert_eq!(fx.reads(COUNT), json!(3));
    assert_eq!(fx.reads(FLOOR), json!(3));
}

#[test]
fn the_booking_pairs_refusal_names_the_pin_that_decides_the_other_row() {
    let fx = Fixture::rooted();
    fx.owner_sets(MAX_PROPOSALS, json!(6));
    let frontier = setting_frontier_of(&fx.vault, &[vault_row(MIN_PROPOSALS)]).expect("frontier");
    // The owner pins the count to 3 here while the other machine raises the floor to 5: this
    // install's hook refuses the floor against the pin, not against the value row under it.
    fx.vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            SetSetting {
                mode: SettingMode::Pin,
                ..SetSetting::vault_value(MAX_PROPOSALS, json!(3))
            },
        )
        .expect("the owner pins the count");
    let pin_act = the_head(
        &fx,
        (MAX_PROPOSALS, None, SettingMode::Pin, SettingScope::Vault),
    );
    fx.desktop_sets(&frontier, MIN_PROPOSALS, json!(5));
    let floor_act = the_head(&fx, vault_row(MIN_PROPOSALS));

    let notice = fx.the_notice();
    let mut named = vec![entry_of(pin_act), entry_of(floor_act)];
    named.sort();
    assert_eq!(
        named_refs(&notice),
        named,
        "the notice names the pin that decides the count: {notice:#?}"
    );
    let further = &notice["actions"][0]["args"]["further"][0];
    assert_eq!(
        (&further["key"], &further["pin"], &further["value"]),
        (&json!(MAX_PROPOSALS), &json!(true), &json!(3)),
        "the tap edits the pin the hook reads: {notice:#?}"
    );
}

#[test]
fn a_feed_refused_here_names_the_seat_of_its_system_too() {
    let fx = Fixture::rooted();
    fx.vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            item_row(FEED, "work-cal", feed_config("work-cal")),
        )
        .expect("the owner installs the feed");
    let feed_act = the_head(&fx, item_slot(FEED, "work-cal"));

    // This install as another machine: it holds the log and no feed row, and a CalDAV seat the
    // owner installed here on the feed's system. Its hook refuses the feed.
    forget_projected_setting_rows(&fx.vault).expect("the rows forgotten");
    fx.vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            item_row(SEAT, "work", seat_setup("work", "work-cal")),
        )
        .expect("the owner installs the seat");
    let seat_act = the_head(&fx, item_slot(SEAT, "work"));
    fx.vault.project_settings().expect("the pass");

    let notice = fx.the_notice();
    let mut named = vec![entry_of(feed_act), entry_of(seat_act)];
    named.sort();
    assert_eq!(
        named_refs(&notice),
        named,
        "the notice names the seat's act too: {notice:#?}"
    );
    let words = words_of(&notice);
    assert!(
        words.contains("It meets your change of `calendar.connector_seat` for `work`"),
        "{words:?}"
    );
}

#[test]
fn a_seat_refused_here_names_the_feed_of_its_system_too() {
    let fx = Fixture::rooted();
    fx.vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            item_row(SEAT, "work", seat_setup("work", "work-cal")),
        )
        .expect("the owner installs the seat");
    let seat_act = the_head(&fx, item_slot(SEAT, "work"));

    // This install as another machine: it holds the log and no seat row, and an ICS feed the
    // owner installed here on the seat's system. Its hook refuses the seat.
    forget_projected_setting_rows(&fx.vault).expect("the rows forgotten");
    fx.vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            item_row(FEED, "work-cal", feed_config("work-cal")),
        )
        .expect("the owner installs the feed");
    let feed_act = the_head(&fx, item_slot(FEED, "work-cal"));
    fx.vault.project_settings().expect("the pass");

    let notice = fx.the_notice();
    let mut named = vec![entry_of(feed_act), entry_of(seat_act)];
    named.sort();
    assert_eq!(
        named_refs(&notice),
        named,
        "the notice names the feed's act too: {notice:#?}"
    );
    let words = words_of(&notice);
    assert!(
        words.contains("It meets your change of `calendar.ics_feed` for `work-cal`"),
        "{words:?}"
    );
}

#[test]
fn two_rows_of_one_act_refused_each_against_its_own_row_raise_a_notice_each() {
    let fx = Fixture::rooted();
    let rows = |key: &str, first: (&str, Value), second: (&str, Value)| {
        json!({
            "key": key,
            "item": first.0,
            "scope": { "kind": "vault" },
            "value": first.1,
            "further": [{
                "key": key,
                "item": second.0,
                "scope": { "kind": "vault" },
                "value": second.1,
            }],
        })
    };
    invoke(
        &fx.as_owner(),
        "vault.settings.set",
        rows(
            FEED,
            ("work-cal", feed_config("work-cal")),
            ("home-cal", feed_config("home-cal")),
        ),
    )
    .expect("the owner installs both feeds as one act");

    // This install as another machine: it holds the log and no feed row, and two CalDAV seats
    // the owner installed here as one act, one on each feed's system. Its hook refuses each feed
    // against its own seat: two refusals of the same two acts.
    forget_projected_setting_rows(&fx.vault).expect("the rows forgotten");
    invoke(
        &fx.as_owner(),
        "vault.settings.set",
        rows(
            SEAT,
            ("work", seat_setup("work", "work-cal")),
            ("home", seat_setup("home", "home-cal")),
        ),
    )
    .expect("the owner installs both seats as one act");
    fx.vault.project_settings().expect("the pass");

    let notices = fx.refusal_notices();
    assert_eq!(
        notices.len(),
        2,
        "a notice for each refused feed: {notices:#?}"
    );
    for system in ["work-cal", "home-cal"] {
        let refused = format!("did not apply your change of `calendar.ics_feed` for `{system}`");
        assert!(
            notices
                .iter()
                .any(|notice| words_of(notice).contains(&refused)),
            "{system}: {notices:#?}"
        );
    }
}

/// The booking pair set on two machines at once (SETTING-PROJECTED-EMERGENCY-PAIR = A): the
/// owner sets the count to 3 on this install, the other machine reads it and lowers it to 2, and
/// the owner raises the floor to 3 here before that act arrives. This install's hook refuses the
/// other machine's count: the floor of 3 above it. The owner's floor act.
fn emergency_pair_set_at_once(fx: &Fixture) -> AuthorityEntryHash {
    fx.owner_sets(MAX_PROPOSALS, json!(3));
    let frontier = setting_frontier_of(&fx.vault, &[vault_row(MAX_PROPOSALS)]).expect("frontier");
    fx.owner_sets(MIN_PROPOSALS, json!(3));
    let floor_act = the_head(fx, vault_row(MIN_PROPOSALS));
    fx.desktop_sets(&frontier, MAX_PROPOSALS, json!(2));
    floor_act
}

#[test]
fn the_booking_pairs_count_lands_here_though_the_hook_refuses_it_and_a_fresh_plan_refuses() {
    let fx = Fixture::rooted();
    let floor_act = emergency_pair_set_at_once(&fx);
    let count_act = the_head(&fx, vault_row(MAX_PROPOSALS));
    assert_eq!(
        fx.reads(MAX_PROPOSALS),
        json!(2),
        "the other machine's count lands here too"
    );
    assert_eq!(fx.reads(MIN_PROPOSALS), json!(3));
    let refusal = emergency_plan_admission(&fx.vault, 2)
        .expect("the policy read")
        .expect_err("a fresh plan refuses");
    assert!(
        refusal.contains(
            "emergency rescheduling is off: booking.emergency.min_proposals (3) is above \
             booking.emergency.max_proposals (2)"
        ),
        "the plan names the floor above the count: {refusal:?}"
    );

    let notice = fx.the_notice();
    let mut named = vec![entry_of(count_act), entry_of(floor_act)];
    named.sort();
    assert_eq!(named_refs(&notice), named, "the notice names both acts");
    let words = words_of(&notice);
    for phrase in [
        "Emergency rescheduling is off: you set min 3 above max 2. Fix it?",
        "Laptop applied your `booking.emergency.max_proposals` = 2, set on Desktop, as every \
         machine does.",
        "It meets your `booking.emergency.min_proposals` = 3, set on Laptop",
    ] {
        assert!(words.contains(phrase), "{phrase:?} in {words:?}");
    }
    assert_eq!(
        notice["actions"],
        json!([{
            "verb": "vault.settings.set",
            "args": {
                "key": MAX_PROPOSALS,
                "item": null,
                "scope": { "kind": "vault" },
                "pin": false,
                "value": 2,
                "further": [{
                    "key": MIN_PROPOSALS,
                    "item": null,
                    "scope": { "kind": "vault" },
                    "pin": false,
                    "value": 3,
                }],
            },
        }]),
        "one tap over both values as they stand here, which the owner may edit"
    );

    // A later pass reads nothing again, and adds no notice.
    let changes = setting_changes(&fx.vault).expect("the change stream").len();
    fx.vault.project_settings().expect("the pass");
    assert_eq!(
        setting_changes(&fx.vault).expect("the change stream").len(),
        changes,
        "the landed row is not projected again"
    );
    assert_eq!(fx.the_notice()["id"], notice["id"]);
}

#[test]
fn the_other_machine_lands_the_booking_pairs_floor_and_finds_the_same_notice() {
    let fx = Fixture::rooted();
    emergency_pair_set_at_once(&fx);
    let notice = fx.the_notice();

    // This install as the other machine holds the pair: its own count of 2 landed, and the
    // owner's floor of 3 arrives from the log. Its hook refuses the floor this time.
    forget_projected_setting_rows(&fx.vault).expect("the rows forgotten");
    set_setting_as_engine(
        &fx.vault,
        None,
        SetSetting::vault_value(MAX_PROPOSALS, json!(2)),
    )
    .expect("the count as the other machine holds it");
    fx.vault.project_settings().expect("the pass");
    assert_eq!(fx.reads(MAX_PROPOSALS), json!(2));
    assert_eq!(
        fx.reads(MIN_PROPOSALS),
        json!(3),
        "the floor lands there too: the pair reads alike on both machines"
    );

    let same = fx.the_notice();
    assert_eq!(
        same["id"], notice["id"],
        "one notice for the pair on every machine"
    );
    let args = &same["actions"][0]["args"];
    assert_eq!(
        (&args["key"], &args["value"]),
        (&json!(MIN_PROPOSALS), &json!(3)),
        "the tap there names the row it refused, as it holds it: {same:#?}"
    );
    assert_eq!(
        (&args["further"][0]["key"], &args["further"][0]["value"]),
        (&json!(MAX_PROPOSALS), &json!(2))
    );
}

#[test]
fn the_owners_tap_of_the_booking_pair_as_edited_settles_it_in_one_act() {
    let fx = Fixture::rooted();
    emergency_pair_set_at_once(&fx);
    let tap = fx.the_notice()["actions"][0].clone();
    assert_eq!(
        tap["args"]["value"],
        json!(2),
        "the tap holds the count that landed here"
    );

    // The owner raises the count back to 3 in the tap and keeps the floor of 3.
    let mut args = tap["args"].clone();
    args["value"] = json!(3);
    invoke(
        &fx.as_owner(),
        tap["verb"].as_str().expect("the verb"),
        args,
    )
    .expect("the owner's tap");
    assert_eq!(fx.reads(MAX_PROPOSALS), json!(3));
    assert_eq!(fx.reads(MIN_PROPOSALS), json!(3));
    assert_eq!(
        the_head(&fx, vault_row(MAX_PROPOSALS)),
        the_head(&fx, vault_row(MIN_PROPOSALS)),
        "one act heads both rows, so every machine projects both"
    );
    assert_eq!(
        emergency_plan_admission(&fx.vault, 3).expect("the policy read"),
        Ok(()),
        "a plan of three times goes out again"
    );

    fx.vault.project_settings().expect("the pass");
    assert_eq!(
        fx.the_notice()["actions"],
        Value::Null,
        "a refusal that no longer stands offers no tap"
    );
}

#[test]
fn an_ordinary_change_that_ends_the_booking_pairs_conflict_ends_its_tap() {
    let fx = Fixture::rooted();
    emergency_pair_set_at_once(&fx);
    assert_eq!(fx.reads(MAX_PROPOSALS), json!(2));

    // The owner lowers the floor to 2 through the key's own door: the count the other machine set
    // is no longer under it, though that act stands as it was here.
    fx.owner_sets(MIN_PROPOSALS, json!(2));
    assert_eq!(
        emergency_plan_admission(&fx.vault, 2).expect("the policy read"),
        Ok(())
    );
    assert_eq!(
        fx.the_notice()["actions"],
        Value::Null,
        "no tap once the rows no longer conflict"
    );
}

/// The tap the booking pair's notice offers: both values as they stand here, the refused row's
/// first.
fn pair_tap((key, value): (&str, Value), (further_key, further_value): (&str, Value)) -> Value {
    json!([{
        "verb": "vault.settings.set",
        "args": {
            "key": key,
            "item": null,
            "scope": { "kind": "vault" },
            "pin": false,
            "value": value,
            "further": [{
                "key": further_key,
                "item": null,
                "scope": { "kind": "vault" },
                "pin": false,
                "value": further_value,
            }],
        },
    }])
}

#[test]
fn the_other_machines_later_equal_count_is_refused_here_while_the_pair_conflicts() {
    let fx = Fixture::rooted();
    let floor_act = emergency_pair_set_at_once(&fx);

    // The other machine, before the owner's floor reaches it, signs the count of 2 again in one
    // act with the search span. This install's row holds that count already, so its write runs
    // no hook.
    let frontier = setting_frontier_of(
        &fx.vault,
        &[vault_row(MAX_PROPOSALS), vault_row(SEARCH_SPAN)],
    )
    .expect("frontier");
    land_setting_batch_from(
        &fx.vault,
        &fx.desktop,
        fx.owner,
        &frontier,
        &[
            (vault_row(MAX_PROPOSALS), Some(json!(2))),
            (vault_row(SEARCH_SPAN), Some(json!(172_800))),
        ],
        T0,
    )
    .expect("the act lands");
    let count_act = the_head(&fx, vault_row(MAX_PROPOSALS));
    assert_eq!(fx.reads(MAX_PROPOSALS), json!(2));
    assert_eq!(
        fx.reads(SEARCH_SPAN),
        json!(172_800),
        "the act's other row lands"
    );
    assert!(
        emergency_plan_admission(&fx.vault, 2)
            .expect("the policy read")
            .is_err(),
        "a fresh plan still refuses: the floor is above the count"
    );

    // The refusal stands for the new act, and its notice offers the tap.
    let notices = fx.refusal_notices();
    let notice = notices
        .iter()
        .find(|notice| named_refs(notice).contains(&entry_of(count_act)))
        .unwrap_or_else(|| panic!("a notice names the new count act: {notices:#?}"));
    let mut named = vec![entry_of(count_act), entry_of(floor_act)];
    named.sort();
    assert_eq!(named_refs(notice), named, "the notice names both acts");
    assert!(
        words_of(notice)
            .contains("Emergency rescheduling is off: you set min 3 above max 2. Fix it?"),
        "{notice:#?}"
    );
    assert_eq!(
        notice["actions"],
        pair_tap((MAX_PROPOSALS, json!(2)), (MIN_PROPOSALS, json!(3))),
        "one tap over both values as they stand here"
    );

    // A later pass reads nothing again.
    fx.vault.project_settings().expect("the pass");
    assert_eq!(fx.refusal_notices().len(), notices.len());
}

#[test]
fn two_machines_acts_on_the_booking_pair_read_in_one_pass_name_the_pair_it_leaves() {
    let fx = Fixture::rooted();
    let tablet = enroll_machine_with_key(&fx.vault, &fx.owner_proof, 9).expect("enrolled");
    fx.vault
        .set_machine_owner_name(&fx.owner_proof, tablet.machine(), Some("Tablet"))
        .expect("the owner names the machine");

    // This install holds the shipped pair, min 2 and max 3. The other machine raises the floor to
    // 4 and a third lowers the count to 1, neither having seen the other's act, and both acts
    // arrive in one commit: one pass reads them, and its hook refuses each against the other row
    // as this install held it.
    let sign = |machine: &EnrolledMachine, key: &str, value: Value| {
        let frontier = setting_frontier_of(&fx.vault, &[vault_row(key)]).expect("frontier");
        sign_setting_act_ahead(
            &fx.vault,
            (machine, fx.owner),
            &frontier,
            (vault_row(key), Some(value)),
            (T0, 0),
        )
        .expect("the act signs")
    };
    let floor = sign(&fx.desktop, MIN_PROPOSALS, json!(4));
    let count = sign(&tablet, MAX_PROPOSALS, json!(1));
    land_signed_setting_acts(&fx.vault, &[&floor, &count], T0).expect("both acts land");
    assert_eq!(fx.reads(MIN_PROPOSALS), json!(4), "the floor lands here");
    assert_eq!(fx.reads(MAX_PROPOSALS), json!(1), "the count lands here");

    let notice = fx.the_notice();
    let mut named = vec![
        entry_of(floor.hash().expect("the floor's hash")),
        entry_of(count.hash().expect("the count's hash")),
    ];
    named.sort();
    assert_eq!(named_refs(&notice), named, "the notice names both acts");
    let words = words_of(&notice);
    for phrase in [
        "Emergency rescheduling is off: you set min 4 above max 1. Fix it?",
        "your `booking.emergency.min_proposals` = 4, set on Desktop",
        "your `booking.emergency.max_proposals` = 1, set on Tablet",
        ", as every machine does.",
    ] {
        assert!(words.contains(phrase), "{phrase:?} in {words:?}");
    }
    assert!(
        !words.contains("must not exceed"),
        "no reason the hook read against the pair before the pass landed it: {words:?}"
    );
    let args = &notice["actions"][0]["args"];
    let mut offered = vec![
        (args["key"].clone(), args["value"].clone()),
        (
            args["further"][0]["key"].clone(),
            args["further"][0]["value"].clone(),
        ),
    ];
    offered.sort_by_key(|(key, _)| key.to_string());
    assert_eq!(
        offered,
        vec![
            (json!(MAX_PROPOSALS), json!(1)),
            (json!(MIN_PROPOSALS), json!(4)),
        ],
        "one tap over both values the pass left here: {notice:#?}"
    );
}

/// The taps `notice` offers: each one's `vault.settings.set` input.
fn taps_of(notice: &Value) -> Vec<Value> {
    notice["actions"]
        .as_array()
        .map(|actions| {
            actions
                .iter()
                .map(|action| {
                    assert_eq!(action["verb"], "vault.settings.set", "{action:#?}");
                    action["args"].clone()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Each row `tap` changes, by its key, to the value it sets (`null` clears).
fn rows_of(tap: &Value) -> std::collections::BTreeMap<String, Value> {
    let further = tap["further"].as_array().cloned().unwrap_or_default();
    std::iter::once(tap.clone())
        .chain(further)
        .map(|row| {
            let key = row["key"].as_str().expect("a key").to_owned();
            (key, row["value"].clone())
        })
        .collect()
}

/// The tap of `notice` that keeps the row of `key` and clears every other row it names.
fn tap_keeping(notice: &Value, key: &str) -> Value {
    taps_of(notice)
        .into_iter()
        .find(|tap| {
            rows_of(tap)
                .iter()
                .all(|(row, value)| (row == key) != value.is_null())
        })
        .unwrap_or_else(|| panic!("a tap keeps `{key}` and clears the rest: {notice:#?}"))
}

impl Fixture {
    /// The owner's read of the row of `key` for the item `item`.
    fn reads_item(&self, key: &str, item: &str) -> Value {
        invoke(
            &self.as_owner(),
            "vault.settings.get",
            json!({ "key": key, "item": item }),
        )
        .expect("the owner reads the row")["value"]
            .clone()
    }

    /// The owner's change on this install of the row of `key` for the item `item`.
    fn owner_sets_item(&self, key: &str, item: &str, value: Value) {
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                item_row(key, item, value),
            )
            .expect("the owner's change");
    }

    /// The other machine's act on the row of `key` for the item `item` to `value` (`None`
    /// clears), signed on `frontier`, landed here as a peer's entry lands: its commit runs the
    /// pass.
    fn desktop_sets_item(
        &self,
        frontier: &SettingFrontier,
        (key, item): (&str, &str),
        value: Option<Value>,
    ) {
        land_setting_act_from(
            &self.vault,
            &self.desktop,
            self.owner,
            frontier,
            item_slot(key, item),
            value,
            T0,
        )
        .expect("the act lands");
    }
}

/// The calendar pair set on two machines at once (SETTING-PROJECTED-CALENDAR-SYSTEM-CLAIM = A):
/// the owner installs the ICS feed `work-cal` on this install, and the other machine, before
/// that act reaches it, installs a CalDAV seat on the feed's system. This install's hook refuses
/// the seat.
fn seat_set_elsewhere_on_the_feeds_system(fx: &Fixture) {
    let frontier = setting_frontier_of(&fx.vault, &[item_slot(SEAT, "work")]).expect("frontier");
    fx.owner_sets_item(FEED, "work-cal", feed_config("work-cal"));
    fx.desktop_sets_item(
        &frontier,
        (SEAT, "work"),
        Some(seat_setup("work", "work-cal")),
    );
}

/// The other side of the pair: the owner installs the CalDAV seat `work` on the system
/// `work-cal` on this install, and the other machine installs an ICS feed on it before the seat
/// reaches it. This install's hook refuses the feed.
fn feed_set_elsewhere_on_the_seats_system(fx: &Fixture) {
    let frontier =
        setting_frontier_of(&fx.vault, &[item_slot(FEED, "work-cal")]).expect("frontier");
    fx.owner_sets_item(SEAT, "work", seat_setup("work", "work-cal"));
    fx.desktop_sets_item(&frontier, (FEED, "work-cal"), Some(feed_config("work-cal")));
}

#[test]
fn a_seat_refused_here_is_quarantined_and_no_later_pass_reads_it_again() {
    let fx = Fixture::rooted();
    seat_set_elsewhere_on_the_feeds_system(&fx);

    assert_eq!(
        fx.reads_item(SEAT, "work"),
        Value::Null,
        "the seat reads the key's strictest value here"
    );
    assert_eq!(
        fx.last_change(SEAT).standing,
        Some(ChangeStanding::Quarantined),
        "the seat's act is quarantined here"
    );
    assert!(
        !fx.reads_item(FEED, "work-cal").is_null(),
        "the feed runs on"
    );
    let again = fx.vault.project_settings().expect("a later pass");
    assert_eq!(
        again.moved, 0,
        "no later pass reads the quarantined seat again"
    );
    let words = words_of(&fx.the_notice());
    assert!(
        words.starts_with(
            "Your 'work-cal' calendar has two complete sources (an ICS feed set on Laptop, a \
             CalDAV seat set on Desktop). Pick one."
        ),
        "{words:?}"
    );
}

#[test]
fn a_feed_refused_here_is_quarantined_and_its_notice_words_the_same_choice() {
    let fx = Fixture::rooted();
    feed_set_elsewhere_on_the_seats_system(&fx);

    assert_eq!(fx.reads_item(FEED, "work-cal"), Value::Null);
    assert_eq!(
        fx.last_change(FEED).standing,
        Some(ChangeStanding::Quarantined),
        "the feed's act is quarantined here"
    );
    assert!(!fx.reads_item(SEAT, "work").is_null(), "the seat runs on");
    let notice = fx.the_notice();
    let words = words_of(&notice);
    assert!(
        words.starts_with(
            "Your 'work-cal' calendar has two complete sources (an ICS feed set on Desktop, a \
             CalDAV seat set on Laptop). Pick one."
        ),
        "{words:?}"
    );
    assert_eq!(
        taps_of(&notice).len(),
        2,
        "a tap for each source: {notice:#?}"
    );
}

#[test]
fn the_owners_pick_of_the_feed_settles_it_where_the_seat_ran() {
    let fx = Fixture::rooted();
    feed_set_elsewhere_on_the_seats_system(&fx);

    // The seat's system goes to the feed the owner keeps: the seat leaves service, and the feed
    // installs here in the same act.
    let tap = tap_keeping(&fx.the_notice(), FEED);
    invoke(&fx.as_owner(), "vault.settings.set", tap).expect("the owner's pick");
    fx.vault.project_settings().expect("the pass");

    assert!(
        !fx.reads_item(FEED, "work-cal").is_null(),
        "the feed is installed here"
    );
    assert_eq!(fx.reads_item(SEAT, "work"), Value::Null, "the seat is out");
    assert_eq!(
        fx.the_notice()["actions"],
        Value::Null,
        "no refusal stands here any more"
    );
}

#[test]
fn the_owners_pick_of_the_seat_settles_it_where_the_feed_ran() {
    let fx = Fixture::rooted();
    seat_set_elsewhere_on_the_feeds_system(&fx);

    let tap = tap_keeping(&fx.the_notice(), SEAT);
    invoke(&fx.as_owner(), "vault.settings.set", tap).expect("the owner's pick");
    fx.vault.project_settings().expect("the pass");

    assert!(
        !fx.reads_item(SEAT, "work").is_null(),
        "the seat is installed here"
    );
    assert_eq!(
        fx.reads_item(FEED, "work-cal"),
        Value::Null,
        "the feed is uninstalled"
    );
    assert_eq!(
        fx.the_notice()["actions"],
        Value::Null,
        "no refusal stands here any more"
    );
}

/// Green on the base too, whose pass reads a refused row again at every pass: it holds the
/// quarantine's own re-read of a row once a row its hook met it with moves.
#[test]
fn a_quarantined_seat_is_read_again_once_the_feed_it_met_is_cleared() {
    let fx = Fixture::rooted();
    seat_set_elsewhere_on_the_feeds_system(&fx);
    assert_eq!(fx.reads_item(SEAT, "work"), Value::Null);

    fx.owner_sets_item(FEED, "work-cal", Value::Null);
    fx.vault.project_settings().expect("the pass");

    assert!(
        !fx.reads_item(SEAT, "work").is_null(),
        "the seat installs here once the feed it met is gone"
    );
}

#[test]
fn a_clear_of_a_seat_in_service_signed_elsewhere_takes_it_out_of_service_here() {
    let fx = Fixture::rooted();
    fx.owner_sets_item(SEAT, "work", seat_setup("work", "work-cal"));
    let frontier = setting_frontier_of(&fx.vault, &[item_slot(SEAT, "work")]).expect("frontier");

    // The other machine clears the seat. This install's hook refuses a change of the seat in
    // service; the quarantine takes it out of service, as the act asks, so no notice is raised.
    fx.desktop_sets_item(&frontier, (SEAT, "work"), None);

    assert_eq!(fx.reads_item(SEAT, "work"), Value::Null, "the seat is out");
    assert_eq!(
        fx.last_change(SEAT).standing,
        Some(ChangeStanding::Quarantined)
    );
    assert!(
        fx.refusal_notices().is_empty(),
        "the row reads as the act asks"
    );
    // A seat out of service keeps its system: a plain feed there is refused as before.
    let refused = fx
        .vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            item_row(FEED, "work-cal", feed_config("work-cal")),
        )
        .expect_err("the seat's system stays its own");
    assert!(
        refused.to_string().contains("imports under this system"),
        "{refused}"
    );
}

impl Fixture {
    /// The owner removes the other machine on this install.
    fn removes_desktop(&self) {
        self.vault
            .set_machine_role(
                &self.owner_proof,
                ActSurface::ThisInstall,
                self.desktop.machine(),
                MachineRole::Removed,
                None,
            )
            .expect("the owner removes the machine");
    }

    /// The other machine's pin of the floor at `floor`, signed before the owner removed it here
    /// and landed after: no removal saw it, so it counts as a safe move and is read as a value
    /// row at the vault, which narrows the shipped floor of 2 and releases nothing.
    fn raced_floor_pin(&self, floor: u64) {
        let pin = (MIN_PROPOSALS, None, SettingMode::Pin, SettingScope::Vault);
        let frontier = setting_frontier_of(&self.vault, &[pin]).expect("frontier");
        self.removes_desktop();
        land_setting_act_from(
            &self.vault,
            &self.desktop,
            self.owner,
            &frontier,
            pin,
            Some(json!(floor)),
            T0,
        )
        .expect("the act lands");
    }
}

#[test]
fn a_floor_pin_read_as_a_value_row_since_the_last_pass_is_refused_against_the_count() {
    let fx = Fixture::rooted();
    fx.raced_floor_pin(1);

    // The pin's projection record is gone, as a row's is once a peer's act arrived and before the
    // pass read it: every read takes the pin at full strength, a floor of 1, and the engine sets
    // the count to 1 under it.
    forget_setting_projection_records(&fx.vault).expect("the records forgotten");
    set_setting_as_engine(
        &fx.vault,
        None,
        SetSetting::vault_value(MAX_PROPOSALS, json!(1)),
    )
    .expect("the count of 1 over a floor of 1");

    // The pass reads the pin again as a value row, the shipped floor of 2 stands above the count
    // of 1, and its equal row is refused under the reading it records (REVIEW-10343 round 2 P1-1).
    fx.vault.project_settings().expect("the pass");
    assert!(
        emergency_plan_admission(&fx.vault, 1)
            .expect("the policy read")
            .is_err(),
        "the floor stands above the count"
    );
    let words = words_of(&fx.the_notice());
    assert!(
        words.contains("Emergency rescheduling is off: you set min 2 above max 1. Fix it?"),
        "{words:?}"
    );
}

#[test]
fn the_booking_pairs_tap_edits_the_floor_pin_read_as_a_value_row() {
    let fx = Fixture::rooted();
    fx.raced_floor_pin(3);
    assert_eq!(
        fx.reads(MIN_PROPOSALS),
        json!(3),
        "the raced pin narrows the floor"
    );

    // A third machine lowers the count to 2 under it: this install's hook refuses the count, the
    // pass lands it all the same, and the notice's tap edits the row that decides the floor, the
    // pin, not an absent value row (REVIEW-10343 round 2 P1-2).
    let tablet = enroll_machine_with_key(&fx.vault, &fx.owner_proof, 9).expect("enrolled");
    let frontier = setting_frontier_of(&fx.vault, &[vault_row(MAX_PROPOSALS)]).expect("frontier");
    land_setting_act_from(
        &fx.vault,
        &tablet,
        fx.owner,
        &frontier,
        vault_row(MAX_PROPOSALS),
        Some(json!(2)),
        T0,
    )
    .expect("the act lands");

    let notice = fx.the_notice();
    let further = &notice["actions"][0]["args"]["further"][0];
    assert_eq!(further["key"], json!(MIN_PROPOSALS), "{notice:#?}");
    assert_eq!(
        further["pin"],
        json!(true),
        "the tap edits the pin: {notice:#?}"
    );
    assert_eq!(further["value"], json!(3), "{notice:#?}");
}

/// Each row `tap` changes, by its key and item, to the value it sets (`null` clears).
fn row_items_of(tap: &Value) -> std::collections::BTreeMap<(String, String), Value> {
    let further = tap["further"].as_array().cloned().unwrap_or_default();
    std::iter::once(tap.clone())
        .chain(further)
        .map(|row| {
            let key = row["key"].as_str().expect("a key").to_owned();
            let item = row["item"].as_str().unwrap_or_default().to_owned();
            ((key, item), row["value"].clone())
        })
        .collect()
}

/// The tap of `notice` that keeps the row of `key` for `item` and clears every other row it
/// names.
fn tap_keeping_item(notice: &Value, (key, item): (&str, &str)) -> Value {
    taps_of(notice)
        .into_iter()
        .find(|tap| {
            row_items_of(tap)
                .iter()
                .all(|((row, at), value)| (row == key && at == item) != value.is_null())
        })
        .unwrap_or_else(|| panic!("a tap keeps `{key}` for `{item}`: {notice:#?}"))
}

/// A CalDAV seat's setup at `seat_ref` of the one calendar of the credential `caldav:work`,
/// importing under `system`: every seat of that calendar names one endpoint, one credential and
/// one collection, so two of them may hold one system.
fn seat_setup_of_one_calendar(seat_ref: &str, system: &str) -> Value {
    let mut setup = seat_setup(seat_ref, system);
    setup["config"]["secret_ref"] = json!("caldav:work");
    setup
}

#[test]
fn a_pick_from_one_calendars_notice_names_no_row_of_another_calendar() {
    let fx = Fixture::rooted();
    let (work, home) = (item_slot(SEAT, "work"), item_slot(SEAT, "home"));
    let frontier = setting_frontier_of(&fx.vault, &[work, home]).expect("frontier");
    fx.owner_sets_item(FEED, "work-cal", feed_config("work-cal"));
    fx.owner_sets_item(FEED, "home-cal", feed_config("home-cal"));

    // The other machine installs a seat on each feed's system in one act: this install refuses
    // each against its own feed and raises a notice each, whose picks name only its calendar's
    // rows (REVIEW-10357 P1-1).
    land_setting_batch_from(
        &fx.vault,
        &fx.desktop,
        fx.owner,
        &frontier,
        &[
            (work, Some(seat_setup("work", "work-cal"))),
            (home, Some(seat_setup("home", "home-cal"))),
        ],
        T0,
    )
    .expect("the act lands");

    let notices = fx.refusal_notices();
    assert_eq!(notices.len(), 2, "a notice for each seat: {notices:#?}");
    for notice in &notices {
        let other = if words_of(notice).contains("'work-cal' calendar") {
            ["home", "home-cal"]
        } else {
            ["work", "work-cal"]
        };
        let taps = taps_of(notice);
        assert_eq!(taps.len(), 2, "a tap for each of its sources: {notice:#?}");
        for tap in &taps {
            for (_, item) in row_items_of(tap).keys() {
                assert!(!other.contains(&item.as_str()), "{item} in {tap:#?}");
            }
        }
    }
}

#[test]
fn the_pick_of_the_feed_clears_every_seat_that_holds_its_system() {
    let fx = Fixture::rooted();
    let frontier = setting_frontier_of(
        &fx.vault,
        &[item_slot(SEAT, "work"), item_slot(SEAT, "work2")],
    )
    .expect("frontier");
    fx.owner_sets_item(FEED, "work-cal", feed_config("work-cal"));

    // The other machine installs two seats of one calendar on the feed's system, in two acts:
    // this install quarantines both, and the pick of the feed clears both (REVIEW-10357 P1-2).
    for seat in ["work", "work2"] {
        fx.desktop_sets_item(
            &frontier,
            (SEAT, seat),
            Some(seat_setup_of_one_calendar(seat, "work-cal")),
        );
    }

    let notices = fx.refusal_notices();
    assert!(!notices.is_empty(), "a notice of the refused seats");
    for notice in &notices {
        let rows = row_items_of(&tap_keeping_item(notice, (FEED, "work-cal")));
        for seat in ["work", "work2"] {
            assert_eq!(
                rows.get(&(SEAT.to_owned(), seat.to_owned())),
                Some(&Value::Null),
                "the pick of the feed clears the seat `{seat}`: {notice:#?}"
            );
        }
    }
}

#[test]
fn the_owners_pick_of_another_calendars_seat_takes_the_seat_here_out_of_service() {
    let fx = Fixture::rooted();
    let frontier = setting_frontier_of(&fx.vault, &[item_slot(SEAT, "team")]).expect("frontier");
    fx.owner_sets_item(SEAT, "work", seat_setup("work", "work-cal"));

    // The other machine installs a seat of another calendar on the same system: this install
    // quarantines it, and the owner keeps it, in one act that clears the seat installed here
    // (REVIEW-10357 P1-3).
    let mut team = seat_setup("team", "work-cal");
    team["config"]["calendar_ref"] = json!("team");
    fx.desktop_sets_item(&frontier, (SEAT, "team"), Some(team));
    assert_eq!(fx.reads_item(SEAT, "team"), Value::Null, "quarantined here");

    let tap = tap_keeping_item(&fx.the_notice(), (SEAT, "team"));
    invoke(&fx.as_owner(), "vault.settings.set", tap).expect("the owner's pick");
    fx.vault.project_settings().expect("the pass");

    assert!(
        !fx.reads_item(SEAT, "team").is_null(),
        "the seat the owner kept is installed here"
    );
    assert_eq!(
        fx.reads_item(SEAT, "work"),
        Value::Null,
        "the other is out of service"
    );
}
