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
//!   holds it in service refuses;
//! - another machine's copy of the same notice, which holds no marks, keeps the owner's
//!   acknowledgement here.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_refusal_notice`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingChange, SettingMode, SettingScope,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
#[cfg(feature = "sync")]
use oneiron::test_doors::setting::land_notification_copy_without_receipts;
use oneiron::test_doors::setting::{
    EnrolledMachine, SettingFrontier, SlotName, enroll_machine_with_key,
    forget_projected_setting_rows, forget_setting_projection_records, land_setting_act_from,
    land_setting_batch_from, set_setting_as_engine, setting_changes, setting_frontier_of,
    setting_slot_heads,
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
fn a_seat_refused_here_offers_no_tap_that_leaves_it_with_no_value() {
    let fx = Fixture::rooted();
    fx.vault
        .set_setting(
            SettingCaller::Owner(&fx.owner_proof),
            item_row(SEAT, "work", seat_setup("work", "work-cal")),
        )
        .expect("the owner installs the seat");

    // This install as another machine: it holds the log, no seat row, and an ICS feed on the
    // seat's system. Its hook refuses the seat, and the machine that installed it holds it in
    // service, so a change of the seat to no value would be refused there.
    forget_projected_setting_rows(&fx.vault).expect("the rows forgotten");
    set_setting_as_engine(
        &fx.vault,
        None,
        item_row(
            FEED,
            "work-cal",
            json!({
                "secret_ref": "ics-feed:work-cal",
                "system": "work-cal",
                "cadence_min_seconds": 600,
                "cadence_max_seconds": 1200,
            }),
        ),
    )
    .expect("the feed on the seat's system");
    fx.vault.project_settings().expect("the pass");

    let notice = fx.the_notice();
    assert_eq!(
        notice["actions"],
        Value::Null,
        "no tap leaves the seat with no value: {notice:#?}"
    );
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
