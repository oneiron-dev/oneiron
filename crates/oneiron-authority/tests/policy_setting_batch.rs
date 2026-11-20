//! A batch is one act (stage 7a-3, DESIGN 1.6 "What travels"):
//! - a batch lists its further rows under `more`, after the act's own keys, and round-trips; a
//!   one-row act keeps the encoding of stage 7a-2;
//! - each row's act names that row's target and `seen` under the batch's one decider, and the act
//!   as it bears on one target is that row alone;
//! - two rows on one target, a row of one of the eight older settings, a batch whose first row is
//!   one of them, a row whose inline value is not its value or is past the bound, and a row whose
//!   slot is another key's or spells the vault value row are no valid act;
//! - an empty `more`, and a row whose slot is not a row's canonical key, do not decode.
//!
//! `cargo test --locked -p oneiron-authority --test policy_setting_batch`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron_authority::authority::{
    ActSurface, AuthorityOp, OwnerAct, OwnerActKind, POLICY_SETTING_INLINE_MAX, PolicySetting,
    PolicySettingRow, PolicySettingSet, decode_op, op_value, policy_setting_target,
    setting_slot_target, setting_value_digest,
};
use oneiron_contracts::entity_id::EntityId;
use oneiron_setting_contract::{RowKey, SettingMode, SettingScope};
use rmpv::Value;

const NUMBER: &str = "test.owner_number";
const CAP: &str = "test.ordered_cap";

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("an id")
}

/// The owner's one-row act setting `NUMBER`'s vault value row to `7`.
fn first_row() -> PolicySettingSet {
    PolicySettingSet {
        act: OwnerAct::by_owner(
            id(1),
            OwnerActKind::PolicySetting,
            policy_setting_target(NUMBER).expect("target"),
            ActSurface::ThisInstall,
            [0; 32],
        ),
        machine: id(2),
        setting: NUMBER.to_owned(),
        prior: [3; 32],
        value: Some(setting_value_digest(b"7")),
        slot: None,
        inline: Some(b"7".to_vec()),
        more: Vec::new(),
    }
}

/// A further row of `setting`'s row `slot` (none: its vault value row) setting `inline`, on `seen`.
fn row(setting: &str, slot: Option<RowKey>, inline: &[u8], seen: u8) -> PolicySettingRow {
    PolicySettingRow {
        setting: setting.to_owned(),
        slot,
        seen: [seen; 32],
        prior: [5; 32],
        value: Some(setting_value_digest(inline)),
        inline: Some(inline.to_vec()),
    }
}

fn pin_of(name: &str) -> RowKey {
    RowKey {
        name: name.to_owned(),
        item: None,
        mode: SettingMode::Pin,
        scope: SettingScope::Vault,
    }
}

/// `first_row` with two more rows: `CAP`'s vault value row and `NUMBER`'s pin.
fn batch() -> PolicySettingSet {
    PolicySettingSet {
        more: vec![
            row(CAP, None, b"4", 8),
            row(NUMBER, Some(pin_of(NUMBER)), b"3", 9),
        ],
        ..first_row()
    }
}

fn wire_keys(set: &PolicySettingSet) -> Vec<String> {
    op_value(&AuthorityOp::PolicySettingSet(set.clone()))
        .as_map()
        .expect("an op map")
        .iter()
        .map(|(key, _)| key.as_str().expect("a text key").to_owned())
        .collect()
}

fn round_trip(set: &PolicySettingSet) -> PolicySettingSet {
    let AuthorityOp::PolicySettingSet(decoded) =
        decode_op(&op_value(&AuthorityOp::PolicySettingSet(set.clone()))).expect("it decodes")
    else {
        panic!("a setting act");
    };
    decoded
}

/// The batch's op value with its `more` list rewritten by `rewrite`.
fn with_more(rewrite: impl Fn(&mut Value)) -> Value {
    let Value::Map(mut entries) = op_value(&AuthorityOp::PolicySettingSet(batch())) else {
        panic!("an op map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("more") {
            rewrite(value);
        }
    }
    Value::Map(entries)
}

#[test]
fn a_batch_round_trips_with_its_rows_after_the_acts_own_keys() {
    assert_eq!(
        wire_keys(&first_row()),
        [
            "kind", "act", "machine", "setting", "prior", "value", "inline"
        ],
        "a one-row act keeps the encoding of stage 7a-2"
    );
    let batch = batch();
    assert_eq!(
        wire_keys(&batch),
        [
            "kind", "act", "machine", "setting", "prior", "value", "inline", "more"
        ]
    );
    assert_eq!(round_trip(&batch), batch);
    batch.validate().expect("a batch of three rows");
}

#[test]
fn each_rows_act_names_its_own_target_and_seen_under_one_decider() {
    let batch = batch();
    let acts = batch.row_acts().expect("row acts");
    let cap = policy_setting_target(CAP).expect("target");
    let pin = setting_slot_target(&pin_of(NUMBER)).expect("target");
    let targets: Vec<_> = acts.iter().map(|(act, _)| (act.target, act.seen)).collect();
    assert_eq!(
        targets,
        [
            (policy_setting_target(NUMBER).expect("target"), [0; 32]),
            (cap, [8; 32]),
            (pin, [9; 32]),
        ]
    );
    for (act, _) in &acts {
        assert_eq!(
            (act.owner, act.by, act.surface, act.act),
            (
                batch.act.owner,
                batch.act.by,
                batch.act.surface,
                batch.act.act
            ),
            "one decider"
        );
    }
    assert_eq!(acts[1].1, Some(setting_value_digest(b"4")));

    let on_cap = batch.on_target(cap).expect("target").expect("a row on it");
    assert_eq!(on_cap.setting, CAP);
    assert_eq!(on_cap.slot, None);
    assert_eq!(on_cap.inline.as_deref(), Some(&b"4"[..]));
    assert_eq!((on_cap.act.target, on_cap.act.seen), (cap, [8; 32]));
    assert!(on_cap.more.is_empty(), "the row alone");
    on_cap.validate().expect("a row alone is a valid act");
    let on_pin = batch.on_target(pin).expect("target").expect("a row on it");
    assert_eq!(on_pin.slot, Some(pin_of(NUMBER)));
    assert_eq!(
        batch
            .on_target(policy_setting_target("test.other").expect("target"))
            .expect("target"),
        None
    );
}

#[test]
fn two_rows_on_one_target_are_no_valid_act() {
    for (what, more) in [
        ("the first row's again", vec![row(NUMBER, None, b"4", 0)]),
        (
            "one further row twice",
            vec![row(CAP, None, b"4", 0), row(CAP, None, b"5", 0)],
        ),
    ] {
        let set = PolicySettingSet {
            more,
            ..first_row()
        };
        assert!(set.validate().is_err(), "{what}");
    }
}

#[test]
fn a_batch_stands_only_on_catalogue_keys() {
    let undo = PolicySetting::UndoSend.wire();
    let older_row = PolicySettingSet {
        more: vec![row(undo, None, b"4", 0)],
        ..first_row()
    };
    assert!(older_row.validate().is_err(), "a row of an older setting");

    let older_first = PolicySettingSet {
        setting: undo.to_owned(),
        act: OwnerAct {
            target: policy_setting_target(undo).expect("target"),
            ..first_row().act
        },
        inline: None,
        more: vec![row(CAP, None, b"4", 0)],
        ..first_row()
    };
    assert!(
        older_first.validate().is_err(),
        "a batch whose first row is an older setting"
    );
    PolicySettingSet {
        more: Vec::new(),
        ..older_first
    }
    .validate()
    .expect("the older setting's act alone");
}

#[test]
fn a_rows_inline_value_and_slot_must_be_well_formed() {
    let wrong_value = PolicySettingRow {
        value: Some(setting_value_digest(b"5")),
        ..row(CAP, None, b"4", 0)
    };
    let past_bound = row(CAP, None, &vec![b'1'; POLICY_SETTING_INLINE_MAX + 1], 0);
    let other_key = row(CAP, Some(pin_of(NUMBER)), b"4", 0);
    let spelled = row(
        CAP,
        Some(RowKey {
            mode: SettingMode::Value,
            ..pin_of(CAP)
        }),
        b"4",
        0,
    );
    for (what, bad) in [
        ("an inline value that is not its value", wrong_value),
        ("an inline value past the bound", past_bound),
        ("a slot of another key", other_key),
        ("the vault value row spelled out", spelled),
    ] {
        let set = PolicySettingSet {
            more: vec![bad],
            ..first_row()
        };
        assert!(set.validate().is_err(), "{what}");
    }
    PolicySettingSet {
        more: vec![row(CAP, None, &vec![b'1'; POLICY_SETTING_INLINE_MAX], 0)],
        ..first_row()
    }
    .validate()
    .expect("at the bound");
}

#[test]
fn an_empty_more_and_a_rows_non_canonical_slot_do_not_decode() {
    assert!(
        decode_op(&with_more(|more| *more = Value::Array(Vec::new()))).is_err(),
        "an empty more"
    );
    assert!(
        decode_op(&with_more(|more| *more = Value::Nil)).is_err(),
        "a more that is no list"
    );
    for bad in [
        Value::Binary(b"test.owner_number".to_vec()),
        Value::Binary(Vec::new()),
        Value::from("test.owner_number"),
    ] {
        let value = with_more(|more| {
            let Value::Array(rows) = more else {
                panic!("a list");
            };
            let Value::Map(entries) = &mut rows[1] else {
                panic!("a row map");
            };
            for (key, value) in entries.iter_mut() {
                if key.as_str() == Some("slot") {
                    *value = bad.clone();
                }
            }
        });
        assert!(decode_op(&value).is_err(), "{bad:?}");
    }
}
