//! A move's carried rows as one copy (stage 7a-4, DESIGN 1.6 "A move across machines"):
//! - a copy round-trips: its carrier, and each carried row with its `seen` and the acts it names,
//!   each by its own row;
//! - the copy's row on a target is that row alone;
//! - no valid copy: no row; a row that is not a carried row, or not at a project's scope; a row of
//!   one of the eight older settings; a row that names no act; a name of another key or item, or
//!   at a scope that is no project's; one name twice; two rows on one target;
//! - a row list or a name list that is no list, a slot that is not a row's canonical key, and a
//!   key the op does not know do not decode.
//!
//! `cargo test --locked -p oneiron-authority --test setting_copy_op`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron_authority::authority::{
    AuthorityOp, PolicySetting, SettingCopy, SettingCopyName, SettingCopyRow, decode_op, op_value,
    setting_slot_target,
};
use oneiron_contracts::entity_id::EntityId;
use oneiron_setting_contract::{RowKey, SettingMode, SettingScope};
use rmpv::Value;

const CAP: &str = "test.ordered_cap";
const LIST: &str = "test.permit_list";

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("an id")
}

/// `key`'s item-less `mode` row on the project `project`.
fn slot(key: &str, mode: SettingMode, project: u8) -> RowKey {
    RowKey {
        name: key.to_owned(),
        item: None,
        mode,
        scope: SettingScope::Project(id(project)),
    }
}

fn name(slot: RowKey, act: u8) -> SettingCopyName {
    SettingCopyName {
        slot,
        act: [act; 32],
    }
}

/// `CAP`'s carried row on project 9: the owner's value row on line 7, his pin on line 8, and the
/// carried row's own head.
fn cap_row() -> SettingCopyRow {
    SettingCopyRow {
        slot: slot(CAP, SettingMode::Carried, 9),
        seen: [4; 32],
        names: vec![
            name(slot(CAP, SettingMode::Value, 7), 11),
            name(slot(CAP, SettingMode::Pin, 8), 12),
            name(slot(CAP, SettingMode::Carried, 9), 13),
        ],
    }
}

/// A copy of two carried rows on project 9: `CAP`'s, and `LIST`'s from line 7.
fn copy() -> SettingCopy {
    SettingCopy {
        machine: id(2),
        rows: vec![
            cap_row(),
            SettingCopyRow {
                slot: slot(LIST, SettingMode::Carried, 9),
                seen: [0; 32],
                names: vec![name(slot(LIST, SettingMode::Value, 7), 14)],
            },
        ],
    }
}

fn round_trip(copy: &SettingCopy) -> SettingCopy {
    let AuthorityOp::SettingCopy(decoded) =
        decode_op(&op_value(&AuthorityOp::SettingCopy(copy.clone()))).expect("it decodes")
    else {
        panic!("a copy");
    };
    decoded
}

/// The copy's op value with its first row's map rewritten by `rewrite`.
fn with_first_row(rewrite: impl Fn(&mut Vec<(Value, Value)>)) -> Value {
    let Value::Map(mut entries) = op_value(&AuthorityOp::SettingCopy(copy())) else {
        panic!("an op map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("rows") {
            let Value::Array(rows) = value else {
                panic!("a list");
            };
            let Value::Map(row) = &mut rows[0] else {
                panic!("a row map");
            };
            rewrite(row);
        }
    }
    Value::Map(entries)
}

#[test]
fn a_copy_round_trips_with_each_row_and_the_acts_it_names() {
    let copy = copy();
    copy.validate().expect("a copy of two carried rows");
    assert_eq!(round_trip(&copy), copy);
    let keys: Vec<String> = op_value(&AuthorityOp::SettingCopy(copy.clone()))
        .as_map()
        .expect("an op map")
        .iter()
        .map(|(key, _)| key.as_str().expect("a text key").to_owned())
        .collect();
    assert_eq!(keys, ["kind", "machine", "rows"]);

    let list = setting_slot_target(&slot(LIST, SettingMode::Carried, 9)).expect("target");
    let row = copy.on_target(list).expect("target").expect("a row on it");
    assert_eq!(row.slot, slot(LIST, SettingMode::Carried, 9));
    assert_eq!(row.names.len(), 1);
    let elsewhere = setting_slot_target(&slot(CAP, SettingMode::Carried, 1)).expect("target");
    assert_eq!(copy.on_target(elsewhere).expect("target"), None);
}

#[test]
fn a_copy_that_breaks_its_shape_is_no_valid_copy() {
    let only = |row: SettingCopyRow| SettingCopy {
        rows: vec![row],
        ..copy()
    };
    let named = |names: Vec<SettingCopyName>| only(SettingCopyRow { names, ..cap_row() });
    let older = PolicySetting::UndoSend.wire();
    let cases = [
        (
            "no row",
            SettingCopy {
                rows: Vec::new(),
                ..copy()
            },
        ),
        (
            "a value row, not a carried one",
            only(SettingCopyRow {
                slot: slot(CAP, SettingMode::Value, 9),
                ..cap_row()
            }),
        ),
        (
            "a carried row at the vault's scope",
            only(SettingCopyRow {
                slot: RowKey {
                    scope: SettingScope::Vault,
                    ..slot(CAP, SettingMode::Carried, 9)
                },
                ..cap_row()
            }),
        ),
        (
            "a row of an older setting",
            only(SettingCopyRow {
                slot: slot(older, SettingMode::Carried, 9),
                names: vec![name(slot(older, SettingMode::Value, 7), 11)],
                ..cap_row()
            }),
        ),
        ("a row that names no act", named(Vec::new())),
        (
            "a name of another key",
            named(vec![name(slot(LIST, SettingMode::Value, 7), 11)]),
        ),
        (
            "a name of another item",
            named(vec![name(
                RowKey {
                    item: Some("other".to_owned()),
                    ..slot(CAP, SettingMode::Value, 7)
                },
                11,
            )]),
        ),
        (
            "a name at the vault's scope",
            named(vec![name(
                RowKey {
                    scope: SettingScope::Vault,
                    ..slot(CAP, SettingMode::Value, 7)
                },
                11,
            )]),
        ),
        (
            "one name twice",
            named(vec![
                name(slot(CAP, SettingMode::Value, 7), 11),
                name(slot(CAP, SettingMode::Value, 7), 11),
            ]),
        ),
        (
            "two rows on one target",
            SettingCopy {
                rows: vec![cap_row(), cap_row()],
                ..copy()
            },
        ),
    ];
    for (what, copy) in cases {
        assert!(copy.validate().is_err(), "{what}");
    }
}

#[test]
fn a_row_list_that_is_no_list_a_non_canonical_slot_and_an_unknown_key_do_not_decode() {
    let Value::Map(mut entries) = op_value(&AuthorityOp::SettingCopy(copy())) else {
        panic!("an op map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("rows") {
            *value = Value::Nil;
        }
    }
    assert!(
        decode_op(&Value::Map(entries)).is_err(),
        "a row list that is no list"
    );
    assert!(
        decode_op(&with_first_row(|row| {
            for (key, value) in row.iter_mut() {
                if key.as_str() == Some("names") {
                    *value = Value::from("names");
                }
            }
        }))
        .is_err(),
        "a name list that is no list"
    );
    for bad in [
        Value::Binary(CAP.as_bytes().to_vec()),
        Value::Binary(Vec::new()),
        Value::from(CAP),
    ] {
        let value = with_first_row(|row| {
            for (key, value) in row.iter_mut() {
                if key.as_str() == Some("slot") {
                    *value = bad.clone();
                }
            }
        });
        assert!(decode_op(&value).is_err(), "a slot of {bad:?}");
    }
    assert!(
        decode_op(&with_first_row(|row| {
            row.push((Value::from("value"), Value::Nil));
        }))
        .is_err(),
        "a row key the op does not know"
    );
}
