//! A setting act names its row and carries its value (stage 7a-2, DESIGN 1.6 "What travels"):
//! - an older act (no slot, no inline value) keeps its six wire keys and decodes as it did;
//! - an act that names a slot and carries its value round-trips, on the slot's own target, and
//!   the vault value row with no item keeps the key's target of stage 7a-1;
//! - an inline value whose BLAKE3 is not the act's value, one longer than the bound, or one on a
//!   clear is no valid act;
//! - a slot of another key, a slot that spells the vault value row, and a slot or inline value on
//!   one of the eight older settings are no valid act;
//! - a slot whose bytes are not a row's canonical key does not decode.
//!
//! `cargo test --locked -p oneiron-authority --test policy_setting_slot`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron_authority::authority::{
    ActSurface, AuthorityOp, OwnerAct, OwnerActKind, POLICY_SETTING_INLINE_MAX, PolicySetting,
    PolicySettingSet, decode_op, op_value, policy_setting_target, setting_slot_target,
};
use oneiron_contracts::entity_id::EntityId;
use oneiron_setting_contract::{RowKey, SettingMode, SettingScope};
use rmpv::Value;

const NAME: &str = "test.owner_number";

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("an id")
}

/// The row `mode` of `NAME` at `scope`, with no item.
fn slot(mode: SettingMode, scope: SettingScope) -> RowKey {
    RowKey {
        name: NAME.to_owned(),
        item: None,
        mode,
        scope,
    }
}

/// The owner's act on `slot` (none: the vault value row) setting `inline`, on the slot's target.
fn owners(slot: Option<RowKey>, inline: &[u8]) -> PolicySettingSet {
    let target = match &slot {
        Some(slot) => setting_slot_target(slot).expect("target"),
        None => policy_setting_target(NAME).expect("target"),
    };
    PolicySettingSet {
        act: OwnerAct::by_owner(
            id(1),
            OwnerActKind::PolicySetting,
            target,
            ActSurface::ThisInstall,
            [0; 32],
        ),
        machine: id(2),
        setting: NAME.to_owned(),
        prior: [3; 32],
        value: Some(*blake3::hash(inline).as_bytes()),
        slot,
        inline: Some(inline.to_vec()),
    }
}

/// The op's wire keys, in their order.
fn wire_keys(set: &PolicySettingSet) -> Vec<String> {
    op_value(&AuthorityOp::PolicySettingSet(set.clone()))
        .as_map()
        .expect("an op map")
        .iter()
        .map(|(key, _)| key.as_str().expect("a text key").to_owned())
        .collect()
}

/// `set` through the wire and back.
fn round_trip(set: &PolicySettingSet) -> PolicySettingSet {
    let AuthorityOp::PolicySettingSet(decoded) =
        decode_op(&op_value(&AuthorityOp::PolicySettingSet(set.clone()))).expect("it decodes")
    else {
        panic!("a setting act");
    };
    decoded
}

#[test]
fn an_older_act_keeps_its_six_keys_and_decodes_as_it_did() {
    let older = PolicySettingSet {
        slot: None,
        inline: None,
        ..owners(None, b"7")
    };
    assert_eq!(
        wire_keys(&older),
        ["kind", "act", "machine", "setting", "prior", "value"],
        "no new key on an act that names neither"
    );
    assert_eq!(round_trip(&older), older);
    older.validate().expect("an older act stays valid");
}

#[test]
fn an_act_naming_its_slot_and_value_round_trips_on_the_slots_target() {
    let vault_row = owners(None, b"7");
    assert_eq!(
        wire_keys(&vault_row),
        [
            "kind", "act", "machine", "setting", "prior", "value", "inline"
        ]
    );
    assert_eq!(round_trip(&vault_row), vault_row);
    vault_row.validate().expect("the vault value row");
    assert_eq!(
        vault_row.target().expect("target"),
        policy_setting_target(NAME).expect("target"),
        "the vault value row keeps the key's target"
    );
    assert_eq!(
        setting_slot_target(&slot(SettingMode::Value, SettingScope::Vault)).expect("target"),
        policy_setting_target(NAME).expect("target"),
        "the slot target of the vault value row is the key's"
    );

    let project = id(0x31);
    let mut targets = Vec::new();
    for named in [
        slot(SettingMode::Value, SettingScope::Project(project)),
        slot(SettingMode::Pin, SettingScope::Vault),
        slot(SettingMode::Pin, SettingScope::Project(project)),
        RowKey {
            item: Some("email".to_owned()),
            ..slot(SettingMode::Value, SettingScope::Vault)
        },
    ] {
        let set = owners(Some(named.clone()), b"3");
        assert_eq!(
            wire_keys(&set),
            [
                "kind", "act", "machine", "setting", "prior", "value", "slot", "inline"
            ]
        );
        assert_eq!(round_trip(&set), set, "{named:?}");
        set.validate()
            .unwrap_or_else(|error| panic!("{named:?}: {error:?}"));
        let target = set.target().expect("target");
        assert_ne!(target, policy_setting_target(NAME).expect("target"));
        targets.push(target);
    }
    targets.sort();
    targets.dedup();
    assert_eq!(targets.len(), 4, "each row has a frontier of its own");

    let cleared = PolicySettingSet {
        value: None,
        inline: None,
        ..owners(
            Some(slot(SettingMode::Pin, SettingScope::Project(project))),
            b"3",
        )
    };
    assert_eq!(round_trip(&cleared), cleared);
    cleared.validate().expect("a clear of a named row");
}

#[test]
fn an_inline_value_must_be_the_acts_value_within_its_bound_and_never_on_a_clear() {
    let set = owners(None, b"7");
    let refused = [
        (
            "another digest",
            PolicySettingSet {
                value: Some([9; 32]),
                ..set.clone()
            },
        ),
        (
            "a clear",
            PolicySettingSet {
                value: None,
                ..set.clone()
            },
        ),
        (
            "past the bound",
            owners(None, &vec![b'1'; POLICY_SETTING_INLINE_MAX + 1]),
        ),
    ];
    for (what, act) in refused {
        assert!(act.validate().is_err(), "{what}");
    }
    owners(None, &vec![b'1'; POLICY_SETTING_INLINE_MAX])
        .validate()
        .expect("at the bound");
}

#[test]
fn a_slot_of_another_key_the_vault_row_spelled_out_or_an_older_setting_is_no_valid_act() {
    let other_key = RowKey {
        name: "test.other_number".to_owned(),
        ..slot(SettingMode::Pin, SettingScope::Vault)
    };
    let spelled = slot(SettingMode::Value, SettingScope::Vault);
    for (what, named) in [("another key", other_key), ("the vault row", spelled)] {
        let mut set = owners(Some(named.clone()), b"7");
        set.act.target = setting_slot_target(&named).expect("target");
        assert!(set.validate().is_err(), "{what}");
    }

    let undo = PolicySetting::UndoSend;
    let older = PolicySettingSet {
        setting: undo.wire().to_owned(),
        act: OwnerAct {
            target: policy_setting_target(undo.wire()).expect("target"),
            ..owners(None, b"7").act
        },
        ..owners(None, b"7")
    };
    assert!(
        older.validate().is_err(),
        "an inline value on an older setting"
    );
    PolicySettingSet {
        inline: None,
        ..older
    }
    .validate()
    .expect("the older setting's act without one");
}

#[test]
fn a_slot_that_is_not_a_rows_canonical_key_does_not_decode() {
    let set = owners(Some(slot(SettingMode::Pin, SettingScope::Vault)), b"7");
    let Value::Map(mut entries) = op_value(&AuthorityOp::PolicySettingSet(set)) else {
        panic!("an op map");
    };
    for bad in [
        Value::Binary(b"test.owner_number".to_vec()),
        Value::Binary(Vec::new()),
        Value::from("test.owner_number"),
    ] {
        for (key, value) in &mut entries {
            if key.as_str() == Some("slot") {
                *value = bad.clone();
            }
        }
        assert!(decode_op(&Value::Map(entries.clone())).is_err(), "{bad:?}");
    }
}
