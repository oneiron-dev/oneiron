//! The setting an owner act names is its wire text (stage 7a-1, RULING SETTING-7A-SIGNED-ACT-BASE
//! = A): any name of a setting key's shape, checked by shape and never by a catalogue.
//! - each of the eight older settings keeps its wire text, its act kind and its reserved target,
//!   and the rules it had (only the free-time policy is an agent's or is cleared);
//! - a catalogue key's act is the owner's, on the target derived from its name, a set or a clear;
//! - a name of another shape, or a longer one, is no valid act.
//!
//! `cargo test --locked -p oneiron-authority --test policy_setting_name`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron_authority::authority::{
    ActBy, ActSurface, AuthorityOp, OwnerAct, OwnerActKind, POLICY_SETTING_NAME_MAX, PolicySetting,
    PolicySettingSet, is_policy_setting_name, op_value, owner_act_target, policy_setting_target,
};
use oneiron_contracts::entity_id::EntityId;

const OLDER: [PolicySetting; 8] = [
    PolicySetting::DreamerWakePolicy,
    PolicySetting::InferenceDefaults,
    PolicySetting::RoomThreadAdmin,
    PolicySetting::FreeTimePolicy,
    PolicySetting::BoardLayout,
    PolicySetting::NonBaseWorldClaimFraction,
    PolicySetting::DefaultFacet,
    PolicySetting::UndoSend,
];

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("an id")
}

/// The owner's act on `setting` at `target`, setting a value.
fn owners(setting: &str, target: EntityId, kind: OwnerActKind) -> PolicySettingSet {
    PolicySettingSet {
        act: OwnerAct::by_owner(id(1), kind, target, ActSurface::ThisInstall, [0; 32]),
        machine: id(2),
        setting: setting.to_owned(),
        prior: [3; 32],
        value: Some([4; 32]),
    }
}

/// The text the op's `setting` field carries on the wire.
fn wire_setting(set: &PolicySettingSet) -> String {
    let value = op_value(&AuthorityOp::PolicySettingSet(set.clone()));
    value
        .as_map()
        .expect("an op map")
        .iter()
        .find(|(key, _)| key.as_str() == Some("setting"))
        .and_then(|(_, value)| value.as_str())
        .expect("a setting field")
        .to_owned()
}

#[test]
fn the_eight_older_settings_keep_their_text_kind_target_and_rules() {
    for setting in OLDER {
        let name = setting.wire();
        assert!(is_policy_setting_name(name), "{name}");
        assert_eq!(PolicySetting::parse(name), Some(setting));
        let free_time = setting == PolicySetting::FreeTimePolicy;
        let target = if free_time {
            id(9)
        } else {
            let reserved = setting
                .reserved_target()
                .expect("target")
                .expect("a vault-wide setting's reserved target");
            assert_eq!(
                reserved,
                owner_act_target(setting.as_str()).expect("target"),
                "{name}: the reserved target its acts always named"
            );
            assert_eq!(reserved, policy_setting_target(name).expect("target"));
            reserved
        };
        let set = owners(name, target, setting.act_kind());
        assert_eq!(wire_setting(&set), name, "the wire text is as before");
        set.validate()
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));

        let cleared = PolicySettingSet {
            value: None,
            ..set.clone()
        };
        let by_agent = PolicySettingSet {
            act: OwnerAct {
                by: ActBy::Agent {
                    agent: target,
                    grant: id(8),
                },
                ..set.act
            },
            ..set.clone()
        };
        assert_eq!(cleared.validate().is_ok(), free_time, "{name}: a clear");
        assert_eq!(by_agent.validate().is_ok(), free_time, "{name}: an agent");
    }
}

#[test]
fn a_catalogue_keys_act_is_the_owners_on_the_target_of_its_name() {
    let name = "outbound.undo_send";
    assert_eq!(PolicySetting::parse(name), None, "no older setting");
    let target = policy_setting_target(name).expect("target");
    assert_eq!(
        target,
        owner_act_target("settings.outbound.undo_send").expect("target")
    );
    let set = owners(name, target, OwnerActKind::PolicySetting);
    assert_eq!(wire_setting(&set), name);
    set.validate().expect("the owner sets a catalogue key");
    PolicySettingSet {
        value: None,
        ..set.clone()
    }
    .validate()
    .expect("the owner clears a catalogue key");

    let refused = [
        (
            "another target",
            owners(name, id(5), OwnerActKind::PolicySetting),
        ),
        (
            "another kind",
            owners(name, target, OwnerActKind::FreeTimePolicy),
        ),
        (
            "an agent",
            PolicySettingSet {
                act: OwnerAct {
                    by: ActBy::Agent {
                        agent: id(6),
                        grant: id(7),
                    },
                    ..set.act
                },
                ..set.clone()
            },
        ),
        (
            "an answered ask",
            PolicySettingSet {
                act: OwnerAct {
                    answer: Some(id(6)),
                    ..set.act
                },
                ..set.clone()
            },
        ),
    ];
    for (what, act) in refused {
        assert!(act.validate().is_err(), "{what}");
    }
}

#[test]
fn a_name_of_another_shape_is_no_valid_act() {
    let longest = "a".repeat(POLICY_SETTING_NAME_MAX);
    assert!(is_policy_setting_name(&longest));
    let longer = "a".repeat(POLICY_SETTING_NAME_MAX + 1);
    for bad in [
        "",
        "Outbound.x",
        "a..b",
        ".a",
        "a.",
        "a b",
        "a\0b",
        longer.as_str(),
    ] {
        assert!(!is_policy_setting_name(bad), "{bad:?}");
        let target = owner_act_target(&format!("settings.{bad}")).expect("target");
        assert!(
            owners(bad, target, OwnerActKind::PolicySetting)
                .validate()
                .is_err(),
            "{bad:?}"
        );
    }
}
