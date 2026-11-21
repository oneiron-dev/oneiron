//! The names of 2 name lists in `oneiron-delivery-vocabulary`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-delivery-vocabulary/src/delivery_window/types.rs`

use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowContextCondition;
use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowResolvedLevel;
use serde::Deserialize;
use serde::de::IntoDeserializer;
use serde::de::value::{Error as ValueError, StrDeserializer};

/// Every row of `DeliveryWindowContextCondition`, as its hand table spelled it.
const DELIVERY_WINDOW_CONTEXT_CONDITION_ROWS: [(DeliveryWindowContextCondition, &str); 4] = [
    (
        DeliveryWindowContextCondition::CalendarBusy,
        "calendar_busy",
    ),
    (DeliveryWindowContextCondition::FocusOn, "focus_on"),
    (DeliveryWindowContextCondition::Driving, "driving"),
    (DeliveryWindowContextCondition::Asleep, "asleep"),
];

#[test]
fn every_delivery_window_context_condition_keeps_its_name() {
    assert_eq!(
        DeliveryWindowContextCondition::CalendarBusy.as_str(),
        "calendar_busy"
    );
    assert_eq!(DeliveryWindowContextCondition::FocusOn.as_str(), "focus_on");
    assert_eq!(DeliveryWindowContextCondition::Driving.as_str(), "driving");
    assert_eq!(DeliveryWindowContextCondition::Asleep.as_str(), "asleep");
}

#[test]
fn every_delivery_window_context_condition_name_is_its_serde_name() {
    for (row, name) in DELIVERY_WINDOW_CONTEXT_CONDITION_ROWS {
        let reader: StrDeserializer<'_, ValueError> = name.into_deserializer();
        let read =
            DeliveryWindowContextCondition::deserialize(reader).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn delivery_window_context_condition_parse_reads_each_name_back() {
    for (row, name) in DELIVERY_WINDOW_CONTEXT_CONDITION_ROWS {
        assert_eq!(
            DeliveryWindowContextCondition::parse(name),
            Some(row),
            "{name}"
        );
    }
    assert_eq!(DeliveryWindowContextCondition::parse("not.a.row"), None);
}

/// Every row of `DeliveryWindowResolvedLevel`, as its hand table spelled it.
const DELIVERY_WINDOW_RESOLVED_LEVEL_ROWS: [(DeliveryWindowResolvedLevel, &str); 2] = [
    (DeliveryWindowResolvedLevel::PlainChat, "plain_chat"),
    (DeliveryWindowResolvedLevel::Push, "push"),
];

#[test]
fn every_delivery_window_resolved_level_keeps_its_name() {
    assert_eq!(
        DeliveryWindowResolvedLevel::PlainChat.as_str(),
        "plain_chat"
    );
    assert_eq!(DeliveryWindowResolvedLevel::Push.as_str(), "push");
}

#[test]
fn every_delivery_window_resolved_level_name_is_its_serde_name() {
    for (row, name) in DELIVERY_WINDOW_RESOLVED_LEVEL_ROWS {
        let reader: StrDeserializer<'_, ValueError> = name.into_deserializer();
        let read = DeliveryWindowResolvedLevel::deserialize(reader).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn delivery_window_resolved_level_parse_reads_each_name_back() {
    for (row, name) in DELIVERY_WINDOW_RESOLVED_LEVEL_ROWS {
        assert_eq!(
            DeliveryWindowResolvedLevel::parse(name),
            Some(row),
            "{name}"
        );
    }
    assert_eq!(DeliveryWindowResolvedLevel::parse("not.a.row"), None);
}
