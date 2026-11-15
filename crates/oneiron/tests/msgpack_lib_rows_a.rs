//! Each lookup below reads one key of a stored MessagePack map. A map that holds the key twice,
//! which no writer ever wrote (K-proof
//! /Users/olety/Desktop/temp/vibe-build-20261017/lanes/kimi/OPUS-UC08-MSGPACK/legs/kproof-pr5a/KPROOF.md),
//! reads as absent or is refused. Red on the base, where each lookup returned the first value.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::repeated_key_lib_rows as door;
use rmpv::Value;

/// `{"k": 1}`, as a writer writes it.
fn once() -> Vec<(Value, Value)> {
    vec![(Value::from("k"), Value::from(1))]
}

/// `{"k": 1, "k": 2}`: a map no writer ever wrote.
fn twice() -> Vec<(Value, Value)> {
    vec![
        (Value::from("k"), Value::from(1)),
        (Value::from("k"), Value::from(2)),
    ]
}

#[test]
fn annotation_map_get_reads_a_repeated_key_as_absent() {
    assert_eq!(
        door::annotation_map_get(&Value::Map(once()), "k"),
        Some(Value::from(1))
    );
    assert_eq!(door::annotation_map_get(&Value::Map(twice()), "k"), None);
}

#[test]
fn continuation_field_reads_a_repeated_key_as_absent() {
    assert_eq!(
        door::continuation_field(&Value::Map(once()), "k"),
        Some(Value::from(1))
    );
    assert_eq!(door::continuation_field(&Value::Map(twice()), "k"), None);
}

#[test]
fn dispatch_outcome_map_get_refuses_a_repeated_key() {
    assert_eq!(
        door::dispatch_outcome_map_get(&once(), "k").ok(),
        Some(Value::from(1))
    );
    assert!(door::dispatch_outcome_map_get(&twice(), "k").is_err());
}

#[test]
fn fit_map_entry_reads_a_repeated_key_as_absent() {
    assert_eq!(door::fit_map_entry(&once(), "k"), Some(Value::from(1)));
    assert_eq!(door::fit_map_entry(&twice(), "k"), None);
}

#[test]
fn quote_field_reads_a_repeated_key_as_absent() {
    assert_eq!(door::quote_field(&once(), "k"), Some(Value::from(1)));
    assert_eq!(door::quote_field(&twice(), "k"), None);
}

#[test]
fn retained_field_refuses_a_repeated_key() {
    assert_eq!(
        door::retained_field(&Value::Map(once()), "k").ok(),
        Some(Value::from(1))
    );
    assert!(door::retained_field(&Value::Map(twice()), "k").is_err());
}
