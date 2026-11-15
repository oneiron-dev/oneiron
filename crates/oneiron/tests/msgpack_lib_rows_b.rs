//! Each lookup below reads one key of a stored MessagePack map. A map that holds the key twice,
//! which no writer ever wrote (K-proof
//! /Users/olety/Desktop/temp/vibe-build-20261017/lanes/kimi/OPUS-UC08-MSGPACK/legs/kproof-pr5b/KPROOF.md),
//! is refused. Red on the base, where each lookup returned the first value.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::lib_rows_b_repeated_key as door;
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
fn proposal_field_refuses_a_repeated_key() {
    assert_eq!(
        door::proposal_field(&once(), "k").ok(),
        Some(Some(Value::from(1)))
    );
    assert_eq!(door::proposal_field(&once(), "absent").ok(), Some(None));
    assert!(door::proposal_field(&twice(), "k").is_err());
}

#[test]
fn settlement_field_refuses_a_repeated_key() {
    assert_eq!(
        door::settlement_field(&once(), "k").ok(),
        Some(Some(Value::from(1)))
    );
    assert_eq!(door::settlement_field(&once(), "absent").ok(), Some(None));
    assert!(door::settlement_field(&twice(), "k").is_err());
}

#[test]
fn roster_required_refuses_a_repeated_key() {
    assert_eq!(
        door::roster_required(&once(), "k").ok(),
        Some(Value::from(1))
    );
    assert!(door::roster_required(&once(), "absent").is_err());
    assert!(door::roster_required(&twice(), "k").is_err());
}
