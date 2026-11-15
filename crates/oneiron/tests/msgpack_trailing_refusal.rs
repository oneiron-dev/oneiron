//! Each decoder below reads exactly one MessagePack value: a row with one byte after it, which no
//! writer ever wrote (K-proof
//! /Users/olety/Desktop/temp/vibe-build-20261017/lanes/kimi/OPUS-UC08-MSGPACK/legs/kproof-pr1/KPROOF.md),
//! is refused. Red on the base, where each decoder read the value and ignored the rest.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::msgpack_trailing as door;

/// One `{"k": 1}` map row, as a writer writes it.
fn sample_map() -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(
        &mut bytes,
        &rmpv::Value::Map(vec![(rmpv::Value::from("k"), rmpv::Value::from(1))]),
    )
    .expect("a one-entry map serializes");
    bytes
}

/// `bytes` with one nil byte after the value: a row no writer ever wrote.
fn with_trailer(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.push(0xc0);
    bytes
}

#[test]
fn human_task_storage_refuses_a_trailing_byte() {
    let raw = sample_map();
    assert!(
        oneiron_store::human_task::storage::decode_map(&raw, "test row").is_ok(),
        "the plain row decodes"
    );
    assert!(
        oneiron_store::human_task::storage::decode_map(&with_trailer(raw), "test row").is_err(),
        "the row plus one trailer byte is refused"
    );
}

#[test]
fn skill_attribution_codec_refuses_a_trailing_byte() {
    let raw = sample_map();
    assert!(
        oneiron_store::skill_attribution::codec::decode_value(&raw).is_ok(),
        "the plain row decodes"
    );
    assert!(
        oneiron_store::skill_attribution::codec::decode_value(&with_trailer(raw)).is_err(),
        "the row plus one trailer byte is refused"
    );
}

#[test]
fn consolidation_value_refuses_a_trailing_byte() {
    let raw = sample_map();
    assert!(
        door::consolidation_value_decode(&raw).is_ok(),
        "the plain row decodes"
    );
    assert!(
        door::consolidation_value_decode(&with_trailer(raw)).is_err(),
        "the row plus one trailer byte is refused"
    );
}

#[test]
fn outcome_value_refuses_a_trailing_byte() {
    let raw = sample_map();
    assert!(
        door::outcome_value_decode(&raw).is_ok(),
        "the plain row decodes"
    );
    assert!(
        door::outcome_value_decode(&with_trailer(raw)).is_err(),
        "the row plus one trailer byte is refused"
    );
}

#[test]
fn receipt_row_refuses_a_trailing_byte() {
    let raw = sample_map();
    assert!(
        door::receipt_row_decode(&raw).is_ok(),
        "the plain row decodes"
    );
    assert!(
        door::receipt_row_decode(&with_trailer(raw)).is_err(),
        "the row plus one trailer byte is refused"
    );
}

#[test]
fn miner_row_refuses_a_trailing_byte() {
    let raw = door::miner_row_sample();
    assert!(door::miner_row_decode(&raw), "the plain row decodes");
    assert!(
        !door::miner_row_decode(&with_trailer(raw)),
        "the row plus one trailer byte is refused"
    );
}
