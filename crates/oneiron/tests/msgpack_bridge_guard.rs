//! The MessagePack/JSON bridge keeps every value it gave (PLAN-UC-08 PR 6a): the lib's
//! JSON-to-MessagePack copies became one conversion, and the two strict MessagePack-to-JSON
//! converters became one. Each case holds on the base and on the head.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::msgpack_bridge as door;
use oneiron::{Error, msgpack_value_from_json};
use rmpv::Value;
use serde_json::json;

fn bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("a Vec takes every value");
    out
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

/// A one-byte string that is no UTF-8, as a reader decodes it.
fn non_utf8_text() -> Value {
    let value = rmpv::decode::read_value(&mut &[0xa1, 0xff][..]).expect("a one-byte string reads");
    assert!(value.as_str().is_none());
    value
}

/// `0` inside `depth` arrays, as JSON and as MessagePack.
fn nested(depth: usize) -> (serde_json::Value, Value) {
    let (mut json, mut value) = (json!(0), Value::from(0));
    for _ in 0..depth {
        json = serde_json::Value::Array(vec![json]);
        value = Value::Array(vec![value]);
    }
    (json, value)
}

#[test]
fn json_numbers_keep_their_kind_and_objects_their_key_order() {
    let json = json!({
        "unsigned": u64::MAX,
        "signed": i64::MIN,
        "minus_one": -1,
        "float": 1.5,
        "whole_float": 2.0,
        "text": "t",
        "list": [null, true, {"k": "v"}],
    });
    let expected = map(vec![
        ("unsigned", Value::from(u64::MAX)),
        ("signed", Value::from(i64::MIN)),
        ("minus_one", Value::from(-1)),
        ("float", Value::F64(1.5)),
        ("whole_float", Value::F64(2.0)),
        ("text", Value::from("t")),
        (
            "list",
            Value::Array(vec![
                Value::Nil,
                Value::Boolean(true),
                map(vec![("k", Value::from("v"))]),
            ]),
        ),
    ]);
    let value = msgpack_value_from_json(&json).expect("plain JSON converts");
    assert_eq!(value, expected);
    assert_eq!(bytes(&value), bytes(&expected));
}

#[test]
fn json_the_reader_cannot_read_back_is_refused() {
    // Debug frames for 600 nested arrays outgrow a test thread's default stack.
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            let (json, value) = nested(200);
            assert_eq!(
                msgpack_value_from_json(&json).expect("200 arrays read back"),
                value
            );
            let refused = msgpack_value_from_json(&nested(600).0);
            assert!(
                matches!(
                    refused,
                    Err(Error::InvalidClaimBody("value is not valid MessagePack"))
                ),
                "{refused:?}"
            );
        })
        .expect("the test thread starts")
        .join()
        .expect("the test thread ends without a panic");
}

#[test]
fn claim_value_json_holds_what_json_holds_exactly() {
    let value = map(vec![
        ("unsigned", Value::from(u64::MAX)),
        ("signed", Value::from(i64::MIN)),
        ("narrow_float", Value::F32(1.5)),
        ("float", Value::F64(0.25)),
        ("text", Value::from("t")),
        (
            "list",
            Value::Array(vec![Value::Nil, Value::Boolean(false)]),
        ),
    ]);
    assert_eq!(
        door::claim_value_json(&value),
        Some(json!({
            "unsigned": u64::MAX,
            "signed": i64::MIN,
            "narrow_float": 1.5,
            "float": 0.25,
            "text": "t",
            "list": [null, false],
        }))
    );
    for (case, value) in [
        ("binary", Value::Binary(vec![1])),
        ("extension", Value::Ext(1, vec![1])),
        ("nan", Value::F64(f64::NAN)),
        ("infinite narrow float", Value::F32(f32::INFINITY)),
        ("non-UTF-8 text", non_utf8_text()),
        (
            "repeated key",
            map(vec![("k", Value::from(1)), ("k", Value::from(2))]),
        ),
        (
            "non-text key",
            Value::Map(vec![(Value::from(1), Value::from(1))]),
        ),
        ("nested binary", Value::Array(vec![Value::Binary(vec![])])),
    ] {
        assert_eq!(door::claim_value_json(&value), None, "{case}");
    }
}

#[test]
fn manifest_json_is_offered_only_where_it_writes_back_the_body() {
    let body = bytes(&map(vec![
        ("float", Value::F64(1.5)),
        ("count", Value::from(7)),
        ("offset", Value::from(-3)),
        (
            "flags",
            Value::Array(vec![Value::Boolean(true), Value::Nil]),
        ),
        ("name", Value::from("seed")),
    ]));
    assert_eq!(
        door::manifest_json(&body),
        Some(json!({
            "float": 1.5,
            "count": 7,
            "offset": -3,
            "flags": [true, null],
            "name": "seed",
        }))
    );
    // 7 written as a uint64: its JSON form writes it back in one byte.
    let wide = [0x81, 0xa1, b'n', 0xcf, 0, 0, 0, 0, 0, 0, 0, 7];
    let mut trailing = body.clone();
    trailing.push(0xc0);
    for (case, body) in [
        ("32-bit float", bytes(&map(vec![("f", Value::F32(1.5))]))),
        ("wide integer", wide.to_vec()),
        ("trailing byte", trailing),
        ("binary", bytes(&map(vec![("b", Value::Binary(vec![1]))]))),
        (
            "repeated key",
            bytes(&map(vec![("k", Value::from(1)), ("k", Value::from(2))])),
        ),
        (
            "non-text key",
            bytes(&Value::Map(vec![(Value::from(1), Value::from(1))])),
        ),
    ] {
        assert_eq!(door::manifest_json(&body), None, "{case}");
    }
}
