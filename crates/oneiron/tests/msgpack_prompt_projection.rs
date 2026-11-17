//! UC-08 PR 6b (FIX PROMPT-PROJECTION-INVALID-UTF8): hydration's two field
//! projections, the fields of a released CLAIM body and the fields of an
//! entity body, read a MessagePack string that is not UTF-8 as the
//! `{"redacted":"invalid_utf8_string"}` marker that the public JSON API shows
//! (`oneiron::msgpack_value_to_json`). Before, hydration wrote an empty
//! string, which a model reads as a real, empty value.
//!
//! Every other kind of value reads as before: the last test pins hydration's
//! reading of each one (green on main and on the head).
//!
//! The doors are compiled only under the test command's
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::hydration_decode_guard::{decode_entity_fields, released_claim_fields};
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId};
use rmpv::Value;
use serde_json::json;

/// A MessagePack string (a two-byte fixstr) whose bytes are not UTF-8.
fn not_utf8() -> Value {
    let value = rmpv::decode::read_value(&mut &[0xa2, 0xff, 0xfe][..]).expect("a fixstr decodes");
    assert!(
        matches!(&value, Value::String(text) if text.as_str().is_none()),
        "the fixture is a string that is not UTF-8",
    );
    value
}

/// What the public JSON API shows for a string that is not UTF-8.
fn marker() -> serde_json::Value {
    json!({ "redacted": "invalid_utf8_string" })
}

fn encode(value: &Value) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, value).expect("encode fixture");
    body
}

/// The `val` field hydration releases from a CLAIM whose value is `value`.
fn released_val(value: Value) -> serde_json::Value {
    let subject = EntityId::from_bytes([0x3c; 16]).expect("subject id");
    let body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    let raw = encode_claim_body(&body).expect("encode the claim");
    let mut fields = released_claim_fields(&raw).expect("hydration releases the claim's fields");
    fields
        .remove("val")
        .expect("a released claim has a val field")
}

#[test]
fn a_claim_value_not_utf8_reads_as_the_marker() {
    assert_eq!(
        released_val(not_utf8()),
        marker(),
        "a claim value that is not UTF-8",
    );
    assert_eq!(
        released_val(Value::Array(vec![Value::from("kept"), not_utf8()])),
        json!(["kept", marker()]),
        "a string that is not UTF-8 inside an array",
    );
    assert_eq!(
        released_val(Value::Map(vec![(Value::from("note"), not_utf8())])),
        json!({ "note": marker() }),
        "a string that is not UTF-8 under a map key",
    );
}

#[test]
fn an_entity_field_not_utf8_reads_as_the_marker() {
    let body = encode(&Value::Map(vec![
        (Value::from("title"), Value::from("Lunch")),
        (Value::from("note"), not_utf8()),
    ]));
    for write_accepted in [false, true] {
        let fields = decode_entity_fields(&body, write_accepted)
            .expect("a MessagePack map decodes to fields");
        assert_eq!(
            fields.get("title"),
            Some(&json!("Lunch")),
            "write_accepted {write_accepted}: a UTF-8 field reads as its text",
        );
        assert_eq!(
            fields.get("note"),
            Some(&marker()),
            "write_accepted {write_accepted}: a field that is not UTF-8",
        );
    }
}

#[test]
fn every_other_value_reads_as_before() {
    let value = Value::Map(vec![
        (Value::from("nil"), Value::Nil),
        (Value::from("flag"), Value::from(true)),
        (Value::from("big"), Value::from(u64::MAX)),
        (Value::from("low"), Value::from(i64::MIN)),
        (Value::from("half"), Value::F32(0.5)),
        (Value::from("quarter"), Value::F64(0.25)),
        (Value::from("nan"), Value::F64(f64::NAN)),
        (Value::from("inf"), Value::F32(f32::INFINITY)),
        (Value::from("bytes"), Value::Binary(vec![0x61])),
        (Value::from("ext"), Value::Ext(7, vec![0x61])),
        (Value::from("text"), Value::from("plain")),
        (Value::from(7), Value::from("a number key is dropped")),
        (
            not_utf8(),
            Value::from("a key that is not UTF-8 is dropped"),
        ),
        (Value::from("twice"), Value::from(1)),
        (Value::from("twice"), Value::from(2)),
        (
            Value::from("list"),
            Value::Array(vec![Value::Nil, Value::from(-3), Value::Binary(Vec::new())]),
        ),
    ]);
    let expected = json!({
        "nil": null,
        "flag": true,
        "big": u64::MAX,
        "low": i64::MIN,
        "half": 0.5,
        "quarter": 0.25,
        "nan": null,
        "inf": null,
        "bytes": null,
        "ext": null,
        "text": "plain",
        "twice": 2,
        "list": [null, -3, null],
    });
    assert_eq!(released_val(value.clone()), expected, "a claim value");
    let body = encode(&Value::Map(vec![(Value::from("field"), value)]));
    for write_accepted in [false, true] {
        let fields = decode_entity_fields(&body, write_accepted)
            .expect("a MessagePack map decodes to fields");
        assert_eq!(
            fields.get("field"),
            Some(&expected),
            "write_accepted {write_accepted}: an entity field",
        );
    }
}
