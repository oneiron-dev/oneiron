//! The one reader for untyped MessagePack rows (`oneiron_contracts::msgpack`, PLAN-UC-08
//! PR 0): one value and no trailer, a duplicate key refused by every keyed read, and a
//! strict key-set check. Each refusal names its variant (and its key).

use oneiron_contracts::msgpack::{
    Entries, MsgpackError, decode, decode_map, decode_row, encode, encode_row,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

fn text(key: &str, value: impl Into<Value>) -> (Value, Value) {
    (Value::from(key), value.into())
}

fn bytes_of(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("a Vec takes the value");
    bytes
}

fn sample() -> Value {
    map(vec![
        text("kind", "note"),
        text("count", 7u64),
        text("delta", -3i64),
        text("open", true),
        text("blob", Value::Binary(vec![0, 1, 2])),
        text("parts", Value::Array(vec![Value::from(1u64), Value::Nil])),
        text("inner", map(vec![text("depth", 2u64)])),
        text("ratio", Value::F64(0.5)),
        text("ext", Value::Ext(4, vec![9])),
    ])
}

#[test]
fn encode_writes_the_bytes_rmpv_writes() {
    let value = sample();
    assert_eq!(encode(&value), bytes_of(&value));
    assert_eq!(decode(&encode(&value)), Ok(value));
}

#[test]
fn decode_refuses_a_trailing_byte() {
    let mut bytes = bytes_of(&sample());
    bytes.push(0xc0);
    assert_eq!(decode(&bytes), Err(MsgpackError::Trailing));
    assert_eq!(decode_map(&bytes), Err(MsgpackError::Trailing));
}

#[test]
fn decode_refuses_a_second_whole_value() {
    let mut bytes = bytes_of(&Value::from(1u64));
    bytes.extend(bytes_of(&Value::from(2u64)));
    assert_eq!(decode(&bytes), Err(MsgpackError::Trailing));
}

#[test]
fn decode_refuses_empty_and_truncated_bytes_as_malformed() {
    assert!(matches!(decode(&[]), Err(MsgpackError::Malformed(_))));
    let bytes = bytes_of(&sample());
    let truncated = &bytes[..bytes.len() - 1];
    assert!(matches!(decode(truncated), Err(MsgpackError::Malformed(_))));
}

#[test]
fn decode_map_refuses_a_value_that_is_not_a_map() {
    let bytes = bytes_of(&Value::Array(vec![
        Value::from("kind"),
        Value::from("note"),
    ]));
    assert_eq!(decode_map(&bytes), Err(MsgpackError::NotMap));
    let entries = decode_map(&bytes_of(&sample())).expect("a map decodes");
    assert_eq!(Value::Map(entries), sample());
}

#[test]
fn entries_of_refuses_a_value_that_is_not_a_map() {
    assert!(matches!(
        Entries::of(&Value::from("kind")),
        Err(MsgpackError::NotMap)
    ));
    assert!(matches!(
        Entries::of(&Value::Nil),
        Err(MsgpackError::NotMap)
    ));
}

#[test]
fn get_refuses_a_duplicate_key() {
    let value = map(vec![
        text("kind", "note"),
        text("other", 1u64),
        text("kind", "task"),
    ]);
    let entries = Entries::of(&value).expect("a map");
    assert_eq!(
        entries.get("kind"),
        Err(MsgpackError::DuplicateKey("kind".to_owned()))
    );
    assert_eq!(
        entries.require("kind"),
        Err(MsgpackError::DuplicateKey("kind".to_owned()))
    );
    assert_eq!(
        entries.str("kind"),
        Err(MsgpackError::DuplicateKey("kind".to_owned()))
    );
    assert_eq!(entries.get("other"), Ok(Some(&Value::from(1u64))));
}

#[test]
fn get_reads_absent_as_none_and_skips_keys_that_are_not_text() {
    let value = map(vec![
        (Value::from(1u64), Value::from("one")),
        text("kind", "note"),
    ]);
    let entries = Entries::of(&value).expect("a map");
    assert_eq!(entries.get("absent"), Ok(None));
    assert_eq!(entries.get("1"), Ok(None));
    assert_eq!(entries.str("kind"), Ok("note"));
    assert_eq!(
        entries.require("absent"),
        Err(MsgpackError::MissingKey("absent".to_owned()))
    );
}

#[test]
fn typed_getters_read_their_type_and_refuse_another() {
    let value = sample();
    let entries = Entries::of(&value).expect("a map");
    assert_eq!(entries.str("kind"), Ok("note"));
    assert_eq!(entries.u64("count"), Ok(7));
    assert_eq!(entries.i64("delta"), Ok(-3));
    assert_eq!(entries.i64("count"), Ok(7));
    assert_eq!(entries.bool("open"), Ok(true));
    assert_eq!(entries.bytes("blob"), Ok(&[0u8, 1, 2][..]));
    assert_eq!(
        entries.array("parts"),
        Ok(&[Value::from(1u64), Value::Nil][..])
    );
    assert_eq!(
        entries.map("inner").and_then(|inner| inner.u64("depth")),
        Ok(2)
    );
    for (key, read) in [
        ("kind", entries.u64("kind").err()),
        ("delta", entries.u64("delta").err()),
        ("count", entries.str("count").err()),
        ("kind", entries.bytes("kind").err()),
        ("blob", entries.str("blob").err()),
        ("open", entries.array("open").err()),
        ("parts", entries.map("parts").err()),
        ("ratio", entries.i64("ratio").err()),
        ("ext", entries.bool("ext").err()),
    ] {
        assert_eq!(read, Some(MsgpackError::WrongType(key.to_owned())), "{key}");
    }
    assert_eq!(
        entries.str("absent"),
        Err(MsgpackError::MissingKey("absent".to_owned()))
    );
}

#[test]
fn str_refuses_a_string_that_is_not_utf8() {
    // fixstr of length 2 holding bytes that are not UTF-8.
    let bytes = [0x81, 0xa4, b'k', b'i', b'n', b'd', 0xa2, 0xff, 0xfe];
    let value = decode(&bytes).expect("rmpv keeps a non-UTF-8 string");
    let entries = Entries::of(&value).expect("a map");
    assert_eq!(
        entries.str("kind"),
        Err(MsgpackError::WrongType("kind".to_owned()))
    );
}

#[test]
fn exact_keys_accepts_the_declared_set() {
    let value = map(vec![text("b", 2u64), text("a", 1u64), text("note", "x")]);
    let entries = Entries::of(&value).expect("a map");
    let checked = entries
        .exact_keys(&["a", "b"], &["note", "absent_optional"])
        .expect("the declared set");
    assert_eq!(checked.u64("a"), Ok(1));
    assert!(entries.exact_keys(&["a", "b", "note"], &[]).is_ok());
    let empty = map(vec![]);
    assert!(
        Entries::of(&empty)
            .expect("a map")
            .exact_keys(&[], &["a"])
            .is_ok()
    );
}

#[test]
fn exact_keys_refuses_an_unknown_key() {
    let value = map(vec![text("a", 1u64), text("stray", 2u64)]);
    let entries = Entries::of(&value).expect("a map");
    assert!(matches!(
        entries.exact_keys(&["a"], &["b"]),
        Err(MsgpackError::UnknownKey(key)) if key == "stray"
    ));
}

#[test]
fn exact_keys_refuses_a_missing_required_key() {
    let value = map(vec![text("a", 1u64), text("note", "x")]);
    let entries = Entries::of(&value).expect("a map");
    assert!(matches!(
        entries.exact_keys(&["a", "b"], &["note"]),
        Err(MsgpackError::MissingKey(key)) if key == "b"
    ));
}

#[test]
fn exact_keys_refuses_a_duplicate_key() {
    for value in [
        map(vec![text("a", 1u64), text("b", 2u64), text("a", 3u64)]),
        map(vec![text("a", 1u64), text("note", "x"), text("note", "y")]),
    ] {
        let entries = Entries::of(&value).expect("a map");
        let refused = entries.exact_keys(&["a", "b"], &["note"]);
        assert!(
            matches!(&refused, Err(MsgpackError::DuplicateKey(key)) if key == "a" || key == "note"),
            "{refused:?}"
        );
    }
}

#[test]
fn exact_keys_refuses_a_key_that_is_not_text() {
    let value = map(vec![text("a", 1u64), (Value::from(7u64), Value::Nil)]);
    let entries = Entries::of(&value).expect("a map");
    assert!(matches!(
        entries.exact_keys(&["a"], &[]),
        Err(MsgpackError::NonTextKey)
    ));
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct MinerRow {
    v: u8,
    pattern: String,
    hits: u64,
    tags: Vec<String>,
    last: Option<i64>,
}

fn miner_row() -> MinerRow {
    MinerRow {
        v: 1,
        pattern: "teh -> the".to_owned(),
        hits: 12,
        tags: vec!["typo".to_owned()],
        last: Some(-4),
    }
}

#[test]
fn encode_row_writes_the_bytes_to_vec_named_writes() {
    let row = miner_row();
    let bytes = encode_row(&row).expect("the row encodes");
    assert_eq!(
        bytes,
        rmp_serde::to_vec_named(&row).expect("rmp_serde encodes")
    );
    assert_eq!(decode_row::<MinerRow>(&bytes), Ok(row));
}

#[test]
fn decode_row_refuses_a_typed_row_with_one_trailing_byte() {
    let mut bytes = encode_row(&miner_row()).expect("the row encodes");
    // rmp_serde alone reads the row and leaves the byte: the gap this reader closes.
    assert!(rmp_serde::from_slice::<MinerRow>(&[bytes.as_slice(), &[0xc0]].concat()).is_ok());
    bytes.push(0xc0);
    assert_eq!(decode_row::<MinerRow>(&bytes), Err(MsgpackError::Trailing));
}

#[test]
fn decode_row_keeps_the_rmp_serde_message_for_a_malformed_row() {
    let bytes = bytes_of(&map(vec![text("v", "not a number")]));
    let expected = rmp_serde::from_slice::<MinerRow>(&bytes)
        .expect_err("rmp_serde refuses the row")
        .to_string();
    assert_eq!(
        decode_row::<MinerRow>(&bytes),
        Err(MsgpackError::Malformed(expected.clone()))
    );
    assert_eq!(
        decode_row::<MinerRow>(&bytes)
            .expect_err("refused")
            .to_string(),
        expected
    );
    let truncated = encode_row(&miner_row()).expect("the row encodes");
    let truncated = &truncated[..truncated.len() - 2];
    assert!(matches!(
        decode_row::<MinerRow>(truncated),
        Err(MsgpackError::Malformed(_))
    ));
}

#[test]
fn decode_keeps_the_rmpv_message_for_malformed_bytes() {
    // A fixstr of length 5 that holds one byte.
    let bytes = [0xa5, b'a'];
    let mut rest = &bytes[..];
    let expected = rmpv::decode::read_value(&mut rest)
        .expect_err("the string is cut short")
        .to_string();
    assert_eq!(decode(&bytes), Err(MsgpackError::Malformed(expected)));
}
