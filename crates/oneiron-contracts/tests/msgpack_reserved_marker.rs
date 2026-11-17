//! FIX [MSGPACK-RESERVED-MARKER-READS-AS-NIL]: the one untyped reader
//! (`oneiron_contracts::msgpack::decode`) refuses the reserved marker `0xc1` wherever a value
//! starts; rmpv 1.3 alone reads it as nil, the same value as `0xc0`. Red on main: the
//! `*_is_refused` tests. Guards (green on both): `0xc1` as payload or length bytes, every
//! other marker family, the trailer and truncation refusals, and the typed reader.

use oneiron_contracts::msgpack::{MsgpackError, decode, decode_map, decode_row, encode};
use rmpv::Value;

fn refused_at(bytes: &[u8], at: usize) {
    assert_eq!(
        decode(bytes),
        Err(MsgpackError::Malformed(format!(
            "reserved MessagePack marker 0xc1 at byte {at}"
        ))),
        "bytes {bytes:02x?}"
    );
}

fn reads_as(bytes: &[u8], expected: &Value) {
    assert_eq!(decode(bytes).as_ref(), Ok(expected), "bytes {bytes:02x?}");
}

#[test]
fn reserved_marker_alone_is_refused() {
    refused_at(&[0xc1], 0);
}

#[test]
fn reserved_marker_in_an_array_is_refused() {
    // fixarray [nil, 0xc1]
    refused_at(&[0x92, 0xc0, 0xc1], 2);
}

#[test]
fn reserved_marker_as_a_map_value_is_refused() {
    // fixmap {"k": 0xc1}
    let bytes = [0x81, 0xa1, b'k', 0xc1];
    refused_at(&bytes, 3);
    assert!(
        matches!(decode_map(&bytes), Err(MsgpackError::Malformed(_))),
        "decode_map refuses it as decode does"
    );
}

#[test]
fn reserved_marker_as_a_map_key_is_refused() {
    // fixmap {0xc1: 1}
    refused_at(&[0x81, 0xc1, 0x01], 1);
}

#[test]
fn reserved_marker_deep_in_wide_containers_is_refused() {
    // array16 [map16 {"a": array32 [nil]}, map32 {"b": 0xc1}]
    let bytes = [
        0xdc, 0x00, 0x02, // array16, 2 members
        0xde, 0x00, 0x01, // map16, 1 entry
        0xa1, b'a', // "a"
        0xdd, 0x00, 0x00, 0x00, 0x01, // array32, 1 member
        0xc0, // nil
        0xdf, 0x00, 0x00, 0x00, 0x01, // map32, 1 entry
        0xa1, b'b', // "b"
        0xc1, // reserved, byte 21
    ];
    refused_at(&bytes, 21);
}

#[test]
fn reserved_marker_after_a_payload_holding_0xc1_is_refused() {
    // fixarray [bin8 [0xc1], 0xc1]: the payload byte is data, the marker after it is not.
    refused_at(&[0x92, 0xc4, 0x01, 0xc1, 0xc1], 4);
}

#[test]
fn guard_0xc1_inside_string_binary_and_extension_payloads_reads_as_before() {
    let c1 = |n: usize| vec![0xc1u8; n];
    reads_as(&[0xc4, 0x01, 0xc1], &Value::Binary(c1(1)));
    reads_as(&[0xc5, 0x00, 0x02, 0xc1, 0xc1], &Value::Binary(c1(2)));
    reads_as(&[0xc6, 0x00, 0x00, 0x00, 0x01, 0xc1], &Value::Binary(c1(1)));
    // The extension type byte is data too: 0xc1 as i8 is -63.
    reads_as(&[0xd4, 0xc1, 0xc1], &Value::Ext(-63, c1(1)));
    reads_as(&[0xd5, 0x05, 0xc1, 0xc1], &Value::Ext(5, c1(2)));
    reads_as(&[0xd6, 0x05, 0xc1, 0xc1, 0xc1, 0xc1], &Value::Ext(5, c1(4)));
    let mut fixext8 = vec![0xd7, 0x05];
    fixext8.extend(c1(8));
    reads_as(&fixext8, &Value::Ext(5, c1(8)));
    let mut fixext16 = vec![0xd8, 0xc1];
    fixext16.extend(c1(16));
    reads_as(&fixext16, &Value::Ext(-63, c1(16)));
    reads_as(&[0xc7, 0x01, 0xc1, 0xc1], &Value::Ext(-63, c1(1)));
    reads_as(&[0xc8, 0x00, 0x01, 0x05, 0xc1], &Value::Ext(5, c1(1)));
    reads_as(
        &[0xc9, 0x00, 0x00, 0x00, 0x01, 0x05, 0xc1],
        &Value::Ext(5, c1(1)),
    );
    // Strings that are not UTF-8 keep their bytes.
    for bytes in [
        vec![0xa1, 0xc1],
        vec![0xd9, 0x01, 0xc1],
        vec![0xda, 0x00, 0x01, 0xc1],
        vec![0xdb, 0x00, 0x00, 0x00, 0x01, 0xc1],
    ] {
        match decode(&bytes) {
            Ok(Value::String(text)) => assert_eq!(text.as_bytes(), [0xc1], "bytes {bytes:02x?}"),
            other => panic!("bytes {bytes:02x?} read as {other:?}"),
        }
    }
}

#[test]
fn guard_0xc1_in_fixed_width_data_and_length_fields_reads_as_before() {
    reads_as(&[0xcc, 0xc1], &Value::from(0xc1u64));
    reads_as(&[0xd0, 0xc1], &Value::from(-63i64));
    reads_as(&[0xcd, 0xc1, 0xc1], &Value::from(0xc1c1u64));
    reads_as(
        &[0xd2, 0xc1, 0xc1, 0xc1, 0xc1],
        &Value::from(i64::from(i32::from_be_bytes([0xc1; 4]))),
    );
    let mut u64_bytes = vec![0xcf];
    u64_bytes.extend([0xc1; 8]);
    reads_as(&u64_bytes, &Value::from(u64::from_be_bytes([0xc1; 8])));
    reads_as(
        &[0xca, 0xc1, 0xc1, 0xc1, 0xc1],
        &Value::F32(f32::from_be_bytes([0xc1; 4])),
    );
    let mut f64_bytes = vec![0xcb];
    f64_bytes.extend([0xc1; 8]);
    reads_as(&f64_bytes, &Value::F64(f64::from_be_bytes([0xc1; 8])));
    // Counts and lengths of 0xc1 (193): the walk skips them, it does not read them as markers.
    let mut array16 = vec![0xdc, 0x00, 0xc1];
    array16.extend([0xc0; 0xc1]);
    reads_as(&array16, &Value::Array(vec![Value::Nil; 0xc1]));
    let mut map16 = vec![0xde, 0x00, 0xc1];
    let mut entries = Vec::new();
    for key in 0..0xc1u8 {
        let key = key & 0x7f;
        map16.extend([key, 0xc0]);
        entries.push((Value::from(key), Value::Nil));
    }
    reads_as(&map16, &Value::Map(entries));
    let mut bin16 = vec![0xc5, 0x00, 0xc1];
    bin16.extend([0x00; 0xc1]);
    reads_as(&bin16, &Value::Binary(vec![0x00; 0xc1]));
}

#[test]
fn guard_every_other_marker_family_round_trips() {
    let long_text = "x".repeat(40);
    let wide = Value::Array((0..20u64).map(Value::from).collect());
    let value = Value::Map(vec![
        (Value::from("nil"), Value::Nil),
        (
            Value::from("bools"),
            Value::Array(vec![Value::from(true), Value::from(false)]),
        ),
        (
            Value::from("unsigned"),
            Value::Array(
                [0u64, 127, 128, 256, 70_000, u64::MAX]
                    .into_iter()
                    .map(Value::from)
                    .collect(),
            ),
        ),
        (
            Value::from("signed"),
            Value::Array(
                [-1i64, -100, -1_000, -100_000, i64::MIN]
                    .into_iter()
                    .map(Value::from)
                    .collect(),
            ),
        ),
        (
            Value::from("floats"),
            Value::Array(vec![Value::F32(1.5), Value::F64(-2.25)]),
        ),
        (Value::from("text"), Value::from("text")),
        (Value::from("long text"), Value::from(long_text.as_str())),
        (Value::from("binary"), Value::Binary(vec![0xc1; 3])),
        (Value::from("ext"), Value::Ext(7, vec![0xc1])),
        (Value::from("ext8"), Value::Ext(-1, vec![0xc1; 5])),
        (Value::from("wide"), wide),
    ]);
    let bytes = encode(&value);
    assert_eq!(decode(&bytes), Ok(value));
    reads_as(&[0xc0], &Value::Nil);
}

#[test]
fn guard_trailer_and_truncation_refusals_are_unchanged() {
    // The trailer check runs first: 0xc1 then a byte stays a trailer refusal.
    assert_eq!(decode(&[0xc1, 0x00]), Err(MsgpackError::Trailing));
    // A cut-short array stays the decoder's own refusal.
    assert!(
        matches!(decode(&[0x92, 0xc1]), Err(MsgpackError::Malformed(message)) if !message.contains("reserved"))
    );
}

#[test]
fn guard_typed_rows_already_refuse_0xc1() {
    assert!(decode_row::<Option<u8>>(&[0xc1]).is_err());
    assert!(decode_row::<Vec<Option<u8>>>(&[0x91, 0xc1]).is_err());
}
