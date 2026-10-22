//! A lossless identity for an accepted MessagePack claim value (FIX 10090).
//!
//! The JSON projection a saved query matches on and shows its judge
//! collapses distinctions a value can carry: a non-finite float reads as
//! null, and a map keeps one entry per repeated string key. Two different
//! accepted values could then hash alike and reuse a memo. So the evidence
//! hash also covers these bytes, taken from the ORIGINAL value: each node
//! type-tagged and length-framed, a float at its own width and exact bits
//! (infinities, every NaN payload, signed zero), strings, binaries and
//! extensions kept apart, and a map's every entry, duplicates included, in a
//! canonical order. Matching and the judge still read the projection,
//! byte-for-byte as before.

/// One relevant claim's predicate beside its value's canonical bytes.
pub(super) type ClaimValueFingerprint = (String, Vec<u8>);

const NIL: u8 = 0;
const BOOLEAN: u8 = 1;
const UNSIGNED: u8 = 2;
const SIGNED: u8 = 3;
const F32: u8 = 4;
const F64: u8 = 5;
const STRING: u8 = 6;
const BINARY: u8 = 7;
const ARRAY: u8 = 8;
const MAP: u8 = 9;
const EXT: u8 = 10;

/// `value` as canonical bytes: injective over MessagePack values, so two
/// values that differ in any way the format can tell apart never share them.
pub(super) fn canonical_msgpack_value_bytes(value: &rmpv::Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, value);
    out
}

fn write_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u64).to_be_bytes());
}

fn write_framed(out: &mut Vec<u8>, bytes: &[u8]) {
    write_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn write_value(out: &mut Vec<u8>, value: &rmpv::Value) {
    match value {
        rmpv::Value::Nil => out.push(NIL),
        rmpv::Value::Boolean(flag) => {
            out.push(BOOLEAN);
            out.push(u8::from(*flag));
        }
        // A MessagePack integer is unsigned, or a negative signed one.
        rmpv::Value::Integer(number) => match number.as_u64() {
            Some(unsigned) => {
                out.push(UNSIGNED);
                out.extend_from_slice(&unsigned.to_be_bytes());
            }
            None => {
                out.push(SIGNED);
                out.extend_from_slice(&number.as_i64().unwrap_or(i64::MIN).to_be_bytes());
            }
        },
        rmpv::Value::F32(number) => {
            out.push(F32);
            out.extend_from_slice(&number.to_bits().to_be_bytes());
        }
        rmpv::Value::F64(number) => {
            out.push(F64);
            out.extend_from_slice(&number.to_bits().to_be_bytes());
        }
        // The raw bytes, valid UTF-8 or not: the tag keeps it a string.
        rmpv::Value::String(text) => {
            out.push(STRING);
            write_framed(out, text.as_bytes());
        }
        rmpv::Value::Binary(bytes) => {
            out.push(BINARY);
            write_framed(out, bytes);
        }
        rmpv::Value::Array(values) => {
            out.push(ARRAY);
            write_len(out, values.len());
            for value in values {
                write_value(out, value);
            }
        }
        // Every entry, each self-delimiting, sorted by its own bytes: the
        // order an encoder wrote them in moves nothing, a repeated key is
        // kept, and the count is framed.
        rmpv::Value::Map(entries) => {
            out.push(MAP);
            write_len(out, entries.len());
            let mut encoded: Vec<Vec<u8>> = entries
                .iter()
                .map(|(key, value)| {
                    let mut entry = Vec::new();
                    write_value(&mut entry, key);
                    write_value(&mut entry, value);
                    entry
                })
                .collect();
            encoded.sort_unstable();
            for entry in encoded {
                out.extend_from_slice(&entry);
            }
        }
        rmpv::Value::Ext(tag, bytes) => {
            out.push(EXT);
            out.extend_from_slice(&tag.to_be_bytes());
            write_framed(out, bytes);
        }
    }
}
