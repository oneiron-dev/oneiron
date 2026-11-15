//! The one canonical byte form of a structured value (DESIGN section 1.5).
//!
//! The canonical bytes of a record are its named MessagePack encoding, written one way:
//! 1. encode with `rmp_serde::to_vec_named` (a struct is a map keyed by field name, a
//!    unit variant is its name, any other variant is a one-entry map);
//! 2. in every map, sort the entries by the bytes of the encoded key, ascending, byte by
//!    byte, and refuse two equal keys (the map rule of deterministic CBOR, RFC 8949
//!    section 4.2.1, applied to MessagePack);
//! 3. write every integer in its shortest form, and a non-negative integer as unsigned;
//! 4. write every float as 64 bits, every NaN as the one bit pattern
//!    `0x7ff8000000000000`; `-0.0` stays `-0.0`, and each infinity has one spelling;
//! 5. strings, binaries, arrays, maps and extensions take the shortest length header.
//!
//! MessagePack and not JSON: the form writes NaN, every `u64` and `i64`, and raw bytes,
//! so it has nothing to refuse or alias. What it cannot see is a set serialized in an
//! arbitrary order (a `HashSet`, or a `Vec` built from a `HashMap`): a hashed type uses
//! `BTreeSet` or sorts first, as with every serde format.

use rmpv::Value;
use std::fmt;

/// The bits every NaN is written with.
const CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
/// The MessagePack marker of a 64-bit float.
const FLOAT64_MARKER: u8 = 0xcb;

/// Why a value has no canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalBytesError {
    /// The value's `Serialize` failed, it nests deeper than the encoder's limit
    /// (1,024 levels), or a length does not fit a MessagePack header.
    Encode(String),
    /// A map holds two entries whose keys have equal canonical bytes.
    DuplicateKey,
}

impl fmt::Display for CanonicalBytesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(reason) => write!(formatter, "canonical bytes: encode failed: {reason}"),
            Self::DuplicateKey => {
                formatter.write_str("canonical bytes: a map holds two equal keys")
            }
        }
    }
}

impl std::error::Error for CanonicalBytesError {}

/// The canonical bytes of a value. Public for the few sites that store or compare the
/// bytes; a digest of a value is [`crate::Fingerprint::of_record`].
///
/// The bytes are those of the value's serde form. A MessagePack value already held as
/// an [`rmpv::Value`] goes through [`canonical_value_bytes`] instead: `rmpv`'s
/// `Serialize` writes a string that is not valid UTF-8 as a binary, so here the two
/// would give one byte string.
///
/// # Errors
/// [`CanonicalBytesError::Encode`] when the value's `Serialize` fails or nests too deep;
/// [`CanonicalBytesError::DuplicateKey`] when a map holds two equal keys.
pub fn canonical_bytes<T: serde::Serialize + ?Sized>(
    record: &T,
) -> Result<Vec<u8>, CanonicalBytesError> {
    let named = rmp_serde::to_vec_named(record)
        .map_err(|error| CanonicalBytesError::Encode(error.to_string()))?;
    let mut reader = named.as_slice();
    let value = rmpv::decode::read_value(&mut reader)
        .map_err(|error| CanonicalBytesError::Encode(error.to_string()))?;
    let mut canonical = Vec::with_capacity(named.len());
    write_canonical(&value, &mut canonical)?;
    Ok(canonical)
}

/// The canonical bytes of a MessagePack value, written from the value itself with no
/// serde step, so a string that is not valid UTF-8 keeps the string marker and never
/// equals a binary. Equals [`canonical_bytes`] for every value without such a string.
///
/// # Errors
/// [`CanonicalBytesError::Encode`] when a length does not fit a MessagePack header;
/// [`CanonicalBytesError::DuplicateKey`] when a map holds two equal keys.
pub fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>, CanonicalBytesError> {
    let mut canonical = Vec::new();
    write_canonical(value, &mut canonical)?;
    Ok(canonical)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalBytesError> {
    match value {
        Value::Nil => rmp::encode::write_nil(out).map_err(write_failed)?,
        Value::Boolean(flag) => rmp::encode::write_bool(out, *flag).map_err(write_failed)?,
        Value::Integer(integer) => match integer.as_u64() {
            Some(unsigned) => {
                rmp::encode::write_uint(out, unsigned).map_err(write_failed)?;
            }
            None => {
                let signed = integer.as_i64().ok_or_else(|| {
                    CanonicalBytesError::Encode("an integer outside u64 and i64".to_owned())
                })?;
                rmp::encode::write_sint(out, signed).map_err(write_failed)?;
            }
        },
        Value::F32(float) => write_float(f64::from(*float), out),
        Value::F64(float) => write_float(*float, out),
        Value::String(text) => {
            // The raw bytes under the string marker, valid UTF-8 or not: a string
            // never becomes a binary, as `rmpv::encode::write_value` would make it.
            let bytes = text.as_bytes();
            rmp::encode::write_str_len(out, header_len(bytes.len())?).map_err(write_failed)?;
            out.extend_from_slice(bytes);
        }
        Value::Binary(bytes) => {
            rmp::encode::write_bin_len(out, header_len(bytes.len())?).map_err(write_failed)?;
            out.extend_from_slice(bytes);
        }
        Value::Array(items) => {
            rmp::encode::write_array_len(out, header_len(items.len())?).map_err(write_failed)?;
            for item in items {
                write_canonical(item, out)?;
            }
        }
        Value::Map(entries) => write_map(entries, out)?,
        Value::Ext(kind, data) => {
            rmp::encode::write_ext_meta(out, header_len(data.len())?, *kind)
                .map_err(write_failed)?;
            out.extend_from_slice(data);
        }
    }
    Ok(())
}

/// The entries sorted by their keys' canonical bytes, each key's bytes then its value.
///
/// Only the keys are encoded apart; each value is written straight into `out`, so a
/// value nested in many maps is written once, not copied at every level.
fn write_map(entries: &[(Value, Value)], out: &mut Vec<u8>) -> Result<(), CanonicalBytesError> {
    let mut keyed = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let mut key_bytes = Vec::new();
        write_canonical(key, &mut key_bytes)?;
        keyed.push((key_bytes, value));
    }
    keyed.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(CanonicalBytesError::DuplicateKey);
    }
    rmp::encode::write_map_len(out, header_len(keyed.len())?).map_err(write_failed)?;
    for (key_bytes, value) in keyed {
        out.extend_from_slice(&key_bytes);
        write_canonical(value, out)?;
    }
    Ok(())
}

fn write_float(value: f64, out: &mut Vec<u8>) {
    let bits = if value.is_nan() {
        CANONICAL_NAN_BITS
    } else {
        value.to_bits()
    };
    out.push(FLOAT64_MARKER);
    out.extend_from_slice(&bits.to_be_bytes());
}

fn header_len(len: usize) -> Result<u32, CanonicalBytesError> {
    u32::try_from(len).map_err(|_| {
        CanonicalBytesError::Encode("a length above the MessagePack header limit".to_owned())
    })
}

/// A write into a `Vec` cannot fail; this maps the writer's error type anyway.
fn write_failed<E: fmt::Debug>(error: E) -> CanonicalBytesError {
    CanonicalBytesError::Encode(format!("{error:?}"))
}
