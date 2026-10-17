//! A shared vault's id on the wire (OF-158): a decimal string, since a `u64`
//! past 2^53 does not survive a JavaScript number. Rust keeps the `u64`.
//!
//! `#[serde(with = "crate::federation::vault_id_decimal")]` on every field
//! that carries the id, beside `#[schemars(with = "String")]` where the type
//! derives a schema; `scripts/sdk/facade_types.py` reads a `decimal` codec as
//! a string, so the generated TypeScript, Python and UniFFI types say so too.
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn serialize<S: Serializer>(id: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(id)
}

/// Only ASCII digits: no sign, no space, no number form.
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let text = String::deserialize(deserializer)?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(serde::de::Error::custom(
            "a vault id is a decimal string of ASCII digits",
        ));
    }
    text.parse()
        .map_err(|_| serde::de::Error::custom("a vault id is at most 18446744073709551615"))
}
