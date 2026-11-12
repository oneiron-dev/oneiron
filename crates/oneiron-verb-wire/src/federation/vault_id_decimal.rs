//! Moved from `crates/oneiron/src/federation/vault_id_decimal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserializer;
use serde::Serializer;

pub fn serialize<S: Serializer>(id: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(id)
}

/// Only ASCII digits: no sign, no space, no number form.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let text = String::deserialize(deserializer)?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(serde::de::Error::custom(
            "a vault id is a decimal string of ASCII digits",
        ));
    }
    text.parse()
        .map_err(|_| serde::de::Error::custom("a vault id is at most 18446744073709551615"))
}
