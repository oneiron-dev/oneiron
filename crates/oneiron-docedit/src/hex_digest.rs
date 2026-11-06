//! A 32-byte digest or fingerprint field as 64 lowercase hex digits on a
//! human-readable wire (JSON), and as its bytes on a binary one
//! (MessagePack), unchanged there (FIX 9342): a client reads and sends the
//! same text, and a stored row keeps its bytes.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::edit::transaction::Digest;

fn parse<E: serde::de::Error>(text: &str) -> Result<[u8; 32], E> {
    Digest::from_hex(text)
        .map(|digest| digest.0)
        .ok_or_else(|| E::custom("not a lowercase hex digest"))
}

/// Writes `bytes` as hex to a human-readable wire, else as its bytes.
///
/// # Errors
/// The serializer's.
pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&Digest(*bytes).to_hex())
    } else {
        bytes.serialize(serializer)
    }
}

/// Reads hex from a human-readable wire, else the bytes.
///
/// # Errors
/// The deserializer's, or text that is not 64 lowercase hex digits.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
    if deserializer.is_human_readable() {
        parse(&String::deserialize(deserializer)?)
    } else {
        <[u8; 32]>::deserialize(deserializer)
    }
}

/// The same codec for an optional digest: absent or null is `None`.
pub mod option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::edit::transaction::Digest;

    /// Writes `value` as optional hex to a human-readable wire, else as its
    /// optional bytes.
    ///
    /// # Errors
    /// The serializer's.
    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            value
                .map(|bytes| Digest(bytes).to_hex())
                .serialize(serializer)
        } else {
            value.serialize(serializer)
        }
    }

    /// Reads optional hex from a human-readable wire, else optional bytes.
    ///
    /// # Errors
    /// The deserializer's, or text that is not 64 lowercase hex digits.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        if deserializer.is_human_readable() {
            Option::<String>::deserialize(deserializer)?
                .map(|text| super::parse(&text))
                .transpose()
        } else {
            Option::<[u8; 32]>::deserialize(deserializer)
        }
    }
}
