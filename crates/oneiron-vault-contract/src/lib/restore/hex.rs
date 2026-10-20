//! Byte fields on the restore wire, spelled as the rest of the contract
//! spells bytes: lowercase hex strings ([`crate::hex`]). A reader takes
//! lowercase hex only, of the field's exact length; anything else is a
//! refusal, never a guess.

use serde::{Deserialize, Deserializer, Serializer};

/// The bytes `text` spells, when it is lowercase hex.
fn decode(text: &str) -> Option<Vec<u8>> {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        .then(|| crate::from_hex(text))
        .flatten()
}

/// The refusal of a field that is not the bytes it should be.
fn refused<E: serde::de::Error>() -> E {
    E::custom("a byte field is not lowercase hex of its length")
}

/// A fixed-length byte array as hex.
pub(crate) mod array {
    use super::{Deserialize, Deserializer, Serializer, decode, refused};

    pub(crate) fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::hex(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(deserializer)?;
        decode(&text)
            .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
            .ok_or_else(refused)
    }
}

/// An optional fixed-length byte array as hex, or `null`.
pub(crate) mod option_array {
    use super::{Deserialize, Deserializer, Serializer, decode, refused};

    pub(crate) fn serialize<S: Serializer, const N: usize>(
        bytes: &Option<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&crate::hex(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<Option<[u8; N]>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| {
                decode(&text)
                    .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
                    .ok_or_else(refused)
            })
            .transpose()
    }
}

/// Bytes of any length as hex.
pub(crate) mod bytes {
    use super::{Deserialize, Deserializer, Serializer, decode, refused};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::hex(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        decode(&text).ok_or_else(refused)
    }
}
