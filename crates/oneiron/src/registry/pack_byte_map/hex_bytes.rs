//! Canonical hex identities, never opaque byte-array credential containers.
use serde::{Deserialize, Deserializer, Serializer, de::Error};
pub(super) fn serialize<S: Serializer, const N: usize>(
    value: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let text: String = value
        .iter()
        .flat_map(|b| {
            [
                char::from(b"0123456789abcdef"[(b >> 4) as usize]),
                char::from(b"0123456789abcdef"[(b & 15) as usize]),
            ]
        })
        .collect();
    serializer.serialize_str(&text)
}
pub(super) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let text = String::deserialize(deserializer)?;
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(D::Error::custom("noncanonical fixed-width hex identity"));
    }
    let mut bytes = [0; N];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot =
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(D::Error::custom)?;
    }
    Ok(bytes)
}
