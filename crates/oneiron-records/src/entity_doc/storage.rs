//! Moved from `crates/oneiron/src/entity_doc/storage.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Location of the body text. Editable metadata shares its owning document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextField {
    /// A body containing only UTF-8 text.
    Utf8Body,
    /// A named UTF-8 string in a MessagePack map.
    MapField(String),
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut reader = std::io::Cursor::new(bytes);
    let value = T::deserialize(&mut rmp_serde::Deserializer::new(&mut reader))
        .map_err(|_| Error::CorruptedIndex("entity document row"))?;
    if usize::try_from(reader.position()).ok() != Some(bytes.len()) {
        return Err(Error::CorruptedIndex("trailing entity document row bytes"));
    }
    Ok(value)
}
