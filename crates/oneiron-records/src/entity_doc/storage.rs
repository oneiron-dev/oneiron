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

/// The kind of owner a document head belongs to (FIX 11535). The head is
/// keyed by its owner's id either way; only a stored entity has a ledger row.
/// An entity's head names no kind: only an artifact's head writes one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentOwnerKind {
    /// A stored entity: a record whose text lives on this plane.
    #[default]
    Entity,
    /// A finalized proposal-text artifact (ED-00), which has no ledger row:
    /// its artifact record names this head.
    ProposalArtifact,
}

impl DocumentOwnerKind {
    fn is_entity(&self) -> bool {
        *self == Self::Entity
    }
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
