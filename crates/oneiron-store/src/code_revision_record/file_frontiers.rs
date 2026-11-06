//! Pure tested-file frontier map validation and codecs.

use crate::code_document_values::CodeDocumentFrontier;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

pub fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
        "invalid tested file frontier map",
    ))
}

pub fn from_value(value: &Value) -> Result<BTreeMap<[u8; 32], CodeDocumentFrontier>> {
    let Value::Array(entries) = value else {
        return Err(invalid());
    };
    let mut out = BTreeMap::new();
    for entry in entries {
        let Value::Binary(bytes) = entry else {
            return Err(invalid());
        };
        let mut cursor = std::io::Cursor::new(bytes);
        let frontier: CodeDocumentFrontier =
            serde::Deserialize::deserialize(&mut rmp_serde::Deserializer::new(&mut cursor))
                .map_err(|_| invalid())?;
        if cursor.position() != bytes.len() as u64
            || out.insert(frontier.document_id, frontier).is_some()
        {
            return Err(invalid());
        }
    }
    Ok(out)
}
