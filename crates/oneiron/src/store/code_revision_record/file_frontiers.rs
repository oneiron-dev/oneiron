//! Pure tested-file frontier map validation and codecs.

use super::CodeRevision;
use crate::error::{ArtifactError, Error, Result};
use crate::store::code_document_values::CodeDocumentFrontier;
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
        "invalid tested file frontier map",
    ))
}

pub(crate) fn validate(revision: &CodeRevision) -> Result<()> {
    let mut paths = BTreeSet::new();
    for (id, frontier) in &revision.file_frontiers {
        if id != &frontier.document_id
            || !paths.insert((&frontier.repo, &frontier.path))
            || frontier.version.is_empty()
            || frontier.version.iter().any(|(_, c)| *c <= 0)
            || frontier.version.windows(2).any(|w| w[0].0 >= w[1].0)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(crate) fn to_value(revision: &CodeRevision) -> Result<Value> {
    revision
        .file_frontiers
        .values()
        .map(|f| {
            Ok(Value::Binary(
                rmp_serde::to_vec_named(f).map_err(|_| invalid())?,
            ))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

pub(crate) fn from_value(value: &Value) -> Result<BTreeMap<[u8; 32], CodeDocumentFrontier>> {
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
