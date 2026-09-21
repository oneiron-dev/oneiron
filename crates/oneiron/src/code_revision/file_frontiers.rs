//! Canonical tested-file maps and their fold input, verified from persisted operations.

use super::CodeRevision;
use crate::code_document::{CodeDocumentFrontier, verify_frontier_in_txn};
use crate::error::{ArtifactError, Error, Result};
use crate::store::Store;
use heed::RoTxn;
use rmpv::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
        "invalid tested file frontier map",
    ))
}

pub(super) fn validate(revision: &CodeRevision) -> Result<()> {
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

pub(super) fn to_value(revision: &CodeRevision) -> Result<Value> {
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

pub(super) fn from_value(value: &Value) -> Result<BTreeMap<[u8; 32], CodeDocumentFrontier>> {
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

pub(super) fn artifact_hash(
    store: &Store,
    txn: &RoTxn<'_>,
    revision: &CodeRevision,
    body: &[u8],
) -> Result<[u8; 32]> {
    validate(revision)?;
    let body_hash: [u8; 32] = Sha256::digest(body).into();
    if revision.file_frontiers.is_empty() && revision.commit_metadata.is_none() {
        return Ok(body_hash);
    }
    let mut h = Sha256::new();
    h.update(b"oneiron:code-revision-tested-files:v1");
    h.update(body_hash);
    if let Some(metadata) = &revision.commit_metadata {
        super::commit_metadata::validate(revision)?;
        let encoded = super::codec::encode_value(
            &super::commit_metadata::to_value(Some(metadata)),
            "commit metadata encode",
        )?;
        h.update(b"commit-metadata:v1");
        h.update((encoded.len() as u64).to_be_bytes());
        h.update(encoded);
    }

    h.update((revision.file_frontiers.len() as u64).to_be_bytes());
    for frontier in revision.file_frontiers.values() {
        // Never trust a caller's file fold. Decode the immutable snapshot and
        // recompute every operation, actor stamp, version and rendered body.
        verify_frontier_in_txn(store, txn, frontier)?;
        let encoded = rmp_serde::to_vec_named(frontier).map_err(|_| invalid())?;
        h.update((encoded.len() as u64).to_be_bytes());
        h.update(encoded);
    }
    Ok(h.finalize().into())
}
