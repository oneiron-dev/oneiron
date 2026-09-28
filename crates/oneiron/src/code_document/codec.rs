//! Strict durable document rows and canonical operation folds.

use loro::{IdSpan, LoroDoc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{ArtifactError, Error, Result};

use super::types::CodeDocumentFrontier;

pub(super) fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
        "invalid code document state",
    ))
}

pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid())
}

pub(super) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The `CODE_DOCUMENT_PATH` row's key: a sha256 of the length-prefixed repo
/// and path, with no separate table prefix (the typed table supplies that).
pub(super) fn path_hash(repo: &str, path: &str) -> [u8; 32] {
    let mut bytes = (repo.len() as u64).to_be_bytes().to_vec();
    bytes.extend_from_slice(repo.as_bytes());
    bytes.extend_from_slice(path.as_bytes());
    hash(&bytes)
}

pub(super) fn key(prefix: &[u8], id: &[u8; 32]) -> Vec<u8> {
    [prefix, id.as_slice()].concat()
}

/// The full `CODE_DOCUMENT_PATH` row key, prefix included: also folded into
/// the genesis document-id hash and the rename-generation counter's key, so
/// those two derivations keep calling this rather than the typed table.
pub(super) fn path_key(repo: &str, path: &str) -> Vec<u8> {
    key(b"code_document:path:v1:", &path_hash(repo, path))
}

pub(super) fn validate_path(repo: &str, path: &str) -> Result<()> {
    if repo.trim().is_empty()
        || repo.len() > 4096
        || repo.contains('\0')
        || path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.contains(['\\', '\0'])
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn doc_from_snapshot(bytes: &[u8]) -> Result<LoroDoc> {
    LoroDoc::from_snapshot(bytes).map_err(|_| invalid())
}

/// Hash every operation in peer/counter order. JSON export for an ID span is
/// deterministic in Loro. Sorting dependency IDs also removes arrival order.
/// Ref identities, file content and actor/session messages are all covered.
pub(super) fn frontier(doc: &LoroDoc, repo: &str, id: [u8; 32]) -> Result<CodeDocumentFrontier> {
    let meta = doc.get_map("meta");
    let path = meta
        .get("path")
        .and_then(|v| match v {
            loro::ValueOrContainer::Value(loro::LoroValue::String(s)) => Some(s.to_string()),
            _ => None,
        })
        .ok_or_else(invalid)?;
    validate_path(repo, &path)?;
    let mut version: Vec<_> = doc.oplog_vv().iter().map(|(p, c)| (*p, *c)).collect();
    version.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron:code-document-ops:v1");
    hasher.update(id);
    hasher.update((repo.len() as u64).to_be_bytes());
    hasher.update(repo.as_bytes());
    for (peer, counter) in &version {
        let mut changes = doc.export_json_in_id_span(IdSpan::new(*peer, 0, *counter));
        for change in &mut changes {
            change.deps.sort_by_key(|id| (id.peer, id.counter));
        }
        let raw = serde_json::to_vec(&changes).map_err(|_| invalid())?;
        hasher.update((raw.len() as u64).to_be_bytes());
        hasher.update(raw);
    }
    Ok(CodeDocumentFrontier {
        document_id: id,
        repo: repo.to_owned(),
        path,
        version,
        op_fold: hasher.finalize().into(),
        text_hash: hash(doc.get_text("body").to_string().as_bytes()),
    })
}
