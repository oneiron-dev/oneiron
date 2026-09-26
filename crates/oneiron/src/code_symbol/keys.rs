//! Manifest and revision-index key families and the deterministic symbol entity id.

use heed::RwTxn;
use sha2::{Digest, Sha256};

use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::CODE_SYMBOL_ENTITY;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

use super::codec::hash_text_field;
use super::types::{
    CODE_SYMBOL_FINGERPRINT_LEN, CODE_SYMBOL_KIND_MAX_BYTES, CODE_SYMBOL_NAME_MAX_BYTES, CodeChunk,
    CodeSymbolManifest, CodeSymbolRevision,
};
use super::validate::{
    compare_chunks, validate_chunk, validate_manifest_path, validate_symbol_shape, validate_text,
};
use crate::error::CodeError;

/// Per-code-artifact code-symbol manifest row. Key: id16.
pub(super) const MANIFEST: SideTable<EntityId, CodeSymbolManifest, Raw> =
    SideTable::new(&side_table::CODE_SYMBOL_MANIFEST);

/// Index of symbol revisions by repo/path/name/fingerprint, empty marker value. Key (after the
/// table's own prefix): string(repo_ref) "\x00" string(path) "\x00" string(name) "\x00"
/// hash32(fingerprint) "\x00" id16 — spelled by [`code_symbol_revision_index_key`] /
/// [`code_symbol_revision_index_prefix`], not decoded field-by-field (a text field is never split
/// back out of its NUL separator).
pub(super) const REVISION_INDEX: SideTable<Vec<u8>, (), Raw> =
    SideTable::new(&side_table::CODE_SYMBOL_REVISION_INDEX);

pub fn code_symbol_entity_id(repo_ref: &RepoRef, symbol: &CodeSymbolRevision) -> Result<EntityId> {
    validate_symbol_shape(symbol)?;
    EntityId::derive(
        CODE_SYMBOL_ENTITY,
        &[
            repo_identity_key(repo_ref).as_bytes(),
            symbol.path.as_bytes(),
            symbol.name.as_bytes(),
            symbol.kind.as_bytes(),
            &symbol.fingerprint,
        ],
    )
}

pub fn derive_symbol_fingerprint(
    path: &str,
    name: &str,
    kind: &str,
    chunks: &[CodeChunk],
) -> Result<[u8; CODE_SYMBOL_FINGERPRINT_LEN]> {
    validate_manifest_path(path)?;
    validate_text(name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
    validate_text(kind, CODE_SYMBOL_KIND_MAX_BYTES, "symbol kind")?;
    if chunks.is_empty() {
        return Err(Error::Code(CodeError::InvalidCodeSymbolManifestBody(
            "symbol fingerprint requires at least one chunk",
        )));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.code_symbol.fingerprint.v1\0");
    hash_text_field(&mut hasher, path);
    hash_text_field(&mut hasher, name);
    hash_text_field(&mut hasher, kind);
    let mut chunks = chunks.iter().collect::<Vec<_>>();
    chunks.sort_by(|left, right| compare_chunks(left, right));
    for chunk in chunks {
        validate_chunk(chunk)?;
        if chunk.path != path {
            return Err(Error::Code(CodeError::InvalidCodeSymbolManifestBody(
                "symbol revision chunk path must match symbol path",
            )));
        }
        hash_text_field(&mut hasher, &chunk.path);
        hasher.update(chunk.start_line.to_le_bytes());
        hasher.update(chunk.end_line.to_le_bytes());
        hasher.update(chunk.content_hash);
    }
    Ok(hasher.finalize().into())
}

pub(super) fn repo_identity_key(repo_ref: &RepoRef) -> String {
    match repo_ref {
        RepoRef::LocalFolder { path, .. } => format!("local:{path}"),
        RepoRef::GitHubAtCommit { owner, repo, .. } => format!("github:{owner}/{repo}"),
    }
}

/// [`REVISION_INDEX`]'s key for one (repo_ref, path, name, fingerprint) group, without the
/// trailing id: the scan prefix [`lookup_code_symbol_blame`](super::storage) walks.
pub(super) fn code_symbol_revision_index_prefix(
    repo_ref: &RepoRef,
    path: &str,
    name: &str,
    fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
) -> Vec<u8> {
    let repo_ref = repo_ref.canonical();
    let mut key =
        Vec::with_capacity(repo_ref.len() + path.len() + name.len() + fingerprint.len() + 4);
    push_index_text(&mut key, &repo_ref);
    push_index_text(&mut key, path);
    push_index_text(&mut key, name);
    key.extend_from_slice(fingerprint);
    key.push(0);
    key
}

pub(super) fn code_symbol_revision_index_key(
    repo_ref: &RepoRef,
    path: &str,
    name: &str,
    fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
    id: &EntityId,
) -> Vec<u8> {
    let mut key = code_symbol_revision_index_prefix(repo_ref, path, name, fingerprint);
    key.extend_from_slice(id.as_bytes());
    key
}

pub(super) fn push_index_text(key: &mut Vec<u8>, text: &str) {
    key.extend_from_slice(text.as_bytes());
    key.push(0);
}

pub(super) fn id_from_index_key(
    key: &[u8],
    prefix_len: usize,
    context: &'static str,
) -> Result<EntityId> {
    let id_bytes = key
        .get(prefix_len..)
        .ok_or(Error::CorruptedIndex(context))?;
    if id_bytes.len() != 16 {
        return Err(Error::CorruptedIndex(context));
    }
    EntityId::from_bytes(
        id_bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex(context))?,
    )
    .map_err(|_| Error::CorruptedIndex(context))
}

pub(super) fn delete_index_rows_for_id(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let id_bytes = id.as_bytes();
    let keys: Vec<Vec<u8>> = REVISION_INDEX
        .scan(store, wtxn)?
        .into_iter()
        .filter_map(|(key, ())| {
            let well_shaped = key.len() > id_bytes.len()
                && key.ends_with(id_bytes)
                && key[key.len() - id_bytes.len() - 1] == 0;
            well_shaped.then_some(key)
        })
        .collect();
    for key in keys {
        REVISION_INDEX.delete(store, wtxn, &key)?;
    }
    Ok(())
}
