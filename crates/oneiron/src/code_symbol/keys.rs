//! Manifest and revision-index key families and the deterministic symbol entity id.

use heed::RwTxn;
use sha2::{Digest, Sha256};

use crate::codebase::RepoRef;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::store::Store;

use super::codec::{hash_len, hash_text_field};
use super::types::{
    CODE_SYMBOL_FINGERPRINT_LEN, CODE_SYMBOL_KIND_MAX_BYTES, CODE_SYMBOL_NAME_MAX_BYTES, CodeChunk,
    CodeSymbolRevision,
};
use super::validate::{
    compare_chunks, validate_chunk, validate_manifest_path, validate_symbol_shape, validate_text,
};
use crate::error::CodeError;

pub(super) const CODE_SYMBOL_MANIFEST_KEY_PREFIX: &[u8] = b"code_symbol:manifest:v1:";

pub(super) const CODE_SYMBOL_REVISION_INDEX_KEY_PREFIX: &[u8] = b"code_symbol:revision:v1:";

pub(super) const CODE_SYMBOL_ENTITY_ID_DOMAIN: &[u8] = b"oneiron:code-symbol-entity:v1";

pub fn code_symbol_entity_id(repo_ref: &RepoRef, symbol: &CodeSymbolRevision) -> Result<EntityId> {
    validate_symbol_shape(symbol)?;
    deterministic_entity_id(
        CODE_SYMBOL_ENTITY_ID_DOMAIN,
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

pub(super) fn deterministic_entity_id(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
    for salt in 0_u64..=u64::MAX {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(salt.to_le_bytes());
        for part in parts {
            hash_len(&mut hasher, part.len())?;
            hasher.update(part);
        }
        let hash = hasher.finalize();
        let mut id = [0_u8; ENTITY_ID_LEN];
        id.copy_from_slice(&hash[..ENTITY_ID_LEN]);
        if let Ok(id) = EntityId::from_bytes(id) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "code symbol deterministic entity id exhausted salt space",
    ))
}

pub(super) fn code_symbol_manifest_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODE_SYMBOL_MANIFEST_KEY_PREFIX.len() + id.as_bytes().len());
    key.extend_from_slice(CODE_SYMBOL_MANIFEST_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

pub(super) fn code_symbol_revision_index_prefix(
    repo_ref: &RepoRef,
    path: &str,
    name: &str,
    fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
) -> Vec<u8> {
    let repo_ref = repo_ref.canonical();
    let mut key = Vec::with_capacity(
        CODE_SYMBOL_REVISION_INDEX_KEY_PREFIX.len()
            + repo_ref.len()
            + path.len()
            + name.len()
            + fingerprint.len()
            + 4,
    );
    key.extend_from_slice(CODE_SYMBOL_REVISION_INDEX_KEY_PREFIX);
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
    prefix: &[u8],
    id: &EntityId,
) -> Result<()> {
    let mut keys = Vec::new();
    for entry in store.vault_meta.prefix_iter(&*wtxn, prefix)? {
        let (key, _) = entry?;
        if key.len() >= prefix.len() + 1 + id.as_bytes().len()
            && key.ends_with(id.as_bytes())
            && key[key.len() - id.as_bytes().len() - 1] == 0
        {
            keys.push(key.to_vec());
        }
    }
    for key in keys {
        store.vault_meta.delete(wtxn, &key)?;
    }
    Ok(())
}
