use heed::{RoTxn, RwTxn};
use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::code_artifact::decode_code_artifact_body;
use crate::codebase::{CODEBASE_COMMIT_HASH_HEX_LEN, CODEBASE_FILE_PATH_MAX_BYTES, RepoRef};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{ENTITY_TYPE_CODE_ARTIFACT, EntityId};

pub const CODE_SYMBOL_TEXT_HASH_LEN: usize = 32;
pub const CODE_SYMBOL_FINGERPRINT_LEN: usize = 32;
pub const CODE_SYMBOL_NAME_MAX_BYTES: usize = 1024;
pub const CODE_SYMBOL_KIND_MAX_BYTES: usize = 128;
pub const CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES: usize = 512;
pub const CODE_SYMBOL_MANIFEST_MAX_CHUNKS: usize = 100_000;
pub const CODE_SYMBOL_MANIFEST_MAX_SYMBOLS: usize = 100_000;
pub const CODE_SYMBOL_MANIFEST_BODY_KEYS: [&str; 4] =
    ["repo_ref", "commit_hash", "chunks", "symbols"];
pub const CODE_SYMBOL_CHUNK_KEYS: [&str; 4] = ["path", "start_line", "end_line", "content_hash"];
pub const CODE_SYMBOL_REVISION_KEYS: [&str; 7] = [
    "path",
    "name",
    "kind",
    "fingerprint",
    "chunk_indexes",
    "provenance_claim_id",
    "source_session",
];

const KEY_REPO_REF: &str = CODE_SYMBOL_MANIFEST_BODY_KEYS[0];
const KEY_COMMIT_HASH: &str = CODE_SYMBOL_MANIFEST_BODY_KEYS[1];
const KEY_CHUNKS: &str = CODE_SYMBOL_MANIFEST_BODY_KEYS[2];
const KEY_SYMBOLS: &str = CODE_SYMBOL_MANIFEST_BODY_KEYS[3];
const KEY_PATH: &str = CODE_SYMBOL_CHUNK_KEYS[0];
const KEY_START_LINE: &str = CODE_SYMBOL_CHUNK_KEYS[1];
const KEY_END_LINE: &str = CODE_SYMBOL_CHUNK_KEYS[2];
const KEY_CONTENT_HASH: &str = CODE_SYMBOL_CHUNK_KEYS[3];
const KEY_NAME: &str = CODE_SYMBOL_REVISION_KEYS[1];
const KEY_KIND: &str = CODE_SYMBOL_REVISION_KEYS[2];
const KEY_FINGERPRINT: &str = CODE_SYMBOL_REVISION_KEYS[3];
const KEY_CHUNK_INDEXES: &str = CODE_SYMBOL_REVISION_KEYS[4];
const KEY_PROVENANCE_CLAIM_ID: &str = CODE_SYMBOL_REVISION_KEYS[5];
const KEY_SOURCE_SESSION: &str = CODE_SYMBOL_REVISION_KEYS[6];

const CODE_SYMBOL_MANIFEST_KEY_PREFIX: &[u8] = b"code_symbol:manifest:v1:";
const CODE_SYMBOL_REVISION_INDEX_KEY_PREFIX: &[u8] = b"code_symbol:revision:v1:";

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeChunk {
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub content_hash: [u8; CODE_SYMBOL_TEXT_HASH_LEN],
}

impl CodeChunk {
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        start_line: u32,
        end_line: u32,
        content_hash: [u8; CODE_SYMBOL_TEXT_HASH_LEN],
    ) -> Self {
        Self {
            path: path.into(),
            start_line,
            end_line,
            content_hash,
        }
    }

    pub fn from_text(
        path: impl Into<String>,
        start_line: u32,
        end_line: u32,
        text: &str,
    ) -> Result<Self> {
        Ok(Self::new(
            path,
            start_line,
            end_line,
            sha256_bytes(text.as_bytes()),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeSymbolRevision {
    pub path: String,
    pub name: String,
    pub kind: String,
    pub fingerprint: [u8; CODE_SYMBOL_FINGERPRINT_LEN],
    pub chunk_indexes: Vec<u32>,
    pub provenance_claim_id: Option<EntityId>,
    pub source_session: Option<String>,
}

impl CodeSymbolRevision {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        name: impl Into<String>,
        kind: impl Into<String>,
        fingerprint: [u8; CODE_SYMBOL_FINGERPRINT_LEN],
        chunk_indexes: Vec<u32>,
        provenance_claim_id: Option<EntityId>,
        source_session: Option<String>,
    ) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            kind: kind.into(),
            fingerprint,
            chunk_indexes,
            provenance_claim_id,
            source_session,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeSymbolManifest {
    pub repo_ref: RepoRef,
    pub commit_hash: Option<String>,
    pub chunks: Vec<CodeChunk>,
    pub symbols: Vec<CodeSymbolRevision>,
}

impl CodeSymbolManifest {
    pub fn new(
        repo_ref: RepoRef,
        commit_hash: Option<String>,
        chunks: Vec<CodeChunk>,
        mut symbols: Vec<CodeSymbolRevision>,
    ) -> Result<Self> {
        let (chunks, remapped_indexes) = sort_chunks_with_index_remap(chunks)?;
        symbols.sort_by(compare_symbols);
        for symbol in &mut symbols {
            for index in &mut symbol.chunk_indexes {
                let old_index = usize::try_from(*index).map_err(|_| {
                    Error::InvalidCodeSymbolManifestBody(
                        "symbol revision chunk index exceeds usize",
                    )
                })?;
                *index = *remapped_indexes.get(old_index).ok_or(
                    Error::InvalidCodeSymbolManifestBody(
                        "symbol revision chunk index is out of bounds",
                    ),
                )?;
            }
            symbol.chunk_indexes.sort_unstable();
            symbol.chunk_indexes.dedup();
        }
        let manifest = Self {
            repo_ref,
            commit_hash: commit_hash.map(normalize_commit_hash).transpose()?,
            chunks,
            symbols,
        };
        validate_code_symbol_manifest(&manifest)?;
        Ok(manifest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodeSymbolBlame {
    pub code_artifact_id: EntityId,
    pub provenance_claim_id: Option<EntityId>,
    pub source_session: Option<String>,
}

pub fn encode_code_symbol_manifest(manifest: &CodeSymbolManifest) -> Result<Vec<u8>> {
    validate_code_symbol_manifest(manifest)?;
    let chunks = manifest
        .chunks
        .iter()
        .map(|chunk| {
            Value::Map(vec![
                (Value::from(KEY_PATH), Value::from(chunk.path.as_str())),
                (
                    Value::from(KEY_START_LINE),
                    Value::Integer(u64::from(chunk.start_line).into()),
                ),
                (
                    Value::from(KEY_END_LINE),
                    Value::Integer(u64::from(chunk.end_line).into()),
                ),
                (
                    Value::from(KEY_CONTENT_HASH),
                    Value::Binary(chunk.content_hash.to_vec()),
                ),
            ])
        })
        .collect();
    let symbols = manifest
        .symbols
        .iter()
        .map(|symbol| {
            Value::Map(vec![
                (Value::from(KEY_PATH), Value::from(symbol.path.as_str())),
                (Value::from(KEY_NAME), Value::from(symbol.name.as_str())),
                (Value::from(KEY_KIND), Value::from(symbol.kind.as_str())),
                (
                    Value::from(KEY_FINGERPRINT),
                    Value::Binary(symbol.fingerprint.to_vec()),
                ),
                (
                    Value::from(KEY_CHUNK_INDEXES),
                    Value::Array(
                        symbol
                            .chunk_indexes
                            .iter()
                            .map(|index| Value::Integer(u64::from(*index).into()))
                            .collect(),
                    ),
                ),
                (
                    Value::from(KEY_PROVENANCE_CLAIM_ID),
                    symbol
                        .provenance_claim_id
                        .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
                ),
                (
                    Value::from(KEY_SOURCE_SESSION),
                    symbol
                        .source_session
                        .as_deref()
                        .map_or(Value::Nil, Value::from),
                ),
            ])
        })
        .collect();
    let value = Value::Map(vec![
        (
            Value::from(KEY_REPO_REF),
            Value::from(manifest.repo_ref.canonical()),
        ),
        (
            Value::from(KEY_COMMIT_HASH),
            manifest
                .commit_hash
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
        (Value::from(KEY_CHUNKS), Value::Array(chunks)),
        (Value::from(KEY_SYMBOLS), Value::Array(symbols)),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("code symbol manifest MessagePack encode failed"))?;
    Ok(out)
}

pub fn decode_code_symbol_manifest(bytes: &[u8]) -> Result<CodeSymbolManifest> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("manifest is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "trailing bytes after manifest map",
        ));
    }
    decode_code_symbol_manifest_value(&value)
}

pub fn derive_code_chunks_from_text_diff(
    path: &str,
    old_text: &str,
    new_text: &str,
) -> Result<Vec<CodeChunk>> {
    validate_manifest_path(path)?;
    if old_text == new_text {
        return Ok(Vec::new());
    }

    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();
    if old_lines.len() == new_lines.len() {
        return changed_equal_length_chunks(path, &old_lines, &new_lines, new_text);
    }

    let mut prefix = 0;
    let min_len = old_lines.len().min(new_lines.len());
    while prefix < min_len && old_lines[prefix] == new_lines[prefix] {
        prefix += 1;
    }

    let mut suffix = 0;
    while suffix < old_lines.len().saturating_sub(prefix)
        && suffix < new_lines.len().saturating_sub(prefix)
        && old_lines[old_lines.len() - 1 - suffix] == new_lines[new_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let new_end = new_lines.len().saturating_sub(suffix);
    Ok(vec![chunk_for_line_range(
        path, &new_lines, prefix, new_end, new_text,
    )?])
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
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol fingerprint requires at least one chunk",
        ));
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
            return Err(Error::InvalidCodeSymbolManifestBody(
                "symbol revision chunk path must match symbol path",
            ));
        }
        hash_text_field(&mut hasher, &chunk.path);
        hasher.update(chunk.start_line.to_le_bytes());
        hasher.update(chunk.end_line.to_le_bytes());
        hasher.update(chunk.content_hash);
    }
    Ok(hasher.finalize().into())
}

impl Vault {
    pub fn put_code_symbol_manifest(
        &self,
        code_artifact_id: &EntityId,
        manifest: &CodeSymbolManifest,
    ) -> Result<()> {
        validate_code_symbol_manifest(manifest)?;
        let encoded = encode_code_symbol_manifest(manifest)?;
        let mut wtxn = self.store.env.write_txn()?;
        validate_code_artifact_target(&self.store, &wtxn, code_artifact_id, &manifest.repo_ref)?;

        delete_code_symbol_manifest_in_txn(&self.store, &mut wtxn, code_artifact_id)?;
        self.store.vault_meta.put(
            &mut wtxn,
            &code_symbol_manifest_key(code_artifact_id),
            &encoded,
        )?;
        for symbol in &manifest.symbols {
            self.store.vault_meta.put(
                &mut wtxn,
                &code_symbol_revision_index_key(
                    &manifest.repo_ref,
                    &symbol.path,
                    &symbol.name,
                    &symbol.fingerprint,
                    code_artifact_id,
                ),
                &[],
            )?;
        }
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_code_symbol_manifest(
        &self,
        code_artifact_id: &EntityId,
    ) -> Result<Option<CodeSymbolManifest>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &code_symbol_manifest_key(code_artifact_id))?
        else {
            return Ok(None);
        };
        let manifest = decode_code_symbol_manifest(raw)?;
        validate_code_artifact_target(&self.store, &rtxn, code_artifact_id, &manifest.repo_ref)?;
        Ok(Some(manifest))
    }

    pub fn code_symbol_blame(
        &self,
        code_artifact_id: &EntityId,
        path: &str,
        name: &str,
        fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
    ) -> Result<Option<CodeSymbolBlame>> {
        validate_manifest_path(path)?;
        validate_text(name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
        let Some(manifest) = self.get_code_symbol_manifest(code_artifact_id)? else {
            return Ok(None);
        };
        Ok(manifest
            .symbols
            .iter()
            .find(|symbol| {
                symbol.path == path && symbol.name == name && &symbol.fingerprint == fingerprint
            })
            .map(|symbol| CodeSymbolBlame {
                code_artifact_id: *code_artifact_id,
                provenance_claim_id: symbol.provenance_claim_id,
                source_session: symbol.source_session.clone(),
            }))
    }

    pub fn lookup_code_symbol_blame(
        &self,
        repo_ref: &RepoRef,
        path: &str,
        name: &str,
        fingerprint: &[u8; CODE_SYMBOL_FINGERPRINT_LEN],
    ) -> Result<Option<CodeSymbolBlame>> {
        validate_manifest_path(path)?;
        validate_text(name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
        let rtxn = self.store.env.read_txn()?;
        let prefix = code_symbol_revision_index_prefix(repo_ref, path, name, fingerprint);
        let mut result = None;
        for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = entry?;
            let id = id_from_index_key(key, prefix.len(), "code symbol revision index key")?;
            match validate_code_artifact_entity_exists(&self.store, &rtxn, &id) {
                Ok(()) => {}
                Err(Error::EntityNotFound) => continue,
                Err(err) => return Err(err),
            }
            if let Some(raw) = self
                .store
                .vault_meta
                .get(&rtxn, &code_symbol_manifest_key(&id))?
            {
                let manifest = decode_code_symbol_manifest(raw)?;
                if manifest.repo_ref != *repo_ref {
                    return Err(Error::InvalidCodeSymbolManifestBody(
                        "symbol revision index repo_ref does not match manifest",
                    ));
                }
                validate_code_artifact_target(&self.store, &rtxn, &id, &manifest.repo_ref)?;
                if let Some(symbol) = manifest.symbols.iter().find(|symbol| {
                    symbol.path == path && symbol.name == name && &symbol.fingerprint == fingerprint
                }) {
                    result = Some(CodeSymbolBlame {
                        code_artifact_id: id,
                        provenance_claim_id: symbol.provenance_claim_id,
                        source_session: symbol.source_session.clone(),
                    });
                }
            }
        }
        Ok(result)
    }
}

pub(crate) fn delete_code_symbol_manifest_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let key = code_symbol_manifest_key(id);
    let Some(raw) = store.vault_meta.get(wtxn, &key)?.map(<[u8]>::to_vec) else {
        return Ok(false);
    };

    store.vault_meta.delete(wtxn, &key)?;
    match decode_code_symbol_manifest(&raw) {
        Ok(manifest) => {
            for symbol in &manifest.symbols {
                store.vault_meta.delete(
                    wtxn,
                    &code_symbol_revision_index_key(
                        &manifest.repo_ref,
                        &symbol.path,
                        &symbol.name,
                        &symbol.fingerprint,
                        id,
                    ),
                )?;
            }
        }
        Err(_) => {
            delete_index_rows_for_id(store, wtxn, CODE_SYMBOL_REVISION_INDEX_KEY_PREFIX, id)?;
        }
    }
    Ok(true)
}

fn decode_code_symbol_manifest_value(value: &Value) -> Result<CodeSymbolManifest> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "manifest must be a MessagePack map",
        ));
    };

    let mut repo_ref: Option<RepoRef> = None;
    let mut commit_hash: Option<Option<String>> = None;
    let mut chunks: Option<Vec<CodeChunk>> = None;
    let mut symbols: Option<Vec<CodeSymbolRevision>> = None;
    let mut seen = [false; CODE_SYMBOL_MANIFEST_BODY_KEYS.len()];

    for (key, value) in entries {
        let key = string_key(key, "manifest keys must be strings")?;
        let Some(index) = CODE_SYMBOL_MANIFEST_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "manifest key is not in the pinned CODE_SYMBOL_MANIFEST_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "duplicate manifest key",
            ));
        }
        seen[index] = true;
        match CODE_SYMBOL_MANIFEST_BODY_KEYS[index] {
            KEY_REPO_REF => {
                let text = value.as_str().ok_or(Error::InvalidCodeSymbolManifestBody(
                    "repo_ref must be a UTF-8 string",
                ))?;
                repo_ref = Some(RepoRef::parse(text).map_err(|_| {
                    Error::InvalidCodeSymbolManifestBody("repo_ref must be a valid v1 repo_ref")
                })?);
            }
            KEY_COMMIT_HASH => {
                commit_hash = Some(match value {
                    Value::Nil => None,
                    _ => Some(normalize_commit_hash(value.as_str().ok_or(
                        Error::InvalidCodeSymbolManifestBody(
                            "commit_hash must be null or a UTF-8 string",
                        ),
                    )?)?),
                });
            }
            KEY_CHUNKS => {
                let Value::Array(values) = value else {
                    return Err(Error::InvalidCodeSymbolManifestBody(
                        "chunks must be a MessagePack array",
                    ));
                };
                chunks = Some(
                    values
                        .iter()
                        .map(decode_code_chunk)
                        .collect::<Result<Vec<_>>>()?,
                );
            }
            KEY_SYMBOLS => {
                let Value::Array(values) = value else {
                    return Err(Error::InvalidCodeSymbolManifestBody(
                        "symbols must be a MessagePack array",
                    ));
                };
                symbols = Some(
                    values
                        .iter()
                        .map(decode_code_symbol_revision)
                        .collect::<Result<Vec<_>>>()?,
                );
            }
            _ => unreachable!("index resolved from CODE_SYMBOL_MANIFEST_BODY_KEYS"),
        }
    }

    let manifest = CodeSymbolManifest {
        repo_ref: repo_ref.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required manifest key repo_ref",
        ))?,
        commit_hash: commit_hash.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required manifest key commit_hash",
        ))?,
        chunks: chunks.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required manifest key chunks",
        ))?,
        symbols: symbols.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required manifest key symbols",
        ))?,
    };
    validate_code_symbol_manifest(&manifest)?;
    Ok(manifest)
}

fn decode_code_chunk(value: &Value) -> Result<CodeChunk> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "chunk must be a MessagePack map",
        ));
    };
    let mut path: Option<String> = None;
    let mut start_line: Option<u32> = None;
    let mut end_line: Option<u32> = None;
    let mut content_hash: Option<[u8; CODE_SYMBOL_TEXT_HASH_LEN]> = None;
    let mut seen = [false; CODE_SYMBOL_CHUNK_KEYS.len()];

    for (key, value) in entries {
        let key = string_key(key, "chunk keys must be strings")?;
        let Some(index) = CODE_SYMBOL_CHUNK_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "chunk key is not in the pinned CODE_SYMBOL_CHUNK_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeSymbolManifestBody("duplicate chunk key"));
        }
        seen[index] = true;
        match CODE_SYMBOL_CHUNK_KEYS[index] {
            KEY_PATH => {
                let text = value.as_str().ok_or(Error::InvalidCodeSymbolManifestBody(
                    "chunk path must be a UTF-8 string",
                ))?;
                validate_manifest_path(text)?;
                path = Some(text.to_owned());
            }
            KEY_START_LINE => start_line = Some(u32_from_value(value, "start_line")?),
            KEY_END_LINE => end_line = Some(u32_from_value(value, "end_line")?),
            KEY_CONTENT_HASH => content_hash = Some(binary_32(value, "content_hash")?),
            _ => unreachable!("index resolved from CODE_SYMBOL_CHUNK_KEYS"),
        }
    }

    let chunk = CodeChunk {
        path: path.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required chunk key path",
        ))?,
        start_line: start_line.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required chunk key start_line",
        ))?,
        end_line: end_line.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required chunk key end_line",
        ))?,
        content_hash: content_hash.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required chunk key content_hash",
        ))?,
    };
    validate_chunk(&chunk)?;
    Ok(chunk)
}

fn decode_code_symbol_revision(value: &Value) -> Result<CodeSymbolRevision> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol revision must be a MessagePack map",
        ));
    };
    let mut path: Option<String> = None;
    let mut name: Option<String> = None;
    let mut kind: Option<String> = None;
    let mut fingerprint: Option<[u8; CODE_SYMBOL_FINGERPRINT_LEN]> = None;
    let mut chunk_indexes: Option<Vec<u32>> = None;
    let mut provenance_claim_id: Option<Option<EntityId>> = None;
    let mut source_session: Option<Option<String>> = None;
    let mut seen = [false; CODE_SYMBOL_REVISION_KEYS.len()];

    for (key, value) in entries {
        let key = string_key(key, "symbol revision keys must be strings")?;
        let Some(index) = CODE_SYMBOL_REVISION_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "symbol revision key is not in the pinned CODE_SYMBOL_REVISION_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "duplicate symbol revision key",
            ));
        }
        seen[index] = true;
        match CODE_SYMBOL_REVISION_KEYS[index] {
            KEY_PATH => {
                let text = value.as_str().ok_or(Error::InvalidCodeSymbolManifestBody(
                    "symbol path must be a UTF-8 string",
                ))?;
                validate_manifest_path(text)?;
                path = Some(text.to_owned());
            }
            KEY_NAME => {
                let text = value.as_str().ok_or(Error::InvalidCodeSymbolManifestBody(
                    "symbol name must be a UTF-8 string",
                ))?;
                validate_text(text, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
                name = Some(text.to_owned());
            }
            KEY_KIND => {
                let text = value.as_str().ok_or(Error::InvalidCodeSymbolManifestBody(
                    "symbol kind must be a UTF-8 string",
                ))?;
                validate_text(text, CODE_SYMBOL_KIND_MAX_BYTES, "symbol kind")?;
                kind = Some(text.to_owned());
            }
            KEY_FINGERPRINT => fingerprint = Some(binary_32(value, "fingerprint")?),
            KEY_CHUNK_INDEXES => chunk_indexes = Some(decode_chunk_indexes(value)?),
            KEY_PROVENANCE_CLAIM_ID => {
                provenance_claim_id = Some(match value {
                    Value::Nil => None,
                    _ => Some(entity_id_from_value(value, "provenance_claim_id")?),
                });
            }
            KEY_SOURCE_SESSION => {
                source_session = Some(match value {
                    Value::Nil => None,
                    _ => {
                        let text = value.as_str().ok_or(Error::InvalidCodeSymbolManifestBody(
                            "source_session must be null or a UTF-8 string",
                        ))?;
                        validate_text(
                            text,
                            CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES,
                            "source_session",
                        )?;
                        Some(text.to_owned())
                    }
                });
            }
            _ => unreachable!("index resolved from CODE_SYMBOL_REVISION_KEYS"),
        }
    }

    let symbol = CodeSymbolRevision {
        path: path.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required symbol revision key path",
        ))?,
        name: name.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required symbol revision key name",
        ))?,
        kind: kind.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required symbol revision key kind",
        ))?,
        fingerprint: fingerprint.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required symbol revision key fingerprint",
        ))?,
        chunk_indexes: chunk_indexes.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required symbol revision key chunk_indexes",
        ))?,
        provenance_claim_id: provenance_claim_id.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required symbol revision key provenance_claim_id",
        ))?,
        source_session: source_session.ok_or(Error::InvalidCodeSymbolManifestBody(
            "missing required symbol revision key source_session",
        ))?,
    };
    validate_symbol_shape(&symbol)?;
    Ok(symbol)
}

fn validate_code_symbol_manifest(manifest: &CodeSymbolManifest) -> Result<()> {
    let canonical_repo_ref = manifest.repo_ref.canonical();
    if RepoRef::parse(&canonical_repo_ref)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("repo_ref must be a valid v1 repo_ref"))?
        != manifest.repo_ref
    {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "repo_ref must be a canonical v1 repo_ref",
        ));
    }
    if let Some(commit_hash) = &manifest.commit_hash {
        validate_normalized_commit_hash(commit_hash)?;
    }
    if let Some(repo_commit) = manifest.repo_ref.commit_hash()
        && manifest.commit_hash.as_deref() != Some(repo_commit)
    {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "GitHub repo_ref commit must match manifest commit_hash",
        ));
    }
    if manifest.chunks.len() > CODE_SYMBOL_MANIFEST_MAX_CHUNKS {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "chunk manifest exceeds 100000 entries",
        ));
    }
    if manifest.symbols.len() > CODE_SYMBOL_MANIFEST_MAX_SYMBOLS {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol manifest exceeds 100000 entries",
        ));
    }

    let mut previous_chunk: Option<&CodeChunk> = None;
    for chunk in &manifest.chunks {
        validate_chunk(chunk)?;
        if let Some(previous) = previous_chunk
            && compare_chunks(previous, chunk) != std::cmp::Ordering::Less
        {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "chunks must be sorted and unique",
            ));
        }
        previous_chunk = Some(chunk);
    }

    let mut previous_symbol: Option<&CodeSymbolRevision> = None;
    for symbol in &manifest.symbols {
        validate_symbol_shape(symbol)?;
        validate_symbol_indexes(symbol, &manifest.chunks)?;
        if let Some(previous) = previous_symbol
            && compare_symbols(previous, symbol) != std::cmp::Ordering::Less
        {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "symbol revisions must be sorted and unique",
            ));
        }
        previous_symbol = Some(symbol);
    }
    Ok(())
}

fn validate_chunk(chunk: &CodeChunk) -> Result<()> {
    validate_manifest_path(&chunk.path)?;
    if chunk.start_line == 0 || chunk.end_line == 0 || chunk.start_line > chunk.end_line {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "chunk line range must be 1-based and ordered",
        ));
    }
    Ok(())
}

fn validate_symbol_shape(symbol: &CodeSymbolRevision) -> Result<()> {
    validate_manifest_path(&symbol.path)?;
    validate_text(&symbol.name, CODE_SYMBOL_NAME_MAX_BYTES, "symbol name")?;
    validate_text(&symbol.kind, CODE_SYMBOL_KIND_MAX_BYTES, "symbol kind")?;
    if let Some(session) = &symbol.source_session {
        validate_text(
            session,
            CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES,
            "source_session",
        )?;
    }
    Ok(())
}

fn validate_symbol_indexes(symbol: &CodeSymbolRevision, chunks: &[CodeChunk]) -> Result<()> {
    if symbol.chunk_indexes.is_empty() {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol revision must reference at least one chunk",
        ));
    }
    let mut previous: Option<u32> = None;
    for raw_index in &symbol.chunk_indexes {
        let index = usize::try_from(*raw_index)
            .ok()
            .filter(|index| *index < chunks.len())
            .ok_or(Error::InvalidCodeSymbolManifestBody(
                "symbol revision chunk index is out of bounds",
            ))?;
        if chunks[index].path != symbol.path {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "symbol revision chunk path must match symbol path",
            ));
        }
        if let Some(previous) = previous
            && previous >= *raw_index
        {
            return Err(Error::InvalidCodeSymbolManifestBody(
                "symbol revision chunk indexes must be sorted and unique",
            ));
        }
        previous = Some(*raw_index);
    }
    Ok(())
}

fn validate_manifest_path(path: &str) -> Result<()> {
    validate_text(path, CODEBASE_FILE_PATH_MAX_BYTES, "file path")?;
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "file path must be repository-relative",
        ));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "file path must be normalized and cannot contain . or .. segments",
        ));
    }
    Ok(())
}

fn validate_text(text: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidCodeSymbolManifestBody(field));
    }
    if text.trim() != text {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "text fields must not have leading or trailing whitespace",
        ));
    }
    if text.chars().any(char::is_control) {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "text fields must not contain control characters",
        ));
    }
    Ok(())
}

fn normalize_commit_hash(input: impl AsRef<str>) -> Result<String> {
    let input = input.as_ref();
    if input.len() != CODEBASE_COMMIT_HASH_HEX_LEN || !input.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "commit hash must be 40 hexadecimal characters",
        ));
    }
    Ok(input.to_ascii_lowercase())
}

fn validate_normalized_commit_hash(input: &str) -> Result<()> {
    if normalize_commit_hash(input)? != input {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "commit hash must use lowercase hexadecimal",
        ));
    }
    Ok(())
}

fn changed_equal_length_chunks(
    path: &str,
    old_lines: &[&str],
    new_lines: &[&str],
    new_text: &str,
) -> Result<Vec<CodeChunk>> {
    let mut chunks = Vec::new();
    let mut index = 0;
    while index < new_lines.len() {
        if old_lines[index] == new_lines[index] {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < new_lines.len() && old_lines[index] != new_lines[index] {
            index += 1;
        }
        chunks.push(chunk_for_line_range(
            path, new_lines, start, index, new_text,
        )?);
    }
    Ok(chunks)
}

fn chunk_for_line_range(
    path: &str,
    lines: &[&str],
    start: usize,
    end: usize,
    source_text: &str,
) -> Result<CodeChunk> {
    let line_number = u32::try_from(start + 1)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("line number exceeds u32"))?;
    if start == end {
        return CodeChunk::from_text(path, line_number, line_number, "");
    }
    let end_line = u32::try_from(end)
        .map_err(|_| Error::InvalidCodeSymbolManifestBody("line number exceeds u32"))?;
    let mut text = lines[start..end].join("\n");
    if end == lines.len() && source_text.ends_with('\n') {
        text.push('\n');
    }
    CodeChunk::from_text(path, line_number, end_line, &text)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hash_text_field(hasher: &mut Sha256, text: &str) {
    hasher.update((text.len() as u64).to_le_bytes());
    hasher.update(text.as_bytes());
}

fn compare_chunks(a: &CodeChunk, b: &CodeChunk) -> std::cmp::Ordering {
    a.path
        .cmp(&b.path)
        .then_with(|| a.start_line.cmp(&b.start_line))
        .then_with(|| a.end_line.cmp(&b.end_line))
        .then_with(|| a.content_hash.cmp(&b.content_hash))
}

fn sort_chunks_with_index_remap(chunks: Vec<CodeChunk>) -> Result<(Vec<CodeChunk>, Vec<u32>)> {
    let mut indexed = chunks.into_iter().enumerate().collect::<Vec<_>>();
    indexed.sort_by(|(_, left), (_, right)| compare_chunks(left, right));
    let mut remapped = vec![0_u32; indexed.len()];
    let mut sorted = Vec::with_capacity(indexed.len());
    for (new_index, (old_index, chunk)) in indexed.into_iter().enumerate() {
        remapped[old_index] = u32::try_from(new_index).map_err(|_| {
            Error::InvalidCodeSymbolManifestBody("chunk manifest exceeds u32 indexes")
        })?;
        sorted.push(chunk);
    }
    Ok((sorted, remapped))
}

fn compare_symbols(a: &CodeSymbolRevision, b: &CodeSymbolRevision) -> std::cmp::Ordering {
    a.path
        .cmp(&b.path)
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.fingerprint.cmp(&b.fingerprint))
}

fn string_key<'a>(value: &'a Value, context: &'static str) -> Result<&'a str> {
    value
        .as_str()
        .ok_or(Error::InvalidCodeSymbolManifestBody(context))
}

fn u32_from_value(value: &Value, field: &'static str) -> Result<u32> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(Error::InvalidCodeSymbolManifestBody(field))
}

fn binary_32(value: &Value, field: &'static str) -> Result<[u8; 32]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidCodeSymbolManifestBody(field));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidCodeSymbolManifestBody(field))
}

fn decode_chunk_indexes(value: &Value) -> Result<Vec<u32>> {
    let Value::Array(values) = value else {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "chunk_indexes must be a MessagePack array",
        ));
    };
    values
        .iter()
        .map(|value| u32_from_value(value, "chunk index"))
        .collect()
}

fn entity_id_from_value(value: &Value, field: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidCodeSymbolManifestBody(field));
    };
    EntityId::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidCodeSymbolManifestBody(field))?,
    )
    .map_err(|_| Error::InvalidCodeSymbolManifestBody(field))
}

fn validate_code_artifact_target(
    store: &Store,
    rtxn: &RoTxn<'_>,
    code_artifact_id: &EntityId,
    repo_ref: &RepoRef,
) -> Result<()> {
    let Some(raw) = store.entities.get(rtxn, code_artifact_id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol manifest target is not a CODE_ARTIFACT",
        ));
    }
    let artifact = decode_code_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    let artifact_repo_ref = RepoRef::parse(&artifact.repo_ref).map_err(|_| {
        Error::InvalidCodeSymbolManifestBody("CODE artifact repo_ref must be a valid v1 repo_ref")
    })?;
    if &artifact_repo_ref != repo_ref {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol manifest repo_ref must match CODE artifact repo_ref",
        ));
    }
    Ok(())
}

fn validate_code_artifact_entity_exists(
    store: &Store,
    rtxn: &RoTxn<'_>,
    code_artifact_id: &EntityId,
) -> Result<()> {
    let Some(raw) = store.entities.get(rtxn, code_artifact_id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
        return Err(Error::InvalidCodeSymbolManifestBody(
            "symbol manifest target is not a CODE_ARTIFACT",
        ));
    }
    Ok(())
}

fn code_symbol_manifest_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODE_SYMBOL_MANIFEST_KEY_PREFIX.len() + id.as_bytes().len());
    key.extend_from_slice(CODE_SYMBOL_MANIFEST_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

fn code_symbol_revision_index_prefix(
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

fn code_symbol_revision_index_key(
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

fn push_index_text(key: &mut Vec<u8>, text: &str) {
    key.extend_from_slice(text.as_bytes());
    key.push(0);
}

fn id_from_index_key(key: &[u8], prefix_len: usize, context: &'static str) -> Result<EntityId> {
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

fn delete_index_rows_for_id(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_artifact::{
        CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody, encode_code_artifact_body,
    };
    use crate::error::ErrorKind;
    use crate::types::{HnswConfig, TextAnalyzerConfig, TimeRange, VaultConfig};

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config.text_analyzer = TextAnalyzerConfig::default();
        config
    }

    fn repo_ref() -> RepoRef {
        RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")
            .expect("repo ref")
    }

    fn repo_ref_b() -> RepoRef {
        RepoRef::parse("github:oneiron-dev/oneiron#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("repo ref")
    }

    fn code_body(repo_ref: &RepoRef) -> CodeArtifactBody {
        CodeArtifactBody::new(
            "Summarize symbol provenance.",
            [0xC5; CODE_ARTIFACT_SUMMARY_HASH_LEN],
            repo_ref.canonical(),
        )
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).expect("entity id")
    }

    fn manifest_with_blame(
        claim_id: Option<EntityId>,
        source_session: Option<String>,
    ) -> Result<CodeSymbolManifest> {
        let chunks = vec![
            CodeChunk::from_text("src/lib.rs", 10, 12, "pub fn answer() -> u8 {\n    42\n}\n")?,
            CodeChunk::from_text("src/lib.rs", 1, 3, "mod answer;\n")?,
        ];
        let fingerprint =
            derive_symbol_fingerprint("src/lib.rs", "answer", "function", &[chunks[0].clone()])?;
        CodeSymbolManifest::new(
            repo_ref(),
            Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
            chunks,
            vec![CodeSymbolRevision::new(
                "src/lib.rs",
                "answer",
                "function",
                fingerprint,
                vec![0],
                claim_id,
                source_session,
            )],
        )
    }

    #[test]
    fn code_symbol_manifest_codec_is_deterministic_and_sorts_constructor_inputs() -> Result<()> {
        let manifest = manifest_with_blame(Some(entity(0xA1)), Some("session-alpha".to_owned()))?;
        assert_eq!(manifest.chunks[0].start_line, 1);
        assert_eq!(manifest.chunks[1].start_line, 10);
        assert_eq!(
            manifest.symbols[0].chunk_indexes,
            vec![1],
            "constructor must remap symbol indexes after sorting chunks"
        );

        let encoded = encode_code_symbol_manifest(&manifest)?;
        let decoded = decode_code_symbol_manifest(&encoded)?;
        let encoded_again = encode_code_symbol_manifest(&decoded)?;

        assert_eq!(decoded, manifest);
        assert_eq!(encoded_again, encoded);
        Ok(())
    }

    #[test]
    fn code_symbol_manifest_codec_rejects_unsorted_or_duplicate_symbol_revisions() {
        let mut manifest = manifest_with_blame(None, None).expect("manifest");
        let duplicate = manifest.symbols[0].clone();
        manifest.symbols.push(duplicate);

        let err =
            encode_code_symbol_manifest(&manifest).expect_err("duplicate symbols fail closed");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);
    }

    #[test]
    fn code_symbol_manifest_rejects_symbol_chunks_from_another_path() -> Result<()> {
        let chunks = vec![CodeChunk::from_text(
            "src/other.rs",
            1,
            1,
            "fn other() {}\n",
        )?];

        let err = CodeSymbolManifest::new(
            repo_ref(),
            Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
            chunks,
            vec![CodeSymbolRevision::new(
                "src/lib.rs",
                "answer",
                "function",
                [0xAA; CODE_SYMBOL_FINGERPRINT_LEN],
                vec![0],
                None,
                None,
            )],
        )
        .expect_err("symbol cannot point at chunks from another file");

        assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);
        Ok(())
    }

    #[test]
    fn text_diff_derives_stable_code_chunks() -> Result<()> {
        let old = "fn a() {\n    one();\n}\nfn b() {\n    two();\n}\n";
        let new = "fn a() {\n    one_more();\n}\nfn b() {\n    two_more();\n}\n";

        let chunks = derive_code_chunks_from_text_diff("src/lib.rs", old, new)?;

        assert_eq!(chunks.len(), 2);
        assert_eq!((chunks[0].start_line, chunks[0].end_line), (2, 2));
        assert_eq!(
            chunks[0].content_hash,
            sha256_bytes("    one_more();".as_bytes())
        );
        assert_eq!((chunks[1].start_line, chunks[1].end_line), (5, 5));
        assert_eq!(
            chunks[1].content_hash,
            sha256_bytes("    two_more();".as_bytes())
        );
        Ok(())
    }

    #[test]
    fn text_diff_preserves_equal_length_eof_newline_in_chunk_hash() -> Result<()> {
        let chunks = derive_code_chunks_from_text_diff("src/lib.rs", "a\nb\n", "a\nc\n")?;

        assert_eq!(chunks.len(), 1);
        assert_eq!((chunks[0].start_line, chunks[0].end_line), (2, 2));
        assert_eq!(chunks[0].content_hash, sha256_bytes("c\n".as_bytes()));
        Ok(())
    }

    #[test]
    fn symbol_fingerprint_canonicalizes_chunk_order() -> Result<()> {
        let first = CodeChunk::from_text("src/lib.rs", 1, 1, "fn first() {}\n")?;
        let second = CodeChunk::from_text("src/lib.rs", 10, 10, "fn second() {}\n")?;

        let ordered = derive_symbol_fingerprint(
            "src/lib.rs",
            "answer",
            "function",
            &[first.clone(), second.clone()],
        )?;
        let reversed =
            derive_symbol_fingerprint("src/lib.rs", "answer", "function", &[second, first])?;

        assert_eq!(ordered, reversed);
        Ok(())
    }

    #[test]
    fn symbol_blame_returns_provenance_claim_and_source_session_when_available() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity(0xB1);
        let claim_id = entity(0xC1);
        let repo_ref = repo_ref();
        let manifest = manifest_with_blame(Some(claim_id), Some("codex-session-001".to_owned()))?;
        let fingerprint = manifest.symbols[0].fingerprint;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_ref),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_code_symbol_manifest(&id, &manifest)?;

        let direct = vault
            .code_symbol_blame(&id, "src/lib.rs", "answer", &fingerprint)?
            .expect("direct blame");
        assert_eq!(direct.provenance_claim_id, Some(claim_id));
        assert_eq!(direct.source_session.as_deref(), Some("codex-session-001"));

        let lookup = vault
            .lookup_code_symbol_blame(&repo_ref, "src/lib.rs", "answer", &fingerprint)?
            .expect("indexed blame");
        assert_eq!(lookup, direct);
        Ok(())
    }

    #[test]
    fn symbol_blame_lookup_skips_orphaned_index_after_code_artifact_delete() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity(0xB3);
        let repo_ref = repo_ref();
        let manifest = manifest_with_blame(None, None)?;
        let fingerprint = manifest.symbols[0].fingerprint;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_ref),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_code_symbol_manifest(&id, &manifest)?;

        assert!(vault.delete_entity(&id)?);

        assert!(
            vault
                .lookup_code_symbol_blame(&repo_ref, "src/lib.rs", "answer", &fingerprint)?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn symbol_blame_lookup_fails_closed_after_code_artifact_repo_ref_overwrite() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity(0xB4);
        let repo_a = repo_ref();
        let repo_b = repo_ref_b();
        let manifest = manifest_with_blame(None, None)?;
        let fingerprint = manifest.symbols[0].fingerprint;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_a),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_code_symbol_manifest(&id, &manifest)?;
        vault.put_code_artifact(
            &id,
            &code_body(&repo_b),
            TimeRange { start: 12, end: 12 },
            13,
        )?;

        let err = vault
            .lookup_code_symbol_blame(&repo_a, "src/lib.rs", "answer", &fingerprint)
            .expect_err("stale sidecar must not return blame after repo_ref overwrite");
        assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);

        let err = vault
            .code_symbol_blame(&id, "src/lib.rs", "answer", &fingerprint)
            .expect_err("direct stale sidecar read must fail closed");
        assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);
        Ok(())
    }

    #[test]
    fn symbol_blame_lookup_propagates_corrupt_live_entity() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity(0xB5);
        let repo_ref = repo_ref();
        let manifest = manifest_with_blame(None, None)?;
        let fingerprint = manifest.symbols[0].fingerprint;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_ref),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_code_symbol_manifest(&id, &manifest)?;
        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), b"bad")?;
            Ok(())
        })?;

        let err = vault
            .lookup_code_symbol_blame(&repo_ref, "src/lib.rs", "answer", &fingerprint)
            .expect_err("corrupt live entity must not be swallowed as no-blame");
        assert_eq!(err.kind(), ErrorKind::CorruptedIndex);
        Ok(())
    }

    #[test]
    fn symbol_blame_lookup_propagates_corrupt_manifest_sidecar() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity(0xB6);
        let repo_ref = repo_ref();
        let manifest = manifest_with_blame(None, None)?;
        let fingerprint = manifest.symbols[0].fingerprint;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_ref),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_code_symbol_manifest(&id, &manifest)?;
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, &code_symbol_manifest_key(&id), b"\xc1")?;
            Ok(())
        })?;

        let err = vault
            .lookup_code_symbol_blame(&repo_ref, "src/lib.rs", "answer", &fingerprint)
            .expect_err("corrupt manifest must not be swallowed as no-blame");
        assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);
        Ok(())
    }

    #[test]
    fn corrupt_manifest_fallback_deletes_only_well_shaped_index_rows_for_id() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity(0xB7);
        let repo_ref = repo_ref();
        let manifest = manifest_with_blame(None, None)?;
        let fingerprint = manifest.symbols[0].fingerprint;
        let well_shaped_key =
            code_symbol_revision_index_key(&repo_ref, "src/lib.rs", "answer", &fingerprint, &id);
        let mut malformed_key = CODE_SYMBOL_REVISION_INDEX_KEY_PREFIX.to_vec();
        malformed_key.extend_from_slice(b"malformed");
        malformed_key.extend_from_slice(id.as_bytes());

        vault.put_code_artifact(
            &id,
            &code_body(&repo_ref),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_code_symbol_manifest(&id, &manifest)?;
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .put(wtxn, &code_symbol_manifest_key(&id), b"\xc1")?;
            vault.store.vault_meta.put(wtxn, &malformed_key, &[])?;
            assert!(delete_code_symbol_manifest_in_txn(&vault.store, wtxn, &id)?);
            Ok(())
        })?;

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &code_symbol_manifest_key(&id))?
                .is_none()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &well_shaped_key)?
                .is_none()
        );
        assert!(vault.store.vault_meta.get(&rtxn, &malformed_key)?.is_some());
        Ok(())
    }

    #[test]
    fn symbol_manifest_repo_ref_must_match_code_artifact() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity(0xB2);
        let repo_ref = repo_ref();
        let other_repo =
            RepoRef::parse("github:oneiron-dev/other#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
        let manifest = manifest_with_blame(None, None)?;

        vault.put_code_artifact(
            &id,
            &code_body(&other_repo),
            TimeRange { start: 10, end: 10 },
            11,
        )?;

        let err = vault
            .put_code_symbol_manifest(&id, &manifest)
            .expect_err("manifest cannot be attached to another repo");
        assert_eq!(err.kind(), ErrorKind::InvalidCodeSymbolManifestBody);

        let artifact = encode_code_artifact_body(&code_body(&repo_ref))?;
        assert!(decode_code_artifact_body(&artifact).is_ok());
        Ok(())
    }
}
