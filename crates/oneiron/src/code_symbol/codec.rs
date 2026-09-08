//! Pinned body keys and the manifest / chunk / revision / entity-body encode-decode.

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::keys::repo_identity_key;
use super::types::{
    CODE_SYMBOL_FINGERPRINT_LEN, CODE_SYMBOL_KIND_MAX_BYTES, CODE_SYMBOL_NAME_MAX_BYTES,
    CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES, CODE_SYMBOL_TEXT_HASH_LEN, CodeChunk, CodeSymbolManifest,
    CodeSymbolRevision,
};
use super::validate::{
    normalize_commit_hash, validate_chunk, validate_code_symbol_manifest, validate_manifest_path,
    validate_symbol_shape, validate_text,
};

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

pub const CODE_SYMBOL_ENTITY_BODY_KEYS: [&str; 8] = [
    "schema_version",
    "repo_key",
    "path",
    "name",
    "kind",
    "fingerprint",
    "start_line",
    "end_line",
];

pub(super) const KEY_REPO_REF: &str = CODE_SYMBOL_MANIFEST_BODY_KEYS[0];

pub(super) const KEY_COMMIT_HASH: &str = CODE_SYMBOL_MANIFEST_BODY_KEYS[1];

pub(super) const KEY_CHUNKS: &str = CODE_SYMBOL_MANIFEST_BODY_KEYS[2];

pub(super) const KEY_SYMBOLS: &str = CODE_SYMBOL_MANIFEST_BODY_KEYS[3];

pub(super) const KEY_PATH: &str = CODE_SYMBOL_CHUNK_KEYS[0];

pub(super) const KEY_START_LINE: &str = CODE_SYMBOL_CHUNK_KEYS[1];

pub(super) const KEY_END_LINE: &str = CODE_SYMBOL_CHUNK_KEYS[2];

pub(super) const KEY_CONTENT_HASH: &str = CODE_SYMBOL_CHUNK_KEYS[3];

pub(super) const KEY_NAME: &str = CODE_SYMBOL_REVISION_KEYS[1];

pub(super) const KEY_KIND: &str = CODE_SYMBOL_REVISION_KEYS[2];

pub(super) const KEY_FINGERPRINT: &str = CODE_SYMBOL_REVISION_KEYS[3];

pub(super) const KEY_CHUNK_INDEXES: &str = CODE_SYMBOL_REVISION_KEYS[4];

pub(super) const KEY_PROVENANCE_CLAIM_ID: &str = CODE_SYMBOL_REVISION_KEYS[5];

pub(super) const KEY_SOURCE_SESSION: &str = CODE_SYMBOL_REVISION_KEYS[6];

pub(super) const KEY_SCHEMA_VERSION: &str = CODE_SYMBOL_ENTITY_BODY_KEYS[0];

pub(super) const KEY_REPO_KEY: &str = CODE_SYMBOL_ENTITY_BODY_KEYS[1];

pub(super) const CODE_SYMBOL_ENTITY_SCHEMA_VERSION: u64 = 1;

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

pub(super) fn decode_code_symbol_manifest_value(value: &Value) -> Result<CodeSymbolManifest> {
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

pub(super) fn decode_code_chunk(value: &Value) -> Result<CodeChunk> {
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

pub(super) fn decode_code_symbol_revision(value: &Value) -> Result<CodeSymbolRevision> {
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

pub(super) fn encode_code_symbol_entity_body(
    repo_ref: &RepoRef,
    symbol: &CodeSymbolRevision,
    start_line: u32,
    end_line: u32,
) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::Integer(CODE_SYMBOL_ENTITY_SCHEMA_VERSION.into()),
        ),
        (
            Value::from(KEY_REPO_KEY),
            Value::from(repo_identity_key(repo_ref)),
        ),
        (Value::from(KEY_PATH), Value::from(symbol.path.as_str())),
        (Value::from(KEY_NAME), Value::from(symbol.name.as_str())),
        (Value::from(KEY_KIND), Value::from(symbol.kind.as_str())),
        (
            Value::from(KEY_FINGERPRINT),
            Value::Binary(symbol.fingerprint.to_vec()),
        ),
        (
            Value::from(KEY_START_LINE),
            Value::Integer(u64::from(start_line).into()),
        ),
        (
            Value::from(KEY_END_LINE),
            Value::Integer(u64::from(end_line).into()),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("code symbol entity MessagePack encode failed"))?;
    Ok(out)
}

pub(super) fn string_key<'a>(value: &'a Value, context: &'static str) -> Result<&'a str> {
    value
        .as_str()
        .ok_or(Error::InvalidCodeSymbolManifestBody(context))
}

pub(super) fn u32_from_value(value: &Value, field: &'static str) -> Result<u32> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(Error::InvalidCodeSymbolManifestBody(field))
}

pub(super) fn binary_32(value: &Value, field: &'static str) -> Result<[u8; 32]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidCodeSymbolManifestBody(field));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidCodeSymbolManifestBody(field))
}

pub(super) fn decode_chunk_indexes(value: &Value) -> Result<Vec<u32>> {
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

pub(super) fn entity_id_from_value(value: &Value, field: &'static str) -> Result<EntityId> {
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

pub(super) fn hash_text_field(hasher: &mut Sha256, text: &str) {
    hasher.update((text.len() as u64).to_le_bytes());
    hasher.update(text.as_bytes());
}

pub(super) fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(super) fn hash_len(hasher: &mut Sha256, len: usize) -> Result<()> {
    let len = u64::try_from(len)
        .map_err(|_| Error::ArithmeticOverflow("code symbol hash material length overflow"))?;
    hasher.update(len.to_le_bytes());
    Ok(())
}
