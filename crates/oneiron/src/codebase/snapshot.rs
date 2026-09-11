//! Codebase snapshot value type, MessagePack codec, fork/scope hashing, and manifest validation.

use super::ingest::{read_asset_blob, validate_manifest_path, validate_project_id};
use super::repo_ref::{RepoRef, normalize_commit_hash, validate_normalized_commit_hash};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::CodeError;
use crate::error::{Error, Result};
use rmpv::Value;

pub const CODEBASE_PROJECT_ID_MAX_BYTES: usize = 256;

pub const CODEBASE_FILE_PATH_MAX_BYTES: usize = 4096;

pub const CODEBASE_CONTENT_HASH_LEN: usize = 32;

pub const CODEBASE_FORK_HASH_LEN: usize = 32;

pub const CODEBASE_SCOPE_KEY_LEN: usize = 32;

pub const CODEBASE_SNAPSHOT_MAX_FILES: usize = 100_000;

pub const CODEBASE_SNAPSHOT_BODY_KEYS: [&str; 6] = [
    "project_id",
    "repo_ref",
    "commit_hash",
    "fork_hash",
    "scope_key",
    "files",
];

pub const CODEBASE_FILE_ENTRY_KEYS: [&str; 3] = ["path", "content_hash", "size_bytes"];

const KEY_PROJECT_ID: &str = CODEBASE_SNAPSHOT_BODY_KEYS[0];

const KEY_REPO_REF: &str = CODEBASE_SNAPSHOT_BODY_KEYS[1];

const KEY_COMMIT_HASH: &str = CODEBASE_SNAPSHOT_BODY_KEYS[2];

const KEY_FORK_HASH: &str = CODEBASE_SNAPSHOT_BODY_KEYS[3];

const KEY_SCOPE_KEY: &str = CODEBASE_SNAPSHOT_BODY_KEYS[4];

const KEY_FILES: &str = CODEBASE_SNAPSHOT_BODY_KEYS[5];

const KEY_FILE_PATH: &str = CODEBASE_FILE_ENTRY_KEYS[0];

const KEY_FILE_CONTENT_HASH: &str = CODEBASE_FILE_ENTRY_KEYS[1];

const KEY_FILE_SIZE_BYTES: &str = CODEBASE_FILE_ENTRY_KEYS[2];

const CODEBASE_FORK_HASH_DOMAIN: &[u8] = b"oneiron:codebase-forkhash:v1";

const CODEBASE_SCOPE_KEY_DOMAIN: &[u8] = b"oneiron:codebase-scope:v1";

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodebaseFileEntry {
    pub path: String,
    pub content_hash: [u8; CODEBASE_CONTENT_HASH_LEN],
    pub size_bytes: u64,
}

impl CodebaseFileEntry {
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        content_hash: [u8; CODEBASE_CONTENT_HASH_LEN],
        size_bytes: u64,
    ) -> Self {
        Self {
            path: path.into(),
            content_hash,
            size_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodebaseSnapshot {
    pub project_id: String,
    pub repo_ref: RepoRef,
    pub commit_hash: Option<String>,
    pub fork_hash: CodebaseForkHash,
    pub scope_key: CodebaseScopeKey,
    pub files: Vec<CodebaseFileEntry>,
}

impl CodebaseSnapshot {
    pub fn new(
        project_id: impl Into<String>,
        repo_ref: RepoRef,
        commit_hash: Option<String>,
        files: Vec<CodebaseFileEntry>,
    ) -> Result<Self> {
        let project_id = project_id.into();
        let mut snapshot = Self {
            fork_hash: [0; CODEBASE_FORK_HASH_LEN],
            scope_key: codebase_scope_key(&project_id, &repo_ref)?,
            project_id,
            repo_ref,
            commit_hash: commit_hash.map(normalize_commit_hash).transpose()?,
            files,
        };
        snapshot.files.sort_by(|a, b| a.path.cmp(&b.path));
        snapshot.fork_hash = codebase_fork_hash(&snapshot.files)?;
        validate_codebase_snapshot(&snapshot)?;
        Ok(snapshot)
    }
}

pub struct CodebaseSnapshotMount<'a> {
    pub(super) vault: &'a Vault,
    pub(super) code_artifact_id: EntityId,
    pub(super) snapshot: CodebaseSnapshot,
}

impl CodebaseSnapshotMount<'_> {
    #[must_use]
    pub fn code_artifact_id(&self) -> EntityId {
        self.code_artifact_id
    }

    #[must_use]
    pub fn snapshot(&self) -> &CodebaseSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        true
    }

    pub fn list_files(&self) -> Vec<&str> {
        self.snapshot
            .files
            .iter()
            .map(|entry| entry.path.as_str())
            .collect()
    }

    pub fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>> {
        validate_manifest_path(path)?;
        let Ok(index) = self
            .snapshot
            .files
            .binary_search_by(|entry| entry.path.as_str().cmp(path))
        else {
            return Ok(None);
        };
        read_asset_blob(self.vault, &self.snapshot.files[index].content_hash).map(Some)
    }
}

pub fn encode_codebase_snapshot(snapshot: &CodebaseSnapshot) -> Result<Vec<u8>> {
    validate_codebase_snapshot(snapshot)?;
    let files = snapshot
        .files
        .iter()
        .map(|entry| {
            Value::Map(vec![
                (Value::from(KEY_FILE_PATH), Value::from(entry.path.as_str())),
                (
                    Value::from(KEY_FILE_CONTENT_HASH),
                    Value::Binary(entry.content_hash.to_vec()),
                ),
                (
                    Value::from(KEY_FILE_SIZE_BYTES),
                    Value::Integer(entry.size_bytes.into()),
                ),
            ])
        })
        .collect();
    let value = Value::Map(vec![
        (
            Value::from(KEY_PROJECT_ID),
            Value::from(snapshot.project_id.as_str()),
        ),
        (
            Value::from(KEY_REPO_REF),
            Value::from(snapshot.repo_ref.canonical()),
        ),
        (
            Value::from(KEY_COMMIT_HASH),
            snapshot
                .commit_hash
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_FORK_HASH),
            Value::Binary(snapshot.fork_hash.to_vec()),
        ),
        (
            Value::from(KEY_SCOPE_KEY),
            Value::Binary(snapshot.scope_key.to_vec()),
        ),
        (Value::from(KEY_FILES), Value::Array(files)),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("codebase snapshot MessagePack encode failed"))?;
    Ok(out)
}

pub fn decode_codebase_snapshot(bytes: &[u8]) -> Result<CodebaseSnapshot> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "snapshot is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "trailing bytes after snapshot map",
        )));
    }
    decode_codebase_snapshot_value(&value)
}

fn decode_codebase_snapshot_value(value: &Value) -> Result<CodebaseSnapshot> {
    let Value::Map(entries) = value else {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "snapshot must be a MessagePack map",
        )));
    };

    let mut project_id: Option<String> = None;
    let mut repo_ref: Option<RepoRef> = None;
    let mut commit_hash: Option<Option<String>> = None;
    let mut fork_hash: Option<CodebaseForkHash> = None;
    let mut scope_key: Option<CodebaseScopeKey> = None;
    let mut files: Option<Vec<CodebaseFileEntry>> = None;
    let mut seen = [false; CODEBASE_SNAPSHOT_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "snapshot keys must be strings",
            )));
        };
        let Some(index) = CODEBASE_SNAPSHOT_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "snapshot key is not in the pinned CODEBASE_SNAPSHOT_BODY_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "duplicate snapshot key",
            )));
        }
        seen[index] = true;

        match CODEBASE_SNAPSHOT_BODY_KEYS[index] {
            KEY_PROJECT_ID => {
                let text =
                    value
                        .as_str()
                        .ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                            "project_id must be a UTF-8 string",
                        )))?;
                validate_project_id(text)?;
                project_id = Some(text.to_owned());
            }
            KEY_REPO_REF => {
                let text =
                    value
                        .as_str()
                        .ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                            "repo_ref must be a UTF-8 string",
                        )))?;
                repo_ref = Some(RepoRef::parse(text)?);
            }
            KEY_COMMIT_HASH => {
                commit_hash = Some(match value {
                    Value::Nil => None,
                    _ => Some(normalize_commit_hash(value.as_str().ok_or(
                        Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                            "commit_hash must be null or a UTF-8 string",
                        )),
                    )?)?),
                });
            }
            KEY_FORK_HASH => {
                fork_hash = Some(hash_from_value::<CODEBASE_FORK_HASH_LEN>(
                    value,
                    "fork_hash must be 32-byte binary",
                )?);
            }
            KEY_SCOPE_KEY => {
                scope_key = Some(hash_from_value::<CODEBASE_SCOPE_KEY_LEN>(
                    value,
                    "scope_key must be 32-byte binary",
                )?);
            }
            KEY_FILES => {
                let Value::Array(values) = value else {
                    return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                        "files must be a MessagePack array",
                    )));
                };
                files = Some(
                    values
                        .iter()
                        .map(decode_codebase_file_entry)
                        .collect::<Result<Vec<_>>>()?,
                );
            }
            _ => unreachable!("index resolved from CODEBASE_SNAPSHOT_BODY_KEYS"),
        }
    }

    let mut snapshot = CodebaseSnapshot {
        project_id: project_id.ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "missing required snapshot key project_id",
        )))?,
        repo_ref: repo_ref.ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "missing required snapshot key repo_ref",
        )))?,
        commit_hash: commit_hash.ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "missing required snapshot key commit_hash",
        )))?,
        fork_hash: [0; CODEBASE_FORK_HASH_LEN],
        scope_key: [0; CODEBASE_SCOPE_KEY_LEN],
        files: files.ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "missing required snapshot key files",
        )))?,
    };
    let expected_fork_hash = codebase_fork_hash(&snapshot.files)?;
    let expected_scope_key = codebase_scope_key(&snapshot.project_id, &snapshot.repo_ref)?;
    snapshot.fork_hash = fork_hash.unwrap_or(expected_fork_hash);
    snapshot.scope_key = scope_key.unwrap_or(expected_scope_key);
    if snapshot.fork_hash != expected_fork_hash {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "fork_hash must match the file manifest",
        )));
    }
    if snapshot.scope_key != expected_scope_key {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "scope_key must match project_id and repo_ref",
        )));
    }
    validate_codebase_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn decode_codebase_file_entry(value: &Value) -> Result<CodebaseFileEntry> {
    let Value::Map(entries) = value else {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "file entry must be a MessagePack map",
        )));
    };

    let mut path: Option<String> = None;
    let mut content_hash: Option<[u8; CODEBASE_CONTENT_HASH_LEN]> = None;
    let mut size_bytes: Option<u64> = None;
    let mut seen = [false; CODEBASE_FILE_ENTRY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "file entry keys must be strings",
            )));
        };
        let Some(index) = CODEBASE_FILE_ENTRY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "file entry key is not in the pinned CODEBASE_FILE_ENTRY_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "duplicate file entry key",
            )));
        }
        seen[index] = true;

        match CODEBASE_FILE_ENTRY_KEYS[index] {
            KEY_FILE_PATH => {
                let text =
                    value
                        .as_str()
                        .ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                            "file path must be a UTF-8 string",
                        )))?;
                validate_manifest_path(text)?;
                path = Some(text.to_owned());
            }
            KEY_FILE_CONTENT_HASH => {
                let Value::Binary(bytes) = value else {
                    return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                        "content_hash must be MessagePack binary",
                    )));
                };
                content_hash = Some(bytes.as_slice().try_into().map_err(|_| {
                    Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                        "content_hash must be 32-byte binary",
                    ))
                })?);
            }
            KEY_FILE_SIZE_BYTES => {
                size_bytes = Some(value.as_u64().ok_or(Error::Code(
                    CodeError::InvalidCodebaseSnapshotBody(
                        "size_bytes must be an unsigned integer",
                    ),
                ))?);
            }
            _ => unreachable!("index resolved from CODEBASE_FILE_ENTRY_KEYS"),
        }
    }

    Ok(CodebaseFileEntry {
        path: path.ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "missing required file entry key path",
        )))?,
        content_hash: content_hash.ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "missing required file entry key content_hash",
        )))?,
        size_bytes: size_bytes.ok_or(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "missing required file entry key size_bytes",
        )))?,
    })
}

pub(super) fn validate_codebase_snapshot(snapshot: &CodebaseSnapshot) -> Result<()> {
    validate_project_id(&snapshot.project_id)?;
    let canonical_repo_ref = snapshot.repo_ref.canonical();
    if RepoRef::parse(&canonical_repo_ref)? != snapshot.repo_ref {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "repo_ref must be a canonical v1 repo_ref",
        )));
    }
    if let Some(commit_hash) = &snapshot.commit_hash {
        validate_normalized_commit_hash(commit_hash)?;
    }
    if let Some(repo_commit) = snapshot.repo_ref.commit_hash()
        && snapshot.commit_hash.as_deref() != Some(repo_commit)
    {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "repo_ref commit must match snapshot commit_hash",
        )));
    }
    if snapshot.fork_hash != codebase_fork_hash(&snapshot.files)? {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "fork_hash must match the file manifest",
        )));
    }
    if snapshot.scope_key != codebase_scope_key(&snapshot.project_id, &snapshot.repo_ref)? {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "scope_key must match project_id and repo_ref",
        )));
    }
    if snapshot.files.len() > CODEBASE_SNAPSHOT_MAX_FILES {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "file manifest exceeds 100000 entries",
        )));
    }

    let mut previous: Option<&str> = None;
    for entry in &snapshot.files {
        validate_manifest_path(&entry.path)?;
        if let Some(prev) = previous
            && prev >= entry.path.as_str()
        {
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "file manifest paths must be sorted and unique",
            )));
        }
        previous = Some(entry.path.as_str());
    }
    Ok(())
}

fn hash_from_value<const N: usize>(value: &Value, context: &'static str) -> Result<[u8; N]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(context)));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Code(CodeError::InvalidCodebaseSnapshotBody(context)))
}

fn codebase_fork_hash(files: &[CodebaseFileEntry]) -> Result<CodebaseForkHash> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CODEBASE_FORK_HASH_DOMAIN);
    write_hash_len(&mut hasher, files.len())?;
    for entry in files {
        validate_manifest_path(&entry.path)?;
        write_hash_str(&mut hasher, &entry.path)?;
        hasher.update(&entry.content_hash);
        hasher.update(&entry.size_bytes.to_le_bytes());
    }
    Ok(hasher.finalize().into())
}

fn codebase_scope_key(project_id: &str, repo_ref: &RepoRef) -> Result<CodebaseScopeKey> {
    validate_project_id(project_id)?;
    let repo_ref = repo_ref.canonical();
    let mut hasher = blake3::Hasher::new();
    hasher.update(CODEBASE_SCOPE_KEY_DOMAIN);
    write_hash_str(&mut hasher, project_id)?;
    write_hash_str(&mut hasher, &repo_ref)?;
    Ok(hasher.finalize().into())
}

fn write_hash_str(hasher: &mut blake3::Hasher, value: &str) -> Result<()> {
    write_hash_len(hasher, value.len())?;
    hasher.update(value.as_bytes());
    Ok(())
}

pub(super) fn write_hash_len(hasher: &mut blake3::Hasher, value: usize) -> Result<()> {
    let value = u64::try_from(value)
        .map_err(|_| Error::ArithmeticOverflow("codebase hash length overflow"))?;
    hasher.update(&value.to_le_bytes());
    Ok(())
}

pub(super) fn validate_bounded_text(
    text: &str,
    max_bytes: usize,
    context: &'static str,
) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(context)));
    }
    if text.chars().any(char::is_control) {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "text fields must not contain control characters",
        )));
    }
    Ok(())
}

pub type CodebaseForkHash = [u8; CODEBASE_FORK_HASH_LEN];

pub type CodebaseScopeKey = [u8; CODEBASE_SCOPE_KEY_LEN];
