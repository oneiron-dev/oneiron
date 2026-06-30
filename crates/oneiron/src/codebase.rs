use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, secret_scan};
use crate::code_artifact::decode_code_artifact_body;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{ENTITY_TYPE_CODE_ARTIFACT, EntityId};

pub const CODEBASE_REPO_REF_MAX_BYTES: usize = 1024;
pub const CODEBASE_PROJECT_ID_MAX_BYTES: usize = 256;
pub const CODEBASE_FILE_PATH_MAX_BYTES: usize = 4096;
pub const CODEBASE_CONTENT_HASH_LEN: usize = 32;
pub const CODEBASE_COMMIT_HASH_HEX_LEN: usize = 40;
pub const CODEBASE_SNAPSHOT_MAX_FILES: usize = 100_000;
pub const CODEBASE_SNAPSHOT_BODY_KEYS: [&str; 4] =
    ["project_id", "repo_ref", "commit_hash", "files"];
pub const CODEBASE_FILE_ENTRY_KEYS: [&str; 3] = ["path", "content_hash", "size_bytes"];

const KEY_PROJECT_ID: &str = CODEBASE_SNAPSHOT_BODY_KEYS[0];
const KEY_REPO_REF: &str = CODEBASE_SNAPSHOT_BODY_KEYS[1];
const KEY_COMMIT_HASH: &str = CODEBASE_SNAPSHOT_BODY_KEYS[2];
const KEY_FILES: &str = CODEBASE_SNAPSHOT_BODY_KEYS[3];
const KEY_FILE_PATH: &str = CODEBASE_FILE_ENTRY_KEYS[0];
const KEY_FILE_CONTENT_HASH: &str = CODEBASE_FILE_ENTRY_KEYS[1];
const KEY_FILE_SIZE_BYTES: &str = CODEBASE_FILE_ENTRY_KEYS[2];

const CODEBASE_SNAPSHOT_KEY_PREFIX: &[u8] = b"codebase:snapshot:v1:";
const CODEBASE_REPO_INDEX_KEY_PREFIX: &[u8] = b"codebase:repo:v1:";
const CODEBASE_PROJECT_INDEX_KEY_PREFIX: &[u8] = b"codebase:project:v1:";

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoRef {
    LocalFolder {
        path: String,
    },
    GitHubAtCommit {
        owner: String,
        repo: String,
        commit: String,
    },
}

impl RepoRef {
    pub fn parse(input: &str) -> Result<Self> {
        validate_bounded_text(
            input,
            CODEBASE_REPO_REF_MAX_BYTES,
            "repo_ref must be non-empty and at most 1024 bytes",
        )?;
        if input.trim() != input {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "repo_ref must not have leading or trailing whitespace",
            ));
        }

        if let Some(path) = input.strip_prefix("local:") {
            return parse_local_repo_ref(path);
        }
        if let Some(path) = input.strip_prefix("file://") {
            return parse_local_repo_ref(path);
        }

        if let Some(rest) = input.strip_prefix("github:") {
            return parse_github_repo_ref(rest);
        }
        if let Some(rest) = input.strip_prefix("git:") {
            return parse_github_repo_ref(rest);
        }
        parse_github_repo_ref(input)
    }

    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::LocalFolder { path } => format!("local:{path}"),
            Self::GitHubAtCommit {
                owner,
                repo,
                commit,
            } => {
                format!("github:{owner}/{repo}#{commit}")
            }
        }
    }

    #[must_use]
    pub fn commit_hash(&self) -> Option<&str> {
        match self {
            Self::LocalFolder { .. } => None,
            Self::GitHubAtCommit { commit, .. } => Some(commit.as_str()),
        }
    }
}

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
    pub files: Vec<CodebaseFileEntry>,
}

impl CodebaseSnapshot {
    pub fn new(
        project_id: impl Into<String>,
        repo_ref: RepoRef,
        commit_hash: Option<String>,
        files: Vec<CodebaseFileEntry>,
    ) -> Result<Self> {
        let mut snapshot = Self {
            project_id: project_id.into(),
            repo_ref,
            commit_hash: commit_hash.map(normalize_commit_hash).transpose()?,
            files,
        };
        snapshot.files.sort_by(|a, b| a.path.cmp(&b.path));
        validate_codebase_snapshot(&snapshot)?;
        Ok(snapshot)
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
        (Value::from(KEY_FILES), Value::Array(files)),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("codebase snapshot MessagePack encode failed"))?;
    Ok(out)
}

pub fn decode_codebase_snapshot(bytes: &[u8]) -> Result<CodebaseSnapshot> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidCodebaseSnapshotBody("snapshot is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "trailing bytes after snapshot map",
        ));
    }
    decode_codebase_snapshot_value(&value)
}

pub(crate) fn codebase_candidate_matches_filters(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    repo_ref: Option<&RepoRef>,
    project_id: Option<&str>,
) -> Result<bool> {
    if let Some(repo_ref) = repo_ref {
        let key = codebase_repo_index_key(repo_ref, id);
        if store.vault_meta.get(rtxn, &key)?.is_none() {
            return Ok(false);
        }
    }
    if let Some(project_id) = project_id {
        validate_project_id(project_id)?;
        let key = codebase_project_index_key(project_id, id);
        if store.vault_meta.get(rtxn, &key)?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn delete_codebase_snapshot_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let key = codebase_snapshot_key(id);
    let Some(raw) = store.vault_meta.get(wtxn, &key)?.map(<[u8]>::to_vec) else {
        return Ok(false);
    };

    match decode_codebase_snapshot(&raw) {
        Ok(snapshot) => {
            store.vault_meta.delete(wtxn, &key)?;
            delete_exact_index_rows_for_snapshot(store, wtxn, id, &snapshot)?;
        }
        Err(_) => {
            store.vault_meta.delete(wtxn, &key)?;
            delete_index_rows_for_id(store, wtxn, CODEBASE_REPO_INDEX_KEY_PREFIX, id)?;
            delete_index_rows_for_id(store, wtxn, CODEBASE_PROJECT_INDEX_KEY_PREFIX, id)?;
        }
    }
    Ok(true)
}

pub(crate) fn reconcile_codebase_snapshot_after_code_artifact_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    old_code_artifact_body: &[u8],
    new_code_artifact_body: &[u8],
) -> Result<()> {
    let key = codebase_snapshot_key(id);
    let Some(raw) = store.vault_meta.get(wtxn, &key)?.map(<[u8]>::to_vec) else {
        return Ok(());
    };

    let new_repo_ref = code_artifact_repo_ref_from_body(new_code_artifact_body)?;
    let old_repo_ref = code_artifact_repo_ref_from_body(old_code_artifact_body).ok();
    let snapshot = match decode_codebase_snapshot(&raw) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            delete_codebase_snapshot_in_txn(store, wtxn, id)?;
            return Ok(());
        }
    };

    if old_repo_ref.as_ref() != Some(&new_repo_ref) || snapshot.repo_ref != new_repo_ref {
        delete_codebase_snapshot_in_txn(store, wtxn, id)?;
    }
    Ok(())
}

impl Vault {
    pub fn put_codebase_snapshot(
        &self,
        code_artifact_id: &EntityId,
        snapshot: &CodebaseSnapshot,
    ) -> Result<()> {
        validate_codebase_snapshot(snapshot)?;
        scan_codebase_snapshot_metadata(snapshot)?;
        let encoded = encode_codebase_snapshot(snapshot)?;
        let mut wtxn = self.store.env.write_txn()?;
        let Some(raw) = self
            .store
            .entities
            .get(&wtxn, code_artifact_id.as_bytes())?
        else {
            return Err(Error::EntityNotFound);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "snapshot target is not a CODE_ARTIFACT",
            ));
        }
        let artifact = decode_code_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let artifact_repo_ref = RepoRef::parse(&artifact.repo_ref)?;
        if artifact_repo_ref != snapshot.repo_ref {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "snapshot repo_ref must match CODE artifact repo_ref",
            ));
        }

        delete_codebase_snapshot_in_txn(&self.store, &mut wtxn, code_artifact_id)?;
        self.store.vault_meta.put(
            &mut wtxn,
            &codebase_snapshot_key(code_artifact_id),
            &encoded,
        )?;
        self.store.vault_meta.put(
            &mut wtxn,
            &codebase_repo_index_key(&snapshot.repo_ref, code_artifact_id),
            &[],
        )?;
        self.store.vault_meta.put(
            &mut wtxn,
            &codebase_project_index_key(&snapshot.project_id, code_artifact_id),
            &[],
        )?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_codebase_snapshot(
        &self,
        code_artifact_id: &EntityId,
    ) -> Result<Option<CodebaseSnapshot>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &codebase_snapshot_key(code_artifact_id))?
        else {
            return Ok(None);
        };
        decode_codebase_snapshot(raw).map(Some)
    }

    pub fn codebase_snapshots_by_repo_ref(&self, repo_ref: &RepoRef) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let prefix = codebase_repo_index_prefix(repo_ref);
        codebase_ids_by_index_prefix(&self.store, &rtxn, &prefix)
    }

    pub fn codebase_snapshots_by_project_id(&self, project_id: &str) -> Result<Vec<EntityId>> {
        validate_project_id(project_id)?;
        let rtxn = self.store.env.read_txn()?;
        let prefix = codebase_project_index_prefix(project_id);
        codebase_ids_by_index_prefix(&self.store, &rtxn, &prefix)
    }
}

fn decode_codebase_snapshot_value(value: &Value) -> Result<CodebaseSnapshot> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "snapshot must be a MessagePack map",
        ));
    };

    let mut project_id: Option<String> = None;
    let mut repo_ref: Option<RepoRef> = None;
    let mut commit_hash: Option<Option<String>> = None;
    let mut files: Option<Vec<CodebaseFileEntry>> = None;
    let mut seen = [false; CODEBASE_SNAPSHOT_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "snapshot keys must be strings",
            ));
        };
        let Some(index) = CODEBASE_SNAPSHOT_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "snapshot key is not in the pinned CODEBASE_SNAPSHOT_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodebaseSnapshotBody("duplicate snapshot key"));
        }
        seen[index] = true;

        match CODEBASE_SNAPSHOT_BODY_KEYS[index] {
            KEY_PROJECT_ID => {
                let text = value.as_str().ok_or(Error::InvalidCodebaseSnapshotBody(
                    "project_id must be a UTF-8 string",
                ))?;
                validate_project_id(text)?;
                project_id = Some(text.to_owned());
            }
            KEY_REPO_REF => {
                let text = value.as_str().ok_or(Error::InvalidCodebaseSnapshotBody(
                    "repo_ref must be a UTF-8 string",
                ))?;
                repo_ref = Some(RepoRef::parse(text)?);
            }
            KEY_COMMIT_HASH => {
                commit_hash = Some(match value {
                    Value::Nil => None,
                    _ => Some(normalize_commit_hash(value.as_str().ok_or(
                        Error::InvalidCodebaseSnapshotBody(
                            "commit_hash must be null or a UTF-8 string",
                        ),
                    )?)?),
                });
            }
            KEY_FILES => {
                let Value::Array(values) = value else {
                    return Err(Error::InvalidCodebaseSnapshotBody(
                        "files must be a MessagePack array",
                    ));
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

    let snapshot = CodebaseSnapshot {
        project_id: project_id.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required snapshot key project_id",
        ))?,
        repo_ref: repo_ref.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required snapshot key repo_ref",
        ))?,
        commit_hash: commit_hash.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required snapshot key commit_hash",
        ))?,
        files: files.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required snapshot key files",
        ))?,
    };
    validate_codebase_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn decode_codebase_file_entry(value: &Value) -> Result<CodebaseFileEntry> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "file entry must be a MessagePack map",
        ));
    };

    let mut path: Option<String> = None;
    let mut content_hash: Option<[u8; CODEBASE_CONTENT_HASH_LEN]> = None;
    let mut size_bytes: Option<u64> = None;
    let mut seen = [false; CODEBASE_FILE_ENTRY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "file entry keys must be strings",
            ));
        };
        let Some(index) = CODEBASE_FILE_ENTRY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "file entry key is not in the pinned CODEBASE_FILE_ENTRY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "duplicate file entry key",
            ));
        }
        seen[index] = true;

        match CODEBASE_FILE_ENTRY_KEYS[index] {
            KEY_FILE_PATH => {
                let text = value.as_str().ok_or(Error::InvalidCodebaseSnapshotBody(
                    "file path must be a UTF-8 string",
                ))?;
                validate_manifest_path(text)?;
                path = Some(text.to_owned());
            }
            KEY_FILE_CONTENT_HASH => {
                let Value::Binary(bytes) = value else {
                    return Err(Error::InvalidCodebaseSnapshotBody(
                        "content_hash must be MessagePack binary",
                    ));
                };
                content_hash = Some(bytes.as_slice().try_into().map_err(|_| {
                    Error::InvalidCodebaseSnapshotBody("content_hash must be 32-byte binary")
                })?);
            }
            KEY_FILE_SIZE_BYTES => {
                size_bytes = Some(value.as_u64().ok_or(Error::InvalidCodebaseSnapshotBody(
                    "size_bytes must be an unsigned integer",
                ))?);
            }
            _ => unreachable!("index resolved from CODEBASE_FILE_ENTRY_KEYS"),
        }
    }

    Ok(CodebaseFileEntry {
        path: path.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required file entry key path",
        ))?,
        content_hash: content_hash.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required file entry key content_hash",
        ))?,
        size_bytes: size_bytes.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required file entry key size_bytes",
        ))?,
    })
}

fn validate_codebase_snapshot(snapshot: &CodebaseSnapshot) -> Result<()> {
    validate_project_id(&snapshot.project_id)?;
    let canonical_repo_ref = snapshot.repo_ref.canonical();
    if RepoRef::parse(&canonical_repo_ref)? != snapshot.repo_ref {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "repo_ref must be a canonical v1 repo_ref",
        ));
    }
    if let Some(commit_hash) = &snapshot.commit_hash {
        validate_normalized_commit_hash(commit_hash)?;
    }
    if let Some(repo_commit) = snapshot.repo_ref.commit_hash()
        && snapshot.commit_hash.as_deref() != Some(repo_commit)
    {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "GitHub repo_ref commit must match snapshot commit_hash",
        ));
    }
    if snapshot.files.len() > CODEBASE_SNAPSHOT_MAX_FILES {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "file manifest exceeds 100000 entries",
        ));
    }

    let mut previous: Option<&str> = None;
    for entry in &snapshot.files {
        validate_manifest_path(&entry.path)?;
        if let Some(prev) = previous
            && prev >= entry.path.as_str()
        {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "file manifest paths must be sorted and unique",
            ));
        }
        previous = Some(entry.path.as_str());
    }
    Ok(())
}

fn scan_codebase_snapshot_metadata(snapshot: &CodebaseSnapshot) -> Result<()> {
    secret_scan::scan_metadata_field(&snapshot.project_id)?;
    let repo_ref = snapshot.repo_ref.canonical();
    secret_scan::scan_metadata_field(&repo_ref)?;
    if let Some(commit_hash) = &snapshot.commit_hash {
        secret_scan::scan_metadata_field(commit_hash)?;
    }
    for entry in &snapshot.files {
        secret_scan::scan_metadata_field(&entry.path)?;
    }
    Ok(())
}

fn validate_project_id(project_id: &str) -> Result<()> {
    validate_bounded_text(
        project_id,
        CODEBASE_PROJECT_ID_MAX_BYTES,
        "project_id must be non-empty and at most 256 bytes",
    )?;
    if project_id.trim() != project_id {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "project_id must not have leading or trailing whitespace",
        ));
    }
    Ok(())
}

fn validate_manifest_path(path: &str) -> Result<()> {
    validate_bounded_text(
        path,
        CODEBASE_FILE_PATH_MAX_BYTES,
        "file path must be non-empty and at most 4096 bytes",
    )?;
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "file path must be repository-relative",
        ));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "file path must be normalized and cannot contain . or .. segments",
        ));
    }
    Ok(())
}

fn validate_bounded_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidCodebaseSnapshotBody(context));
    }
    if text.chars().any(char::is_control) {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "text fields must not contain control characters",
        ));
    }
    Ok(())
}

fn parse_local_repo_ref(path: &str) -> Result<RepoRef> {
    validate_bounded_text(
        path,
        CODEBASE_FILE_PATH_MAX_BYTES,
        "local repo_ref path must be non-empty and at most 4096 bytes",
    )?;
    if path.trim() != path {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "local repo_ref path must not have leading or trailing whitespace",
        ));
    }
    Ok(RepoRef::LocalFolder {
        path: path.to_owned(),
    })
}

fn parse_github_repo_ref(input: &str) -> Result<RepoRef> {
    let rest = input
        .strip_prefix("https://github.com/")
        .or_else(|| input.strip_prefix("http://github.com/"))
        .or_else(|| input.strip_prefix("git@github.com:"))
        .unwrap_or(input);
    let (repo_path, commit) = rest
        .split_once('#')
        .ok_or(Error::InvalidCodebaseSnapshotBody(
            "GitHub repo_ref must include #<40-hex-commit>",
        ))?;
    let commit = normalize_commit_hash(commit)?;

    let repo_path = repo_path.trim_end_matches(".git");
    let mut parts = repo_path.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if parts.next().is_some() || owner.is_empty() || repo.is_empty() {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "GitHub repo_ref must identify owner/repo",
        ));
    }
    validate_github_segment(owner, "GitHub owner")?;
    validate_github_segment(repo, "GitHub repo")?;
    Ok(RepoRef::GitHubAtCommit {
        owner: owner.to_owned(),
        repo: repo.to_owned(),
        commit,
    })
}

fn validate_github_segment(segment: &str, context: &'static str) -> Result<()> {
    if segment.len() > 100
        || !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidCodebaseSnapshotBody(context));
    }
    Ok(())
}

fn normalize_commit_hash(input: impl AsRef<str>) -> Result<String> {
    let input = input.as_ref();
    if input.len() != CODEBASE_COMMIT_HASH_HEX_LEN || !input.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "commit hash must be 40 hexadecimal characters",
        ));
    }
    Ok(input.to_ascii_lowercase())
}

fn validate_normalized_commit_hash(input: &str) -> Result<()> {
    if normalize_commit_hash(input)? != input {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "commit hash must use lowercase hexadecimal",
        ));
    }
    Ok(())
}

fn codebase_snapshot_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODEBASE_SNAPSHOT_KEY_PREFIX.len() + id.as_bytes().len());
    key.extend_from_slice(CODEBASE_SNAPSHOT_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

fn codebase_repo_index_prefix(repo_ref: &RepoRef) -> Vec<u8> {
    scoped_index_prefix(
        CODEBASE_REPO_INDEX_KEY_PREFIX,
        repo_ref.canonical().as_bytes(),
    )
}

fn codebase_project_index_prefix(project_id: &str) -> Vec<u8> {
    scoped_index_prefix(CODEBASE_PROJECT_INDEX_KEY_PREFIX, project_id.as_bytes())
}

fn codebase_repo_index_key(repo_ref: &RepoRef, id: &EntityId) -> Vec<u8> {
    scoped_index_key(
        CODEBASE_REPO_INDEX_KEY_PREFIX,
        repo_ref.canonical().as_bytes(),
        id,
    )
}

fn codebase_project_index_key(project_id: &str, id: &EntityId) -> Vec<u8> {
    scoped_index_key(CODEBASE_PROJECT_INDEX_KEY_PREFIX, project_id.as_bytes(), id)
}

fn code_artifact_repo_ref_from_body(bytes: &[u8]) -> Result<RepoRef> {
    let artifact = decode_code_artifact_body(bytes)?;
    RepoRef::parse(&artifact.repo_ref)
        .map_err(|_| Error::InvalidCodeArtifactBody("repo_ref must be a valid v1 repo_ref"))
}

fn delete_exact_index_rows_for_snapshot(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    snapshot: &CodebaseSnapshot,
) -> Result<()> {
    store
        .vault_meta
        .delete(wtxn, &codebase_repo_index_key(&snapshot.repo_ref, id))?;
    store
        .vault_meta
        .delete(wtxn, &codebase_project_index_key(&snapshot.project_id, id))?;
    Ok(())
}

fn scoped_index_prefix(prefix: &[u8], value: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + value.len() + 1);
    key.extend_from_slice(prefix);
    key.extend_from_slice(value);
    key.push(0);
    key
}

fn scoped_index_key(prefix: &[u8], value: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = scoped_index_prefix(prefix, value);
    key.extend_from_slice(id.as_bytes());
    key
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

fn codebase_ids_by_index_prefix(
    store: &Store,
    rtxn: &RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for entry in store.vault_meta.prefix_iter(rtxn, prefix)? {
        let (key, _) = entry?;
        let id_bytes = key
            .get(prefix.len()..)
            .ok_or(Error::CorruptedIndex("codebase index key"))?;
        if id_bytes.len() != 16 {
            return Err(Error::CorruptedIndex("codebase index key"));
        }
        let id = EntityId::from_bytes(
            id_bytes
                .try_into()
                .map_err(|_| Error::CorruptedIndex("codebase index key"))?,
        )
        .map_err(|_| Error::CorruptedIndex("codebase index key"))?;
        let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
            continue;
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_CODE_ARTIFACT {
            ids.push(id);
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_artifact::{CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody};
    use crate::error::{Error, ErrorKind};
    use crate::types::{HnswConfig, PackFormat, TextAnalyzerConfig, TimeRange, VaultConfig};

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
        RepoRef::parse("github:oneiron-dev/other#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("repo ref")
    }

    fn entity_id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).expect("entity id")
    }

    const GITHUB_TOKEN_SECRET_FIXTURE: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

    fn assert_secret_scan_rejected(err: Error) {
        match err {
            Error::GateWriteRejected {
                outcome,
                reason_codes,
            } => {
                assert_eq!(outcome, "deny");
                assert_eq!(
                    reason_codes.as_slice(),
                    &["gate.secret_scan.detected", "gate.secret_scan.github_token"]
                );
            }
            other => panic!("expected secret-scan GateWriteRejected, got {other:?}"),
        }
    }

    fn file(path: &str, hash_byte: u8) -> CodebaseFileEntry {
        CodebaseFileEntry::new(
            path,
            [hash_byte; CODEBASE_CONTENT_HASH_LEN],
            u64::from(hash_byte),
        )
    }

    fn snapshot(project_id: &str, repo_ref: RepoRef) -> Result<CodebaseSnapshot> {
        CodebaseSnapshot::new(
            project_id,
            repo_ref,
            Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
            vec![file("src/lib.rs", 2), file("Cargo.toml", 1)],
        )
    }

    fn code_body(repo_ref: &RepoRef) -> CodeArtifactBody {
        CodeArtifactBody::new(
            "Summarize the codebase snapshot.",
            [0xA5; CODE_ARTIFACT_SUMMARY_HASH_LEN],
            repo_ref.canonical(),
        )
    }

    #[test]
    fn codebase_repo_ref_parse_validates_local_and_github_at_commit() -> Result<()> {
        let local = RepoRef::parse("local:/Users/example/project")?;
        assert_eq!(
            local,
            RepoRef::LocalFolder {
                path: "/Users/example/project".to_owned()
            }
        );
        assert_eq!(local.canonical(), "local:/Users/example/project");

        let github = RepoRef::parse(
            "https://github.com/oneiron-dev/oneiron.git#9D561405A81FFBF29D1369CD848E0EF9FCA4F277",
        )?;
        assert_eq!(github, repo_ref());
        assert_eq!(
            github.canonical(),
            "github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277"
        );

        let err = RepoRef::parse("github:oneiron-dev/oneiron#main")
            .expect_err("branch names are not commit-pinned repo refs");
        assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
        Ok(())
    }

    #[test]
    fn codebase_snapshot_codec_round_trips_manifest() -> Result<()> {
        let snapshot = snapshot("project.alpha", repo_ref())?;
        assert_eq!(snapshot.files[0].path, "Cargo.toml");
        assert_eq!(snapshot.files[1].path, "src/lib.rs");

        let encoded = encode_codebase_snapshot(&snapshot)?;
        let decoded = decode_codebase_snapshot(&encoded)?;

        assert_eq!(decoded, snapshot);
        Ok(())
    }

    #[test]
    fn codebase_snapshot_codec_rejects_unsorted_or_duplicate_manifest() {
        let raw = CodebaseSnapshot {
            project_id: "project.alpha".to_owned(),
            repo_ref: repo_ref(),
            commit_hash: Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
            files: vec![file("src/lib.rs", 1), file("src/lib.rs", 2)],
        };
        let err = encode_codebase_snapshot(&raw).expect_err("duplicate paths fail closed");
        assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
    }

    #[test]
    fn codebase_snapshot_codec_rejects_backslash_manifest_paths() {
        let raw = CodebaseSnapshot {
            project_id: "project.alpha".to_owned(),
            repo_ref: repo_ref(),
            commit_hash: Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
            files: vec![file("src\\..\\secret", 1)],
        };

        let err = encode_codebase_snapshot(&raw)
            .expect_err("backslash paths must fail closed instead of hiding traversal");

        assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
    }

    #[test]
    fn codebase_snapshot_codec_rejects_invalid_constructed_repo_ref() {
        let raw = CodebaseSnapshot {
            project_id: "project.alpha".to_owned(),
            repo_ref: RepoRef::GitHubAtCommit {
                owner: "oneiron-dev".to_owned(),
                repo: "oneiron".to_owned(),
                commit: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            },
            commit_hash: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
            files: vec![file("src/main.rs", 1)],
        };

        let err = encode_codebase_snapshot(&raw)
            .expect_err("constructed repo_ref values must still satisfy the v1 grammar");

        assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
    }

    #[test]
    fn codebase_snapshot_vault_round_trip_and_queries() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = EntityId::now();
        let repo_ref = repo_ref();
        let snapshot = snapshot("project.alpha", repo_ref.clone())?;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_ref),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_codebase_snapshot(&id, &snapshot)?;

        assert_eq!(vault.get_codebase_snapshot(&id)?, Some(snapshot));
        assert_eq!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?, vec![id]);
        assert_eq!(
            vault.codebase_snapshots_by_project_id("project.alpha")?,
            vec![id]
        );
        assert!(
            vault
                .codebase_snapshots_by_project_id("project.beta")?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn codebase_snapshot_rejects_secret_file_path_before_sidecar_mutation() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity_id(0x33);
        let repo_ref = repo_ref();
        let safe_snapshot = snapshot("project.alpha", repo_ref.clone())?;
        let secret_path = format!("src/{GITHUB_TOKEN_SECRET_FIXTURE}");
        let secret_snapshot = CodebaseSnapshot::new(
            "project.alpha",
            repo_ref.clone(),
            Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
            vec![file("Cargo.toml", 1), file(&secret_path, 3)],
        )?;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_ref),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_codebase_snapshot(&id, &safe_snapshot)?;

        let err = vault
            .put_codebase_snapshot(&id, &secret_snapshot)
            .expect_err("secret file path must reject before sidecar mutation");

        assert_secret_scan_rejected(err);
        assert_eq!(vault.get_codebase_snapshot(&id)?, Some(safe_snapshot));
        assert_eq!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?, vec![id]);
        assert_eq!(
            vault.codebase_snapshots_by_project_id("project.alpha")?,
            vec![id]
        );
        Ok(())
    }

    #[test]
    fn codebase_snapshot_delete_cleans_sidecar_indexes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = EntityId::now();
        let repo_ref = repo_ref();
        let snapshot = snapshot("project.alpha", repo_ref.clone())?;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_ref),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_codebase_snapshot(&id, &snapshot)?;
        assert_eq!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?, vec![id]);

        assert!(vault.delete_entity(&id)?);

        assert!(vault.get_codebase_snapshot(&id)?.is_none());
        assert!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?.is_empty());
        assert!(
            vault
                .codebase_snapshots_by_project_id("project.alpha")?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn codebase_snapshot_batch_delete_cleans_sidecar_indexes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity_id(0x31);
        let repo_ref = repo_ref();
        let snapshot = snapshot("project.alpha", repo_ref.clone())?;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_ref),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_codebase_snapshot(&id, &snapshot)?;

        vault.batch().delete(&id).commit()?;

        assert!(vault.get_codebase_snapshot(&id)?.is_none());
        assert!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?.is_empty());
        assert!(
            vault
                .codebase_snapshots_by_project_id("project.alpha")?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn codebase_snapshot_code_artifact_repo_ref_overwrite_cleans_sidecar_indexes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let id = entity_id(0x32);
        let repo_a = repo_ref();
        let repo_b = repo_ref_b();
        let snapshot = snapshot("project.alpha", repo_a.clone())?;

        vault.put_code_artifact(
            &id,
            &code_body(&repo_a),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_codebase_snapshot(&id, &snapshot)?;
        assert_eq!(vault.codebase_snapshots_by_repo_ref(&repo_a)?, vec![id]);

        vault.put_code_artifact(
            &id,
            &code_body(&repo_b),
            TimeRange { start: 12, end: 12 },
            13,
        )?;

        assert!(vault.get_codebase_snapshot(&id)?.is_none());
        assert!(vault.codebase_snapshots_by_repo_ref(&repo_a)?.is_empty());
        assert!(vault.codebase_snapshots_by_repo_ref(&repo_b)?.is_empty());
        assert!(
            vault
                .codebase_snapshots_by_project_id("project.alpha")?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn codebase_filters_apply_to_search_and_context_pack() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let repo_a = repo_ref();
        let repo_b = repo_ref_b();
        let id_a = EntityId::now();
        let id_b = EntityId::now();

        vault.put_code_artifact(
            &id_a,
            &code_body(&repo_a),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_codebase_snapshot(&id_a, &snapshot("project.alpha", repo_a.clone())?)?;
        vault.put_code_artifact(
            &id_b,
            &code_body(&repo_b),
            TimeRange { start: 12, end: 12 },
            13,
        )?;
        vault.put_codebase_snapshot(
            &id_b,
            &CodebaseSnapshot::new(
                "project.beta",
                repo_b,
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
                vec![file("src/main.rs", 3)],
            )?,
        )?;
        vault
            .batch()
            .text(&id_a, &[("body", "sharedneedle alpha")])
            .text(&id_b, &[("body", "sharedneedle beta")])
            .commit()?;

        let all = vault.query().search_text("sharedneedle", 10).run()?;
        assert_eq!(all.len(), 2);

        let by_repo = vault
            .query()
            .search_text("sharedneedle", 10)
            .filter_repo_ref(repo_a)
            .run()?;
        assert_eq!(by_repo.len(), 1);
        assert_eq!(by_repo[0].id, id_a);

        let by_project = vault
            .query()
            .search_text("sharedneedle", 10)
            .filter_project_id("project.beta")
            .run()?;
        assert_eq!(by_project.len(), 1);
        assert_eq!(by_project[0].id, id_b);

        let pack = vault
            .context_pack()
            .format(PackFormat::Json)
            .search_text("sharedneedle", 10)
            .filter_project_id("project.alpha")
            .run()?;
        assert_eq!(pack.results.len(), 1);
        assert_eq!(pack.results[0].id, id_a);
        Ok(())
    }

    #[test]
    fn codebase_filters_apply_before_channel_top_k_limits() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let repo_a = repo_ref();
        let repo_b = repo_ref_b();
        let id_a = entity_id(0x41);
        let id_b = entity_id(0x42);

        vault.put_code_artifact(
            &id_a,
            &code_body(&repo_a),
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        vault.put_codebase_snapshot(&id_a, &snapshot("project.alpha", repo_a)?)?;
        vault.put_code_artifact(
            &id_b,
            &code_body(&repo_b),
            TimeRange { start: 12, end: 12 },
            13,
        )?;
        vault.put_codebase_snapshot(
            &id_b,
            &CodebaseSnapshot::new(
                "project.beta",
                repo_b,
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
                vec![file("src/main.rs", 3)],
            )?,
        )?;
        vault
            .batch()
            .text(&id_a, &[("body", "needle needle needle needle")])
            .text(&id_b, &[("body", "needle")])
            .vector(&id_a, &[1.0, 0.0, 0.0, 0.0])
            .vector(&id_b, &[0.0, 1.0, 0.0, 0.0])
            .commit()?;

        let unscoped_text_top = vault.query().search_text("needle", 1).run()?;
        assert_eq!(unscoped_text_top.len(), 1);
        assert_eq!(unscoped_text_top[0].id, id_a);

        let scoped_text_top = vault
            .query()
            .search_text("needle", 1)
            .filter_project_id("project.beta")
            .run()?;
        assert_eq!(scoped_text_top.len(), 1);
        assert_eq!(scoped_text_top[0].id, id_b);

        let scoped_pack = vault
            .context_pack()
            .format(PackFormat::Json)
            .search_text("needle", 1)
            .filter_project_id("project.beta")
            .run()?;
        assert_eq!(scoped_pack.results.len(), 1);
        assert_eq!(scoped_pack.results[0].id, id_b);

        let unscoped_vector_top = vault
            .query()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .run()?;
        assert_eq!(unscoped_vector_top.len(), 1);
        assert_eq!(unscoped_vector_top[0].id, id_a);

        let scoped_vector_top = vault
            .query()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
            .filter_project_id("project.beta")
            .run()?;
        assert_eq!(scoped_vector_top.len(), 1);
        assert_eq!(scoped_vector_top[0].id, id_b);
        Ok(())
    }
}
