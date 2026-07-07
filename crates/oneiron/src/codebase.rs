use std::fmt;
use std::path::PathBuf;

use gix::bstr::ByteSlice;
use gix::object::tree::EntryKind;
use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, secret_scan};
use crate::code_artifact::{CodeArtifactBody, decode_code_artifact_body};
use crate::code_symbol::{CodeSymbolSource, derive_code_symbol_graph_from_sources};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{
    ENTITY_ID_LEN, ENTITY_TYPE_ASSET, ENTITY_TYPE_CODE_ARTIFACT, EntityId, TimeRange,
    bytes_to_hex_lower,
};

pub const CODEBASE_REPO_REF_MAX_BYTES: usize = 1024;
pub const CODEBASE_PROJECT_ID_MAX_BYTES: usize = 256;
pub const CODEBASE_FILE_PATH_MAX_BYTES: usize = 4096;
pub const CODEBASE_CONTENT_HASH_LEN: usize = 32;
pub const CODEBASE_FORK_HASH_LEN: usize = 32;
pub const CODEBASE_SCOPE_KEY_LEN: usize = 32;
pub const CODEBASE_COMMIT_HASH_HEX_LEN: usize = 40;
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

const CODEBASE_SNAPSHOT_KEY_PREFIX: &[u8] = b"codebase:snapshot:v1:";
const CODEBASE_REPO_INDEX_KEY_PREFIX: &[u8] = b"codebase:repo:v1:";
const CODEBASE_PROJECT_INDEX_KEY_PREFIX: &[u8] = b"codebase:project:v1:";
const CODEBASE_FORK_INDEX_KEY_PREFIX: &[u8] = b"codebase:fork:v1:";
const CODEBASE_SCOPE_INDEX_KEY_PREFIX: &[u8] = b"codebase:scope:v1:";

const CODEBASE_FORK_HASH_DOMAIN: &[u8] = b"oneiron:codebase-forkhash:v1";
const CODEBASE_SCOPE_KEY_DOMAIN: &[u8] = b"oneiron:codebase-scope:v1";
const CODEBASE_ASSET_ID_DOMAIN: &[u8] = b"oneiron:codebase-asset-entity:v1";
const CODEBASE_SNAPSHOT_ID_DOMAIN: &[u8] = b"oneiron:codebase-snapshot-entity:v1";

pub type CodebaseForkHash = [u8; CODEBASE_FORK_HASH_LEN];
pub type CodebaseScopeKey = [u8; CODEBASE_SCOPE_KEY_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoRef {
    LocalFolder {
        path: String,
        commit: String,
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

    pub fn from_task_list_repo_url(repo_url: &str, commit_ref: &str) -> Result<Self> {
        validate_bounded_text(
            repo_url,
            CODEBASE_REPO_REF_MAX_BYTES,
            "TASK_LIST repoUrl must be non-empty and at most 1024 bytes",
        )?;
        if repo_url.trim() != repo_url {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "TASK_LIST repoUrl must not have leading or trailing whitespace",
            ));
        }
        if repo_url.contains('#') {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "TASK_LIST repoUrl migration requires commit_ref separately",
            ));
        }
        let commit = normalize_commit_hash(commit_ref)?;
        Self::parse(&format!("{repo_url}#{commit}"))
    }

    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::LocalFolder { path, commit } => format!("local:{path}#{commit}"),
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
            Self::LocalFolder { commit, .. } => Some(commit.as_str()),
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoIngestConfig {
    pub repo_path: PathBuf,
    pub editable_whitelist: Vec<String>,
}

impl RepoIngestConfig {
    pub fn new(
        repo_path: impl Into<PathBuf>,
        editable_whitelist: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let editable_whitelist = editable_whitelist
            .into_iter()
            .map(Into::into)
            .map(|path| {
                validate_manifest_path(&path)?;
                Ok(path)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            repo_path: repo_path.into(),
            editable_whitelist,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoIngestResult {
    pub code_artifact_id: EntityId,
    pub snapshot: CodebaseSnapshot,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostedMediaHashMatchInput<'a> {
    pub project_id: &'a str,
    pub path: &'a str,
    pub media_type: &'static str,
    pub content_hash: [u8; CODEBASE_CONTENT_HASH_LEN],
    pub size_bytes: u64,
    pub bytes: &'a [u8],
}

impl fmt::Debug for HostedMediaHashMatchInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostedMediaHashMatchInput")
            .field("project_id", &self.project_id)
            .field("path", &self.path)
            .field("media_type", &self.media_type)
            .field("content_hash", &bytes_to_hex_lower(&self.content_hash))
            .field("size_bytes", &self.size_bytes)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostedMediaHashMatchDecision {
    NoMatch,
    KnownMatch { provider: String, reference: String },
}

pub trait HostedMediaHashMatchProvider {
    fn check_hosted_media(
        &self,
        input: HostedMediaHashMatchInput<'_>,
    ) -> Result<HostedMediaHashMatchDecision>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopHostedMediaHashMatchProvider;

impl HostedMediaHashMatchProvider for NoopHostedMediaHashMatchProvider {
    fn check_hosted_media(
        &self,
        _input: HostedMediaHashMatchInput<'_>,
    ) -> Result<HostedMediaHashMatchDecision> {
        Ok(HostedMediaHashMatchDecision::NoMatch)
    }
}

pub struct CodebaseSnapshotMount<'a> {
    vault: &'a Vault,
    code_artifact_id: EntityId,
    snapshot: CodebaseSnapshot,
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

pub(crate) fn codebase_candidate_matches_scope_key(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    scope_key: &CodebaseScopeKey,
) -> Result<bool> {
    Ok(store
        .vault_meta
        .get(rtxn, &codebase_scope_index_key(scope_key, id))?
        .is_some())
}

pub(crate) fn delete_codebase_snapshot_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let key = codebase_snapshot_key(id);
    let Some(raw) = store.vault_meta.get(wtxn, &key)?.map(<[u8]>::to_vec) else {
        delete_index_rows_for_id(store, wtxn, CODEBASE_SCOPE_INDEX_KEY_PREFIX, id)?;
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
            delete_index_rows_for_id(store, wtxn, CODEBASE_FORK_INDEX_KEY_PREFIX, id)?;
            delete_index_rows_for_id(store, wtxn, CODEBASE_SCOPE_INDEX_KEY_PREFIX, id)?;
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
    pub fn ingest_local_repo_at_commit(
        &self,
        project_id: impl Into<String>,
        config: &RepoIngestConfig,
        commit_ref: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<RepoIngestResult> {
        let provider = NoopHostedMediaHashMatchProvider;
        self.ingest_local_repo_at_commit_with_hosted_media_hash_match_provider(
            project_id, config, commit_ref, occurred, learned_at, &provider,
        )
    }

    pub fn ingest_local_repo_at_commit_with_hosted_media_hash_match_provider(
        &self,
        project_id: impl Into<String>,
        config: &RepoIngestConfig,
        commit_ref: &str,
        occurred: TimeRange,
        learned_at: u64,
        hash_match_provider: &(impl HostedMediaHashMatchProvider + ?Sized),
    ) -> Result<RepoIngestResult> {
        let project_id = project_id.into();
        validate_project_id(&project_id)?;
        if commit_ref.trim().is_empty() || commit_ref.chars().any(char::is_control) {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "commit_ref must be non-empty and cannot contain control characters",
            ));
        }

        let repo = gix::discover(&config.repo_path).map_err(|_| {
            Error::InvalidCodebaseSnapshotBody("repo_path must point inside a local Git repository")
        })?;
        let commit_id = repo
            .rev_parse_single(commit_ref)
            .map_err(|_| Error::InvalidCodebaseSnapshotBody("commit_ref did not resolve"))?;
        let commit_object = commit_id.object().map_err(|_| {
            Error::InvalidCodebaseSnapshotBody("commit_ref object could not be read")
        })?;
        let commit = commit_object.try_into_commit().map_err(|_| {
            Error::InvalidCodebaseSnapshotBody("commit_ref must resolve to a commit")
        })?;
        let commit_hash = commit.id().to_string();
        let tree = commit
            .tree()
            .map_err(|_| Error::InvalidCodebaseSnapshotBody("commit tree could not be read"))?;
        let repo_path = std::fs::canonicalize(&config.repo_path).map_err(|_| {
            Error::InvalidCodebaseSnapshotBody("repo_path must be a canonicalizable local path")
        })?;
        let repo_ref = RepoRef::LocalFolder {
            path: repo_path.to_string_lossy().into_owned(),
            commit: commit_hash.clone(),
        };

        let mut blobs = Vec::<RepoIngestBlob>::new();
        collect_repo_blobs(&tree, "", &mut blobs)?;
        blobs.sort_by(|a, b| a.path.cmp(&b.path));
        check_hosted_media_hash_matches(&project_id, &blobs, hash_match_provider)?;

        let files = blobs
            .iter()
            .map(|blob| {
                Ok(CodebaseFileEntry::new(
                    blob.path.clone(),
                    blob.content_hash,
                    blob.size_bytes,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let snapshot = CodebaseSnapshot::new(
            project_id,
            repo_ref.clone(),
            Some(commit_hash.clone()),
            files,
        )?;
        let code_artifact_id = codebase_snapshot_entity_id(&snapshot)?;
        let code_body = CodeArtifactBody::new(
            "Summarize the repository snapshot.",
            snapshot.fork_hash,
            repo_ref.canonical(),
        );
        let code_body = crate::code_artifact::encode_code_artifact_body(&code_body)?;

        let mut batch = self.batch();
        for blob in &blobs {
            let asset_id = codebase_asset_entity_id(&blob.content_hash)?;
            batch = batch.put(
                &asset_id,
                ENTITY_TYPE_ASSET,
                occurred,
                learned_at,
                &blob.data,
            );
        }
        batch
            .put(
                &code_artifact_id,
                ENTITY_TYPE_CODE_ARTIFACT,
                occurred,
                learned_at,
                &code_body,
            )
            .commit()?;
        self.put_codebase_snapshot(&code_artifact_id, &snapshot)?;
        let symbol_sources = blobs
            .iter()
            .filter_map(|blob| {
                let text = std::str::from_utf8(&blob.data).ok()?;
                Some(CodeSymbolSource::new(blob.path.as_str(), text))
            })
            .collect::<Vec<_>>();
        let symbol_graph =
            derive_code_symbol_graph_from_sources(repo_ref, Some(commit_hash), symbol_sources)?;
        self.put_code_symbol_graph(&code_artifact_id, &symbol_graph, occurred, learned_at)?;

        Ok(RepoIngestResult {
            code_artifact_id,
            snapshot,
        })
    }

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
        self.store.vault_meta.put(
            &mut wtxn,
            &codebase_fork_index_key(&snapshot.fork_hash, code_artifact_id),
            &[],
        )?;
        put_scope_index_rows_for_snapshot(&self.store, &mut wtxn, code_artifact_id, snapshot)?;
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

    pub fn codebase_snapshots_by_fork_hash(
        &self,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let prefix = codebase_fork_index_prefix(fork_hash);
        codebase_ids_by_index_prefix(&self.store, &rtxn, &prefix)
    }

    pub fn mount_codebase_snapshot(
        &self,
        code_artifact_id: &EntityId,
    ) -> Result<Option<CodebaseSnapshotMount<'_>>> {
        let Some(snapshot) = self.get_codebase_snapshot(code_artifact_id)? else {
            return Ok(None);
        };
        Ok(Some(CodebaseSnapshotMount {
            vault: self,
            code_artifact_id: *code_artifact_id,
            snapshot,
        }))
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
    let mut fork_hash: Option<CodebaseForkHash> = None;
    let mut scope_key: Option<CodebaseScopeKey> = None;
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

    let mut snapshot = CodebaseSnapshot {
        project_id: project_id.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required snapshot key project_id",
        ))?,
        repo_ref: repo_ref.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required snapshot key repo_ref",
        ))?,
        commit_hash: commit_hash.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required snapshot key commit_hash",
        ))?,
        fork_hash: [0; CODEBASE_FORK_HASH_LEN],
        scope_key: [0; CODEBASE_SCOPE_KEY_LEN],
        files: files.ok_or(Error::InvalidCodebaseSnapshotBody(
            "missing required snapshot key files",
        ))?,
    };
    let expected_fork_hash = codebase_fork_hash(&snapshot.files)?;
    let expected_scope_key = codebase_scope_key(&snapshot.project_id, &snapshot.repo_ref)?;
    snapshot.fork_hash = fork_hash.unwrap_or(expected_fork_hash);
    snapshot.scope_key = scope_key.unwrap_or(expected_scope_key);
    if snapshot.fork_hash != expected_fork_hash {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "fork_hash must match the file manifest",
        ));
    }
    if snapshot.scope_key != expected_scope_key {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "scope_key must match project_id and repo_ref",
        ));
    }
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
            "repo_ref commit must match snapshot commit_hash",
        ));
    }
    if snapshot.fork_hash != codebase_fork_hash(&snapshot.files)? {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "fork_hash must match the file manifest",
        ));
    }
    if snapshot.scope_key != codebase_scope_key(&snapshot.project_id, &snapshot.repo_ref)? {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "scope_key must match project_id and repo_ref",
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

fn hash_from_value<const N: usize>(value: &Value, context: &'static str) -> Result<[u8; N]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidCodebaseSnapshotBody(context));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidCodebaseSnapshotBody(context))
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

fn write_hash_len(hasher: &mut blake3::Hasher, value: usize) -> Result<()> {
    let value = u64::try_from(value)
        .map_err(|_| Error::ArithmeticOverflow("codebase hash length overflow"))?;
    hasher.update(&value.to_le_bytes());
    Ok(())
}

struct RepoIngestBlob {
    path: String,
    content_hash: [u8; CODEBASE_CONTENT_HASH_LEN],
    size_bytes: u64,
    data: Vec<u8>,
}

fn check_hosted_media_hash_matches(
    project_id: &str,
    blobs: &[RepoIngestBlob],
    provider: &(impl HostedMediaHashMatchProvider + ?Sized),
) -> Result<()> {
    for blob in blobs {
        let Some(media_type) = hosted_media_type_for_blob(&blob.path, &blob.data) else {
            continue;
        };
        let decision = provider.check_hosted_media(HostedMediaHashMatchInput {
            project_id,
            path: &blob.path,
            media_type,
            content_hash: blob.content_hash,
            size_bytes: blob.size_bytes,
            bytes: &blob.data,
        })?;
        match decision {
            HostedMediaHashMatchDecision::NoMatch => {}
            HostedMediaHashMatchDecision::KnownMatch {
                provider,
                reference,
            } => {
                return Err(Error::HostedMediaHashMatchKnownMatch {
                    provider: provider.into_boxed_str(),
                    reference: reference.into_boxed_str(),
                    path: blob.path.clone().into_boxed_str(),
                    content_hash: Box::new(blob.content_hash),
                });
            }
        }
    }
    Ok(())
}

fn hosted_media_type_for_blob(path: &str, bytes: &[u8]) -> Option<&'static str> {
    sniff_hosted_media_type(bytes).or_else(|| hosted_media_type_for_path(path))
}

fn hosted_media_type_for_path(path: &str) -> Option<&'static str> {
    let (_, extension) = path.rsplit_once('.')?;
    if extension.eq_ignore_ascii_case("png") {
        Some("image/png")
    } else if extension.eq_ignore_ascii_case("jpg") || extension.eq_ignore_ascii_case("jpeg") {
        Some("image/jpeg")
    } else if extension.eq_ignore_ascii_case("gif") {
        Some("image/gif")
    } else if extension.eq_ignore_ascii_case("webp") {
        Some("image/webp")
    } else if extension.eq_ignore_ascii_case("avif") {
        Some("image/avif")
    } else if extension.eq_ignore_ascii_case("heic") {
        Some("image/heic")
    } else if extension.eq_ignore_ascii_case("heif") {
        Some("image/heif")
    } else if extension.eq_ignore_ascii_case("mp4") || extension.eq_ignore_ascii_case("m4v") {
        Some("video/mp4")
    } else if extension.eq_ignore_ascii_case("mov") {
        Some("video/quicktime")
    } else if extension.eq_ignore_ascii_case("webm") {
        Some("video/webm")
    } else {
        None
    }
}

fn sniff_hosted_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.len() >= 3 && bytes[0..3] == [0xff, 0xd8, 0xff] {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if let Some(media_type) = sniff_iso_bmff_media_type(bytes) {
        Some(media_type)
    } else if bytes.starts_with(b"\x1a\x45\xdf\xa3")
        && bytes[..bytes.len().min(64)]
            .windows(4)
            .any(|w| w == b"webm")
    {
        Some("video/webm")
    } else {
        None
    }
}

fn sniff_iso_bmff_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 12 || &bytes[4..8] != b"ftyp" {
        return None;
    }
    let box_len = u32::from_be_bytes(bytes[0..4].try_into().ok()?) as usize;
    if box_len < 12 {
        return None;
    }
    let scan_len = box_len.min(bytes.len()).min(128);
    let brands = bytes[8..scan_len].chunks_exact(4);
    let mut fallback_video = false;
    for brand in brands {
        match brand {
            b"avif" | b"avis" => return Some("image/avif"),
            b"heic" | b"heix" | b"hevc" | b"hevx" => return Some("image/heic"),
            b"heif" | b"mif1" | b"msf1" => return Some("image/heif"),
            b"qt  " => return Some("video/quicktime"),
            b"isom" | b"iso2" | b"mp41" | b"mp42" | b"m4v " | b"M4V " | b"avc1" | b"dash" => {
                fallback_video = true;
            }
            _ => {}
        }
    }
    fallback_video.then_some("video/mp4")
}

fn collect_repo_blobs(
    tree: &gix::Tree<'_>,
    prefix: &str,
    out: &mut Vec<RepoIngestBlob>,
) -> Result<()> {
    for entry in tree.iter() {
        let entry = entry.map_err(|_| {
            Error::InvalidCodebaseSnapshotBody("Git tree entry could not be decoded")
        })?;
        let filename = entry
            .filename()
            .to_str()
            .map_err(|_| Error::InvalidCodebaseSnapshotBody("Git tree path must be UTF-8"))?;
        let path = if prefix.is_empty() {
            filename.to_owned()
        } else {
            format!("{prefix}/{filename}")
        };
        match entry.kind() {
            EntryKind::Tree => {
                validate_manifest_path(&path)?;
                let subtree_object = entry.object().map_err(|_| {
                    Error::InvalidCodebaseSnapshotBody("Git subtree object could not be read")
                })?;
                let subtree = subtree_object.try_into_tree().map_err(|_| {
                    Error::InvalidCodebaseSnapshotBody("Git subtree object could not be read")
                })?;
                collect_repo_blobs(&subtree, &path, out)?;
            }
            EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                validate_manifest_path(&path)?;
                let blob_object = entry.object().map_err(|_| {
                    Error::InvalidCodebaseSnapshotBody("Git blob object could not be read")
                })?;
                let mut blob = blob_object.try_into_blob().map_err(|_| {
                    Error::InvalidCodebaseSnapshotBody("Git blob object could not be read")
                })?;
                let data = blob.take_data();
                let content_hash = *blake3::hash(&data).as_bytes();
                let size_bytes = u64::try_from(data.len())
                    .map_err(|_| Error::ArithmeticOverflow("codebase blob length overflow"))?;
                out.push(RepoIngestBlob {
                    path,
                    content_hash,
                    size_bytes,
                    data,
                });
            }
            EntryKind::Commit => {}
        }
    }
    Ok(())
}

fn read_asset_blob(
    vault: &Vault,
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<Vec<u8>> {
    let asset_id = codebase_asset_entity_id(content_hash)?;
    let Some(raw) = vault.get_raw(&asset_id)? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_ASSET {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "manifest content hash did not resolve to an ASSET",
        ));
    }
    let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    if blake3::hash(&body).as_bytes() != content_hash {
        return Err(Error::CorruptedIndex("codebase asset content hash"));
    }
    Ok(body)
}

fn codebase_asset_entity_id(content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN]) -> Result<EntityId> {
    entity_id_from_hash_material(CODEBASE_ASSET_ID_DOMAIN, &[content_hash])
}

fn codebase_snapshot_entity_id(snapshot: &CodebaseSnapshot) -> Result<EntityId> {
    entity_id_from_hash_material(
        CODEBASE_SNAPSHOT_ID_DOMAIN,
        &[&snapshot.scope_key, &snapshot.fork_hash],
    )
}

pub(crate) fn entity_id_from_hash_material(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
    for salt in 0_u64..=u64::MAX {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&salt.to_le_bytes());
        for part in parts {
            write_hash_len(&mut hasher, part.len())?;
            hasher.update(part);
        }
        let hash = hasher.finalize();
        let mut id = [0_u8; ENTITY_ID_LEN];
        id.copy_from_slice(&hash.as_bytes()[..ENTITY_ID_LEN]);
        if let Ok(id) = EntityId::from_bytes(id) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "codebase deterministic entity id exhausted salt space",
    ))
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

fn parse_local_repo_ref(input: &str) -> Result<RepoRef> {
    let (path, commit) = input
        .split_once('#')
        .ok_or(Error::InvalidCodebaseSnapshotBody(
            "local repo_ref must include #<40-hex-commit>",
        ))?;
    let commit = normalize_commit_hash(commit)?;
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
        commit,
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

fn codebase_fork_index_prefix(fork_hash: &CodebaseForkHash) -> Vec<u8> {
    scoped_index_prefix(CODEBASE_FORK_INDEX_KEY_PREFIX, fork_hash)
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

fn codebase_fork_index_key(fork_hash: &CodebaseForkHash, id: &EntityId) -> Vec<u8> {
    scoped_index_key(CODEBASE_FORK_INDEX_KEY_PREFIX, fork_hash, id)
}

fn codebase_scope_index_key(scope_key: &CodebaseScopeKey, id: &EntityId) -> Vec<u8> {
    scoped_index_key(CODEBASE_SCOPE_INDEX_KEY_PREFIX, scope_key, id)
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
    store
        .vault_meta
        .delete(wtxn, &codebase_fork_index_key(&snapshot.fork_hash, id))?;
    store
        .vault_meta
        .delete(wtxn, &codebase_scope_index_key(&snapshot.scope_key, id))?;
    for entry in &snapshot.files {
        let asset_id = codebase_asset_entity_id(&entry.content_hash)?;
        store.vault_meta.delete(
            wtxn,
            &codebase_scope_index_key(&snapshot.scope_key, &asset_id),
        )?;
    }
    Ok(())
}

fn put_scope_index_rows_for_snapshot(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    code_artifact_id: &EntityId,
    snapshot: &CodebaseSnapshot,
) -> Result<()> {
    store.vault_meta.put(
        wtxn,
        &codebase_scope_index_key(&snapshot.scope_key, code_artifact_id),
        &[],
    )?;
    for entry in &snapshot.files {
        let asset_id = codebase_asset_entity_id(&entry.content_hash)?;
        store.vault_meta.put(
            wtxn,
            &codebase_scope_index_key(&snapshot.scope_key, &asset_id),
            &[],
        )?;
    }
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
    use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
    use crate::code_artifact::{CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody};
    use crate::code_revision::{CODE_REVISION_CLAIM_PREDICATE, CodeRevision};
    use crate::error::{Error, ErrorKind};
    use crate::pipeline::WorldScope;
    use crate::types::{
        ClaimCandidate, ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION,
        EdgeActorClass, EdgeKind, HnswConfig, PackFormat, TextAnalyzerConfig, TimeRange,
        VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
    };
    use std::cell::RefCell;
    use std::fs;
    use std::path::Path;
    use std::process::{Command, Stdio};

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

    fn local_repo_ref() -> RepoRef {
        RepoRef::parse("local:/Users/example/project#9d561405a81ffbf29d1369cd848e0ef9fca4f277")
            .expect("local repo ref")
    }

    fn local_repo_ref_b() -> RepoRef {
        RepoRef::parse("local:/Users/example/project#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("local repo ref")
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

    fn put_session(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
        vault.put_entity(
            &id,
            ENTITY_TYPE_SESSION,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"session",
        )
    }

    fn put_code_revision_claim(
        vault: &Vault,
        id: EntityId,
        subject: EntityId,
        learned_at: u64,
    ) -> Result<()> {
        let actor = EntityId::now();
        vault.put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"repo ref reviewer",
        )?;
        let candidate = ClaimCandidate::new(
            CODE_REVISION_CLAIM_PREDICATE,
            ClaimSubject::Entity(subject),
            Value::from("repo_ref changed"),
            0.9,
        );
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("repo-ref-change"))?,
            ClaimApprovalStatus::Auto,
        );
        vault
            .batch()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
            )
            .commit()?;
        vault.put_edge(&id, EdgeKind::ClaimOf, &subject, 1.0)
    }

    fn run_git(repo_dir: &Path, args: &[&str]) -> Result<()> {
        let status = Command::new("git")
            .args(args)
            .current_dir(repo_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| Error::InvariantViolation("git test command failed to start"))?;
        if !status.success() {
            return Err(Error::InvariantViolation("git test command failed"));
        }
        Ok(())
    }

    fn create_test_repo() -> Result<tempfile::TempDir> {
        let repo_dir = tempfile::tempdir()?;
        fs::create_dir_all(repo_dir.path().join("src"))?;
        fs::write(
            repo_dir.path().join("Cargo.toml"),
            b"[package]\nname = \"tiny\"\n",
        )?;
        fs::write(
            repo_dir.path().join("src/lib.rs"),
            b"pub fn answer() -> u8 { 42 }\n",
        )?;
        run_git(repo_dir.path(), &["init"])?;
        run_git(
            repo_dir.path(),
            &["config", "user.email", "oneiron@example.test"],
        )?;
        run_git(repo_dir.path(), &["config", "user.name", "Oneiron Test"])?;
        run_git(repo_dir.path(), &["add", "."])?;
        run_git(repo_dir.path(), &["commit", "-m", "initial"])?;
        Ok(repo_dir)
    }

    fn commit_test_file(repo_dir: &Path, path: &str, bytes: &[u8], message: &str) -> Result<()> {
        let full_path = repo_dir.join(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(full_path, bytes)?;
        run_git(repo_dir, &["add", path])?;
        run_git(repo_dir, &["commit", "-m", message])
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct HashMatchCall {
        project_id: String,
        path: String,
        media_type: &'static str,
        content_hash: [u8; CODEBASE_CONTENT_HASH_LEN],
        size_bytes: u64,
        bytes: Vec<u8>,
    }

    #[derive(Debug, Default)]
    struct RecordingHashMatchProvider {
        calls: RefCell<Vec<HashMatchCall>>,
    }

    impl HostedMediaHashMatchProvider for RecordingHashMatchProvider {
        fn check_hosted_media(
            &self,
            input: HostedMediaHashMatchInput<'_>,
        ) -> Result<HostedMediaHashMatchDecision> {
            self.calls.borrow_mut().push(HashMatchCall {
                project_id: input.project_id.to_owned(),
                path: input.path.to_owned(),
                media_type: input.media_type,
                content_hash: input.content_hash,
                size_bytes: input.size_bytes,
                bytes: input.bytes.to_vec(),
            });
            Ok(HostedMediaHashMatchDecision::NoMatch)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct KnownMatchProvider;

    impl HostedMediaHashMatchProvider for KnownMatchProvider {
        fn check_hosted_media(
            &self,
            _input: HostedMediaHashMatchInput<'_>,
        ) -> Result<HostedMediaHashMatchDecision> {
            Ok(HostedMediaHashMatchDecision::KnownMatch {
                provider: "unit-provider".to_owned(),
                reference: "case-123".to_owned(),
            })
        }
    }

    #[test]
    fn noop_hosted_media_hash_match_provider_reports_no_match() -> Result<()> {
        let bytes = b"secret-media-bytes";
        let input = HostedMediaHashMatchInput {
            project_id: "project.alpha",
            path: "portrait.JPG",
            media_type: "image/jpeg",
            content_hash: *blake3::hash(bytes).as_bytes(),
            size_bytes: u64::try_from(bytes.len())
                .map_err(|_| Error::ArithmeticOverflow("test bytes"))?,
            bytes,
        };

        let provider = NoopHostedMediaHashMatchProvider;
        assert_eq!(
            provider.check_hosted_media(input)?,
            HostedMediaHashMatchDecision::NoMatch
        );
        assert_eq!(
            hosted_media_type_for_blob("payload.bin", b"\xff\xd8\xff\xe0jpeg-body"),
            Some("image/jpeg")
        );
        assert_eq!(
            hosted_media_type_for_blob("portrait.JPG", b"extension-only-candidate"),
            Some("image/jpeg")
        );
        assert_eq!(hosted_media_type_for_blob("README.md", b"plain text"), None);

        let debug = format!("{input:?}");
        assert!(debug.contains("bytes: \"<redacted>\""));
        assert!(!debug.contains("secret-media-bytes"));
        Ok(())
    }

    #[test]
    fn codebase_repo_ref_parse_validates_local_and_github_at_commit() -> Result<()> {
        let local = local_repo_ref();
        assert_eq!(
            local,
            RepoRef::LocalFolder {
                path: "/Users/example/project".to_owned(),
                commit: "9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned(),
            }
        );
        assert_eq!(
            local.canonical(),
            "local:/Users/example/project#9d561405a81ffbf29d1369cd848e0ef9fca4f277"
        );
        let err = RepoRef::parse("local:/Users/example/project")
            .expect_err("local repo refs must be pinned to a commit");
        assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);

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
    fn task_list_repo_url_migrates_to_repo_ref_with_commit() -> Result<()> {
        let migrated = RepoRef::from_task_list_repo_url(
            "https://github.com/oneiron-dev/oneiron.git",
            "9D561405A81FFBF29D1369CD848E0EF9FCA4F277",
        )?;
        assert_eq!(migrated, repo_ref());

        let local = RepoRef::from_task_list_repo_url(
            "file:///Users/example/project",
            "9d561405a81ffbf29d1369cd848e0ef9fca4f277",
        )?;
        assert_eq!(local, local_repo_ref());
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
            fork_hash: [0; CODEBASE_FORK_HASH_LEN],
            scope_key: [0; CODEBASE_SCOPE_KEY_LEN],
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
            fork_hash: [0; CODEBASE_FORK_HASH_LEN],
            scope_key: [0; CODEBASE_SCOPE_KEY_LEN],
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
            fork_hash: [0; CODEBASE_FORK_HASH_LEN],
            scope_key: [0; CODEBASE_SCOPE_KEY_LEN],
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
    fn repo_ref_change_records_version_history_edges_and_consent_record() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let session = EntityId::now();
        let first_revision_id = EntityId::now();
        let second_revision_id = EntityId::now();
        let provenance_claim_id = EntityId::now();
        let first_repo = local_repo_ref();
        let second_repo = local_repo_ref_b();

        put_session(&vault, session, 90)?;
        vault.put_code_artifact(
            &first_revision_id,
            &code_body(&first_repo),
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )?;
        vault.put_code_artifact(
            &second_revision_id,
            &code_body(&second_repo),
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
        )?;
        put_code_revision_claim(&vault, provenance_claim_id, second_revision_id, 201)?;

        let first_revision = CodeRevision::commit(first_revision_id, session, 100);
        let second_revision =
            CodeRevision::commit_child(second_revision_id, session, first_revision_id, 200)
                .with_provenance_claim_id(provenance_claim_id);
        vault.commit_code_revision(&first_revision)?;
        vault.commit_code_revision(&second_revision)?;

        assert_eq!(
            vault.child_code_revisions(&first_revision_id)?,
            vec![second_revision]
        );
        assert_eq!(
            vault.targets(&second_revision_id, EdgeKind::Supersedes, None)?,
            vec![first_revision_id]
        );
        assert_eq!(
            vault.claims_for_subject(&second_revision_id)?,
            vec![provenance_claim_id]
        );
        let provenance = vault
            .get_claim(&provenance_claim_id)?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(provenance.approval, ClaimApprovalStatus::Auto);
        assert_eq!(provenance.source, Some(ClaimSource::UserStated));
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
    fn local_repo_ingest_is_idempotent_and_mounts_files() -> Result<()> {
        let repo_dir = create_test_repo()?;
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let config = RepoIngestConfig::new(repo_dir.path(), ["src/lib.rs"])?;

        let first = vault.ingest_local_repo_at_commit(
            "project.alpha",
            &config,
            "HEAD",
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        let second = vault.ingest_local_repo_at_commit(
            "project.alpha",
            &config,
            "HEAD",
            TimeRange { start: 10, end: 10 },
            11,
        )?;

        assert_eq!(second.code_artifact_id, first.code_artifact_id);
        assert_eq!(second.snapshot.fork_hash, first.snapshot.fork_hash);
        assert_eq!(second.snapshot.scope_key, first.snapshot.scope_key);
        assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_CODE_ARTIFACT)?, 1);
        assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_ASSET)?, 2);
        assert_eq!(
            vault.codebase_snapshots_by_fork_hash(&first.snapshot.fork_hash)?,
            vec![first.code_artifact_id]
        );

        let mount = vault
            .mount_codebase_snapshot(&first.code_artifact_id)?
            .expect("snapshot mount");
        assert!(mount.is_read_only());
        assert_eq!(mount.list_files(), vec!["Cargo.toml", "src/lib.rs"]);
        assert_eq!(
            mount.read_file("src/lib.rs")?,
            Some(b"pub fn answer() -> u8 { 42 }\n".to_vec())
        );

        let definitions = vault.code_symbol_definitions(&first.code_artifact_id, "answer")?;
        assert_eq!(definitions.len(), 1);
        assert_eq!(
            vault.get_entity_type(&definitions[0].entity_id)?,
            Some(ENTITY_TYPE_CODE_SYMBOL)
        );
        assert!(vault.edge_exists(
            &definitions[0].entity_id,
            EdgeKind::PartOf,
            &first.code_artifact_id
        )?);
        Ok(())
    }

    #[test]
    fn local_repo_ingest_calls_hash_match_provider_for_hosted_media_candidates() -> Result<()> {
        let repo_dir = create_test_repo()?;
        let media_bytes = b"not-a-real-image-but-route-media-by-extension";
        let renamed_media_bytes = b"\x89PNG\r\n\x1a\nmisnamed-png-body";
        commit_test_file(
            repo_dir.path(),
            "assets/payload.bin",
            renamed_media_bytes,
            "add renamed media",
        )?;
        commit_test_file(
            repo_dir.path(),
            "assets/portrait.jpg",
            media_bytes,
            "add media",
        )?;
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let config = RepoIngestConfig::new(repo_dir.path(), ["src/lib.rs"])?;
        let provider = RecordingHashMatchProvider::default();

        vault.ingest_local_repo_at_commit_with_hosted_media_hash_match_provider(
            "project.alpha",
            &config,
            "HEAD",
            TimeRange { start: 10, end: 10 },
            11,
            &provider,
        )?;

        let calls = provider.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls.as_slice(),
            &[
                HashMatchCall {
                    project_id: "project.alpha".to_owned(),
                    path: "assets/payload.bin".to_owned(),
                    media_type: "image/png",
                    content_hash: *blake3::hash(renamed_media_bytes).as_bytes(),
                    size_bytes: u64::try_from(renamed_media_bytes.len())
                        .map_err(|_| Error::ArithmeticOverflow("test renamed media bytes"))?,
                    bytes: renamed_media_bytes.to_vec(),
                },
                HashMatchCall {
                    project_id: "project.alpha".to_owned(),
                    path: "assets/portrait.jpg".to_owned(),
                    media_type: "image/jpeg",
                    content_hash: *blake3::hash(media_bytes).as_bytes(),
                    size_bytes: u64::try_from(media_bytes.len())
                        .map_err(|_| Error::ArithmeticOverflow("test media bytes"))?,
                    bytes: media_bytes.to_vec(),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn local_repo_ingest_preserves_known_match_metadata() -> Result<()> {
        let repo_dir = create_test_repo()?;
        let media_bytes = b"\xff\xd8\xff\xe0known-jpeg";
        commit_test_file(
            repo_dir.path(),
            "assets/known.bin",
            media_bytes,
            "add known media",
        )?;
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let config = RepoIngestConfig::new(repo_dir.path(), ["src/lib.rs"])?;

        let error = vault
            .ingest_local_repo_at_commit_with_hosted_media_hash_match_provider(
                "project.alpha",
                &config,
                "HEAD",
                TimeRange { start: 10, end: 10 },
                11,
                &KnownMatchProvider,
            )
            .unwrap_err();

        match error {
            Error::HostedMediaHashMatchKnownMatch {
                provider,
                reference,
                path,
                content_hash,
            } => {
                assert_eq!(&*provider, "unit-provider");
                assert_eq!(&*reference, "case-123");
                assert_eq!(&*path, "assets/known.bin");
                assert_eq!(*content_hash, *blake3::hash(media_bytes).as_bytes());
            }
            other => panic!("unexpected error: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn codebase_scope_key_clamps_world_set_retrieval() -> Result<()> {
        let repo_dir = create_test_repo()?;
        let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let config = RepoIngestConfig::new(repo_dir.path(), ["src/lib.rs"])?;
        let ingest = vault.ingest_local_repo_at_commit(
            "project.alpha",
            &config,
            "HEAD",
            TimeRange { start: 10, end: 10 },
            11,
        )?;
        let outside = entity_id(0x58);

        vault.put_entity(
            &outside,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 20, end: 20 },
            21,
            b"outside asset",
        )?;
        vault
            .batch()
            .text(&ingest.code_artifact_id, &[("body", "scopeneedle repo")])
            .text(&outside, &[("body", "scopeneedle outside")])
            .commit()?;

        let all = vault.query().search_text("scopeneedle", 10).run()?;
        assert_eq!(all.len(), 2);

        let scoped = vault
            .query()
            .search_text("scopeneedle", 10)
            .world(WorldScope::WorldSet(ingest.snapshot.scope_key))
            .run()?;
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id, ingest.code_artifact_id);

        let asset_id = codebase_asset_entity_id(&ingest.snapshot.files[0].content_hash)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(codebase_candidate_matches_scope_key(
            &vault.store,
            &rtxn,
            &asset_id,
            &ingest.snapshot.scope_key
        )?);
        assert!(!codebase_candidate_matches_scope_key(
            &vault.store,
            &rtxn,
            &outside,
            &ingest.snapshot.scope_key
        )?);
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
