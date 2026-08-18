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
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CODE_ARTIFACT};
use crate::secret_snapshot::{SnapshotCustodyReport, custody_key, encode_report};
use crate::store::Store;
use crate::temporal::TimeRange;

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
    let Some(raw) = store
        .vault_meta
        .get(wtxn, &key)?
        .map(|value| value.to_vec())
    else {
        delete_index_rows_for_id(store, wtxn, CODEBASE_SCOPE_INDEX_KEY_PREFIX, id)?;
        return Ok(false);
    };

    match decode_codebase_snapshot(&raw) {
        Ok(snapshot) => {
            store.vault_meta.delete(wtxn, &key)?;
            // The sidecar is keyed by fork, so retain it while another artifact uses it.
            if !fork_has_other_snapshot(store, wtxn, &snapshot.fork_hash, id)? {
                store
                    .vault_meta
                    .delete(wtxn, &custody_key(&snapshot.fork_hash))?;
            }
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
    let Some(raw) = store
        .vault_meta
        .get(wtxn, &key)?
        .map(|value| value.to_vec())
    else {
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
        // Filter from a read transaction before the artifact identity is committed.
        scan_codebase_snapshot_metadata(&snapshot)?;
        let rtxn = self.store.env.read_txn()?;
        let (files, custody_report) =
            self.apply_custody_to_snapshot(&rtxn, &snapshot, &|path| {
                // `blobs` is sorted by path above, so preserve logarithmic lookup here.
                blobs
                    .binary_search_by_key(&path, |blob| blob.path.as_str())
                    .ok()
                    .map(|index| blobs[index].data.clone())
            })?;
        drop(rtxn);
        let snapshot = CodebaseSnapshot::new(
            snapshot.project_id.clone(),
            snapshot.repo_ref.clone(),
            snapshot.commit_hash,
            files,
        )?;
        // Custody filtering rebuilt the manifest above, so every downstream
        // write derives from the retained snapshot rather than the ingested
        // tree: excluded and quarantined blobs must not survive as raw ASSET
        // bodies or as symbols derived from their contents. Reclaiming blobs
        // persisted by earlier, unfiltered ingests is follow-up ONE-1946.
        let retained_paths = snapshot
            .files
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let code_artifact_id = codebase_snapshot_entity_id(&snapshot)?;
        let code_body = CodeArtifactBody::new(
            "Summarize the repository snapshot.",
            snapshot.fork_hash,
            repo_ref.canonical(),
        );
        let code_body = crate::code_artifact::encode_code_artifact_body(&code_body)?;

        let mut batch = self.batch();
        for blob in &blobs {
            if !retained_paths.contains(blob.path.as_str()) {
                continue;
            }
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
        let mut wtxn = self.store.env.write_txn()?;
        self.put_filtered_codebase_snapshot_in_txn(
            &mut wtxn,
            &code_artifact_id,
            &snapshot,
            custody_report,
        )?;
        wtxn.commit()?;
        let symbol_sources = blobs
            .iter()
            .filter(|blob| retained_paths.contains(blob.path.as_str()))
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
        file_contents: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<()> {
        validate_codebase_snapshot(snapshot)?;
        scan_codebase_snapshot_metadata(snapshot)?;
        let mut wtxn = self.store.env.write_txn()?;
        // Evaluate custody exclusions in the transaction that persists the snapshot.
        let (files, custody_report) =
            self.apply_custody_to_snapshot(&wtxn, snapshot, file_contents)?;
        let filtered_snapshot = CodebaseSnapshot::new(
            snapshot.project_id.clone(),
            snapshot.repo_ref.clone(),
            snapshot.commit_hash.clone(),
            files,
        )?;
        self.put_filtered_codebase_snapshot_in_txn(
            &mut wtxn,
            code_artifact_id,
            &filtered_snapshot,
            custody_report,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    fn put_filtered_codebase_snapshot_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        code_artifact_id: &EntityId,
        filtered_snapshot: &CodebaseSnapshot,
        custody_report: SnapshotCustodyReport,
    ) -> Result<()> {
        let encoded = encode_codebase_snapshot(filtered_snapshot)?;
        let custody_report = encode_report(&custody_report)?;
        let Some(raw) = self.store.entities.get(wtxn, code_artifact_id.as_bytes())? else {
            return Err(Error::EntityNotFound);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "snapshot target is not a CODE_ARTIFACT",
            ));
        }
        let artifact = decode_code_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let artifact_repo_ref = RepoRef::parse(&artifact.repo_ref)?;
        if artifact_repo_ref != filtered_snapshot.repo_ref {
            return Err(Error::InvalidCodebaseSnapshotBody(
                "snapshot repo_ref must match CODE artifact repo_ref",
            ));
        }

        delete_codebase_snapshot_in_txn(&self.store, wtxn, code_artifact_id)?;
        self.store
            .vault_meta
            .put(wtxn, &codebase_snapshot_key(code_artifact_id), &encoded)?;
        self.store.vault_meta.put(
            wtxn,
            &custody_key(&filtered_snapshot.fork_hash),
            &custody_report,
        )?;
        self.store.vault_meta.put(
            wtxn,
            &codebase_repo_index_key(&filtered_snapshot.repo_ref, code_artifact_id),
            &[],
        )?;
        self.store.vault_meta.put(
            wtxn,
            &codebase_project_index_key(&filtered_snapshot.project_id, code_artifact_id),
            &[],
        )?;
        self.store.vault_meta.put(
            wtxn,
            &codebase_fork_index_key(&filtered_snapshot.fork_hash, code_artifact_id),
            &[],
        )?;
        put_scope_index_rows_for_snapshot(&self.store, wtxn, code_artifact_id, filtered_snapshot)?;
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
        decode_codebase_snapshot(&raw).map(Some)
    }

    /// Reads the value-free custody report stored beside a filtered snapshot.
    pub fn get_codebase_snapshot_custody_report(
        &self,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Option<crate::secret_snapshot::SnapshotCustodyReport>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&rtxn, &custody_key(fork_hash))? else {
            return Ok(None);
        };
        rmp_serde::from_slice(&raw)
            .map(Some)
            .map_err(|_| Error::InvalidCodebaseSnapshotBody("decode custody report"))
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

fn fork_has_other_snapshot(
    store: &Store,
    wtxn: &RwTxn<'_>,
    fork_hash: &CodebaseForkHash,
    id: &EntityId,
) -> Result<bool> {
    let prefix = codebase_fork_index_prefix(fork_hash);
    for entry in store.vault_meta.prefix_iter(wtxn, &prefix)? {
        let (key, _) = entry?;
        let Some(bytes) = key.get(prefix.len()..) else {
            return Ok(true);
        };
        let Ok(bytes) = bytes.try_into() else {
            return Ok(true);
        };
        let Ok(other) = EntityId::from_bytes(bytes) else {
            return Ok(true);
        };
        if other != *id {
            return Ok(true);
        }
    }
    Ok(false)
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
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == ENTITY_TYPE_CODE_ARTIFACT {
            ids.push(id);
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests;
