//! Vault persistence for codebase snapshots: ingest methods, transactions, and index keys.

use super::ingest::{
    HostedMediaHashMatchProvider, NoopHostedMediaHashMatchProvider, RepoIngestBlob,
    RepoIngestConfig, RepoIngestResult, check_hosted_media_hash_matches, collect_repo_blobs,
    scan_codebase_snapshot_metadata, validate_project_id,
};
use super::repo_ref::RepoRef;
use super::snapshot::{
    CODEBASE_CONTENT_HASH_LEN, CodebaseFileEntry, CodebaseForkHash, CodebaseScopeKey,
    CodebaseSnapshot, CodebaseSnapshotMount, decode_codebase_snapshot, encode_codebase_snapshot,
    validate_codebase_snapshot, write_hash_len,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::code_artifact::{CodeArtifactBody, decode_code_artifact_body};
use crate::code_symbol::{CodeSymbolSource, derive_code_symbol_graph_from_sources};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::ArtifactError;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CODE_ARTIFACT};
use crate::secret_snapshot::{SnapshotCustodyReport, custody_key, encode_report};
use crate::store::Store;
use crate::temporal::TimeRange;
use heed::{RoTxn, RwTxn};

const CODEBASE_SNAPSHOT_KEY_PREFIX: &[u8] = b"codebase:snapshot:v1:";

const CODEBASE_REPO_INDEX_KEY_PREFIX: &[u8] = b"codebase:repo:v1:";

const CODEBASE_PROJECT_INDEX_KEY_PREFIX: &[u8] = b"codebase:project:v1:";

const CODEBASE_FORK_INDEX_KEY_PREFIX: &[u8] = b"codebase:fork:v1:";

const CODEBASE_SCOPE_INDEX_KEY_PREFIX: &[u8] = b"codebase:scope:v1:";

const CODEBASE_ASSET_ID_DOMAIN: &[u8] = b"oneiron:codebase-asset-entity:v1";

const CODEBASE_SNAPSHOT_ID_DOMAIN: &[u8] = b"oneiron:codebase-snapshot-entity:v1";

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

pub(super) fn codebase_asset_entity_id(
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    entity_id_from_hash_material(CODEBASE_ASSET_ID_DOMAIN, &[content_hash])
}

pub(super) fn codebase_snapshot_entity_id(snapshot: &CodebaseSnapshot) -> Result<EntityId> {
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
    RepoRef::parse(&artifact.repo_ref).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "repo_ref must be a valid v1 repo_ref",
        ))
    })
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
