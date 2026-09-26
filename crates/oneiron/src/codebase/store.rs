//! Vault persistence for codebase snapshots: ingest methods, transactions, and index keys.

use super::ingest::{
    HostedMediaHashMatchProvider, NoopHostedMediaHashMatchProvider, RepoIngestBlob,
    RepoIngestConfig, RepoIngestResult, check_hosted_media_hash_matches, collect_repo_blobs,
    scan_codebase_snapshot_metadata, validate_project_id,
};
use super::repo_ref::RepoRef;
use super::snapshot::{
    CODEBASE_CONTENT_HASH_LEN, CodebaseFileEntry, CodebaseForkHash, CodebaseScopeKey,
    CodebaseSnapshot, CodebaseSnapshotMount, validate_codebase_snapshot, write_hash_len,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::code_artifact::{CodeArtifactBody, decode_code_artifact_body};
use crate::code_symbol::{CodeSymbolSource, derive_code_symbol_graph_from_sources};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{ArtifactError, CodeError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CODE_ARTIFACT};
use crate::secret_snapshot::SnapshotCustodyReport;
use crate::side_table::{self, FixedSideKey, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;
use heed::{RoTxn, RwTxn};

const CODEBASE_ASSET_ID_DOMAIN: &[u8] = b"oneiron:codebase-asset-entity:v1";

const CODEBASE_SNAPSHOT_ID_DOMAIN: &[u8] = b"oneiron:codebase-snapshot-entity:v1";

/// A codebase snapshot's file manifest, keyed by the CODE_ARTIFACT entity id it snapshots.
const SNAPSHOTS: SideTable<EntityId, CodebaseSnapshot, Raw> =
    SideTable::new(&side_table::CODEBASE_SNAPSHOT);

/// The custody report accompanying one filtered snapshot, keyed by its fork hash. The row's
/// codec is `Raw`: the const and key builder used to live in `secret_snapshot.rs`, but every
/// put/get/delete call site has always been here, so the [`crate::side_table::RawValue`] impl
/// lives beside [`SnapshotCustodyReport`] in `secret_snapshot.rs` instead (ONE-side_table).
const CUSTODY_REPORTS: SideTable<String, SnapshotCustodyReport, Raw> =
    SideTable::new(&side_table::SECRET_SNAPSHOT_CODEBASE_CUSTODY);

/// Index from a repo reference's canonical text to the codebase snapshots recorded against it.
const REPO_INDEX: SideTable<TextIndexKey, (), Raw> =
    SideTable::new(&side_table::CODEBASE_REPO_INDEX);

/// Index from a project id to the codebase snapshots recorded against it.
const PROJECT_INDEX: SideTable<TextIndexKey, (), Raw> =
    SideTable::new(&side_table::CODEBASE_PROJECT_INDEX);

/// Index from a fork hash to the codebase snapshots sharing it.
const FORK_INDEX: SideTable<HashIndexKey, (), Raw> =
    SideTable::new(&side_table::CODEBASE_FORK_INDEX);

/// Index from a codebase scope key to the snapshot and asset entities visible under it.
const SCOPE_INDEX: SideTable<HashIndexKey, (), Raw> =
    SideTable::new(&side_table::CODEBASE_SCOPE_INDEX);

/// `<text>` + `\0` + id16 — the shape every text-keyed codebase index row (repo-ref, project id)
/// has always spelled.
struct TextIndexKey {
    value: String,
    id: EntityId,
}

impl SideKey for TextIndexKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.value.as_bytes());
        out.push(0);
        self.id.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let id_start = bytes.len().checked_sub(<EntityId as FixedSideKey>::WIDTH)?;
        let (rest, id) = bytes.split_at(id_start);
        let (&separator, value) = rest.split_last()?;
        if separator != 0 {
            return None;
        }
        Some(Self {
            value: String::from_utf8(value.to_vec()).ok()?,
            id: EntityId::decode_key(id)?,
        })
    }
}

/// `<hash32>` + `\0` + id16 — the shape every hash-keyed codebase index row (fork hash, scope
/// key) has always spelled.
struct HashIndexKey {
    value: [u8; 32],
    id: EntityId,
}

impl SideKey for HashIndexKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value);
        out.push(0);
        self.id.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let id_start = bytes.len().checked_sub(<EntityId as FixedSideKey>::WIDTH)?;
        let (rest, id) = bytes.split_at(id_start);
        let (&separator, value) = rest.split_last()?;
        if separator != 0 {
            return None;
        }
        Some(Self {
            value: value.try_into().ok()?,
            id: EntityId::decode_key(id)?,
        })
    }
}

/// The `EntityId` half of a codebase index key, common to every index shape.
trait IndexRowId {
    fn id(&self) -> EntityId;
}

impl IndexRowId for TextIndexKey {
    fn id(&self) -> EntityId {
        self.id
    }
}

impl IndexRowId for HashIndexKey {
    fn id(&self) -> EntityId {
        self.id
    }
}

pub(crate) fn codebase_candidate_matches_filters(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    repo_ref: Option<&RepoRef>,
    project_id: Option<&str>,
) -> Result<bool> {
    if let Some(repo_ref) = repo_ref {
        let key = TextIndexKey {
            value: repo_ref.canonical(),
            id: *id,
        };
        if !REPO_INDEX.contains(store, rtxn, &key)? {
            return Ok(false);
        }
    }
    if let Some(project_id) = project_id {
        validate_project_id(project_id)?;
        let key = TextIndexKey {
            value: project_id.to_owned(),
            id: *id,
        };
        if !PROJECT_INDEX.contains(store, rtxn, &key)? {
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
    SCOPE_INDEX.contains(
        store,
        rtxn,
        &HashIndexKey {
            value: *scope_key,
            id: *id,
        },
    )
}

pub(crate) fn delete_codebase_snapshot_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    match SNAPSHOTS.get(store, wtxn, id) {
        Ok(None) => {
            delete_index_rows_for_id(SCOPE_INDEX, store, wtxn, id)?;
            Ok(false)
        }
        Ok(Some(snapshot)) => {
            SNAPSHOTS.delete(store, wtxn, id)?;
            // The sidecar is keyed by fork, so retain it while another artifact uses it.
            if !fork_has_other_snapshot(store, wtxn, &snapshot.fork_hash, id)? {
                CUSTODY_REPORTS.delete(store, wtxn, &codebase_custody_key(&snapshot.fork_hash))?;
            }
            delete_exact_index_rows_for_snapshot(store, wtxn, id, &snapshot)?;
            Ok(true)
        }
        Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(_))) => {
            SNAPSHOTS.delete(store, wtxn, id)?;
            delete_index_rows_for_id(REPO_INDEX, store, wtxn, id)?;
            delete_index_rows_for_id(PROJECT_INDEX, store, wtxn, id)?;
            delete_index_rows_for_id(FORK_INDEX, store, wtxn, id)?;
            delete_index_rows_for_id(SCOPE_INDEX, store, wtxn, id)?;
            Ok(true)
        }
        Err(other) => Err(other),
    }
}

pub(crate) fn reconcile_codebase_snapshot_after_code_artifact_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    old_code_artifact_body: &[u8],
    new_code_artifact_body: &[u8],
) -> Result<()> {
    if !SNAPSHOTS.contains(store, wtxn, id)? {
        return Ok(());
    }

    let new_repo_ref = code_artifact_repo_ref_from_body(new_code_artifact_body)?;
    let old_repo_ref = code_artifact_repo_ref_from_body(old_code_artifact_body).ok();

    let snapshot = match SNAPSHOTS.get(store, wtxn, id) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return Ok(()),
        Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(_))) => {
            delete_codebase_snapshot_in_txn(store, wtxn, id)?;
            return Ok(());
        }
        Err(other) => return Err(other),
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
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "commit_ref must be non-empty and cannot contain control characters",
            )));
        }

        let repo = gix::discover(&config.repo_path).map_err(|_| {
            Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "repo_path must point inside a local Git repository",
            ))
        })?;
        let commit_id = repo.rev_parse_single(commit_ref).map_err(|_| {
            Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "commit_ref did not resolve",
            ))
        })?;
        let commit_object = commit_id.object().map_err(|_| {
            Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "commit_ref object could not be read",
            ))
        })?;
        let commit = commit_object.try_into_commit().map_err(|_| {
            Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "commit_ref must resolve to a commit",
            ))
        })?;
        let commit_hash = commit.id().to_string();
        let tree = commit.tree().map_err(|_| {
            Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "commit tree could not be read",
            ))
        })?;
        let repo_path = std::fs::canonicalize(&config.repo_path).map_err(|_| {
            Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "repo_path must be a canonicalizable local path",
            ))
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
        // Validate up front, matching the encode-before-touching-the-entity-record order this
        // put has always used.
        SNAPSHOTS.encode_value(filtered_snapshot)?;
        CUSTODY_REPORTS.encode_value(&custody_report)?;
        let Some(raw) = self
            .store
            .port_entity_record(wtxn, code_artifact_id)?
            .map(|row| row.encode())
        else {
            return Err(Error::EntityNotFound);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "snapshot target is not a CODE_ARTIFACT",
            )));
        }
        let artifact = decode_code_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let artifact_repo_ref = RepoRef::parse(&artifact.repo_ref)?;
        if artifact_repo_ref != filtered_snapshot.repo_ref {
            return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "snapshot repo_ref must match CODE artifact repo_ref",
            )));
        }

        delete_codebase_snapshot_in_txn(&self.store, wtxn, code_artifact_id)?;
        SNAPSHOTS.put(&self.store, wtxn, code_artifact_id, filtered_snapshot)?;
        CUSTODY_REPORTS.put(
            &self.store,
            wtxn,
            &codebase_custody_key(&filtered_snapshot.fork_hash),
            &custody_report,
        )?;
        REPO_INDEX.put(
            &self.store,
            wtxn,
            &TextIndexKey {
                value: filtered_snapshot.repo_ref.canonical(),
                id: *code_artifact_id,
            },
            &(),
        )?;
        PROJECT_INDEX.put(
            &self.store,
            wtxn,
            &TextIndexKey {
                value: filtered_snapshot.project_id.clone(),
                id: *code_artifact_id,
            },
            &(),
        )?;
        FORK_INDEX.put(
            &self.store,
            wtxn,
            &HashIndexKey {
                value: filtered_snapshot.fork_hash,
                id: *code_artifact_id,
            },
            &(),
        )?;
        put_scope_index_rows_for_snapshot(&self.store, wtxn, code_artifact_id, filtered_snapshot)?;
        Ok(())
    }

    pub fn get_codebase_snapshot(
        &self,
        code_artifact_id: &EntityId,
    ) -> Result<Option<CodebaseSnapshot>> {
        let rtxn = self.store.env.read_txn()?;
        SNAPSHOTS.get(&self.store, &rtxn, code_artifact_id)
    }

    /// Reads the value-free custody report stored beside a filtered snapshot.
    pub fn get_codebase_snapshot_custody_report(
        &self,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Option<crate::secret_snapshot::SnapshotCustodyReport>> {
        let rtxn = self.store.env.read_txn()?;
        CUSTODY_REPORTS.get(&self.store, &rtxn, &codebase_custody_key(fork_hash))
    }

    pub fn codebase_snapshots_by_repo_ref(&self, repo_ref: &RepoRef) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        codebase_ids_by_index(
            REPO_INDEX,
            &self.store,
            &rtxn,
            &text_index_scan_prefix(&repo_ref.canonical()),
        )
    }

    pub fn codebase_snapshots_by_project_id(&self, project_id: &str) -> Result<Vec<EntityId>> {
        validate_project_id(project_id)?;
        let rtxn = self.store.env.read_txn()?;
        codebase_ids_by_index(
            PROJECT_INDEX,
            &self.store,
            &rtxn,
            &text_index_scan_prefix(project_id),
        )
    }

    pub fn codebase_snapshots_by_fork_hash(
        &self,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        codebase_ids_by_index(
            FORK_INDEX,
            &self.store,
            &rtxn,
            &hash_index_scan_prefix(fork_hash),
        )
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

/// The `sync_state`-free hex64 key `SnapshotCustodyReport` rows have always used: the lower-case
/// hex spelling of the snapshot's fork hash.
fn codebase_custody_key(fork_hash: &CodebaseForkHash) -> String {
    crate::entity_id::bytes_to_hex_lower(fork_hash)
}

fn text_index_scan_prefix(value: &str) -> Vec<u8> {
    let mut out = value.as_bytes().to_vec();
    out.push(0);
    out
}

fn hash_index_scan_prefix(value: &[u8; 32]) -> Vec<u8> {
    let mut out = value.to_vec();
    out.push(0);
    out
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
    let prefix = hash_index_scan_prefix(fork_hash);
    Ok(FORK_INDEX
        .scan_keys(store, wtxn, &prefix)?
        .into_iter()
        .any(|key| key.id != *id))
}

fn delete_exact_index_rows_for_snapshot(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    snapshot: &CodebaseSnapshot,
) -> Result<()> {
    REPO_INDEX.delete(
        store,
        wtxn,
        &TextIndexKey {
            value: snapshot.repo_ref.canonical(),
            id: *id,
        },
    )?;
    PROJECT_INDEX.delete(
        store,
        wtxn,
        &TextIndexKey {
            value: snapshot.project_id.clone(),
            id: *id,
        },
    )?;
    FORK_INDEX.delete(
        store,
        wtxn,
        &HashIndexKey {
            value: snapshot.fork_hash,
            id: *id,
        },
    )?;
    SCOPE_INDEX.delete(
        store,
        wtxn,
        &HashIndexKey {
            value: snapshot.scope_key,
            id: *id,
        },
    )?;
    for entry in &snapshot.files {
        let asset_id = codebase_asset_entity_id(&entry.content_hash)?;
        SCOPE_INDEX.delete(
            store,
            wtxn,
            &HashIndexKey {
                value: snapshot.scope_key,
                id: asset_id,
            },
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
    SCOPE_INDEX.put(
        store,
        wtxn,
        &HashIndexKey {
            value: snapshot.scope_key,
            id: *code_artifact_id,
        },
        &(),
    )?;
    for entry in &snapshot.files {
        let asset_id = codebase_asset_entity_id(&entry.content_hash)?;
        SCOPE_INDEX.put(
            store,
            wtxn,
            &HashIndexKey {
                value: snapshot.scope_key,
                id: asset_id,
            },
            &(),
        )?;
    }
    Ok(())
}

/// Deletes every row of `table`, across every value it indexes, whose id half matches `id`. Used
/// only when a snapshot row failed to decode, so the values it was indexed under are unknown and
/// the whole table must be swept.
fn delete_index_rows_for_id<K: SideKey + IndexRowId>(
    table: SideTable<K, (), Raw>,
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let matches: Vec<K> = table
        .scan_keys(store, wtxn, &[])?
        .into_iter()
        .filter(|key| key.id() == *id)
        .collect();
    for key in &matches {
        table.delete(store, wtxn, key)?;
    }
    Ok(())
}

fn codebase_ids_by_index<K: SideKey + IndexRowId>(
    table: SideTable<K, (), Raw>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    key_prefix: &[u8],
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for key in table.scan_keys(store, rtxn, key_prefix)? {
        let id = key.id();
        let Some(raw) = store.port_entity_record(rtxn, &id)?.map(|row| row.encode()) else {
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
