//! The local-repo import's one checked writer (moved from `store/mod.rs`,
//! FIX 6867 G1 PR2a): the owner's and trusted callers' import, unchanged,
//! and a run's import of the paths its Grant reads, admitted again in the
//! final writer.

use std::convert::Infallible;
use std::path::Path;

use heed::RoTxn;

use super::super::ingest::{
    HostedMediaHashMatchProvider, NoopHostedMediaHashMatchProvider, RepoIngestBlob,
    RepoIngestConfig, RepoIngestResult, check_hosted_media_hash_matches, collect_repo_blobs,
    scan_codebase_snapshot_metadata, validate_project_id,
};
use super::super::repo_ref::RepoRef;
use super::super::residue::reclaimable_asset_hashes;
use super::super::snapshot::{CodebaseFileEntry, CodebaseSnapshot};
use super::{codebase_asset_entity_id, codebase_snapshot_entity_id};
use crate::Vault;
use crate::code_artifact::CodeArtifactBody;
use crate::code_symbol::{CodeSymbolSource, prepare_code_symbol_graph};
use crate::error::{CodeError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CODE_ARTIFACT};
use crate::temporal::TimeRange;

/// A run's import claims no editable policy, as the owner door's does not.
const NO_EDITABLE_WHITELIST: [&str; 0] = [];

impl Vault {
    /// The owner's and trusted callers' import, as it was: every path, no
    /// admission beyond the importer's own custody writer.
    pub(in crate::codebase) fn ingest_local_repo_with_after_first_pass(
        &self,
        project_id: impl Into<String>,
        config: &RepoIngestConfig,
        commit_ref: &str,
        timing: (TimeRange, u64),
        hash_match_provider: &(impl HostedMediaHashMatchProvider + ?Sized),
        after_first_pass: impl FnOnce() -> Result<()>,
    ) -> Result<RepoIngestResult> {
        let imported = self.ingest_local_repo_checked(
            project_id,
            config,
            commit_ref,
            timing,
            hash_match_provider,
            after_first_pass,
            None,
            |_| Ok(Ok::<(), Infallible>(())),
        )?;
        match imported {
            Ok(imported) => Ok(imported),
            Err(never) => match never {},
        }
    }

    /// A run's import of one committed tree of the stored repo at
    /// `repo_path` (FIX 6867): only the paths `select` keeps reach the
    /// snapshot, its blobs and its symbols, and `admit` judges the run again
    /// in the final writer. A refusal there is the run's, and nothing is
    /// written.
    pub(crate) fn ingest_local_repo_for_run<R>(
        &self,
        project_id: String,
        repo_path: &Path,
        commit: &str,
        timing: (TimeRange, u64),
        select: &dyn Fn(&str) -> bool,
        admit: impl FnOnce(&RoTxn<'_>) -> Result<std::result::Result<(), R>>,
    ) -> Result<std::result::Result<RepoIngestResult, R>> {
        let config = RepoIngestConfig::new(repo_path, NO_EDITABLE_WHITELIST)?;
        self.ingest_local_repo_checked(
            project_id,
            &config,
            commit,
            timing,
            &NoopHostedMediaHashMatchProvider,
            || Ok(()),
            Some(select),
            admit,
        )
    }

    /// The one import body both callers share. `select`, when given, keeps
    /// the paths a run's import may read; `admit` runs first in the final
    /// writer.
    #[allow(
        clippy::too_many_arguments,
        reason = "the moved import body keeps its own arguments beside the run's two"
    )]
    fn ingest_local_repo_checked<R>(
        &self,
        project_id: impl Into<String>,
        config: &RepoIngestConfig,
        commit_ref: &str,
        timing: (TimeRange, u64),
        hash_match_provider: &(impl HostedMediaHashMatchProvider + ?Sized),
        after_first_pass: impl FnOnce() -> Result<()>,
        select: Option<&dyn Fn(&str) -> bool>,
        admit: impl FnOnce(&RoTxn<'_>) -> Result<std::result::Result<(), R>>,
    ) -> Result<std::result::Result<RepoIngestResult, R>> {
        let (occurred, learned_at) = timing;
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
        // A run's import keeps only the paths its Grant reads, before any
        // derived blob, snapshot or symbol is computed (FIX 6867).
        if let Some(select) = select {
            blobs.retain(|blob| select(&blob.path));
        }
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
        // The read pass is useful for early quarantine but does not authorize
        // any writes: a declaration can arrive after it releases its snapshot.
        scan_codebase_snapshot_metadata(&snapshot)?;
        let contents = |path: &str| {
            blobs
                .binary_search_by_key(&path, |blob| blob.path.as_str())
                .ok()
                .map(|index| blobs[index].data.clone())
        };
        let rtxn = self.store.env.read_txn()?;
        self.apply_custody_to_snapshot(&rtxn, &snapshot, &contents)?;
        drop(rtxn);
        after_first_pass()?;
        // Keep main's vault-scoped, test-only writer rendezvous: a registration
        // committed here must be visible to the final writer.
        #[cfg(test)]
        if let Some(hook) = self
            .test_hooks()
            .before_codebase_ingest_writer
            .lock()
            .expect("codebase ingest hook poisoned")
            .take()
        {
            hook();
        }

        // The final writer view decides every derived write, not merely the
        // manifest. A registration committed between passes excludes its blob
        // from ASSET, CODE_SYMBOL and snapshot in one transaction.
        self.with_write_txn_grouped(|wtxn| {
            // A run's admission is judged again in this final writer, before
            // any row is put; a refusal writes nothing.
            if let Err(refused) = admit(wtxn)? {
                return Ok(Err(refused));
            }
            let (files, custody_report) =
                self.apply_custody_to_snapshot(wtxn, &snapshot, &contents)?;
            let filtered_snapshot = CodebaseSnapshot::new(
                snapshot.project_id.clone(),
                snapshot.repo_ref.clone(),
                snapshot.commit_hash.clone(),
                files,
            )?;
            let retained_paths = filtered_snapshot
                .files
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let retained_hashes = filtered_snapshot
                .files
                .iter()
                .map(|entry| entry.content_hash)
                .collect::<std::collections::BTreeSet<_>>();
            let excluded_hashes = blobs
                .iter()
                .filter(|blob| !retained_hashes.contains(&blob.content_hash))
                .map(|blob| blob.content_hash)
                .collect::<std::collections::BTreeSet<_>>();
            let reclaimable = reclaimable_asset_hashes(
                self,
                wtxn,
                &snapshot,
                &custody_report,
                &retained_hashes,
                &excluded_hashes,
            )?;
            let code_artifact_id = codebase_snapshot_entity_id(&filtered_snapshot)?;
            let code_body = CodeArtifactBody::new(
                "Summarize the repository snapshot.",
                filtered_snapshot.fork_hash,
                repo_ref.canonical(),
            );
            let code_body = crate::code_artifact::encode_code_artifact_body(&code_body)?;

            let mut batch = self.batch_in();
            for blob in &blobs {
                if retained_paths.contains(blob.path.as_str()) {
                    let asset_id = codebase_asset_entity_id(&blob.content_hash)?;
                    batch = batch.put(
                        &asset_id,
                        ENTITY_TYPE_ASSET,
                        occurred,
                        learned_at,
                        &blob.data,
                    );
                }
            }
            for hash in reclaimable {
                // The final writer view owns both cleanup and all derived puts.
                // Never remove a hash retained by another path or repository.
                let asset_id = codebase_asset_entity_id(&hash)?;
                if self
                    .store
                    .port_entity_record(wtxn, &asset_id)?
                    .is_some_and(|row| row.entity_type == ENTITY_TYPE_ASSET)
                {
                    batch = batch.delete(&asset_id);
                }
            }
            batch
                .put(
                    &code_artifact_id,
                    ENTITY_TYPE_CODE_ARTIFACT,
                    occurred,
                    learned_at,
                    &code_body,
                )
                .apply(wtxn)?;
            self.put_filtered_codebase_snapshot_in_txn(
                wtxn,
                &code_artifact_id,
                &filtered_snapshot,
                custody_report,
            )?;
            let symbol_sources = blobs
                .iter()
                .filter(|blob| retained_paths.contains(blob.path.as_str()))
                .filter_map(|blob| {
                    let text = std::str::from_utf8(&blob.data).ok()?;
                    Some(CodeSymbolSource::new(blob.path.as_str(), text))
                })
                .collect::<Vec<_>>();
            // Symbol rows first, then every edge a working batch at a time.
            let symbol_graph = prepare_code_symbol_graph(
                repo_ref.clone(),
                Some(commit_hash.clone()),
                symbol_sources,
            )?;
            self.put_prepared_code_symbol_graph_in_txn(
                wtxn,
                &code_artifact_id,
                &symbol_graph,
                occurred,
                learned_at,
            )?;
            Ok(Ok(RepoIngestResult {
                code_artifact_id,
                snapshot: filtered_snapshot,
            }))
        })
    }
}
