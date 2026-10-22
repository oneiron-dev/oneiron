//! A codebase snapshot's repo-marked files and the symbol graphs derived
//! from them (FIX 7608 slice 3).
//!
//! Snapshot custody keeps its exclusions: a declared path, a registered
//! value's bytes and a file whose bytes are missing or do not match its
//! entry stay out, as before. A file a receive mark covers is the one case
//! it treats differently: the release scan's quarantine would erase it from
//! the repo's index, yet it was admitted with its marks, so its source
//! entry and canonical ASSET stay as received and only its index copies are
//! masked. It is not listed as quarantined because its copy is masked.
//!
//! A mask change on a blob a snapshot lists derives that snapshot's symbol
//! graph again from projected full sources, in the writer that changed it.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::super::ingest::read_asset_blob_in_txn;
use super::super::snapshot::{CodebaseFileEntry, CodebaseSnapshot};
use super::SNAPSHOTS;
use crate::Vault;
use crate::code_symbol::{
    CodeSymbolSource, masked_repo_symbol_texts_in_txn, prepare_code_symbol_graph,
};
use crate::error::{Error, Result};
use crate::origin::secret_projection::index::RepoIndexMarks;
use crate::ports::EntityStoreRead;
use crate::secret_snapshot::SnapshotCustodyReport;

impl Vault {
    /// [`Vault::apply_custody_to_snapshot`] with every file a receive mark
    /// covers kept in place of its release-scan quarantine, when its bytes
    /// match its entry. Unmarked files, and every other exclusion, are
    /// custody's verdict unchanged.
    ///
    /// # Errors
    /// As [`Vault::apply_custody_to_snapshot`].
    pub(crate) fn repo_snapshot_inputs_in_txn(
        &self,
        txn: &RoTxn<'_>,
        marks: &RepoIndexMarks,
        snapshot: &CodebaseSnapshot,
        file_contents: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<(Vec<CodebaseFileEntry>, SnapshotCustodyReport)> {
        let (files, mut report) = self.apply_custody_to_snapshot(txn, snapshot, file_contents)?;
        if marks.is_empty() || report.quarantined_paths.is_empty() {
            return Ok((files, report));
        }
        let kept = files
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<BTreeSet<_>>();
        let mut marked = BTreeSet::new();
        for entry in &snapshot.files {
            if kept.contains(entry.path.as_str())
                || !marks.is_marked(&entry.content_hash)
                || !report.quarantined_paths.contains(&entry.path)
            {
                continue;
            }
            let Some(bytes) = file_contents(&entry.path) else {
                continue;
            };
            if bytes.len() as u64 == entry.size_bytes
                && blake3::hash(&bytes).as_bytes() == &entry.content_hash
            {
                marked.insert(entry.path.as_str());
            }
        }
        if marked.is_empty() {
            return Ok((files, report));
        }
        report
            .quarantined_paths
            .retain(|path| !marked.contains(path.as_str()));
        let files = snapshot
            .files
            .iter()
            .filter(|entry| {
                kept.contains(entry.path.as_str()) || marked.contains(entry.path.as_str())
            })
            .cloned()
            .collect();
        Ok((files, report))
    }

    /// Derives again, from projected full sources, the symbol graph of every
    /// snapshot listing a blob in `sources`, in `wtxn`. A snapshot one of
    /// whose files cannot be read keeps its graph as it stands.
    ///
    /// # Errors
    /// A storage error, or a graph the parser or writer refuses.
    pub(crate) fn refresh_repo_symbol_graphs_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        marks: &RepoIndexMarks,
        sources: &BTreeSet<[u8; 32]>,
    ) -> Result<()> {
        for (artifact, snapshot) in SNAPSHOTS.scan(&self.store, wtxn)? {
            if !snapshot
                .files
                .iter()
                .any(|entry| sources.contains(&entry.content_hash))
            {
                continue;
            }
            let Some(row) = self.store.port_entity_record(wtxn, &artifact)? else {
                continue;
            };
            let Some(files) = self.snapshot_file_bytes_in_txn(wtxn, &snapshot)? else {
                continue;
            };
            let texts = masked_repo_symbol_texts_in_txn(
                self,
                wtxn,
                marks,
                files
                    .iter()
                    .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
            )?;
            let graph = prepare_code_symbol_graph(
                snapshot.repo_ref.clone(),
                snapshot.commit_hash.clone(),
                texts
                    .iter()
                    .map(|(path, text)| CodeSymbolSource::new(path, text)),
            )?;
            self.put_prepared_code_symbol_graph_in_txn(
                wtxn,
                &artifact,
                &graph,
                row.occurred,
                row.learned_at,
            )?;
        }
        Ok(())
    }

    /// Every file of `snapshot` with its stored bytes, checked against its
    /// entry; `None` when one is gone or does not check.
    fn snapshot_file_bytes_in_txn(
        &self,
        txn: &RoTxn<'_>,
        snapshot: &CodebaseSnapshot,
    ) -> Result<Option<Vec<(String, Vec<u8>)>>> {
        let mut files = Vec::with_capacity(snapshot.files.len());
        for entry in &snapshot.files {
            match read_asset_blob_in_txn(self, txn, &entry.content_hash) {
                Ok(bytes) => files.push((entry.path.clone(), bytes)),
                Err(error @ (Error::Storage(_) | Error::Io(_) | Error::MapFull)) => {
                    return Err(error);
                }
                Err(_) => return Ok(None),
            }
        }
        Ok(Some(files))
    }
}
