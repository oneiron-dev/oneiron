//! A snapshot file as a masked reader reads it (FIX 7608 slice 2a). A
//! snapshot names each file by the BLAKE3 of its bytes, which is the hash a
//! repo mark keeps of the whole marked blob: the same bytes are the same
//! blob, so a file is joined to its marks by that hash, in whichever store
//! they were pushed, never by guessing a store from the snapshot.
//!
//! The trusted [`CodebaseSnapshotMount::read_file`] stays exact. These are
//! its masked siblings: the same withheld paths are absent, an unmarked
//! file is read by the same read, and a marked one is projected before any
//! byte of it leaves (`origin::secret_projection`).

use std::collections::BTreeMap;

use super::ingest::{read_asset_blob, read_asset_blob_in_txn, validate_manifest_path};
use super::snapshot::{CODEBASE_CONTENT_HASH_LEN, CodebaseSnapshotMount};
use crate::Vault;
use crate::error::Result;
use crate::origin::secret_marks::{
    RepoBlobMarks, RepoMarkFacts, RepoSecretMarkLookup, repo_secret_marks_for_hash_in_txn,
};
use crate::origin::secret_projection::{
    RepoBodyProjection, RepoFileProjectionView, RepoOpaqueFile, RepoSecretAudience,
    project_repo_blob, project_repo_bytes_in_txn,
};

impl CodebaseSnapshotMount<'_> {
    /// [`Self::read_file`] for a masked reader: `None` exactly where it is
    /// `None`, the stored bytes for a file no mark covers, and the
    /// projection of a marked one, its opaque residue found before a byte
    /// is read.
    ///
    /// # Errors
    /// As [`Self::read_file`], or a mark that does not decode.
    pub(crate) fn read_file_projected(&self, path: &str) -> Result<Option<RepoBodyProjection>> {
        validate_manifest_path(path)?;
        if self.withheld.contains(path) {
            return Ok(None);
        }
        let Ok(index) = self
            .snapshot
            .files
            .binary_search_by(|entry| entry.path.as_str().cmp(path))
        else {
            return Ok(None);
        };
        let hash = self.snapshot.files[index].content_hash;
        let marks = {
            let txn = self.vault.store.env.read_txn()?;
            repo_secret_marks_for_hash_in_txn(self.vault, &txn, &hash)?
        };
        project_repo_blob(self.vault, &marks, &RepoSecretAudience::Masked, || {
            read_asset_blob(self.vault, &hash)
        })
        .map(Some)
    }

    /// The content hash and readable marks of the listed file `path`, for a
    /// per-file read that may ask for its real bytes (FIX 7608 2b-ii-B):
    /// `None` exactly where [`Self::read_file_projected`] is `None`. No byte
    /// of the file is read.
    ///
    /// # Errors
    /// As [`Self::read_file_projected`].
    pub(crate) fn file_marks(
        &self,
        path: &str,
    ) -> Result<Option<([u8; CODEBASE_CONTENT_HASH_LEN], RepoBlobMarks)>> {
        validate_manifest_path(path)?;
        if self.withheld.contains(path) {
            return Ok(None);
        }
        let Ok(index) = self
            .snapshot
            .files
            .binary_search_by(|entry| entry.path.as_str().cmp(path))
        else {
            return Ok(None);
        };
        let hash = self.snapshot.files[index].content_hash;
        let txn = self.vault.store.env.read_txn()?;
        let marks = repo_secret_marks_for_hash_in_txn(self.vault, &txn, &hash)?;
        Ok(Some((hash, marks)))
    }

    /// The projection each listed file `select` admits reads as, when a mark
    /// covers it, by path, the marks found in one walk; empty for a snapshot
    /// nothing marks. A withheld file has none: it is absent. No file
    /// `select` refuses is read.
    ///
    /// # Errors
    /// A store failure, or a mark that does not decode.
    pub(crate) fn projected_file_views<F: Fn(&str) -> bool>(
        &self,
        select: F,
    ) -> Result<BTreeMap<String, RepoFileProjectionView>> {
        let facts = {
            let txn = self.vault.store.env.read_txn()?;
            RepoMarkFacts::read_in_txn(self.vault, &txn, RepoSecretMarkLookup::ReadableClaims)?
        };
        let mut views = BTreeMap::new();
        if facts.is_empty() {
            return Ok(views);
        }
        for entry in &self.snapshot.files {
            let marks = facts.for_hash(&entry.content_hash);
            if marks.is_empty() || !select(&entry.path) || self.withheld.contains(&entry.path) {
                continue;
            }
            let body = project_repo_blob(self.vault, &marks, &RepoSecretAudience::Masked, || {
                read_asset_blob(self.vault, &entry.content_hash)
            })?;
            if let Some(view) = body.view() {
                views.insert(entry.path.clone(), view);
            }
        }
        Ok(views)
    }
}

impl Vault {
    /// The projection a masked reader gets of the snapshot ASSET
    /// `content_hash` names, read in `txn`, when a repo mark covers its
    /// bytes; `None` for bytes no mark covers, which the caller serves as it
    /// always has. Opaque residue is answered before the body is read.
    ///
    /// # Errors
    /// A store failure, a mark that does not decode, or the checked body
    /// read's own.
    pub(crate) fn repo_marked_asset_copy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
    ) -> Result<Option<RepoBodyProjection>> {
        let marks = repo_secret_marks_for_hash_in_txn(self, txn, content_hash)?;
        let Some(source_blob) = marks.source_blob().cloned() else {
            return Ok(None);
        };
        if marks.opaque() {
            return Ok(Some(RepoBodyProjection::Opaque(RepoOpaqueFile {
                source_blob,
            })));
        }
        let bytes = read_asset_blob_in_txn(self, txn, content_hash)?;
        project_repo_bytes_in_txn(self, txn, &marks, bytes).map(Some)
    }
}
