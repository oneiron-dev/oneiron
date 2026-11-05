//! Code snapshot vocabulary and the vault-backed read-only mount.

use super::ingest::{read_asset_blob, validate_manifest_path};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

pub use crate::store::code_snapshot::{
    CODEBASE_CONTENT_HASH_LEN, CODEBASE_FILE_ENTRY_KEYS, CODEBASE_FILE_PATH_MAX_BYTES,
    CODEBASE_FORK_HASH_LEN, CODEBASE_PROJECT_ID_MAX_BYTES, CODEBASE_SCOPE_KEY_LEN,
    CODEBASE_SNAPSHOT_BODY_KEYS, CODEBASE_SNAPSHOT_MAX_FILES, CodebaseFileEntry, CodebaseForkHash,
    CodebaseScopeKey, CodebaseSnapshot, decode_codebase_snapshot, encode_codebase_snapshot,
};

pub(super) use crate::store::code_snapshot::snapshot::validate_codebase_snapshot;

pub struct CodebaseSnapshotMount<'a> {
    pub(super) vault: &'a Vault,
    pub(super) code_artifact_id: EntityId,
    pub(super) snapshot: CodebaseSnapshot,
    /// The paths the custody report beside the snapshot's fork withholds: a
    /// file the lift sweep quarantined stays in the manifest its fork hash
    /// binds, and is read as absent (OF-067).
    pub(super) withheld: std::collections::BTreeSet<String>,
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

    /// Whether this mount's custody report reads `path` as absent.
    #[must_use]
    pub(crate) fn is_withheld(&self, path: &str) -> bool {
        self.withheld.contains(path)
    }

    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        true
    }

    /// The paths this mount reads, omitting custody-withheld files.
    pub fn list_files(&self) -> Vec<&str> {
        self.snapshot
            .files
            .iter()
            .filter(|entry| !self.is_withheld(&entry.path))
            .map(|entry| entry.path.as_str())
            .collect()
    }

    pub fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>> {
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
        read_asset_blob(self.vault, &self.snapshot.files[index].content_hash).map(Some)
    }
}
