//! Pointer grammar: pushed-pointer parsing, per-repo intents, pointer field consts.

use super::LfsOid;
use crate::entity_id::EntityId;

/// The `oid sha256:` field of a Git-LFS pointer file.
const LFS_POINTER_OID_FIELD: &str = "oid sha256:";

/// The `size ` field of a Git-LFS pointer file.
const LFS_POINTER_SIZE_FIELD: &str = "size ";

/// The `version ` field of a Git-LFS pointer file.
const LFS_POINTER_VERSION_FIELD: &str = "version ";

/// The optional `ext-N-<name> ` field family of a Git-LFS pointer file.
const LFS_POINTER_EXT_FIELD: &str = "ext-";

/// One LFS pointer, paired with the repository path that carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfsPointerIntent {
    /// The repository the pointer landed in.
    pub repo_id: EntityId,
    /// The repository-relative path of the pointer file.
    pub path: String,
    /// The object id the pointer names.
    pub oid: LfsOid,
    /// The byte length the pointer declares.
    pub size_bytes: u64,
}

/// One LFS pointer a push introduced, before it is scoped to a repository.
///
/// The wire-side pairing (path ↔ pointer) is knowable at the door, where the
/// pushed blobs are still framed; the repository key is knowable only at the
/// landing, where the object store's identity has been proven. This type
/// carries the first half so the second half is added exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfsPushedPointer {
    /// The repository-relative path of the pointer file.
    pub path: String,
    /// The object id the pointer names.
    pub oid: LfsOid,
    /// The byte length the pointer declares.
    pub size_bytes: u64,
}

impl LfsPushedPointer {
    /// Reads a Git-LFS pointer out of the lines a push ADDED to one blob.
    ///
    /// Every added line must be a pointer field, and `oid`/`size` must both be
    /// present and well formed. That conjunction is what keeps an ordinary
    /// source file that happens to mention a SHA-256 from being mistaken for a
    /// pointer: a pointer file is pointer fields and nothing else, so any line
    /// outside the grammar disqualifies the whole blob.
    ///
    /// Reading the ADDED lines (rather than requiring a `version` line) is what
    /// makes a pointer MODIFICATION visible: retargeting a pointer changes
    /// `oid` and `size` while `version` stays context.
    #[must_use]
    pub fn from_pointer_lines(path: &str, added_lines: &[Vec<u8>]) -> Option<Self> {
        let mut oid = None;
        let mut size_bytes = None;
        let mut fields = 0_usize;
        for line in added_lines {
            let line = std::str::from_utf8(line).ok()?;
            if line.is_empty() {
                continue;
            }
            fields += 1;
            if let Some(value) = line.strip_prefix(LFS_POINTER_OID_FIELD) {
                oid = Some(LfsOid::parse_hex(value).ok()?);
            } else if let Some(value) = line.strip_prefix(LFS_POINTER_SIZE_FIELD) {
                size_bytes = Some(value.parse::<u64>().ok()?);
            } else if !line.starts_with(LFS_POINTER_VERSION_FIELD)
                && !line.starts_with(LFS_POINTER_EXT_FIELD)
            {
                return None;
            }
        }
        if fields == 0 {
            return None;
        }
        Some(Self {
            path: path.to_owned(),
            oid: oid?,
            size_bytes: size_bytes?,
        })
    }

    /// Scopes this pointer to one repository.
    #[must_use]
    pub fn intent(&self, repo_id: EntityId) -> LfsPointerIntent {
        LfsPointerIntent {
            repo_id,
            path: self.path.clone(),
            oid: self.oid,
            size_bytes: self.size_bytes,
        }
    }
}
