//! Moved from `crates/oneiron/src/repo_mutation/snapshot.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredRepoSnapshotEntryKind {
    File,
    Symlink,
    /// An index gitlink: content is its OID, never the linked repository.
    Gitlink,
    /// A file snapshot custody keeps out ([`SnapshotCustody`]): its path and
    /// mode, none of its bytes. A restore leaves the file the checkout holds
    /// there as it is.
    Withheld,
}
