//! Exact bundle bytes and modes staged through the existing Git bridge.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::code_tree_blob::MODE_GITLINK;
use crate::git_wire::ids::GitOid;
use crate::git_wire::mutation_commands::path_arg;
use crate::git_wire::mutation_commands::utf8_trimmed;
use crate::git_wire::path_text::git_path_os_str;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

pub static BUNDLE_BLOB_COUNTER: AtomicU64 = AtomicU64::new(1);

/// One entry of a bundle's tree change: its path, its exact new
/// bytes (`None` removes it) and its Git mode once present. For a gitlink,
/// the bytes are its OID, not content from the linked repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleTreeEdit {
    pub path: String,
    pub content: Option<Vec<u8>>,
    pub mode: u32,
}

pub fn gitlink_oid(content: &[u8]) -> Result<String> {
    let oid = std::str::from_utf8(content)
        .map_err(|_| Error::InvalidClaimBody("gitlink OID must be UTF-8"))?;
    Ok(GitOid::parse_hex(oid)?.as_str().to_owned())
}

/// The empty directory standing at `path` in the working tree at `root`,
/// reached through no symlink; `None` for anything else, which Git's own
/// checkout judges.
pub fn empty_directory_in_tree(root: &Path, path: &str) -> Result<Option<std::path::PathBuf>> {
    let mut at = root.to_path_buf();
    // `path` is a Git path's text: each part names its own bytes (FIX 21326).
    for part in path.split('/') {
        at.push(&*git_path_os_str(part)?);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) | Err(_) => return Ok(None),
        }
    }
    Ok(std::fs::read_dir(&at)?.next().is_none().then_some(at))
}
