//! Journaled worktree effects: list, prune, add, remove, and crash-journal settlement.

use std::fs;
use std::path::{Path, PathBuf};

use crate::git_wire::config::GIT_WIRE_DOMAIN;
use crate::git_wire::failure::GitWireFailureClass;
use crate::git_wire::failure::GitWireResult;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::record::GitWireCommitOutcome;
use crate::git_wire::record::GitWireReceipt;
use crate::git_wire::record::GitWireRecordState;
use crate::git_wire::record::GitWireRejection;
use crate::git_wire::record::StoredGitWireRecord;
use crate::git_wire::record::finish_state;
use crate::git_wire::record::hash_field;
use crate::git_wire::record::new_record;
use crate::git_wire::record::receipt_from_stored;
use crate::git_wire::record::worktree_record_key;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::lock_repository;
use oneiron_base::error::Result;

pub fn parse_worktree_listing(stdout: &[u8]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for field in stdout.split(|byte| *byte == 0) {
        let Some(raw) = field.strip_prefix(b"worktree ") else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(raw) else {
            continue;
        };
        paths.push(PathBuf::from(text));
    }
    paths
}

pub fn same_path(left: &Path, right: &Path) -> bool {
    left == right || normalized_path(left) == normalized_path(right)
}

/// A path normalized as far as the filesystem allows.
///
/// A worktree that has just been removed no longer resolves, so falling back to
/// the resolved parent keeps a removed handle comparable with the path git
/// reported for it.
fn normalized_path(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => match parent.canonicalize() {
            Ok(parent) => parent.join(name),
            Err(_) => path.to_path_buf(),
        },
        _ => path.to_path_buf(),
    }
}

pub fn worktree_scope(path: &Path) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"worktree-scope");
    hash_field(
        &mut hasher,
        normalized_path(path).as_os_str().as_encoded_bytes(),
    );
    *hasher.finalize().as_bytes()
}
