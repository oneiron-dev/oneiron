//! The copy directories of masked Git copies (FIX 7608 pre-flip, FIX
//! 10274, FIX 10849), found by the deterministic layout they live in: one
//! directory per canonical store, one per graph inside it.
//!
//! A copy is about its canonical store, so the store's permanent
//! hard-delete marker (presence only, never a missing body) retires it
//! whatever its marks still say, through the ordinary guarded retirement.
//! A graph directory no graph record stands behind any more, of any store,
//! is an orphan: its record's erase took it, or a crash came between the
//! erase and the directory's removal. A copy's directory appears only once
//! its graph record is written (its building directory is never a graph's),
//! so a copy still being made is never one. Only a strict graph id
//! directory is removed: never the canonical store, never a private
//! ingress (a pending push keeps its own), never a building directory, and
//! never a copy store a checkout's worktree is still registered in (its
//! retained work stays). A removal that fails is found again by the next
//! pass.

use std::path::{Path, PathBuf};

use heed::RoTxn;

use super::super::claims::RepoProjectionClaim;
use super::super::git::{REPO_SECRET_PROJECTION_DIR, projection_dir_id};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The copy store's directory inside a copy's own directory, and the
/// directory its linked worktrees register in.
const COPY_STORE_WORKTREES: [&str; 2] = ["repo.git", "worktrees"];

/// Whether the owner erased the canonical store `store_id`: its permanent
/// hard-delete marker exists.
///
/// # Errors
/// A store failure.
pub(crate) fn repo_projection_store_erased_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    store_id: &EntityId,
) -> Result<bool> {
    vault.local_hard_delete_marker_exists_in_txn(txn, store_id)
}

/// Every copy directory on disk, with its canonical store and graph ids
/// (FIX 10275): the copies a pass judges, found without a walk of any
/// claim. None when no copy was ever made.
///
/// # Errors
/// A directory that cannot be listed.
pub(crate) fn copy_dirs(vault: &Vault) -> Result<Vec<(EntityId, EntityId, PathBuf)>> {
    let root = vault.store.env.path().join(REPO_SECRET_PROJECTION_DIR);
    let Ok(stores) = std::fs::read_dir(&root) else {
        return Ok(Vec::new());
    };
    let mut copies = Vec::new();
    for store in stores {
        let store = store?.path();
        let Some(store_id) = projection_dir_id(&store) else {
            continue;
        };
        for graph in std::fs::read_dir(&store)? {
            let path = graph?.path();
            if let Some(graph) = projection_dir_id(&path) {
                copies.push((store_id, graph, path));
            }
        }
    }
    Ok(copies)
}

/// Removes every graph directory, of any store, that no graph record
/// stands behind any more, and answers how many it removed.
///
/// # Errors
/// A store failure reading the records, or a directory that cannot be
/// listed. One copy's failed removal is logged and left for the next pass.
pub(crate) fn collect_orphan_graph_dirs(vault: &Vault) -> Result<usize> {
    let copies = copy_dirs(vault)?;
    if copies.is_empty() {
        return Ok(0);
    }
    let mut orphaned = Vec::new();
    {
        let txn = vault.store.env.read_txn()?;
        for (_, graph, path) in copies {
            if RepoProjectionClaim::load_graph_in_txn(vault, &txn, &graph)?.is_none()
                && !worktree_registered(&path)
            {
                orphaned.push(path);
            }
        }
    }
    let mut removed = 0_usize;
    for path in orphaned {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => removed += 1,
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "an orphaned masked Git copy was not removed; the next pass retries"
            ),
        }
    }
    Ok(removed)
}

/// Whether a checkout's linked worktree is still registered in the copy
/// store under `copy_dir`.
fn worktree_registered(copy_dir: &Path) -> bool {
    let worktrees = COPY_STORE_WORKTREES
        .iter()
        .fold(copy_dir.to_path_buf(), |path, part| path.join(part));
    std::fs::read_dir(worktrees).is_ok_and(|mut entries| entries.next().is_some())
}
