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

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The copy store's directory inside a copy's own directory, and the
/// directory its linked worktrees register in.
const COPY_STORE_WORKTREES: [&str; 2] = ["repo.git", "worktrees"];

/// Whether a checkout's linked worktree is still registered in the copy
/// store under `copy_dir`.
pub fn worktree_registered(copy_dir: &Path) -> bool {
    let worktrees = COPY_STORE_WORKTREES
        .iter()
        .fold(copy_dir.to_path_buf(), |path, part| path.join(part));
    std::fs::read_dir(worktrees).is_ok_and(|mut entries| entries.next().is_some())
}
