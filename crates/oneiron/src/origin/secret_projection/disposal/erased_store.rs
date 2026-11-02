//! The masked copies of an erased canonical store (FIX 7608 pre-flip, FIX
//! 10274): the owner's erase, carried out.
//!
//! A copy is about its canonical store, so the store's permanent
//! hard-delete marker (presence only, never a missing body) retires it
//! whatever its marks still say: a copy whose graph record stands goes
//! through the ordinary guarded retirement, and a copy whose record the
//! erase already took is found here by the deterministic layout it lives
//! in, one directory per erased store and graph. Only a strict graph id
//! directory of a store whose marker exists is removed: never the
//! canonical store, never a private ingress, and never a copy store a
//! checkout's worktree is still registered in (its retained work stays).
//! A removal that fails is found again by the next pass.

use std::path::Path;

use heed::RoTxn;

use super::super::claims::RepoProjectionClaim;
use super::super::git::existing_projection_ingress_root;
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

/// Removes every copy directory of an erased canonical store that no
/// graph record stands behind any more, and answers how many it removed.
///
/// # Errors
/// A store failure reading the markers or records, or a directory that
/// cannot be listed. One copy's failed removal is logged and left for the
/// next pass.
pub(crate) fn collect_erased_store_graphs(vault: &Vault) -> Result<usize> {
    let root = vault
        .store
        .env
        .path()
        .join(super::super::git::REPO_SECRET_PROJECTION_DIR);
    let Ok(stores) = std::fs::read_dir(&root) else {
        return Ok(0);
    };
    let mut orphaned = Vec::new();
    {
        let txn = vault.store.env.read_txn()?;
        for store in stores {
            let store = store?;
            let Some(store_id) = id_dir(&store.path()) else {
                continue;
            };
            if !repo_projection_store_erased_in_txn(vault, &txn, &store_id)? {
                continue;
            }
            let ingress = existing_projection_ingress_root(vault, store_id);
            for graph in std::fs::read_dir(store.path())? {
                let path = graph?.path();
                if path == ingress {
                    continue;
                }
                let Some(graph) = id_dir(&path) else {
                    continue;
                };
                if RepoProjectionClaim::load_graph_in_txn(vault, &txn, &graph)?.is_none()
                    && !worktree_registered(&path)
                {
                    orphaned.push(path);
                }
            }
        }
    }
    let mut removed = 0_usize;
    for path in orphaned {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => removed += 1,
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "an erased store's masked Git copy was not removed; the next pass retries"
            ),
        }
    }
    Ok(removed)
}

/// The id a strict 32-hex directory name is, or `None` for anything else.
fn id_dir(path: &Path) -> Option<EntityId> {
    if !path.is_dir() {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    if name.len() != 32 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    EntityId::from_hex(name).ok()
}

/// Whether a checkout's linked worktree is still registered in the copy
/// store under `copy_dir`.
fn worktree_registered(copy_dir: &Path) -> bool {
    let worktrees = COPY_STORE_WORKTREES
        .iter()
        .fold(copy_dir.to_path_buf(), |path, part| path.join(part));
    std::fs::read_dir(worktrees).is_ok_and(|mut entries| entries.next().is_some())
}
