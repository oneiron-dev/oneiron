//! Door for `tests/repo_anchor_symbol_manifest.rs` (FIX
//! RUN-DECLARE-ANCHOR-MANIFEST): the production selector a run's symbol
//! declaration and queue entry use to find the manifest of the work's base
//! snapshot, called with a registered anchor's folder and a pinned commit.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_symbol::CodeSymbolManifest;
use crate::codebase::{CODEBASE_COMMIT_HASH_HEX_LEN, RepoRef};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// The symbol manifest of the snapshot of `anchor`'s folder `folder` at
/// `base_green`, as `Vault::repo_base_symbol_manifest_in_txn` selects it for
/// a run's work. The anchor's stored pointer is a folder at the zero commit,
/// as `vault.repo.anchor.bind` stores it.
///
/// # Errors
/// The selector's.
pub fn repo_base_symbol_manifest(
    vault: &Vault,
    anchor: EntityId,
    folder: &str,
    base_green: &str,
) -> Result<Option<CodeSymbolManifest>> {
    let anchor_ref = RepoRef::LocalFolder {
        path: folder.to_owned(),
        commit: "0".repeat(CODEBASE_COMMIT_HASH_HEX_LEN),
    };
    let txn = vault.store.env.read_txn()?;
    vault.repo_base_symbol_manifest_in_txn(&txn, anchor, &anchor_ref, base_green)
}
