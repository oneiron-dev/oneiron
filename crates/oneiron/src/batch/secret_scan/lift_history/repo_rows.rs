//! Core half of `batch::secret_scan::lift_history::repo_rows`: its store-layer items live in `oneiron_store::batch::secret_scan::lift_history::repo_rows` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::lift_history::repo_rows::*;

use super::Done;
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self as t, SideTableDecl};
use heed::{RoTxn, RwTxn};
use rmpv::Value;

/// Whether `decl` is one of the two repo-mutation row families.
fn is_repo_row(decl: &SideTableDecl) -> bool {
    std::ptr::eq(decl, &t::REPO_MUTATION_OPLOG) || std::ptr::eq(decl, &t::REPO_MUTATION_PROPOSAL)
}

/// The door's reason for a hit in carrier row `key` (the whole key) of
/// `decl`, by its stored texts; `None` when `decl` has no door here.
pub(super) fn hit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    decl: &SideTableDecl,
    _key: &[u8],
    stored: &[u8],
) -> Result<Option<Option<&'static str>>> {
    if !is_repo_row(decl) {
        return Ok(None);
    }
    let texts = texts_of(stored);
    if texts.is_empty() {
        return Ok(Some(None));
    }
    Ok(Some(crate::batch::secret_scan::carrier_texts_hit_in_txn(
        &vault.store,
        txn,
        &texts,
    )?))
}

/// Reads carrier row `key` (the whole key) of `decl` again and marks a hit
/// it still holds; `None` when `decl` has no door here. The row's bytes
/// stay as they are.
pub(super) fn lift(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    decl: &SideTableDecl,
    key: &[u8],
) -> Result<Option<Done>> {
    if !is_repo_row(decl) {
        return Ok(None);
    }
    let Some(stored) = vault.store.vault_meta.get(txn, key)? else {
        return Ok(Some(Done::Clean));
    };
    let texts = texts_of(&stored);
    let row = key.strip_prefix(decl.prefix).unwrap_or(key);
    let marked =
        crate::batch::secret_scan::mark_carrier_texts_in_txn(vault, txn, decl, row, &texts)?;
    Ok(Some(super::retained::text_done(marked)))
}
