//! Core half of `batch::secret_scan::lift_history::side_rows`: its store-layer items live in `oneiron_store::batch::secret_scan::lift_history::side_rows` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::lift_history::side_rows::*;

use super::super::{admit_side_row, write_payload_hit};
use super::{Done, LiftCause, Page, hex, prefix_end, table_page};
use crate::Vault;
use crate::error::Result;
use crate::side_table::{CodecName, SideTableDecl, authored_vault_meta};
use heed::{RoTxn, RwTxn};
use rmpv::Value;
use std::borrow::Cow;

/// The authored rows after `after` (a whole `vault_meta` key; empty at the
/// start), table by table in prefix order, up to `limit`.
pub(super) fn census(vault: &Vault, txn: &RoTxn<'_>, after: &[u8], limit: usize) -> Result<Page> {
    let mut page = Page {
        read: 0,
        known_reads: Vec::new(),
        hits: Vec::new(),
        next: None,
    };
    let mut left = limit;
    for decl in authored_vault_meta() {
        // A table whose every key is at or before the cursor is done.
        if !after.is_empty() && prefix_end(decl.prefix).is_some_and(|end| end.as_slice() <= after) {
            continue;
        }
        let (rows, ended) = table_page(vault, txn, decl.prefix, after, left)?;
        for (key, value) in &rows {
            page.read += 1;
            if write_payload_hit(value).is_some() {
                page.hits.push(key.clone());
            }
        }
        left = left.saturating_sub(rows.len());
        if !ended || left == 0 {
            page.next = rows.last().map(|(key, _)| key.clone());
            if page.next.is_some() {
                return Ok(page);
            }
        }
    }
    Ok(page)
}

/// Reads row `key` again in the writer's transaction and stores it as the
/// wall admits it when it still holds a hit.
pub(super) fn lift(vault: &Vault, txn: &mut RwTxn<'_>, key: &[u8]) -> Result<Done> {
    let Some(decl) = table_of(key) else {
        return Ok(Done::Clean);
    };
    let Some(row) = vault.store.vault_meta.get(txn, key)?.map(Cow::into_owned) else {
        return Ok(Done::Clean);
    };
    let Some(reason) = write_payload_hit(&row) else {
        return Ok(Done::Clean);
    };
    let admitted = admit_side_row(vault, txn, decl, key, &row, |copy| match decl.accepts {
        Some(accepts) => accepts(copy),
        None => keeps_shape(decl, &row, copy),
    })?;
    let Some(masked) = admitted else {
        return Ok(Done::Propose(LiftCause::Unplaceable, reason));
    };
    vault.store.vault_meta.put(txn, key, &masked)?;
    Ok(Done::Masked {
        history: false,
        reason,
    })
}

/// `side:<table>:<key after its prefix, hex>`.
pub(super) fn path(key: &[u8]) -> String {
    match table_of(key) {
        Some(decl) => format!(
            "side:{}:{}",
            decl.name,
            hex(key.get(decl.prefix.len()..).unwrap_or_default())
        ),
        None => format!("side::{}", hex(key)),
    }
}

/// Whether row `key` is still stored.
pub(super) fn exists(vault: &Vault, txn: &RoTxn<'_>, key: &[u8]) -> Result<bool> {
    Ok(vault.store.vault_meta.get(txn, key)?.is_some())
}

fn table_of(key: &[u8]) -> Option<&'static SideTableDecl> {
    authored_vault_meta().find(|decl| key.starts_with(decl.prefix))
}

/// Whether `after`, a masked copy of `before`, is laid out as it is: the
/// same version byte, and each value of the same kind where it was.
fn keeps_shape(decl: &SideTableDecl, before: &[u8], after: &[u8]) -> bool {
    let skip = usize::from(decl.codec == CodecName::VersionedNamed);
    let (Some((version, before)), Some((again, after))) =
        (before.split_at_checked(skip), after.split_at_checked(skip))
    else {
        return false;
    };
    if version != again {
        return false;
    }
    match (read(before), read(after)) {
        (Some(before), Some(after)) => same_shape(&before, &after),
        _ => false,
    }
}
