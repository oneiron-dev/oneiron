//! The codebase scope index's anchor and symbol rows (FIX 4300,
//! CODE-CUSTODY-01).
//!
//! A repository scope holds the registered repository's CODE anchor, each
//! immutable snapshot CODE, the ASSETs of its files and every symbol its
//! manifest names. The snapshot writer and the symbol manifest writer change
//! these rows in the transaction that changes the snapshot or the manifest.
//! A row that another retained snapshot of the same scope still holds stays:
//! a shared ASSET, a stable symbol id, the anchor.
//!
//! A scope row confers no Grant. A read applies it as a filter after its own
//! admission and its own ScopedRead.

use std::collections::BTreeSet;

use super::*;
use crate::code_symbol::code_symbol_manifest_ids_in_txn;

/// Visits each other retained snapshot of `snapshot`'s scope, beside the one
/// at `id`, until `visit` answers `false`. A scope is one project and one
/// repository at every revision (FIX 4299), so every snapshot that can share
/// it is indexed under its project; the scope check keeps those of this
/// scope. A snapshot body that does not decode holds nothing.
pub(super) fn visit_other_scope_snapshots(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    snapshot: &CodebaseSnapshot,
    mut visit: impl FnMut(&EntityId, &CodebaseSnapshot) -> Result<bool>,
) -> Result<()> {
    let prefix = text_index_scan_prefix(&snapshot.project_id);
    for key in PROJECT_INDEX.scan_keys(store, txn, &prefix)? {
        if key.id == *id {
            continue;
        }
        let other = match SNAPSHOTS.get(store, txn, &key.id) {
            Ok(Some(other)) => other,
            Ok(None) | Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(_))) => continue,
            Err(err) => return Err(err),
        };
        if other.scope_key != snapshot.scope_key {
            continue;
        }
        if !visit(&key.id, &other)? {
            break;
        }
    }
    Ok(())
}

/// Puts the scope rows of `snapshot`'s anchor and of every symbol the
/// manifest stored for `code_artifact_id` names (FIX 4300).
pub(super) fn put_scope_member_rows(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    code_artifact_id: &EntityId,
    snapshot: &CodebaseSnapshot,
) -> Result<()> {
    if let Some(anchor) = snapshot.repository {
        put_scope_row(store, wtxn, &snapshot.scope_key, anchor)?;
    }
    let symbols = code_symbol_manifest_ids_in_txn(store, wtxn, code_artifact_id)?;
    for symbol in symbols {
        put_scope_row(store, wtxn, &snapshot.scope_key, symbol)?;
    }
    Ok(())
}

/// Deletes the scope rows of `snapshot`'s anchor and of the symbols its
/// manifest names that no other retained snapshot of its scope holds (FIX
/// 4300). The anchor's row stays while any other snapshot of the scope
/// stands: every snapshot of a registered scope names the same anchor.
pub(super) fn delete_scope_member_rows(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    snapshot: &CodebaseSnapshot,
) -> Result<()> {
    let symbols = code_symbol_manifest_ids_in_txn(store, wtxn, id)?;
    let (scope_held, unshared) = unshared_symbols(store, wtxn, id, snapshot, symbols)?;
    if let Some(anchor) = snapshot.repository
        && !scope_held
    {
        delete_scope_row(store, wtxn, &snapshot.scope_key, anchor)?;
    }
    for symbol in unshared {
        delete_scope_row(store, wtxn, &snapshot.scope_key, symbol)?;
    }
    Ok(())
}

/// The symbol manifest writer's put (FIX 4300): a scope row for each of
/// `symbols` under the scope of the snapshot stored for `code_artifact_id`.
/// A CODE artifact with no snapshot is in no repository scope.
///
/// # Errors
/// A store failure.
pub(crate) fn put_scope_symbol_rows_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    code_artifact_id: &EntityId,
    symbols: &BTreeSet<EntityId>,
) -> Result<()> {
    let Some(snapshot) = scope_snapshot(store, wtxn, code_artifact_id)? else {
        return Ok(());
    };
    for symbol in symbols {
        put_scope_row(store, wtxn, &snapshot.scope_key, *symbol)?;
    }
    Ok(())
}

/// The symbol manifest writer's delete (FIX 4300): the scope rows of
/// `symbols` under the scope of the snapshot stored for `code_artifact_id`,
/// except those another retained snapshot of that scope names.
///
/// # Errors
/// A store failure.
pub(crate) fn delete_scope_symbol_rows_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    code_artifact_id: &EntityId,
    symbols: BTreeSet<EntityId>,
) -> Result<()> {
    let Some(snapshot) = scope_snapshot(store, wtxn, code_artifact_id)? else {
        return Ok(());
    };
    let (_, unshared) = unshared_symbols(store, wtxn, code_artifact_id, &snapshot, symbols)?;
    for symbol in unshared {
        delete_scope_row(store, wtxn, &snapshot.scope_key, symbol)?;
    }
    Ok(())
}

/// Whether another retained snapshot of `snapshot`'s scope stands, and the
/// ones of `symbols` that no such snapshot's manifest names.
fn unshared_symbols(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    snapshot: &CodebaseSnapshot,
    mut symbols: BTreeSet<EntityId>,
) -> Result<(bool, BTreeSet<EntityId>)> {
    let mut scope_held = false;
    if snapshot.repository.is_none() && symbols.is_empty() {
        return Ok((scope_held, symbols));
    }
    visit_other_scope_snapshots(store, txn, id, snapshot, |other, _| {
        scope_held = true;
        if !symbols.is_empty() {
            for symbol in code_symbol_manifest_ids_in_txn(store, txn, other)? {
                symbols.remove(&symbol);
            }
        }
        Ok(!symbols.is_empty())
    })?;
    Ok((scope_held, symbols))
}

/// The snapshot stored for `code_artifact_id`, whose scope its rows are
/// under; `None` when it has none or its body does not decode.
fn scope_snapshot(
    store: &Store,
    txn: &RoTxn<'_>,
    code_artifact_id: &EntityId,
) -> Result<Option<CodebaseSnapshot>> {
    match SNAPSHOTS.get(store, txn, code_artifact_id) {
        Ok(snapshot) => Ok(snapshot),
        Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(_))) => Ok(None),
        Err(err) => Err(err),
    }
}

fn put_scope_row(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    scope_key: &CodebaseScopeKey,
    id: EntityId,
) -> Result<()> {
    SCOPE_INDEX.put(
        store,
        wtxn,
        &HashIndexKey {
            value: *scope_key,
            id,
        },
        &(),
    )
}

fn delete_scope_row(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    scope_key: &CodebaseScopeKey,
    id: EntityId,
) -> Result<()> {
    SCOPE_INDEX.delete(
        store,
        wtxn,
        &HashIndexKey {
            value: *scope_key,
            id,
        },
    )?;
    Ok(())
}
