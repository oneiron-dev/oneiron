//! The one scope walk every setting read takes (FIX 2957): the value in force
//! over a read's scopes, beside the row that decided it, so a reader that
//! cites its inputs names the rows of the very value it read.

use super::fit::cached_fit;
use super::{
    SettingMode, SettingScope, SettingSpec, StoredSettingRow, read_scopes, read_scopes_in_txn,
    scoped_row,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::TypeRef;
use crate::store::Store;

/// The row that decided a setting read.
pub(super) enum Decided {
    /// The native PUT act of the owner row that decided this read.
    Owner { witness: Option<EntityId> },
    /// One cell's cached fit: its project when it is scoped to one, its
    /// subject when that is not the knob's global one, and its type node
    /// when that is not the root.
    Fit {
        project: Option<EntityId>,
        subject: Option<EntityId>,
        type_node: Option<String>,
    },
    /// The catalog seed.
    Catalog,
}

/// [`super::setting_value_scoped`] inside a transaction the caller already
/// holds.
pub(crate) fn setting_value_in_scope_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    project: Option<EntityId>,
    type_ref: Option<&TypeRef>,
) -> Result<f64> {
    let scopes = read_scopes_in_txn(vault, txn, project, type_ref)?;
    resolve_in_txn(&vault.store, txn, spec, &scopes, type_ref).map(|(value, _)| value)
}

/// [`super::setting_value_scoped`] from the store alone, which cannot
/// resolve a project's goal: goal rows are not read. A reader holding the
/// vault calls [`setting_value_in_scope_in_txn`].
pub(crate) fn setting_value_scoped_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    project: Option<EntityId>,
    type_ref: Option<&TypeRef>,
) -> Result<f64> {
    let scopes = read_scopes(None, project, type_ref);
    resolve_in_txn(store, txn, spec, &scopes, type_ref).map(|(value, _)| value)
}

/// The value in force for `spec` over `scopes`, narrowest first, beside the
/// row that decided it: the narrowest pin the owner set, else the narrowest
/// pin a holder of `engine.controls` set; else, scope by scope, its fit at
/// the type, then its own fit, then its seed; else the vault fit, the vault's
/// seed, the catalog seed. An owner's pin fixes the value until the owner
/// changes it, so no holder's pin at a narrower scope stands over it,
/// whichever of the two was set first. The read's project is the project
/// scope among `scopes` (FIX 6038): a project's fit, and its goal's, are
/// keyed by it. A holder's row on a work budget reads no higher than the
/// owner's seed or pin at that row's scope ([`capped_row_in_txn`]).
///
/// # Errors
///
/// Storage errors; [`crate::error::Error::CorruptedIndex`] on an undecodable row.
pub(super) fn resolve_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    scopes: &[SettingScope],
    type_ref: Option<&TypeRef>,
) -> Result<(f64, Decided)> {
    let mut holder_pin = None;
    for scope in scopes {
        if let Some(row) = scoped_row(store, txn, spec, SettingMode::Pin, scope)? {
            if !row.by_holder {
                return Ok((
                    row.value,
                    Decided::Owner {
                        witness: row.witness,
                    },
                ));
            }
            if holder_pin.is_none() {
                holder_pin = Some((scope, row));
            }
        }
    }
    if let Some((scope, row)) = holder_pin {
        return capped_row_in_txn(store, txn, spec, scope, row);
    }
    let project = scopes.iter().find_map(|scope| match scope {
        SettingScope::Project(project) => Some(*project),
        _ => None,
    });
    let type_node = type_ref
        .filter(|type_ref| !type_ref.is_root())
        .map(|type_ref| type_ref.node_id.as_str());
    for scope in scopes.iter().filter(|scope| **scope != SettingScope::Vault) {
        // Each fit this scope reads, as (project, subject, type node).
        let fits: Vec<(Option<EntityId>, Option<EntityId>, Option<&str>)> = match scope {
            SettingScope::Goal(goal) => type_node
                .map(|node| (project, Some(*goal), Some(node)))
                .into_iter()
                .chain([(project, Some(*goal), None)])
                .collect(),
            SettingScope::Project(project) => type_node
                .map(|node| (Some(*project), None, Some(node)))
                .into_iter()
                .chain([(Some(*project), None, None)])
                .collect(),
            SettingScope::Type(_) => type_node
                .map(|node| (None, None, Some(node)))
                .into_iter()
                .collect(),
            SettingScope::Vault => Vec::new(),
        };
        for (project, subject, node) in fits {
            if let Some(value) = cached_fit(store, txn, spec, project, subject, node)? {
                let type_node = node.map(str::to_owned);
                let decided = Decided::Fit {
                    project,
                    subject,
                    type_node,
                };
                return Ok((value, decided));
            }
        }
        if let Some(row) = scoped_row(store, txn, spec, SettingMode::Seed, scope)? {
            return capped_row_in_txn(store, txn, spec, scope, row);
        }
    }
    if let Some(value) = cached_fit(store, txn, spec, None, None, None)? {
        let decided = Decided::Fit {
            project: None,
            subject: None,
            type_node: None,
        };
        return Ok((value, decided));
    }
    Ok(
        match scoped_row(store, txn, spec, SettingMode::Seed, &SettingScope::Vault)? {
            Some(row) => capped_row_in_txn(store, txn, spec, &SettingScope::Vault, row)?,
            None => (spec.seed, Decided::Catalog),
        },
    )
}

/// The value and witness of the stored `row` over `scope` that decides a
/// read. A holder's row on a work budget reads no higher than the owner's
/// own seed or pin for that knob at the same scope, the cap the holder's
/// door checks ([`super::holder::is_work_budget`]): a cap the owner set or
/// lowered after the holder's row decides instead, cited by its own act
/// (HOLDER-WORK-BUDGET-CAP-ORDER, RULING ROW4-HOLDER-BUDGET-CAP = B). The
/// holder's row stays stored, so raising the cap revives it.
fn capped_row_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    scope: &SettingScope,
    row: StoredSettingRow,
) -> Result<(f64, Decided)> {
    let (mut value, mut witness) = (row.value, row.witness);
    if row.by_holder && super::holder::is_work_budget(spec.key) {
        for mode in [SettingMode::Pin, SettingMode::Seed] {
            if let Some(cap) = scoped_row(store, txn, spec, mode, scope)?
                && !cap.by_holder
                && cap.value < value
            {
                (value, witness) = (cap.value, cap.witness);
            }
        }
    }
    Ok((value, Decided::Owner { witness }))
}
