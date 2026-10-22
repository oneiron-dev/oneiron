//! The one scope walk every setting read takes (FIX 2957): the value in force
//! over a read's scopes, beside the row that decided it, so a reader that
//! cites its inputs names the rows of the very value it read.

use super::{SettingMode, SettingScope, SettingSpec, cached_fit, scoped_row_value};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::TypeRef;
use crate::store::Store;

/// The row that decided a setting read.
pub(super) enum Decided {
    /// An owner pin or seed, which keeps no witness row.
    Owner,
    /// One cell's cached fit: its subject when that is not the knob's global
    /// one, and its type node when that is not the root.
    Fit {
        subject: Option<EntityId>,
        type_node: Option<String>,
    },
    /// The catalog seed.
    Catalog,
}

/// The value in force for `spec` over `scopes`, narrowest first, beside the
/// row that decided it: the narrowest pin; else, scope by scope, its fit at
/// the type, then its own fit, then its seed; else the vault fit, the vault's
/// seed, the catalog seed.
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
    for scope in scopes {
        if let Some(value) = scoped_row_value(store, txn, spec, SettingMode::Pin, scope)? {
            return Ok((value, Decided::Owner));
        }
    }
    let type_node = type_ref
        .filter(|type_ref| !type_ref.is_root())
        .map(|type_ref| type_ref.node_id.as_str());
    for scope in scopes.iter().filter(|scope| **scope != SettingScope::Vault) {
        let fits: Vec<(Option<EntityId>, Option<&str>)> = match scope {
            SettingScope::Goal(subject) | SettingScope::Project(subject) => type_node
                .map(|node| (Some(*subject), Some(node)))
                .into_iter()
                .chain([(Some(*subject), None)])
                .collect(),
            SettingScope::Type(_) => type_node
                .map(|node| (None, Some(node)))
                .into_iter()
                .collect(),
            SettingScope::Vault => Vec::new(),
        };
        for (subject, node) in fits {
            if let Some(value) = cached_fit(store, txn, spec, subject, node)? {
                let type_node = node.map(str::to_owned);
                return Ok((value, Decided::Fit { subject, type_node }));
            }
        }
        if let Some(value) = scoped_row_value(store, txn, spec, SettingMode::Seed, scope)? {
            return Ok((value, Decided::Owner));
        }
    }
    if let Some(value) = cached_fit(store, txn, spec, None, None)? {
        let decided = Decided::Fit {
            subject: None,
            type_node: None,
        };
        return Ok((value, decided));
    }
    Ok(
        match scoped_row_value(store, txn, spec, SettingMode::Seed, &SettingScope::Vault)? {
            Some(value) => (value, Decided::Owner),
            None => (spec.seed, Decided::Catalog),
        },
    )
}
