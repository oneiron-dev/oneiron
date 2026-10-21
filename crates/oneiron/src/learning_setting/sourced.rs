//! A vault-wide setting's value beside the rows it stands on (FIX 7101): what
//! a producer that cites its inputs reads in place of the bare value.

use super::{
    SettingMode, SettingScope, SettingSpec, cached_fit, global_setting_subject, scoped_row_value,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::{LearningPredicate, TypeRef};

/// [`super::setting_value_in_txn`] beside the rows its value stands on: the
/// heads of the vault fit's cells when that fit decides, none when the
/// catalog seed does. `None`, unknown, when an owner pin or seed decides, as
/// an owner row keeps no witness row, and when the fit's cells hold no head.
///
/// # Errors
///
/// As [`super::setting_value_in_txn`].
pub(crate) fn setting_value_sourced_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<(f64, Option<Vec<EntityId>>)> {
    let store = &vault.store;
    let scope = SettingScope::Vault;
    if let Some(value) = scoped_row_value(store, txn, spec, SettingMode::Pin, &scope)? {
        return Ok((value, None));
    }
    if let Some(value) = cached_fit(store, txn, spec, None, None)? {
        return Ok((value, vault_fit_heads_in_txn(vault, txn, spec)?));
    }
    Ok(
        match scoped_row_value(store, txn, spec, SettingMode::Seed, &scope)? {
            Some(value) => (value, None),
            None => (spec.seed, Some(Vec::new())),
        },
    )
}

/// The active head CLAIM of each cell the vault fit of `spec` is cached
/// from: root-typed, on its knob's global subject, with no executor, axis or
/// consent scope. `None` when no such cell holds one.
fn vault_fit_heads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<Option<Vec<EntityId>>> {
    let subject = global_setting_subject(spec.key)?;
    let mut heads = Vec::new();
    for row in crate::learning::evidence::cells_for_subject_in_txn(vault, txn, &subject)? {
        let cell = row.cell;
        if cell.predicate != LearningPredicate::Setting
            || cell.setting_key.as_deref() != Some(spec.key)
            || cell.executor.is_some()
            || cell.axis.is_some()
            || cell.consent_scope.is_some()
            || !cell.type_ref.as_ref().is_some_and(TypeRef::is_root)
        {
            continue;
        }
        heads.extend(
            crate::learning::project::active_heads_in_txn(vault, txn, &cell)?
                .into_iter()
                .map(|(id, _, _)| id),
        );
    }
    Ok((!heads.is_empty()).then_some(heads))
}
