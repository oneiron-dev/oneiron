//! A setting's value beside the rows it stands on (FIX 7101): what a producer
//! that cites its inputs reads in place of the bare value, at the scope its
//! work ran under (FIX 2957).

use super::{global_setting_subject, known_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::{LearningPredicate, TypeRef};
use crate::setting::{FitCell, Setting, SettingSource};

/// [`super::setting_value_in_scope_in_txn`] beside the rows its value stands
/// on, from the same walk: the heads of the deciding fit's cells when a fit
/// decides, the setting change that wrote the deciding seed or pin (the
/// record of that act, by the revision the read names), and none when the
/// shipped seed does. `None`, unknown, when that change is gone, when the
/// deciding row does not decode, or when the fit's cells hold no head.
///
/// # Errors
///
/// As [`super::setting_value_in_scope_in_txn`].
pub(crate) fn setting_value_in_scope_sourced_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &Setting<f64>,
    project: Option<EntityId>,
    type_ref: Option<&TypeRef>,
) -> Result<(f64, Option<Vec<EntityId>>)> {
    let known = known_in_txn(vault, txn, project, type_ref)?;
    let read = key.read_in_txn(vault, txn, &known, None)?;
    let rows = match &read.source {
        SettingSource::Default => Some(Vec::new()),
        SettingSource::Fit(cell) => fit_heads_in_txn(vault, txn, key.spec.name, cell)?,
        SettingSource::Row(_) | SettingSource::Pin(_) => {
            change_row_in_txn(vault, txn, read.revision)?
        }
        SettingSource::Unreadable(_) => None,
    };
    Ok((read.value, rows))
}

/// The change row that wrote the deciding row, by the revision the read names: the record of
/// the act that set it. `None` where no such change stands (erased with its setter's scope).
fn change_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    revision: u64,
) -> Result<Option<Vec<EntityId>>> {
    let Some(after) = revision.checked_sub(1) else {
        return Ok(None);
    };
    let (changes, _) = crate::setting::settings_after_in_txn(&vault.store, txn, Some(after), 1)?;
    Ok(changes
        .into_iter()
        .find(|change| change.sequence == revision)
        .map(|change| vec![change.id]))
}

/// The active head CLAIM of each cell the fit `fit` of the knob `name` is
/// cached from: in its project's scope exactly, else the vault's (FIX 6038);
/// on its goal, else the knob's global subject; at its task type, else
/// root-typed; with no executor, axis or consent scope. `None` when no such
/// cell holds one.
fn fit_heads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    name: &str,
    fit: &FitCell,
) -> Result<Option<Vec<EntityId>>> {
    let (project, type_node) = (fit.project, fit.task_type.as_deref());
    let subject = match fit.goal {
        Some(goal) => goal,
        None => global_setting_subject(name)?,
    };
    let typed = |type_ref: &TypeRef| match type_node {
        Some(node) => type_ref.node_id == node,
        None => type_ref.is_root(),
    };
    let mut heads = Vec::new();
    for row in crate::learning::evidence::cells_for_subject_in_txn(vault, txn, &subject)? {
        let cell = row.cell;
        if cell.predicate != LearningPredicate::Setting
            || cell.setting_key.as_deref() != Some(name)
            || cell.executor.is_some()
            || cell.axis.is_some()
            || cell.consent_scope.is_some()
            || cell.project != project
            || !cell.type_ref.as_ref().is_some_and(typed)
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
