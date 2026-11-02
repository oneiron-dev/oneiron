//! A setting's value beside the rows it stands on (FIX 7101): what a producer
//! that cites its inputs reads in place of the bare value, at the scope its
//! work ran under (FIX 2957).

use super::resolution::{Decided, resolve_in_txn};
use super::{SettingSpec, global_setting_subject, read_scopes_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::{LearningPredicate, TypeRef};

/// [`super::setting_value_in_scope_in_txn`] beside the rows its value stands
/// on, from the same walk: the heads of the deciding fit's cells when a fit
/// decides, none when the catalog seed does. `None`, unknown, when an owner
/// pin or seed decides, as an owner row keeps no witness row, and when the
/// fit's cells hold no head.
///
/// # Errors
///
/// As [`super::setting_value_in_scope_in_txn`].
pub(crate) fn setting_value_in_scope_sourced_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    project: Option<EntityId>,
    type_ref: Option<&TypeRef>,
) -> Result<(f64, Option<Vec<EntityId>>)> {
    let scopes = read_scopes_in_txn(vault, txn, project, type_ref)?;
    let (value, decided) = resolve_in_txn(&vault.store, txn, spec, &scopes, type_ref)?;
    let rows = match decided {
        Decided::Owner => None,
        Decided::Catalog => Some(Vec::new()),
        Decided::Fit {
            project,
            subject,
            type_node,
        } => fit_heads_in_txn(vault, txn, spec, project, subject, type_node.as_deref())?,
    };
    Ok((value, rows))
}

/// The active head CLAIM of each cell one fit of `spec` is cached from: in
/// `project`'s scope exactly, else the vault's (FIX 6038); on `subject`,
/// else its knob's global subject; at `type_node`, else root-typed; with no
/// executor, axis or consent scope. `None` when no such cell holds one.
fn fit_heads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    project: Option<EntityId>,
    subject: Option<EntityId>,
    type_node: Option<&str>,
) -> Result<Option<Vec<EntityId>>> {
    let subject = match subject {
        Some(subject) => subject,
        None => global_setting_subject(spec.key)?,
    };
    let typed = |type_ref: &TypeRef| match type_node {
        Some(node) => type_ref.node_id == node,
        None => type_ref.is_root(),
    };
    let mut heads = Vec::new();
    for row in crate::learning::evidence::cells_for_subject_in_txn(vault, txn, &subject)? {
        let cell = row.cell;
        if cell.predicate != LearningPredicate::Setting
            || cell.setting_key.as_deref() != Some(spec.key)
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
