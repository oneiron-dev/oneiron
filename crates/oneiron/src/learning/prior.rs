//! Priors: everything that is not a cell's own evidence enters with an origin
//! and a weight in runs (ARCH-0003 "The six prior origins").
//!
//! One law covers carried scores, hub imports, type splits and project forks.
//! The engine door here stores a cell's prior; the owner's seed never comes
//! through it, because a seed is a setting row the owner writes
//! ([`crate::learning_setting::put_setting_row`]).

use crate::Vault;
use crate::error::{Error, Result};
use crate::learning_setting::{self, SettingSpec};
use crate::side_table::{self, Named, SideTable};

use super::cell::{LearningCell, LearningPredicate, TypeRef};
use super::estimate::{EstimateForm, EstimateValue, Prior, PriorOrigin};
use super::evidence::{CellRow, ensure_cell_in_txn};
use super::project::project_cell_in_txn;
use super::read::read_learning_in_txn;

/// A cell's stored prior. Key: the cell digest.
pub(crate) const PRIOR: SideTable<[u8; 32], Prior, Named> =
    SideTable::new(&side_table::LEARNING_PRIOR);

/// Stores the prior `cell` starts from and re-projects it.
///
/// Callers are the operations the law names: a hub import (`provenance`), an
/// executor swap (`carried`), a type split or project fork (`parent`), a
/// model's weak guess (`model`) and a pack default (`shipped`).
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a `seed` origin (the owner's seed is a
/// setting row), a malformed prior or cell, or a prior in a form the cell does
/// not carry; storage errors.
pub fn put_cell_prior(vault: &Vault, cell: &LearningCell, prior: &Prior, now: u64) -> Result<()> {
    if prior.origin == PriorOrigin::Seed {
        return Err(Error::InvalidClaimBody(
            "the owner's seed is a setting row, never an engine-written prior",
        ));
    }
    prior.validate()?;
    vault.with_write_txn_grouped(|wtxn| {
        let digest = ensure_cell_in_txn(vault, wtxn, cell, prior.value.form())?;
        PRIOR.put(&vault.store, wtxn, &digest, prior)?;
        project_cell_in_txn(vault, wtxn, &digest, now)?;
        Ok(())
    })
}

/// Keeps the prior a cell borrows (its parent type's, or the same question
/// at another executor) as the cell's stored prior before its first own
/// evidence, so that evidence adds runs against the borrowed weight instead
/// of replacing it ("Receipts then outweigh it, like any prior"). A cell with
/// a stored prior or an own head keeps what it has; a cell that borrows
/// nothing, or borrows in another form than `form`, stores nothing.
///
/// # Errors
///
/// A malformed cell or type ref; storage errors.
pub(crate) fn capture_borrowed_prior_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    type_parents: &[TypeRef],
    form: EstimateForm,
) -> Result<()> {
    let digest = cell.digest();
    if PRIOR.contains(&vault.store, wtxn, &digest)? {
        return Ok(());
    }
    let read = read_learning_in_txn(vault, wtxn, cell, type_parents)?;
    if read.own || read.borrowed_from.is_none() || read.estimate.form() != form {
        return Ok(());
    }
    ensure_cell_in_txn(vault, wtxn, cell, form)?;
    PRIOR.put(&vault.store, wtxn, &digest, &read.estimate.prior)
}

/// The prior in force for a registered cell.
///
/// A `learning.setting` cell starts from the owner's seed for its scope when
/// one is set (its project's, its type's, else the vault's),
/// then from a stored prior, then from the catalog seed at the shipped
/// weight. Every other cell starts from its stored prior, else the shipped
/// default of its form.
pub(crate) fn cell_prior_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &CellRow,
    digest: &[u8; 32],
) -> Result<Prior> {
    if row.cell.predicate == LearningPredicate::Setting
        && let Some(spec) = row
            .cell
            .setting_key
            .as_deref()
            .and_then(learning_setting::setting_spec)
        && let Some((value, weight_runs)) = learning_setting::owner_seed_in_txn(
            &vault.store,
            txn,
            spec,
            row.cell.subject,
            row.cell.type_ref.as_ref(),
        )?
    {
        return Ok(Prior {
            origin: PriorOrigin::Seed,
            value: point_value(row, value),
            weight_runs,
            from: Some(format!("setting row {}", spec.key)),
        });
    }
    if let Some(prior) = PRIOR.get(&vault.store, txn, digest)?
        && prior.value.form() == row.form
    {
        return Ok(prior);
    }
    if row.cell.predicate == LearningPredicate::Setting
        && let Some(spec) = row
            .cell
            .setting_key
            .as_deref()
            .and_then(learning_setting::setting_spec)
    {
        return Ok(shipped_setting_prior(vault, txn, row, spec)?);
    }
    Ok(Prior::shipped(row.form))
}

fn shipped_setting_prior(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &CellRow,
    spec: &SettingSpec,
) -> Result<Prior> {
    let weight_runs = learning_setting::setting_value_in_txn(
        &vault.store,
        txn,
        &learning_setting::LEARNING_SHIPPED_PRIOR_RUNS,
    )?;
    Ok(Prior {
        origin: PriorOrigin::Shipped,
        value: point_value(row, spec.seed),
        weight_runs,
        from: Some(format!("catalog {}", spec.key)),
    })
}

/// A point value in the cell's form: a mean with no spread, or one count of
/// the cell's `of` category.
fn point_value(row: &CellRow, value: f64) -> EstimateValue {
    match row.form {
        EstimateForm::Counts => EstimateValue::Counts {
            counts: std::iter::once((row.of.clone(), 1.0)).collect(),
        },
        EstimateForm::Beta => EstimateValue::Beta {
            alpha: value.clamp(1e-6, 1.0 - 1e-6),
            beta: (1.0 - value).clamp(1e-6, 1.0 - 1e-6),
        },
        EstimateForm::Mean => EstimateValue::Mean {
            mean: value,
            spread: 0.0,
        },
    }
}
