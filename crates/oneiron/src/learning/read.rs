//! Reading measured state back, with the fixed backoff order
//! (ARCH-0003 #learning-qualifiers).
//!
//! At the requested executor: the task type, then its parents, then any type;
//! only then the same for any executor. Borrowed runs enter as a `parent` or
//! `carried` prior, never as own evidence, and a borrowed reading is
//! assembled here at read: it never mints a claim.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning_setting::{self, LEARNING_BORROWED_PRIOR_RUNS};

use super::cell::{LearningCell, TypeRef};
use super::estimate::{Estimate, OwnTally, Prior, PriorOrigin};
use super::evidence::{CELL, cells_for_subject_in_txn};
use super::prior::cell_prior_in_txn;
use super::project::{
    StoredEstimateClaim, active_heads_in_txn, measured_tally_in_txn, window_in_txn,
};

/// One reading of a cell.
#[derive(Debug, Clone, PartialEq)]
pub struct LearningRead {
    /// The estimate in force: the cell's own head, or a zero-run estimate
    /// over a stored, borrowed or shipped prior.
    pub estimate: Estimate,
    /// Whether the estimate rests on the cell's own runs.
    pub own: bool,
    /// The cell a borrowed prior came from.
    pub borrowed_from: Option<LearningCell>,
}

/// The cell's own head, when it has own runs.
///
/// # Errors
///
/// Storage errors.
pub fn learning_estimate(vault: &Vault, cell: &LearningCell) -> Result<Option<Estimate>> {
    let rtxn = vault.store.env.read_txn()?;
    own_estimate_in_txn(vault, &rtxn, cell)
}

/// [`learning_estimate`] beside the rows it was read from, from one snapshot
/// (FIX 5760): the claim of the very head it chose. `None` when the cell has
/// no own head.
///
/// # Errors
///
/// Storage errors.
pub fn learning_estimate_with_sources(
    vault: &Vault,
    cell: &LearningCell,
) -> Result<Option<(Estimate, Vec<EntityId>)>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(own_head_in_txn(vault, &rtxn, cell)?.map(|(estimate, _, claim)| (estimate, vec![claim])))
}

/// [`learning_estimate`] inside the caller's transaction. With two heads
/// after a sync, the richer one reads.
pub(crate) fn own_estimate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
) -> Result<Option<Estimate>> {
    Ok(own_head_in_txn(vault, txn, cell)?.map(|(estimate, _, _)| estimate))
}

/// The head [`own_estimate_in_txn`] reads, with the time it was projected
/// and its claim.
fn own_head_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
) -> Result<Option<(Estimate, u64, EntityId)>> {
    Ok(active_heads_in_txn(vault, txn, cell)?
        .into_iter()
        .filter_map(|(claim, body, at)| {
            StoredEstimateClaim::from_value(&body.value)
                .ok()
                .map(|stored| (stored.estimate, at, claim))
        })
        .filter(|(estimate, _, _)| estimate.ver == super::estimate::ESTIMATOR_VERSION)
        .max_by(|a, b| a.0.runs.total_cmp(&b.0.runs)))
}

/// The measured success and failure mass behind `cell`'s own head, with no
/// prior: its evidence folded again under the head's window at the time the
/// head was projected, so it is the mass that head holds. `None` when the
/// cell has no own head, or its head is not a success estimate. A read only:
/// no backoff, nothing written.
///
/// # Errors
///
/// Storage errors, or a head whose cell is not registered.
pub(crate) fn measured_outcomes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
) -> Result<Option<(f64, f64)>> {
    let Some((estimate, at, _)) = own_head_in_txn(vault, txn, cell)? else {
        return Ok(None);
    };
    let digest = cell.digest();
    let row = CELL
        .get(&vault.store, txn, &digest)?
        .ok_or(Error::CorruptedIndex("learning cell"))?;
    Ok(
        match measured_tally_in_txn(vault, txn, &row, &digest, estimate.window, at)? {
            OwnTally::Beta { wins, losses } => Some((wins, losses)),
            OwnTally::Mean { .. } | OwnTally::Counts { .. } => None,
        },
    )
}

/// Reads `cell` with backoff. `type_parents` is the cell's task-type chain
/// from its parent up to the root, as the type tree reports it.
///
/// Order: the cell's own head; an explicitly stored prior (an executor swap,
/// a hub import, a fork); then borrowing at this executor from each parent
/// type, then any type; then the same at any executor; else the shipped prior.
///
/// # Errors
///
/// Storage errors.
pub fn read_learning(
    vault: &Vault,
    cell: &LearningCell,
    type_parents: &[TypeRef],
) -> Result<LearningRead> {
    let rtxn = vault.store.env.read_txn()?;
    read_learning_in_txn(vault, &rtxn, cell, type_parents)
}

/// The same backoff on a retrieval or projection snapshot.
pub(crate) fn read_learning_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
    type_parents: &[TypeRef],
) -> Result<LearningRead> {
    cell.validate()?;
    for parent in type_parents {
        parent.validate()?;
    }
    if let Some(estimate) = own_estimate_in_txn(vault, txn, cell)? {
        return Ok(LearningRead {
            estimate,
            own: true,
            borrowed_from: None,
        });
    }
    let window = window_in_txn(vault, txn)?;
    let digest = cell.digest();
    let registered = CELL.get(&vault.store, txn, &digest)?;
    if let Some(row) = &registered {
        let prior = cell_prior_in_txn(vault, txn, row, &digest)?;
        if prior.origin != PriorOrigin::Shipped {
            return Ok(LearningRead {
                estimate: Estimate::from_prior(prior, row.of.clone(), window),
                own: false,
                borrowed_from: None,
            });
        }
    }

    let cap =
        learning_setting::setting_value_in_txn(&vault.store, txn, &LEARNING_BORROWED_PRIOR_RUNS)?;
    let subject_cells = cells_for_subject_in_txn(vault, txn, &cell.subject)?;
    for (ignore_executor, origin) in [(false, PriorOrigin::Parent), (true, PriorOrigin::Carried)] {
        let mut candidates: Vec<LearningCell> = Vec::new();
        // The same type at another executor is the carried read's first step.
        if ignore_executor {
            candidates.extend(
                subject_cells
                    .iter()
                    .filter(|row| {
                        row.cell != *cell && row.cell.same_question_modulo(cell, false, true)
                    })
                    .map(|row| row.cell.clone()),
            );
        }
        for parent in type_parents {
            candidates.extend(
                subject_cells
                    .iter()
                    .filter(|row| {
                        row.cell.type_ref.as_ref() == Some(parent)
                            && row.cell.same_question_modulo(cell, true, ignore_executor)
                    })
                    .map(|row| row.cell.clone()),
            );
        }
        // Any type last, the richest cell first.
        let mut any_type: Vec<(f64, LearningCell)> = Vec::new();
        for row in &subject_cells {
            if row.cell != *cell
                && row.cell.same_question_modulo(cell, true, ignore_executor)
                && let Some(estimate) = own_estimate_in_txn(vault, txn, &row.cell)?
            {
                any_type.push((estimate.runs, row.cell.clone()));
            }
        }
        any_type.sort_by(|a, b| b.0.total_cmp(&a.0));
        candidates.extend(any_type.into_iter().map(|(_, c)| c));

        for candidate in candidates {
            if let Some(borrowed) = own_estimate_in_txn(vault, txn, &candidate)? {
                let weight_runs = (borrowed.runs + borrowed.prior.weight_runs).min(cap);
                let from = candidate.conflict_key();
                let prior = Prior {
                    origin,
                    value: borrowed.value.clone(),
                    weight_runs,
                    from: Some(from),
                };
                return Ok(LearningRead {
                    estimate: Estimate::from_prior(prior, borrowed.of.clone(), window),
                    own: false,
                    borrowed_from: Some(candidate),
                });
            }
        }
    }

    let (prior, of) = match &registered {
        Some(row) => (cell_prior_in_txn(vault, txn, row, &digest)?, row.of.clone()),
        None => {
            let form = default_form(cell);
            (
                Prior::shipped(form),
                cell.predicate.default_of(form).to_owned(),
            )
        }
    };
    Ok(LearningRead {
        estimate: Estimate::from_prior(prior, of, window),
        own: false,
        borrowed_from: None,
    })
}

/// The form an unregistered cell reads in: Beta for the success members, a
/// mean for the magnitude members.
fn default_form(cell: &LearningCell) -> super::estimate::EstimateForm {
    use super::cell::LearningPredicate;
    use super::estimate::EstimateForm;
    match cell.predicate {
        LearningPredicate::Reliability | LearningPredicate::RetestNoise => EstimateForm::Beta,
        LearningPredicate::EditCost | LearningPredicate::Setting => EstimateForm::Mean,
    }
}
