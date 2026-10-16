//! Weighted starting points for skill cells. Borrowed history never adds own runs.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::TypeRef;
use crate::learning::evidence::ensure_cell_in_txn;
use crate::learning::prior::PRIOR;
use crate::learning::project::window_in_txn;
use crate::learning::read::read_learning_in_txn;
use crate::learning::{
    Estimate, EstimateForm, EstimateValue, LearningCell, LearningRead, Prior, PriorOrigin,
};

use super::provenance::skill_reliability_prior_in_txn;

/// A typed read uses the shared parent/carried backoff before provenance.
/// Provenance retains the existing trust table, with its mass made explicit.
pub(super) fn read_cell_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
    parents: &[TypeRef],
) -> Result<LearningRead> {
    let read = read_learning_in_txn(vault, txn, cell, parents)?;
    if read.own
        || read.borrowed_from.is_some()
        || read.estimate.prior.origin != PriorOrigin::Shipped
    {
        return Ok(read);
    }
    let prior = provenance_prior_in_txn(vault, txn, &cell.subject)?;
    Ok(LearningRead {
        estimate: Estimate::from_prior(prior, "won", window_in_txn(vault, txn)?),
        own: false,
        borrowed_from: None,
    })
}

pub(super) fn provenance_prior_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Prior> {
    let prior = skill_reliability_prior_in_txn(vault, txn, skill)?;
    Ok(Prior {
        origin: PriorOrigin::Provenance,
        value: EstimateValue::Beta {
            alpha: f64::from(prior.alpha),
            beta: f64::from(prior.beta),
        },
        weight_runs: f64::from(prior.observations()),
        from: Some(skill.to_hex()),
    })
}

/// Capture the borrowed/provenance starting point before the first own run.
/// Later evidence keeps that same prior; an explicit swap/seed may replace it
/// through the shared learning door.
pub(super) fn ensure_prior_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    parents: &[TypeRef],
) -> Result<()> {
    let digest = cell.digest();
    if PRIOR.contains(&vault.store, txn, &digest)? {
        return Ok(());
    }
    let prior = read_cell_in_txn(vault, txn, cell, parents)?.estimate.prior;
    ensure_cell_in_txn(vault, txn, cell, EstimateForm::Beta)?;
    PRIOR.put(&vault.store, txn, &digest, &prior)
}
