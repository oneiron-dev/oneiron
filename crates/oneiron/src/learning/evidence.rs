//! The anchored-evidence ledger: the only input the projector reads.
//!
//! Only anchored outcomes count (ARCH-0079 #scoring): held-out runs, owner
//! verdicts, world outcomes and audits, plus the member-specific retest and
//! fitting checks. Agreement between agents, self-report and confession are
//! refused at this door, so no caller can fold them in by accident.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

use super::cell::{LearningCell, LearningPredicate};
use super::estimate::{Estimate, EstimateForm};
use super::project::project_cell_in_txn;

/// Longest receipt reference, judge revision or goal revision an evidence row keeps.
const MAX_REF_BYTES: usize = 256;

/// Largest single evidence weight: a found hidden flaw at the smallest audit
/// rate stays far below it.
const MAX_WEIGHT: f64 = 1.0e6;

/// One cell's identity and shape. Key: the cell digest.
pub(crate) const CELL: SideTable<[u8; 32], CellRow, Named> =
    SideTable::new(&side_table::LEARNING_CELL);

/// Subject index over cells, so a reader finds a subject's other cells
/// without a full scan. Key: subject id16 + cell digest.
pub(crate) const CELL_BY_SUBJECT: SideTable<(EntityId, [u8; 32]), LearningPredicate, Named> =
    SideTable::new(&side_table::LEARNING_CELL_SUBJECT);

pub(crate) use crate::claim::learning_evidence::EVIDENCE;

/// A registered cell: its key, the form its first evidence fixed and what
/// counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CellRow {
    pub cell: LearningCell,
    pub form: EstimateForm,
    pub of: String,
}

pub use crate::claim::learning_evidence::Anchor;

pub use crate::claim::learning_evidence::EvidenceSource;

pub use crate::claim::learning_evidence::Observation;

pub use crate::claim::learning_evidence::LearningEvidence;

pub use crate::claim::learning_evidence::EvidenceRow;

fn bounded_ref(text: &str, what: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_REF_BYTES || text.contains('\0') {
        return Err(Error::InvalidClaimBody(what));
    }
    Ok(())
}

/// Admits `evidence` into `cell` and re-projects the cell in the same
/// transaction. Recording the same receipt again replaces its row.
///
/// Returns the cell's estimate after the fold (`None` when the window has
/// faded every run to nothing, or the subject was hard-deleted).
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a malformed cell, an unanchored source, an
/// anchor this member does not take, an observation in another form than the
/// cell's, or a bad weight; [`Error::EntityNotFound`] when the subject does not
/// exist; storage errors.
pub fn record_evidence(
    vault: &Vault,
    cell: &LearningCell,
    evidence: &LearningEvidence,
    now: u64,
) -> Result<Option<Estimate>> {
    vault.with_write_txn_grouped(|wtxn| record_evidence_in_txn(vault, wtxn, cell, evidence, now))
}

/// [`record_evidence`] inside the caller's write transaction.
///
/// # Errors
///
/// As [`record_evidence`].
pub(crate) fn record_evidence_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    evidence: &LearningEvidence,
    now: u64,
) -> Result<Option<Estimate>> {
    let anchor = evidence.source.admit()?;
    if !anchor.feeds(cell.predicate) {
        return Err(Error::InvalidClaimBody(
            "this anchor does not feed this learning member",
        ));
    }
    bounded_ref(
        &evidence.receipt,
        "an evidence receipt is 1..=256 bytes without NUL",
    )?;
    if let Some(judge) = &evidence.judge {
        bounded_ref(judge, "a judge revision is 1..=256 bytes without NUL")?;
    }
    if let Some(revision) = &evidence.goal_revision {
        bounded_ref(revision, "a goal revision is 1..=256 bytes without NUL")?;
    }
    if let Some(version) = &evidence.measurement_version {
        bounded_ref(
            version,
            "a measurement version is 1..=256 bytes without NUL",
        )?;
    }
    evidence.observation.validate()?;
    if let Some(label) = &evidence.outcome_label {
        Observation::Category(label.clone()).validate()?;
    }
    if !evidence.weight.is_finite() || evidence.weight <= 0.0 || evidence.weight > MAX_WEIGHT {
        return Err(Error::InvalidClaimBody(
            "an evidence weight is positive and finite",
        ));
    }
    if vault.local_hard_delete_marker_exists_in_txn(wtxn, &cell.subject)? {
        tracing::warn!(
            subject = %cell.subject.to_hex(),
            "learning evidence was not recorded: its subject was hard-deleted"
        );
        return Ok(None);
    }
    let digest = ensure_cell_in_txn(vault, wtxn, cell, evidence.observation.form())?;
    let row = EvidenceRow::of(evidence, anchor);
    EVIDENCE.put(
        &vault.store,
        wtxn,
        &(digest, evidence.receipt.clone()),
        &row,
    )?;
    project_cell_in_txn(vault, wtxn, &digest, now)
}

/// Whether `cell` holds exactly the row [`record_evidence_in_txn`] would store
/// for `evidence`, read in `txn`; nothing is written. Evidence the door would
/// refuse never stands.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn evidence_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
    evidence: &LearningEvidence,
) -> Result<bool> {
    let Ok(anchor) = evidence.source.admit() else {
        return Ok(false);
    };
    let stored = EVIDENCE.get(
        &vault.store,
        txn,
        &(cell.digest(), evidence.receipt.clone()),
    )?;
    Ok(stored == Some(EvidenceRow::of(evidence, anchor)))
}

/// Withdraws the evidence `receipt` gave `cell` (a displaced judgment, an
/// overturned verdict) and re-projects. The receipt itself is untouched.
///
/// # Errors
///
/// Storage errors.
pub fn withdraw_evidence(
    vault: &Vault,
    cell: &LearningCell,
    receipt: &str,
    now: u64,
) -> Result<Option<Estimate>> {
    let digest = cell.digest();
    vault.with_write_txn_grouped(|wtxn| {
        if !EVIDENCE.delete(&vault.store, wtxn, &(digest, receipt.to_owned()))? {
            return super::read::own_estimate_in_txn(vault, wtxn, cell);
        }
        project_cell_in_txn(vault, wtxn, &digest, now)
    })
}

/// [`withdraw_evidence`] inside the caller's write transaction.
///
/// # Errors
///
/// As [`withdraw_evidence`].
pub(crate) fn withdraw_evidence_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    receipt: &str,
    now: u64,
) -> Result<Option<Estimate>> {
    let digest = cell.digest();
    if !EVIDENCE.delete(&vault.store, wtxn, &(digest, receipt.to_owned()))? {
        return super::read::own_estimate_in_txn(vault, wtxn, cell);
    }
    project_cell_in_txn(vault, wtxn, &digest, now)
}

/// Registers `cell` with `form` if it is new, and checks the form otherwise.
/// Returns the cell digest.
pub(crate) fn ensure_cell_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    form: EstimateForm,
) -> Result<[u8; 32]> {
    cell.validate()?;
    if !cell.predicate.admits_form(form) {
        return Err(Error::InvalidClaimBody(
            "this learning member does not carry this estimate form",
        ));
    }
    let digest = cell.digest();
    match CELL.get(&vault.store, wtxn, &digest)? {
        Some(row) if row.form == form => {}
        Some(_) => {
            return Err(Error::InvalidClaimBody(
                "a learning cell keeps the form its first evidence fixed",
            ));
        }
        None => {
            let row = CellRow {
                cell: cell.clone(),
                form,
                of: cell.predicate.default_of(form).to_owned(),
            };
            CELL.put(&vault.store, wtxn, &digest, &row)?;
            CELL_BY_SUBJECT.put(&vault.store, wtxn, &(cell.subject, digest), &cell.predicate)?;
        }
    }
    Ok(digest)
}

/// Every cell registered for `subject`.
pub(crate) fn cells_for_subject_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<Vec<CellRow>> {
    let mut rows = Vec::new();
    for (_, digest) in CELL_BY_SUBJECT.scan_keys(&vault.store, txn, subject.as_bytes())? {
        if let Some(row) = CELL.get(&vault.store, txn, &digest)? {
            rows.push(row);
        }
    }
    Ok(rows)
}

/// A cell's evidence rows, oldest receipt key first.
pub(crate) fn evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Vec<(String, EvidenceRow)>> {
    Ok(EVIDENCE
        .scan_from(&vault.store, txn, digest)?
        .into_iter()
        .map(|((_, receipt), row)| (receipt, row))
        .collect())
}
