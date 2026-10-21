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

/// Longest outcome category name.
const MAX_CATEGORY_BYTES: usize = 64;

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

/// Evidence rows. Key: cell digest + receipt reference.
pub(crate) const EVIDENCE: SideTable<([u8; 32], String), EvidenceRow, Named> =
    SideTable::new(&side_table::LEARNING_EVIDENCE);

/// A registered cell: its key, the form its first evidence fixed and what
/// counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CellRow {
    pub cell: LearningCell,
    pub form: EstimateForm,
    pub of: String,
}

/// An anchored outcome kind.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Anchor {
    /// A held-out run scored against frozen cases.
    HeldOut,
    /// The owner's verdict, including an owner's edit of the output.
    OwnerVerdict,
    /// A later fact in the world that settled the question.
    WorldOutcome,
    /// A random audit; `rate` is the sampling rate in force on its receipt.
    Audit { rate: f64 },
    /// The same case scored twice by the same scorer (`learning.retest_noise`).
    Retest,
    /// A check that fits a named knob (`learning.setting`).
    FittingCheck,
}

impl Anchor {
    /// Whether this anchor may feed `predicate`.
    #[must_use]
    pub const fn feeds(self, predicate: LearningPredicate) -> bool {
        match predicate {
            LearningPredicate::Reliability | LearningPredicate::EditCost => matches!(
                self,
                Self::HeldOut | Self::OwnerVerdict | Self::WorldOutcome | Self::Audit { .. }
            ),
            LearningPredicate::RetestNoise => matches!(self, Self::Retest),
            LearningPredicate::Setting => {
                matches!(
                    self,
                    Self::FittingCheck | Self::Audit { .. } | Self::HeldOut
                )
            }
        }
    }
}

/// Where a candidate piece of evidence came from. Only [`Self::Anchored`] is
/// admitted; the rest exist so a caller holding one gets a named refusal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EvidenceSource {
    Anchored(Anchor),
    /// Two agents agreeing. Never evidence.
    AgentAgreement,
    /// An agent's report about its own work. Never evidence.
    SelfReport,
    /// A confession. It triggers a recheck and never moves a score.
    Confession,
}

impl EvidenceSource {
    /// The admission door.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaimBody`] for every unanchored source, and for an
    /// audit whose rate is not a probability above zero.
    pub fn admit(self) -> Result<Anchor> {
        match self {
            Self::Anchored(Anchor::Audit { rate }) if !(rate > 0.0 && rate <= 1.0) => Err(
                Error::InvalidClaimBody("an audit carries its sampling rate in (0, 1]"),
            ),
            Self::Anchored(anchor) => Ok(anchor),
            Self::AgentAgreement => Err(Error::InvalidClaimBody(
                "agreement between agents is never learning evidence",
            )),
            Self::SelfReport => Err(Error::InvalidClaimBody(
                "an agent's report on its own work is never learning evidence",
            )),
            Self::Confession => Err(Error::InvalidClaimBody(
                "a confession triggers a recheck and is never learning evidence",
            )),
        }
    }
}

/// What one anchored outcome observed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "v", rename_all = "snake_case")]
pub enum Observation {
    /// The named event happened (true) or did not (false).
    Success(bool),
    /// A measured magnitude: a normalized edit distance, a score difference,
    /// a fitted knob value.
    Magnitude(f64),
    /// One outcome category, such as untouched, amended or rejected.
    Category(String),
}

impl Observation {
    /// The estimate form this observation feeds.
    #[must_use]
    pub const fn form(&self) -> EstimateForm {
        match self {
            Self::Success(_) => EstimateForm::Beta,
            Self::Magnitude(_) => EstimateForm::Mean,
            Self::Category(_) => EstimateForm::Counts,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Success(_) => Ok(()),
            Self::Magnitude(x) if x.is_finite() => Ok(()),
            Self::Magnitude(_) => Err(Error::InvalidClaimBody("a magnitude is finite")),
            Self::Category(name)
                if !name.is_empty()
                    && name.len() <= MAX_CATEGORY_BYTES
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') =>
            {
                Ok(())
            }
            Self::Category(_) => Err(Error::InvalidClaimBody(
                "an outcome category is 1..=64 bytes of [a-z0-9_]",
            )),
        }
    }
}

/// One candidate piece of evidence for a cell.
#[derive(Debug, Clone, PartialEq)]
pub struct LearningEvidence {
    /// The receipt it rests on; one row per receipt per cell.
    pub receipt: String,
    /// Unix seconds of the outcome, the time the window fades from.
    pub at: u64,
    pub source: EvidenceSource,
    pub observation: Observation,
    /// The share this receipt contributes: 1 for a whole run, a fraction for
    /// an attributed defect share or a lineage-credit hop.
    pub weight: f64,
    /// The judge revision that scored it, when a judge did.
    pub judge: Option<String>,
    /// Whether the judge scored work done on its own model.
    pub on_judge_model: bool,
    /// The outcome category a mean edit-cost observation also keeps.
    pub outcome_label: Option<String>,
    /// Frozen pack execution/use context; judge and team metadata are evidence,
    /// not reliability key qualifiers.
    pub pack_attribution: Option<crate::receipt::PackLearningContext>,
    /// The effective skill-edit goal revision the outcome was measured under,
    /// frozen at measurement. Metadata, not a cell key qualifier: a goal-axis
    /// settlement accepts the row only when it equals the question's revision.
    pub goal_revision: Option<String>,
}

impl LearningEvidence {
    /// A whole-run anchored observation with no judge.
    #[must_use]
    pub fn anchored(
        receipt: impl Into<String>,
        at: u64,
        anchor: Anchor,
        observation: Observation,
    ) -> Self {
        Self {
            receipt: receipt.into(),
            at,
            source: EvidenceSource::Anchored(anchor),
            observation,
            weight: 1.0,
            judge: None,
            on_judge_model: false,
            outcome_label: None,
            pack_attribution: None,
            goal_revision: None,
        }
    }
}

/// A stored, admitted evidence row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceRow {
    pub at: u64,
    pub anchor: Anchor,
    pub observation: Observation,
    pub weight: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge: Option<String>,
    #[serde(default)]
    pub on_judge_model: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_attribution: Option<crate::receipt::PackLearningContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_revision: Option<String>,
}

fn bounded_ref(text: &str, what: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_REF_BYTES || text.contains('\0') {
        return Err(Error::InvalidClaimBody(what));
    }
    Ok(())
}

/// Admits `evidence` into `cell` and re-projects the cell in the same
/// transaction. Recording the same receipt again replaces its row.
///
/// Returns the cell's estimate after the fold (`None` only when the window has
/// faded every run to nothing).
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
    evidence.observation.validate()?;
    if let Some(label) = &evidence.outcome_label {
        Observation::Category(label.clone()).validate()?;
    }
    if !evidence.weight.is_finite() || evidence.weight <= 0.0 || evidence.weight > MAX_WEIGHT {
        return Err(Error::InvalidClaimBody(
            "an evidence weight is positive and finite",
        ));
    }
    let digest = ensure_cell_in_txn(vault, wtxn, cell, evidence.observation.form())?;
    let row = EvidenceRow {
        at: evidence.at,
        anchor,
        observation: evidence.observation.clone(),
        weight: evidence.weight,
        judge: evidence.judge.clone(),
        on_judge_model: evidence.on_judge_model,
        outcome_label: evidence.outcome_label.clone(),
        pack_attribution: evidence.pack_attribution.clone(),
        goal_revision: evidence.goal_revision.clone(),
    };
    EVIDENCE.put(
        &vault.store,
        wtxn,
        &(digest, evidence.receipt.clone()),
        &row,
    )?;
    project_cell_in_txn(vault, wtxn, &digest, now)
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
