//! OF-578 (ARCH-0053 "Eval authoring", RESEARCH-0937; EVAL-SKILL = A,
//! EVAL-COLDSTART = C, NOT-WORSE = A): the mechanism the eval-authoring skill
//! keeps each seat's test set with, from the vault's own history.
//!
//! ```text
//! receipts ─▶ source family (purpose first: development · judge audit · sealed)
//!                 │
//!                 └─▶ derivation ledger: every case names its receipts and parents,
//!                     and inherits its family; a variant never changes side
//!                          │
//!        sealed families ──┴─▶ date-cut cohort ─▶ exposure ledger (recorded BEFORE release)
//!                                   │                    │
//!                                   │                    └─▶ retire: development, never training
//!                                   └─▶ sufficiency card ─▶ unknown ─▶ sparse owner-label ask
//! ```
//!
//! **Cases are views over receipts, not a second store.** A case holds
//! references: its receipts, the cases it was derived from, its transform,
//! stratum and draw probability, and its labels. The content is the receipts'.
//!
//! **The family gets its split before any variant is made.** A root is
//! assigned to exactly one family per seat, and that family's purpose is fixed
//! at assignment. Derived rows inherit their source's family: a paraphrase, a
//! summary, a translation or a generated rubric lands where its parent is.
//!
//! **Sealed means sealed by date, and every serving is counted.** A cohort is
//! cut from sealed families by receipt date. Its membership is released only
//! through [`Vault::open_eval_cohort`], which records the exposure (a
//! candidate scored, a query served, a promotion decided) in the same
//! transaction. No search, candidate author or rubric fit has a door to it. An
//! exposed cohort retires to development, and a retired family never feeds
//! training. One reference cohort per seat stays fixed for comparison.
//!
//! **Unknown is an answer.** The sufficiency card says "unknown" when the
//! interval spans the margin, a floor slice has too few families, or the set,
//! rubric or canary moved. An unknown card never approves. Only a decision
//! that waits on an unknown card may ask the owner for a label.
//!
//! Phase 1 builds the mechanism only. This module authors no case, runs no
//! replay or judge, and holds no default generator, threshold or schedule.

mod cohort;
mod sufficiency;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::invalid;
use crate::Vault;
use crate::batch::secret_scan::admit_typed;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

pub use cohort::{EvalCohort, EvalExposure, EvalExposureCounts, EvalExposureKind, EvalRelease};
pub use sufficiency::{
    EvalLabelAsk, SufficiencyCard, SufficiencyInput, SufficiencyVerdict, UnknownReason,
    WaitingDecision, sufficiency_card,
};

pub(super) const FAMILY_PREFIX: &[u8] = b"skill_optimize:eval_family:v1:";
pub(super) const ROOT_PREFIX: &[u8] = b"skill_optimize:eval_root:v1:";
pub(super) const CASE_PREFIX: &[u8] = b"skill_optimize:eval_case:v1:";
/// Where the side-row wall says it found a secret in a case (OF-067).
const CASE_PLACE: &str = "side:SKILL_OPTIMIZE_EVAL_CASE";
const LABEL: &str = "eval set row";

const MAX_ROOTS: usize = 256;
const MAX_REF_BYTES: usize = 256;
const MAX_PARENTS: usize = 64;
const MAX_NAME_BYTES: usize = 64;

/// A model function the vault keeps a test set for: "The seats are the
/// companion, a decision seat, the extraction tagger, the embedder and the
/// router." A seat outlives its checkpoint; the model is a pin on what was
/// measured, never the key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalSeat {
    Companion,
    Decision,
    ExtractionTagger,
    Embedder,
    Router,
    /// A host-named seat, such as a role binding: a bounded identifier.
    Named(String),
}

impl EvalSeat {
    fn token(&self) -> Result<String> {
        Ok(match self {
            Self::Companion => "companion".to_owned(),
            Self::Decision => "decision".to_owned(),
            Self::ExtractionTagger => "extraction_tagger".to_owned(),
            Self::Embedder => "embedder".to_owned(),
            Self::Router => "router".to_owned(),
            Self::Named(name) => {
                if name.is_empty()
                    || name.len() > MAX_NAME_BYTES
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
                {
                    return Err(invalid("an eval seat name must be a bounded identifier"));
                }
                format!("named:{name}")
            }
        })
    }
}

/// What a source family is for, fixed when it is assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilyPurpose {
    /// Search, candidate authoring and rubric fitting read these rows.
    Development,
    /// Judge audits read these rows; nothing is ever fitted on them.
    JudgeAudit,
    /// Sealed confirmation: only a date-cut cohort serves them, counted.
    SealedConfirmation,
}

/// The records that share a source, and what their rows are for. A family is
/// never re-purposed; retirement is read from its cohort
/// ([`Vault::eval_family_feeds_training`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFamily {
    pub id: EntityId,
    pub seat: EvalSeat,
    pub purpose: FamilyPurpose,
    /// Source records the family's rows derive from: receipt ids or entity
    /// refs, as the host's lineage resolver found them. Similarity never adds
    /// a root.
    pub roots: BTreeSet<String>,
    pub assigned_at: u64,
}

/// How a case came from its sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationKind {
    /// A past task picked from receipts as it ran.
    Receipt,
    /// A linked failure, its outside repair and the observed outcome.
    Repair,
    Paraphrase,
    Summary,
    Translation,
    Synthetic,
    /// A generated rubric over its parent rows.
    Rubric,
}

/// Where a case's label came from. Outcomes and the owner's picks anchor; a
/// judge's verdict never does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalLabelKind {
    WorldOutcome,
    OwnerPick,
    AdjudicatedAudit,
    JudgeVerdict,
}

impl EvalLabelKind {
    #[must_use]
    pub const fn anchors(self) -> bool {
        !matches!(self, Self::JudgeVerdict)
    }
}

/// One dated, weighted label on a case. `reference` names the outcome fact,
/// ask or audit it came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalLabel {
    pub kind: EvalLabelKind,
    pub value: String,
    pub reference: String,
    pub weight: f64,
    pub at: u64,
}

/// What the eval-authoring skill proposes to record. The family is not part
/// of it: it is inherited from the roots and parents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCaseDraft {
    pub seat: EvalSeat,
    pub kind: DerivationKind,
    /// Receipts the case reads, each already a root of its family.
    pub receipts: Vec<String>,
    /// Cases this one was derived from.
    pub parents: Vec<EntityId>,
    /// The slice the case was drawn for, if any.
    pub stratum: Option<String>,
    /// The probability the case was drawn with, for reweighting.
    pub draw_probability: Option<f64>,
    /// When the source happened: the date a cohort cut reads.
    pub source_at: u64,
}

/// A case in the derivation ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCase {
    pub id: EntityId,
    pub family: EntityId,
    pub seat: EvalSeat,
    pub kind: DerivationKind,
    pub receipts: Vec<String>,
    pub parents: Vec<EntityId>,
    pub stratum: Option<String>,
    pub draw_probability: Option<f64>,
    pub source_at: u64,
    pub recorded_at: u64,
    pub labels: Vec<EvalLabel>,
}

fn encode<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| invalid("eval set row encoding failed"))
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(LABEL))
}

pub(super) fn id_of(raw: &[u8]) -> Result<EntityId> {
    let bytes: [u8; 16] = raw.try_into().map_err(|_| Error::CorruptedIndex(LABEL))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex(LABEL))
}

fn bounded_ref(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_REF_BYTES {
        return Err(invalid(
            "an eval source reference must be nonempty and bounded",
        ));
    }
    Ok(())
}

fn root_key(seat: &EvalSeat, root: &str) -> Result<Vec<u8>> {
    Ok([
        ROOT_PREFIX,
        seat.token()?.as_bytes(),
        b"\0",
        root.as_bytes(),
    ]
    .concat())
}

pub(super) fn family_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SourceFamily>> {
    vault
        .store
        .vault_meta
        .get(txn, &[FAMILY_PREFIX, id.as_bytes()].concat())?
        .map(|raw| decode(&raw))
        .transpose()
}

pub(super) fn case_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EvalCase>> {
    vault
        .store
        .vault_meta
        .get(txn, &[CASE_PREFIX, id.as_bytes()].concat())?
        .map(|raw| decode(&raw))
        .transpose()
}

/// Writes `case` as the side-row wall keeps it (OF-067), and `case` takes its
/// handles. A case is authored and lives outside the declared catalog, so it
/// meets the wall here, as a declared authored row would.
pub(super) fn put_case_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &mut EvalCase,
) -> Result<()> {
    let key = [CASE_PREFIX, case.id.as_bytes()].concat();
    admit_typed(vault, txn, (CASE_PLACE, key.as_slice()), case)?;
    vault.store.vault_meta.put(txn, &key, &encode(case)?)?;
    Ok(())
}

pub(super) fn rows_in_txn<T: serde::de::DeserializeOwned>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<T>> {
    let mut rows = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(txn, prefix)? {
        let (_, raw) = row?;
        rows.push(decode(&raw)?);
    }
    Ok(rows)
}

impl Vault {
    /// Give `roots` their family and its purpose, before any case derives
    /// from them. A replay over roots the family already holds returns it. New
    /// roots may join a family that holds some of the others, under the same
    /// purpose. Roots split across families, or a purpose that differs from
    /// the family's, are conflicting lineage and are refused.
    /// # Errors
    /// Empty, oversized or unbounded roots, an invalid seat, conflicting
    /// lineage or purpose, or storage errors.
    pub fn assign_eval_family(
        &self,
        seat: &EvalSeat,
        roots: &BTreeSet<String>,
        purpose: FamilyPurpose,
        at: u64,
    ) -> Result<SourceFamily> {
        if roots.is_empty() || roots.len() > MAX_ROOTS {
            return Err(invalid("an eval family needs 1..=256 source roots"));
        }
        for root in roots {
            bounded_ref(root)?;
        }
        self.with_write_txn_grouped(|txn| {
            let mut known = BTreeSet::new();
            for root in roots {
                if let Some(raw) = self.store.vault_meta.get(txn, &root_key(seat, root)?)? {
                    known.insert(id_of(&raw)?);
                }
            }
            if known.len() > 1 {
                return Err(invalid(
                    "these roots already belong to different eval families",
                ));
            }
            let mut family = match known.first() {
                Some(id) => family_in_txn(self, txn, id)?.ok_or(Error::CorruptedIndex(LABEL))?,
                None => SourceFamily {
                    id: self.store.clock.entity_id()?,
                    seat: seat.clone(),
                    purpose,
                    roots: BTreeSet::new(),
                    assigned_at: at,
                },
            };
            if family.purpose != purpose || &family.seat != seat {
                return Err(invalid("an eval family keeps the purpose it was assigned"));
            }
            if family.roots.len() + roots.difference(&family.roots).count() > MAX_ROOTS {
                return Err(invalid("an eval family holds at most 256 source roots"));
            }
            let fresh: Vec<String> = roots.difference(&family.roots).cloned().collect();
            if fresh.is_empty() {
                return Ok(family);
            }
            for root in &fresh {
                self.store
                    .vault_meta
                    .put(txn, &root_key(seat, root)?, family.id.as_bytes())?;
            }
            family.roots.extend(fresh);
            self.store.vault_meta.put(
                txn,
                &[FAMILY_PREFIX, family.id.as_bytes()].concat(),
                &encode(&family)?,
            )?;
            Ok(family)
        })
    }

    /// The family `root` belongs to for `seat`, if assigned.
    /// # Errors
    /// An invalid seat, an unreadable row, or storage errors.
    pub fn eval_family_of_root(&self, seat: &EvalSeat, root: &str) -> Result<Option<SourceFamily>> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&txn, &root_key(seat, root)?)? else {
            return Ok(None);
        };
        let id = id_of(&raw)?;
        family_in_txn(self, &txn, &id)
    }

    /// Record one case in the derivation ledger. Its family is inherited:
    /// every receipt must already be a root of one family for this seat, and
    /// every parent must be a case of that same family. A case with neither
    /// receipts nor parents has no lineage and is refused. Nothing here
    /// generates, replays or scores the case.
    /// # Errors
    /// Unbounded references, an unassigned receipt, lineage that spans
    /// families or seats, an invalid draw probability, or storage errors.
    pub fn record_eval_case(&self, draft: &EvalCaseDraft, at: u64) -> Result<EvalCase> {
        if (draft.receipts.is_empty() && draft.parents.is_empty())
            || draft.receipts.len() > MAX_ROOTS
            || draft.parents.len() > MAX_PARENTS
        {
            return Err(invalid(
                "an eval case names 1..=256 receipts or 1..=64 parents",
            ));
        }
        for receipt in &draft.receipts {
            bounded_ref(receipt)?;
        }
        if draft
            .stratum
            .as_ref()
            .is_some_and(|stratum| stratum.trim().is_empty() || stratum.len() > MAX_NAME_BYTES)
            || draft
                .draw_probability
                .is_some_and(|p| !p.is_finite() || p <= 0.0 || p > 1.0)
        {
            return Err(invalid(
                "an eval case stratum or draw probability is invalid",
            ));
        }
        self.with_write_txn_grouped(|txn| {
            let mut families = BTreeSet::new();
            for receipt in &draft.receipts {
                let raw = self
                    .store
                    .vault_meta
                    .get(txn, &root_key(&draft.seat, receipt)?)?
                    .ok_or(invalid(
                        "assign the receipt's family before deriving a case from it",
                    ))?;
                families.insert(id_of(&raw)?);
            }
            for parent in &draft.parents {
                let parent = case_in_txn(self, txn, parent)?
                    .ok_or(invalid("an eval case parent is not in the ledger"))?;
                if parent.seat != draft.seat {
                    return Err(invalid("an eval case cannot derive across seats"));
                }
                families.insert(parent.family);
            }
            if families.len() != 1 {
                return Err(invalid("an eval case's lineage spans more than one family"));
            }
            let family = families.pop_first().ok_or(Error::CorruptedIndex(LABEL))?;
            let mut case = EvalCase {
                id: self.store.clock.entity_id()?,
                family,
                seat: draft.seat.clone(),
                kind: draft.kind,
                receipts: draft.receipts.clone(),
                parents: draft.parents.clone(),
                stratum: draft.stratum.clone(),
                draw_probability: draft.draw_probability,
                source_at: draft.source_at,
                recorded_at: at,
                labels: Vec::new(),
            };
            put_case_in_txn(self, txn, &mut case)?;
            Ok(case)
        })
    }

    /// Attach an outcome, audit or judge label to a case. An owner's pick
    /// arrives only through [`Vault::record_eval_label_pick`]; labels are
    /// appended, never rewritten.
    /// # Errors
    /// An owner-pick label here, an unbounded value or reference, a weight
    /// outside 0..=1, a missing case, or storage errors.
    pub fn label_eval_case(&self, case: &EntityId, label: EvalLabel) -> Result<EvalCase> {
        if label.kind == EvalLabelKind::OwnerPick {
            return Err(invalid("an owner's pick is recorded through its ask"));
        }
        self.with_write_txn_grouped(|txn| append_label_in_txn(self, txn, case, label.clone()))
    }

    /// The development or judge-audit cases of a seat, for search, authoring,
    /// rubric fitting (development only) and judge audits. Sealed rows have no
    /// read here: they are served only by [`Vault::open_eval_cohort`].
    /// Development includes the rows of retired cohorts.
    /// # Errors
    /// A sealed-confirmation purpose, unreadable rows, or storage errors.
    pub fn eval_cases(&self, seat: &EvalSeat, purpose: FamilyPurpose) -> Result<Vec<EvalCase>> {
        if purpose == FamilyPurpose::SealedConfirmation {
            return Err(invalid(
                "sealed eval cases are served only through their cohort",
            ));
        }
        let txn = self.store.env.read_txn()?;
        let retired = cohort::retired_families_in_txn(self, &txn, seat)?;
        let mut cases = Vec::new();
        for case in rows_in_txn::<EvalCase>(self, &txn, CASE_PREFIX)? {
            if &case.seat != seat {
                continue;
            }
            let family =
                family_in_txn(self, &txn, &case.family)?.ok_or(Error::CorruptedIndex(LABEL))?;
            let effective = if retired.contains(&family.id) {
                FamilyPurpose::Development
            } else {
                family.purpose
            };
            if effective == purpose {
                cases.push(case);
            }
        }
        Ok(cases)
    }

    /// Whether a family's rows may feed training: a development family that
    /// was never sealed. "A held-out family never feeds training", retired or
    /// not, and judge-audit rows are never fitted on.
    /// # Errors
    /// A missing family, unreadable rows, or storage errors.
    pub fn eval_family_feeds_training(&self, family: &EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let family = family_in_txn(self, &txn, family)?.ok_or(Error::EntityNotFound)?;
        Ok(family.purpose == FamilyPurpose::Development)
    }
}

pub(super) fn append_label_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &EntityId,
    label: EvalLabel,
) -> Result<EvalCase> {
    if label.value.trim().is_empty()
        || label.value.len() > MAX_REF_BYTES
        || label.reference.len() > MAX_REF_BYTES
        || !label.weight.is_finite()
        || !(0.0..=1.0).contains(&label.weight)
    {
        return Err(invalid(
            "an eval label needs a bounded value and a 0..=1 weight",
        ));
    }
    let mut row = case_in_txn(vault, txn, case)?.ok_or(Error::EntityNotFound)?;
    if row.labels.iter().any(|existing| {
        existing.kind == label.kind
            && existing.reference == label.reference
            && !label.reference.is_empty()
    }) {
        return Ok(row);
    }
    row.labels.push(label);
    put_case_in_txn(vault, txn, &mut row)?;
    Ok(row)
}
