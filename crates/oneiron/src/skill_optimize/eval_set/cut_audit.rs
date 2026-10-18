//! The near-copy audit every cohort cut commits with (ARCH-0053: "At each
//! cut, a near-copy audit runs across the splits. It only flags rows for
//! review; similarity proves nothing.").
//!
//! The audit compares each case the cut takes with every case of another
//! purpose for the same seat: development, judge audit, and the families of
//! retired cohorts. It scores token 5-gram Jaccard over normalized text and
//! flags each pair at or above the threshold. A flag changes no membership
//! and no purpose.
//!
//! The text is read here, for this comparison alone: the row keeps refs,
//! scores and coverage, never text or shingles, and nothing here serves a
//! cohort, so an audit counts no exposure. A case whose text could not be
//! read is a coverage gap. The cut still stands, and its audit says plainly
//! that it is incomplete; a gap is never read as clean.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use super::authoring::{LineageReader, SOURCE_TURN_ROOT, amendment_artifact};
use super::cohort::{EvalCohort, cut_members_in_txn, membership_digest, retired_families_in_txn};
use super::{CASE_PREFIX, EvalCase, EvalSeat, FamilyPurpose, family_in_txn, rows_in_txn};
use crate::Vault;
use crate::edit_distance::reservoir::amendment_receipt_id;
use crate::edit_distance::{ProposalArtifactRef, finalized_proposal_text};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::attempt_pack_receipt;
use crate::side_table::{self, Named, SideTable};

/// One cut's audit. Key: the cohort's id.
const AUDIT: SideTable<EntityId, EvalCutAudit, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_EVAL_CUT_AUDIT);

// The method pin, in one place: a later revision changes it here and names
// itself on every row it writes.
const METHOD_NAME: &str = "token-5gram-jaccard";
const METHOD_REVISION: u32 = 1;
/// Unicode NFKC, then lower case as the case fold, then whitespace tokens.
const NORMALIZER: &str = "nfkc-casefold-whitespace";
const SHINGLE_SIZE: usize = 5;
const THRESHOLD: f64 = 0.8;

/// A text's shingles, each kept only as its hash.
type Shingles = BTreeSet<[u8; 32]>;
/// A cut's would-be members, and the cases of other purposes they meet.
type AuditSides = (Vec<AuditCase>, Vec<AuditCase>);

/// The method a cut was audited by, pinned on its row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditMethodPin {
    pub name: String,
    pub revision: u32,
    pub normalizer: String,
    pub shingle_size: u64,
    pub threshold: f64,
}

/// One case the audit read: its refs and purposes, never its text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCase {
    pub case: EntityId,
    pub family: EntityId,
    pub receipts: Vec<String>,
    pub parents: Vec<EntityId>,
    /// The purpose its family was assigned.
    pub assigned_purpose: FamilyPurpose,
    /// What it reads as now: a retired cohort's families are development.
    pub effective_purpose: FamilyPurpose,
}

/// A cut member and a case of another purpose whose texts overlap at or
/// above the threshold: flagged for review, never moved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NearCopyFlag {
    pub member_case: EntityId,
    pub other_case: EntityId,
    pub score: f64,
    pub intersection: u64,
    pub union: u64,
}

/// One comparison source the audit could not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    pub case: EntityId,
    /// The source whose text was missing; `None` when the case names no
    /// source with text at all.
    pub source: Option<String>,
}

/// Whether every audited case's text was read, and what was not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCoverage {
    pub complete: bool,
    pub gaps: Vec<CoverageGap>,
}

/// The near-copy audit one cohort was cut with: who authored the cut, every
/// case compared, the pinned method, the flags and the coverage. It holds no
/// text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCutAudit {
    pub cohort: EntityId,
    pub seat: EvalSeat,
    pub cut_at: u64,
    pub rubric_revision: String,
    pub membership_digest: String,
    /// The authoring attempt, the skill revision it ran and the inventory
    /// it read.
    pub attempt: EntityId,
    pub skill: EntityId,
    pub skill_revision: String,
    pub inventory_digest: String,
    pub members: Vec<AuditCase>,
    pub compared: Vec<AuditCase>,
    pub method: AuditMethodPin,
    /// Pairs scored: each member with text against each other case with
    /// text.
    pub comparisons: u64,
    pub flags: Vec<NearCopyFlag>,
    pub coverage: AuditCoverage,
}

/// Who authored a cut: the attempt, its skill revision and the inventory it
/// read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuditProvenance {
    pub(super) attempt: EntityId,
    pub(super) skill: EntityId,
    pub(super) revision: String,
    pub(super) inventory_digest: String,
}

/// The audit a cut commits with, run on the members it would take before
/// the cut and checked against them in the cut's own transaction. Only the
/// eval-authoring pass runs one.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalCutAuditDraft {
    seat: EvalSeat,
    from: u64,
    until: u64,
    provenance: AuditProvenance,
    membership_digest: String,
    members: Vec<AuditCase>,
    compared: Vec<AuditCase>,
    comparisons: u64,
    flags: Vec<NearCopyFlag>,
    gaps: Vec<CoverageGap>,
}

impl EvalCutAuditDraft {
    /// Whether this audit is of a cut of `from..until` for `seat`.
    pub(super) fn covers(&self, seat: &EvalSeat, from: u64, until: u64) -> bool {
        &self.seat == seat && self.from == from && self.until == until
    }

    /// The digest of the members this audit compared.
    pub(super) fn membership_digest(&self) -> &str {
        &self.membership_digest
    }

    /// Whether every audited case's text was read.
    pub(super) fn complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// The row the cut keeps beside `cohort`.
    pub(super) fn row(&self, cohort: &EvalCohort) -> EvalCutAudit {
        EvalCutAudit {
            cohort: cohort.id,
            seat: cohort.seat.clone(),
            cut_at: cohort.cut_at,
            rubric_revision: cohort.rubric_revision.clone(),
            membership_digest: cohort.membership_digest.clone(),
            attempt: self.provenance.attempt,
            skill: self.provenance.skill,
            skill_revision: self.provenance.revision.clone(),
            inventory_digest: self.provenance.inventory_digest.clone(),
            members: self.members.clone(),
            compared: self.compared.clone(),
            method: AuditMethodPin {
                name: METHOD_NAME.to_owned(),
                revision: METHOD_REVISION,
                normalizer: NORMALIZER.to_owned(),
                shingle_size: u64::try_from(SHINGLE_SIZE).unwrap_or(u64::MAX),
                threshold: THRESHOLD,
            },
            comparisons: self.comparisons,
            flags: self.flags.clone(),
            coverage: AuditCoverage {
                complete: self.complete(),
                gaps: self.gaps.clone(),
            },
        }
    }
}

pub(super) fn put_audit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    audit: &EvalCutAudit,
) -> Result<()> {
    AUDIT.put(&vault.store, txn, &audit.cohort, audit)
}

fn audit_case(case: EvalCase, assigned: FamilyPurpose, effective: FamilyPurpose) -> AuditCase {
    AuditCase {
        case: case.id,
        family: case.family,
        receipts: case.receipts,
        parents: case.parents,
        assigned_purpose: assigned,
        effective_purpose: effective,
    }
}

/// The members a cut of `from..until` would take now, and every case of the
/// seat that reads as another purpose; `None` when the cut would take none.
fn audit_cases(
    vault: &Vault,
    seat: &EvalSeat,
    from: u64,
    until: u64,
) -> Result<Option<AuditSides>> {
    let txn = vault.store.env.read_txn()?;
    let (families, members) = cut_members_in_txn(vault, &txn, seat, from, until)?;
    if families.is_empty() {
        return Ok(None);
    }
    let retired = retired_families_in_txn(vault, &txn, seat)?;
    let mut purposes: BTreeMap<EntityId, FamilyPurpose> = BTreeMap::new();
    let mut compared = Vec::new();
    for case in rows_in_txn::<EvalCase>(vault, &txn, CASE_PREFIX)? {
        if &case.seat != seat {
            continue;
        }
        let assigned = if let Some(purpose) = purposes.get(&case.family) {
            *purpose
        } else {
            let purpose = family_in_txn(vault, &txn, &case.family)?
                .ok_or(Error::CorruptedIndex("eval case without its family"))?
                .purpose;
            purposes.insert(case.family, purpose);
            purpose
        };
        let effective = if retired.contains(&case.family) {
            FamilyPurpose::Development
        } else {
            assigned
        };
        if effective != FamilyPurpose::SealedConfirmation {
            compared.push(audit_case(case, assigned, effective));
        }
    }
    let members = members
        .into_iter()
        .map(|case| {
            audit_case(
                case,
                FamilyPurpose::SealedConfirmation,
                FamilyPurpose::SealedConfirmation,
            )
        })
        .collect();
    Ok(Some((members, compared)))
}

/// The TURNs and proposal artifacts behind a case's receipts: an amendment
/// receipt's own artifact, and what an attempt receipt's lineage resolves.
fn text_sources(
    vault: &Vault,
    lineage: &LineageReader,
    receipts: &[String],
) -> Result<(BTreeSet<EntityId>, BTreeSet<EntityId>)> {
    let mut turns = BTreeSet::new();
    let mut artifacts = BTreeSet::new();
    for receipt in receipts {
        if let Some(artifact) = amendment_artifact(receipt) {
            artifacts.insert(artifact);
        } else if let Some(record) = attempt_pack_receipt(vault, receipt)? {
            let resolved = lineage.resolve(vault, &record)?;
            turns.extend(resolved.turns);
            artifacts.extend(resolved.artifacts);
        }
    }
    Ok((turns, artifacts))
}

/// The purpose-limited reader: one case's source text, for this audit's
/// comparison alone, with each source it could not read noted as a gap.
fn case_texts(
    vault: &Vault,
    lineage: &LineageReader,
    case: &AuditCase,
    gaps: &mut Vec<CoverageGap>,
) -> Result<Vec<String>> {
    let (turns, artifacts) = text_sources(vault, lineage, &case.receipts)?;
    let mut texts = Vec::new();
    {
        let txn = vault.store.env.read_txn()?;
        for turn in turns {
            match crate::embed::turn_text_in_txn(vault, &txn, &turn)? {
                Some(text) => texts.push(text),
                None => gaps.push(CoverageGap {
                    case: case.case,
                    source: Some(format!("{SOURCE_TURN_ROOT}{}", turn.to_hex())),
                }),
            }
        }
    }
    for artifact in artifacts {
        match finalized_proposal_text(vault, ProposalArtifactRef::new(artifact))? {
            Some(proposal) => {
                texts.push(proposal.proposed_text);
                texts.push(proposal.final_text);
            }
            None => gaps.push(CoverageGap {
                case: case.case,
                source: Some(amendment_receipt_id(artifact)),
            }),
        }
    }
    Ok(texts)
}

/// Token shingles of `texts` under the pinned normalizer, each kept only as
/// its hash. A text shorter than one shingle is one shingle.
fn shingles(texts: &[String]) -> Shingles {
    let mut set = BTreeSet::new();
    for text in texts {
        let normalized: String = text.as_str().nfkc().flat_map(char::to_lowercase).collect();
        let tokens: Vec<&str> = normalized.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        for window in tokens.windows(SHINGLE_SIZE.min(tokens.len())) {
            set.insert(*blake3::hash(window.join(" ").as_bytes()).as_bytes());
        }
    }
    set
}

/// Each case's shingles, with the gaps of every case none could be read
/// for.
fn case_shingles(
    vault: &Vault,
    lineage: &LineageReader,
    cases: &[AuditCase],
    gaps: &mut Vec<CoverageGap>,
) -> Result<Vec<(EntityId, Shingles)>> {
    let mut read = Vec::with_capacity(cases.len());
    for case in cases {
        let before = gaps.len();
        let set = shingles(&case_texts(vault, lineage, case, gaps)?);
        if set.is_empty() {
            if gaps.len() == before {
                gaps.push(CoverageGap {
                    case: case.case,
                    source: None,
                });
            }
        } else {
            read.push((case.case, set));
        }
    }
    Ok(read)
}

/// Runs the near-copy audit of a cut of `window` for `seat`, on the members
/// it would take now; `None` when it would take none.
pub(super) fn prepare_cut_audit(
    vault: &Vault,
    lineage: &LineageReader,
    seat: &EvalSeat,
    window: (u64, u64),
    provenance: AuditProvenance,
) -> Result<Option<EvalCutAuditDraft>> {
    let (from, until) = window;
    let Some((members, compared)) = audit_cases(vault, seat, from, until)? else {
        return Ok(None);
    };
    let mut gaps = Vec::new();
    let left = case_shingles(vault, lineage, &members, &mut gaps)?;
    let right = case_shingles(vault, lineage, &compared, &mut gaps)?;
    let mut comparisons = 0_u64;
    let mut flags = Vec::new();
    for (member, member_set) in &left {
        for (other, other_set) in &right {
            comparisons = comparisons.saturating_add(1);
            let intersection = member_set.intersection(other_set).count();
            let union = member_set.len() + other_set.len() - intersection;
            let score = intersection as f64 / union as f64;
            if score >= THRESHOLD {
                flags.push(NearCopyFlag {
                    member_case: *member,
                    other_case: *other,
                    score,
                    intersection: u64::try_from(intersection).unwrap_or(u64::MAX),
                    union: u64::try_from(union).unwrap_or(u64::MAX),
                });
            }
        }
    }
    let member_ids: Vec<EntityId> = members.iter().map(|case| case.case).collect();
    Ok(Some(EvalCutAuditDraft {
        seat: seat.clone(),
        from,
        until,
        provenance,
        membership_digest: membership_digest(&member_ids),
        members,
        compared,
        comparisons,
        flags,
        gaps,
    }))
}

impl Vault {
    /// The near-copy audit a cohort was cut with, if one was kept.
    /// # Errors
    /// An unreadable row, or storage errors.
    pub fn eval_cut_audit(&self, cohort: &EntityId) -> Result<Option<EvalCutAudit>> {
        let txn = self.store.env.read_txn()?;
        AUDIT.get(&self.store, &txn, cohort)
    }
}
