//! The eval-authoring pass (OF-578, ARCH-0053 "Eval authoring"): the Coach's
//! nightly upkeep of each seat's test set, which the shipped `eval-authoring`
//! skill decides.
//!
//! Fixed code reads what the skill decides on: the recent attempt receipts
//! that record a seat, grouped by the lineage the vault holds for them, with
//! the outcome each one's grounded evidence gives, and each seat's families,
//! cases and cohorts with what the cohorts served. That inventory is metadata
//! only: ids, times, kinds, purposes and counts, never a case's text, trace or
//! output. The skill answers with one plan: a purpose for each new source
//! group, the candidates to keep as cases, the cuts to make and the cohorts to
//! retire. Fixed code applies it in order, through the eval-set doors, which
//! keep their own refusals: families for whole groups first, then cases and
//! their labels, then each cut with its audit, then retirements.
//!
//! - **Lineage is fixed code's.** A candidate's roots are its receipt, the
//!   amendments the host grounded on it and the TURNs their proposals came
//!   from, and its run's derived-from chain. Similarity never adds a root. A
//!   group whose roots already sit in two families is reported, never merged.
//! - **Labels are evidence.** An amendment measured on the run's proposal
//!   (amended or kept), or the owner's pick on a preference pair that holds
//!   the receipt, is an outcome. A judge's verdict never is, and no evidence
//!   is no label.
//! - **A plan is checked whole.** A plan for another inventory, or one naming
//!   a group, candidate, seat or cohort the inventory did not hold, is refused
//!   before anything applies. How many cases it keeps is the skill's call.

mod apply;
mod lineage;

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::cohort::{cohorts_in_txn, exposure_in_txn};
use super::{
    CASE_PREFIX, DerivationKind, EvalCase, EvalExposureCounts, EvalLabelKind, EvalSeat,
    FAMILY_PREFIX, FamilyPurpose, SourceFamily, family_in_txn, invalid, root_family_in_txn,
    rows_in_txn,
};
use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::receipt::{MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptQuery, ReceiptRecord};

pub use apply::{
    CaseDecision, CutDecision, EvalAuthoringPlan, EvalAuthoringReport, EvalAuthoringSkip,
    EvalCohortDecision, EvalCohortSetup, FamilyDecision, apply_eval_authoring_plan,
    setup_eval_cohorts,
};
pub(super) use lineage::{LineageReader, SOURCE_TURN_ROOT, amendment_artifact};
use lineage::{ReceiptLineage, receipt_seat};

/// How far back one pass reads attempt receipts: the Coach's own pacing.
const EVAL_AUTHORING_WINDOW_SECS: u64 = 30 * 24 * 60 * 60;
/// Most candidates one pass reads, the newest first. The rest wait for a
/// later pass; this paces the reading, never what the skill may keep.
const EVAL_AUTHORING_MAX_CANDIDATES: usize = 256;
const INVENTORY_DOMAIN: &[u8] = b"skill_optimize:eval_authoring_inventory:v1\0";

/// One label fixed code found for a candidate in grounded evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CandidateLabel {
    pub kind: EvalLabelKind,
    /// `amended` or `kept` for an amendment, `preferred` or `not_preferred`
    /// for an owner's pick.
    pub value: String,
    /// The amendment receipt or preference pair it came from.
    pub reference: String,
    pub at: u64,
    /// The candidate's case already holds it.
    pub held: bool,
    /// The rows the label's value was read from, as fixed code found them
    /// (FIX 5761); kept from the skill, which never asserts them.
    #[serde(skip)]
    pub source_rows: Option<Vec<EntityId>>,
}

/// One recent attempt receipt that records a seat: a candidate case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvalCandidate {
    /// The attempt's pack receipt id.
    pub id: String,
    pub seat: EvalSeat,
    pub group: String,
    /// When the attempt ended: the date a cut reads.
    pub at: u64,
    pub labels: Vec<CandidateLabel>,
    /// The case already recorded for this receipt, if one is.
    pub case: Option<EntityId>,
    /// The rows the receipt's attempt read, as fixed code resolved them
    /// (FIX 5761); kept from the skill, which never asserts them.
    #[serde(skip)]
    pub source_rows: Option<Vec<EntityId>>,
}

/// Candidates that share a root: one source family's worth of history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvalSourceGroup {
    pub id: String,
    pub seat: EvalSeat,
    pub candidates: usize,
    /// Candidates with a grounded outcome label.
    pub labelled: usize,
    pub roots: usize,
    /// Roots no family holds yet.
    pub fresh_roots: usize,
    /// The family the group's roots already belong to, and its fixed purpose.
    pub family: Option<EntityId>,
    pub purpose: Option<FamilyPurpose>,
    /// Why the group cannot be placed, when it cannot.
    pub blocked: Option<String>,
    /// The roots themselves, which stay with fixed code.
    #[serde(skip)]
    root_set: BTreeSet<String>,
}

/// How many of a seat's families have each purpose.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct PurposeCounts {
    pub development: usize,
    pub judge_audit: usize,
    pub sealed_confirmation: usize,
}

/// A sealed family no cohort holds yet: what a cut could take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UncutFamily {
    pub family: EntityId,
    pub cases: usize,
    /// The first and last source date of its cases.
    pub first_at: u64,
    pub last_at: u64,
}

/// One cohort of a seat, as the skill reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CohortSummary {
    pub id: EntityId,
    pub from: u64,
    pub until: u64,
    pub reference: bool,
    pub retired: bool,
    pub members: usize,
    pub families: usize,
    pub rubric_revision: String,
    pub exposure: EvalExposureCounts,
}

/// One seat's set as it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SeatInventory {
    pub seat: EvalSeat,
    pub families: PurposeCounts,
    pub cases: usize,
    pub cohorts: Vec<CohortSummary>,
    pub uncut: Vec<UncutFamily>,
}

/// What the eval-authoring skill reads: metadata only, never a case's text,
/// trace, output or success check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvalAuthoringInventory {
    /// SHA-256 over the rest of the inventory; a plan names it.
    pub inventory_digest: String,
    pub built_at: u64,
    /// The start of the receipt window the candidates came from.
    pub from: u64,
    pub groups: Vec<EvalSourceGroup>,
    pub candidates: Vec<EvalCandidate>,
    pub seats: Vec<SeatInventory>,
}

impl EvalAuthoringInventory {
    /// Whether the pass has anything for the skill: a labelled candidate with
    /// no case, a label a case lacks, a sealed family a past window could cut,
    /// or a live non-reference cohort that has served.
    #[must_use]
    pub fn has_work(&self) -> bool {
        let blocked: BTreeSet<&str> = self
            .groups
            .iter()
            .filter(|group| group.blocked.is_some())
            .map(|group| group.id.as_str())
            .collect();
        let cases = self
            .candidates
            .iter()
            .any(|candidate| match candidate.case {
                None => !candidate.labels.is_empty() && !blocked.contains(candidate.group.as_str()),
                Some(_) => candidate.labels.iter().any(|label| !label.held),
            });
        let cuts = self.seats.iter().any(|seat| {
            seat.uncut
                .iter()
                .any(|family| family.last_at < self.built_at)
        });
        let retirements = self
            .seats
            .iter()
            .flat_map(|seat| &seat.cohorts)
            .any(|cohort| !cohort.retired && !cohort.reference && cohort.exposure.served());
        cases || cuts || retirements
    }
}

/// The newest pack receipts of the window that record a seat. Only an
/// attempt's terminal pack receipt carries an executor seat.
fn recent_candidates(vault: &Vault, from: u64, now: u64) -> Result<Vec<(ReceiptRecord, EvalSeat)>> {
    Ok(vault
        .receipts(ReceiptQuery {
            kinds: BTreeSet::from([ReceiptKind::Outbound]),
            start_at: Some(from),
            end_at: Some(now),
            limit: MAX_RECEIPT_QUERY_SCAN,
            ..ReceiptQuery::default()
        })?
        .into_iter()
        .filter_map(|receipt| receipt_seat(&receipt).map(|seat| (receipt, seat)))
        .take(EVAL_AUTHORING_MAX_CANDIDATES)
        .collect())
}

/// One candidate with its resolved lineage.
struct Sourced {
    receipt: ReceiptRecord,
    seat: EvalSeat,
    lineage: ReceiptLineage,
}

fn find(parent: &mut [usize], mut node: usize) -> usize {
    while parent[node] != node {
        parent[node] = parent[parent[node]];
        node = parent[node];
    }
    node
}

/// The candidates that share a root for the same seat, in groups, each in
/// receipt order.
fn group_by_roots(sourced: &[Sourced]) -> Vec<Vec<usize>> {
    let mut parent: Vec<usize> = (0..sourced.len()).collect();
    let mut owner: BTreeMap<(&EvalSeat, &str), usize> = BTreeMap::new();
    for (index, item) in sourced.iter().enumerate() {
        for root in &item.lineage.roots {
            match owner.entry((&item.seat, root.as_str())) {
                Entry::Vacant(slot) => {
                    slot.insert(index);
                }
                Entry::Occupied(slot) => {
                    let (a, b) = (find(&mut parent, *slot.get()), find(&mut parent, index));
                    if a != b {
                        parent[a.max(b)] = a.min(b);
                    }
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..sourced.len() {
        groups
            .entry(find(&mut parent, index))
            .or_default()
            .push(index);
    }
    groups.into_values().collect()
}

/// One group's standing against the root index: the family its roots reach,
/// and why it cannot be placed, when it cannot.
fn source_group(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: String,
    members: &[&Sourced],
) -> Result<EvalSourceGroup> {
    let seat =
        members
            .first()
            .map(|member| member.seat.clone())
            .ok_or(Error::InvariantViolation(
                "an eval source group has no candidate",
            ))?;
    let root_set: BTreeSet<String> = members
        .iter()
        .flat_map(|member| member.lineage.roots.iter().cloned())
        .collect();
    let mut known = BTreeSet::new();
    let mut fresh_roots = 0;
    for root in &root_set {
        match root_family_in_txn(vault, txn, &seat, root)? {
            Some(family) => {
                known.insert(family);
            }
            None => fresh_roots += 1,
        }
    }
    let family = match known.first() {
        Some(id) if known.len() == 1 => Some(
            family_in_txn(vault, txn, id)?
                .ok_or(Error::CorruptedIndex("eval root without its family"))?,
        ),
        _ => None,
    };
    // A family holds every root its lineage has (Rule 5); assigning it
    // measures its size.
    let blocked =
        (known.len() > 1).then_some("these roots already belong to different eval families");
    Ok(EvalSourceGroup {
        id,
        seat,
        candidates: members.len(),
        labelled: members
            .iter()
            .filter(|member| !member.lineage.labels.is_empty())
            .count(),
        roots: root_set.len(),
        fresh_roots,
        family: family.as_ref().map(|family| family.id),
        purpose: family.as_ref().map(|family| family.purpose),
        blocked: blocked.map(str::to_owned),
        root_set,
    })
}

/// One seat's families, cases and cohorts, with what each cohort served.
fn seat_inventory(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seat: &EvalSeat,
    families: &[SourceFamily],
    cases: &[EvalCase],
) -> Result<SeatInventory> {
    let mut counts = PurposeCounts::default();
    for family in families.iter().filter(|family| &family.seat == seat) {
        match family.purpose {
            FamilyPurpose::Development => counts.development += 1,
            FamilyPurpose::JudgeAudit => counts.judge_audit += 1,
            FamilyPurpose::SealedConfirmation => counts.sealed_confirmation += 1,
        }
    }
    let mut cohorts = cohorts_in_txn(vault, txn, seat)?;
    cohorts.sort_by_key(|cohort| (cohort.cut_at, cohort.id));
    let held: BTreeSet<EntityId> = cohorts
        .iter()
        .flat_map(|cohort| cohort.families.iter().copied())
        .collect();
    let sealed: BTreeSet<EntityId> = families
        .iter()
        .filter(|family| {
            &family.seat == seat
                && family.purpose == FamilyPurpose::SealedConfirmation
                && !held.contains(&family.id)
        })
        .map(|family| family.id)
        .collect();
    let mut uncut: BTreeMap<EntityId, UncutFamily> = BTreeMap::new();
    let seat_cases: Vec<&EvalCase> = cases.iter().filter(|case| &case.seat == seat).collect();
    for case in seat_cases
        .iter()
        .filter(|case| sealed.contains(&case.family))
    {
        let row = uncut.entry(case.family).or_insert(UncutFamily {
            family: case.family,
            cases: 0,
            first_at: case.source_at,
            last_at: case.source_at,
        });
        row.cases += 1;
        row.first_at = row.first_at.min(case.source_at);
        row.last_at = row.last_at.max(case.source_at);
    }
    let mut summaries = Vec::with_capacity(cohorts.len());
    for cohort in &cohorts {
        summaries.push(CohortSummary {
            id: cohort.id,
            from: cohort.from,
            until: cohort.until,
            reference: cohort.reference,
            retired: cohort.retired_at.is_some(),
            members: cohort.cases.len(),
            families: cohort.families.len(),
            rubric_revision: cohort.rubric_revision.clone(),
            exposure: exposure_in_txn(vault, txn, &cohort.id)?,
        });
    }
    Ok(SeatInventory {
        seat: seat.clone(),
        families: counts,
        cases: seat_cases.len(),
        cohorts: summaries,
        uncut: uncut.into_values().collect(),
    })
}

fn inventory_digest(inventory: &EvalAuthoringInventory) -> Result<String> {
    let body = rmp_serde::to_vec_named(&(
        inventory.built_at,
        inventory.from,
        &inventory.groups,
        &inventory.candidates,
        &inventory.seats,
    ))
    .map_err(|_| invalid("eval authoring inventory encoding failed"))?;
    let mut hash = Sha256::new();
    hash.update(INVENTORY_DOMAIN);
    hash.update(body);
    // The roots stay with fixed code, but a moved lineage is another
    // inventory.
    for group in &inventory.groups {
        hash.update(group.id.as_bytes());
        hash.update(
            u64::try_from(group.root_set.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for root in &group.root_set {
            hash.update(u64::try_from(root.len()).unwrap_or(u64::MAX).to_be_bytes());
            hash.update(root.as_bytes());
        }
    }
    Ok(bytes_to_hex_lower(&hash.finalize()))
}

/// Reads the inventory the eval-authoring skill decides on, as of `now`: the
/// window's pack receipts that record a seat, at most
/// `EVAL_AUTHORING_MAX_CANDIDATES` of them, the newest first, grouped by
/// lineage, and each seat's set.
/// # Errors
/// Unreadable rows, or storage errors.
pub fn eval_authoring_inventory(vault: &Vault, now: u64) -> Result<EvalAuthoringInventory> {
    let from = now.saturating_sub(EVAL_AUTHORING_WINDOW_SECS);
    let lineage = LineageReader::read(vault)?;
    let mut sourced = Vec::new();
    for (receipt, seat) in recent_candidates(vault, from, now)? {
        let resolved = lineage.resolve(vault, &receipt)?;
        // A session turn is pipeline-inert: nothing derives from it.
        if !resolved.off_record {
            sourced.push(Sourced {
                receipt,
                seat,
                lineage: resolved,
            });
        }
    }
    let txn = vault.store.env.read_txn()?;
    let cases = rows_in_txn::<EvalCase>(vault, &txn, CASE_PREFIX)?;
    let families = rows_in_txn::<SourceFamily>(vault, &txn, FAMILY_PREFIX)?;
    // A case is reused when it reads exactly the candidate's receipt.
    let mut by_receipt: BTreeMap<(&EvalSeat, &str), &EvalCase> = BTreeMap::new();
    for case in &cases {
        if let [receipt] = case.receipts.as_slice()
            && case.parents.is_empty()
            && case.kind == DerivationKind::Receipt
        {
            by_receipt
                .entry((&case.seat, receipt.as_str()))
                .or_insert(case);
        }
    }
    let mut groups = Vec::new();
    let mut candidates = Vec::new();
    for (number, members) in group_by_roots(&sourced).into_iter().enumerate() {
        let id = format!("g{}", number + 1);
        let members: Vec<&Sourced> = members.into_iter().map(|index| &sourced[index]).collect();
        for member in &members {
            let case = by_receipt
                .get(&(&member.seat, member.receipt.receipt_id.as_str()))
                .copied();
            let labels = member
                .lineage
                .labels
                .iter()
                .map(|label| CandidateLabel {
                    held: case.is_some_and(|case| {
                        case.labels.iter().any(|held| {
                            held.kind == label.kind && held.reference == label.reference
                        })
                    }),
                    ..label.clone()
                })
                .collect();
            candidates.push(EvalCandidate {
                id: member.receipt.receipt_id.clone(),
                seat: member.seat.clone(),
                group: id.clone(),
                at: member.receipt.occurred_at,
                labels,
                case: case.map(|case| case.id),
                source_rows: member.lineage.sources.clone(),
            });
        }
        groups.push(source_group(vault, &txn, id, &members)?);
    }
    let seats: BTreeSet<&EvalSeat> = sourced
        .iter()
        .map(|item| &item.seat)
        .chain(families.iter().map(|family| &family.seat))
        .collect();
    let mut seat_rows = Vec::with_capacity(seats.len());
    for seat in seats {
        seat_rows.push(seat_inventory(vault, &txn, seat, &families, &cases)?);
    }
    let mut inventory = EvalAuthoringInventory {
        inventory_digest: String::new(),
        built_at: now,
        from,
        groups,
        candidates,
        seats: seat_rows,
    };
    inventory.inventory_digest = inventory_digest(&inventory)?;
    Ok(inventory)
}
