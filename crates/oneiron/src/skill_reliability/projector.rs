//! Project attributed skill outcomes into the shared learning.reliability cells.

mod actor_displacement;
pub(crate) use actor_displacement::reconcile_displaced_actor_credit_in_txn;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::Vault;
use crate::claim::learning_evidence::Anchor;
use crate::claim::learning_evidence::EVIDENCE;
use crate::claim::learning_evidence::EvidenceRow;
use crate::claim::learning_evidence::EvidenceSource;
use crate::claim::learning_evidence::LearningEvidence;
use crate::claim::learning_evidence::Observation;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::LearningCell;
use crate::learning::evidence::cells_for_subject_in_txn;
use crate::learning::project::project_cell_in_txn;
use crate::receipt::ReceiptRecord;
use crate::skill_attribution::{AttributionJudgment, AttributionVerdict, attribution_judgments};
use crate::skill_attribution::{LateCreditReceipt, StandingCreditObservation};
use crate::temporal::TimeRange;

use super::amended::amended_receipt_shares_in_txn;
use super::anchored_amendment::{AnchoredEffect, anchored_rows_in_txn, effective_evidence_in_txn};
use super::codec::invalid;
use super::equivalent::redirect_equivalent_subjects_in_txn;
use super::ledger::{projection_outcomes_in_txn, receipt_executor, receipt_manifest_names_skill};
use super::outcome_position::OutcomeReadPosition;
use super::outcome_write::record_outcome_positioned_in_txn;
use super::posterior::SkillReliabilityPosterior;
use super::priors::ensure_prior_in_txn;
use super::provenance::skill_reliability_prior;
use super::read::{
    SkillReliabilityQuery, posterior_from_estimate, resolved_estimate_in_txn, validate_executor,
};

pub const PREDICATE_SKILL_RELIABILITY: &str =
    crate::write_envelope::learning_predicate::PREDICATE_LEARNING_RELIABILITY;

/// Receipt task placement: JSON {node_id, tree_version}. Missing is invalid.
pub const FIELD_SKILL_TYPE_REF: &str = "typeRef";
/// Receipt anchor: a serialized learning::Anchor, not agent agreement.
pub const FIELD_SKILL_LEARNING_ANCHOR: &str = "learning.anchor";
/// The effective skill-edit goal revision the run's `axis` was measured under,
/// stamped by whoever stamps `axis` and `learning.anchor`. Copied as is, never
/// looked up at projection.
pub const FIELD_SKILL_GOAL_REVISION: &str = "learning.goal_revision";
/// The existing attempt success lane measures this axis unless explicitly stamped.
pub const SKILL_OUTCOME_AXIS: &str = "quality";

pub(super) fn receipt_query(receipt: &ReceiptRecord) -> Result<SkillReliabilityQuery> {
    let type_ref = serde_json::from_str(
        receipt
            .fields
            .get(FIELD_SKILL_TYPE_REF)
            .ok_or(invalid("a skill outcome requires its task typeRef"))?,
    )
    .map_err(|_| invalid("invalid skill receipt typeRef"))?;
    let type_parents = receipt
        .fields
        .get("typeParents")
        .map(|raw| serde_json::from_str(raw))
        .transpose()
        .map_err(|_| invalid("invalid skill receipt type parents"))?
        .unwrap_or_default();
    let query = SkillReliabilityQuery {
        type_ref,
        axis: receipt
            .fields
            .get("axis")
            .cloned()
            .unwrap_or_else(|| SKILL_OUTCOME_AXIS.to_owned()),
        type_parents,
        // The run's project as the terminal receipt froze it (FIX 6038).
        project: receipt.task_project()?,
    };
    query.validate()?;
    Ok(query)
}

/// The person's mirror of an anchored restatement keeps the held credit
/// cell's coordinates (REVIEW-4322 P1): the attempt receipt's axis defaults
/// to quality, while the credited outcome may stand on another axis, so the
/// person row moves only subject and executor, never coordinates.
fn anchored_person_cell(held: &LearningCell, person: EntityId) -> Option<LearningCell> {
    let (Some(type_ref), Some(axis)) = (held.type_ref.clone(), held.axis.clone()) else {
        return None;
    };
    let cell = LearningCell::new(crate::learning::LearningPredicate::Reliability, person)
        .executor(person.to_hex())
        .type_ref(type_ref)
        .axis(axis)
        .project(held.project);
    cell.validate().ok()?;
    Some(cell)
}

/// Combines two person-observation candidates (REVIEW-4322 P1): any standing
/// loss wins over a win — the pack_learning person rule — otherwise the
/// heavier weight stands, so concurrent restatements converge instead of
/// overwriting each other by pass order.
fn combine_person_observation(
    a: Option<(bool, f64)>,
    b: Option<(bool, f64)>,
) -> Option<(bool, f64)> {
    match (a, b) {
        (None, c) => c,
        (c, None) => c,
        (Some((false, w1)), Some((false, w2))) => Some((false, w1.max(w2))),
        (Some((true, w1)), Some((true, w2))) => Some((true, w1.max(w2))),
        (Some((false, w)), _) | (_, Some((false, w))) => Some((false, w)),
    }
}

/// The person observation the credit's subjects currently stand on
/// (REVIEW-4322 P1): each credited subject contributes its amended share as
/// a loss or its standing credit observation, combined like the
/// pack_learning person rule. The subject set is the credit's effective
/// subjects — the latest adjustment's, else the sealed receipt's — plus the
/// restated subject, so a later-added subject's loss or standing counts.
/// Recomputed every pass, so an amendment landing, a share shrinking, or a
/// subject leaving moves the person row the same pass it moves the skill
/// rows; `exclude` drops a withdrawing subject before the combine.
fn recomputed_person_observation(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    credit: &LateCreditReceipt,
    attempt: &str,
    restated: EntityId,
    exclude: Option<&EntityId>,
) -> Result<StandingCreditObservation> {
    let Some(mut subjects) =
        crate::skill_attribution::effective_credit_subjects_in_txn(&vault.store, txn, credit)?
    else {
        return Ok(StandingCreditObservation::Unknown);
    };
    if Some(&restated) != exclude && !subjects.contains(&restated) {
        subjects.push(restated);
        subjects.sort();
    }
    let mut best: Option<(bool, f64)> = None;
    for subject in subjects {
        if Some(&subject) == exclude {
            continue;
        }
        // The skill restatement's executor-agnostic amended map (both arm
        // prefixes, maximum share), so a share recorded under another
        // executor still governs the person row.
        let shares = amended_receipt_shares_in_txn(vault, txn, &subject)?;
        let candidate = if let Some(share) = shares.get(attempt) {
            Some((false, f64::from(*share)))
        } else {
            match crate::skill_attribution::standing_credit_observation_in_txn(
                vault, txn, credit, &subject,
            )? {
                StandingCreditObservation::Credited(success, weight) => Some((success, weight)),
                StandingCreditObservation::Uncredited => None,
                StandingCreditObservation::Unknown => {
                    return Ok(StandingCreditObservation::Unknown);
                }
            }
        };
        best = combine_person_observation(best, candidate);
    }
    Ok(match best {
        Some((success, weight)) => StandingCreditObservation::Credited(success, weight),
        None => StandingCreditObservation::Uncredited,
    })
}

/// Whether the person row already folds `observation` (REVIEW-4322 P1):
/// judge and pack metadata drift between crediting skills is not a reason
/// to rewrite — only the folded observation, weight, anchor and time matter.
fn person_row_current(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    receipt: &str,
    anchor: Anchor,
    observation: (bool, f64),
    at: u64,
) -> Result<bool> {
    let key = (cell.digest(), receipt.to_owned());
    Ok(match EVIDENCE.get(&vault.store, txn, &key)? {
        Some(stored) => {
            stored.anchor == anchor
                && stored.at == at
                && stored.observation == Observation::Success(observation.0)
                && stored.weight == observation.1
        }
        None => false,
    })
}

/// The anchor `evidence` carries; person evidence is always anchored.
fn person_anchor(evidence: &LearningEvidence) -> Option<Anchor> {
    match evidence.source {
        EvidenceSource::Anchored(anchor) => Some(anchor),
        _ => None,
    }
}

/// Writes the recomputed person observation for `evidence`'s receipt
/// (REVIEW-4322 P1): the template's other fields stay this subject's, only
/// the observation and weight are the cross-subject recompute. Skips a row
/// that already folds the recompute.
fn record_recomputed_person_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    evidence: &LearningEvidence,
    observation: (bool, f64),
    at: u64,
    changed: &mut BTreeSet<[u8; 32]>,
) -> Result<()> {
    if let Some(anchor) = person_anchor(evidence)
        && person_row_current(
            vault,
            txn,
            cell,
            &evidence.receipt,
            anchor,
            observation,
            evidence.at,
        )?
    {
        return Ok(());
    }
    let mut recomputed = evidence.clone();
    recomputed.observation = Observation::Success(observation.0);
    recomputed.weight = observation.1;
    crate::learning::record_evidence_in_txn(vault, txn, cell, &recomputed, at)?;
    changed.remove(&cell.digest());
    Ok(())
}

/// Records an ordinary desired person row folded with the row standing under
/// the shared cell (REVIEW-4322 P1): the loss-dominates/max-weight fold, so
/// one skill's win never overwrites another path's loss for the same
/// receipt. Skips a row that already folds the combine.
fn record_combined_person_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    evidence: &LearningEvidence,
    at: u64,
    changed: &mut BTreeSet<[u8; 32]>,
) -> Result<()> {
    let mine = match evidence.observation {
        Observation::Success(success) => (success, evidence.weight),
        _ => {
            crate::learning::record_evidence_in_txn(vault, txn, cell, evidence, at)?;
            changed.remove(&cell.digest());
            return Ok(());
        }
    };
    let key = (cell.digest(), evidence.receipt.clone());
    let mut fold = mine;
    if let Some(stored) = EVIDENCE.get(&vault.store, txn, &key)?
        && let Observation::Success(stored_success) = stored.observation
    {
        fold = combine_person_observation(Some((stored_success, stored.weight)), Some(mine))
            .unwrap_or(mine);
    }
    if let Some(anchor) = person_anchor(evidence)
        && person_row_current(
            vault,
            txn,
            cell,
            &evidence.receipt,
            anchor,
            fold,
            evidence.at,
        )?
    {
        return Ok(());
    }
    let mut combined = evidence.clone();
    combined.observation = Observation::Success(fold.0);
    combined.weight = fold.1;
    crate::learning::record_evidence_in_txn(vault, txn, cell, &combined, at)?;
    changed.remove(&cell.digest());
    Ok(())
}

/// Projects `learning.reliability` over one SK-04 attribution pass.
///
/// Records the defect losses those judgments carry and re-projects every skill
/// they touched, returning those skills in first-seen order. Lapse and
/// discovery judgments are read and deliberately contribute nothing.
///
/// Each skill is recorded and projected in ONE write transaction, so a skill's
/// outcome rows and its claim never disagree. Across skills the pass is
/// resumable rather than atomic: the posterior is RECOMPUTED from the outcome
/// ledger every time, so an interrupted pass leaves stale claims that the next
/// pass corrects — never double-counted ones.
///
/// **Every judgment is re-grounded here, not trusted.** [`AttributionJudgment`]
/// is a public type with public fields, so the argument is caller-owned data —
/// and this function authors reserved `learning.*` truth through the engine-owned
/// door. So a row counts only if it IS the row ONE-1737's projector persisted
/// at that sequence (`attribution_judgments` is the stack seam, and the seam is
/// over PERSISTED judgments) and its citation resolves to a real pack receipt
/// whose manifest loaded this skill — the same grounding
/// [`record_skill_contributing_win`](crate::skill_reliability::record_skill_contributing_win) runs on the α side. Ungrounded rows are
/// SKIPPED rather than fatal: one forged row must not deny a whole pass.
pub fn project_skill_reliability(
    vault: &Vault,
    judgments: &[AttributionJudgment],
) -> Result<Vec<EntityId>> {
    project_skill_reliability_with_positions(vault, judgments, None)
}

/// Projects judgments with independently requested placement for each new outcome.
///
/// Keys are persisted judgment sequences, not outcome row identities. Each entry
/// declares the placement of that judgment's derived outcome; the judgment's own
/// read position is not used. Missing entries leave placement unknown. Held rows
/// never adopt a later request, and all original grounding checks still apply.
/// Placement grants no read: readers must re-admit the physical outcome.
pub fn project_skill_reliability_with_positions(
    vault: &Vault,
    judgments: &[AttributionJudgment],
    output_positions: Option<&BTreeMap<u64, OutcomeReadPosition>>,
) -> Result<Vec<EntityId>> {
    let persisted = persisted_judgments_by_sequence(vault)?;
    let mut batches: Vec<(EntityId, Option<String>, Vec<&AttributionJudgment>)> = Vec::new();
    for judgment in judgments {
        if judgment.verdict != AttributionVerdict::SkillDefect {
            continue;
        }
        // The subject of a defect verdict is a SKILL by SK-04's routing, but a
        // projector that trusts that without checking would mint a reliability
        // claim on whatever entity a malformed row named.
        let Some(subject) = judgment.subject else {
            continue;
        };
        let Some(record) = vault.get_skill_record(&subject)? else {
            continue;
        };
        // A callable's loss belongs to the executors that invoked it, which
        // the attempt stamp may not name; the sweep charges those pairs.
        if record.role == crate::skill::SkillRole::Callable {
            continue;
        }
        // A judgment with nothing to cite cannot be counted: the row it would
        // write has no key, and a loss with no trace is the thing the doctrine
        // header exists to refuse.
        let Some(receipt_ref) = judgment.evidence_receipts.first() else {
            continue;
        };
        // …and a citation that names no stamped receipt, or a receipt whose
        // pack never loaded this skill, is a trace only in shape.
        let Some(receipt) = crate::receipt::attempt_pack_receipt(vault, receipt_ref)? else {
            continue;
        };
        if !receipt_manifest_names_skill(&receipt, &record) {
            continue;
        }
        // Grounded — but grounding is not authorization. This row must also BE
        // the row ONE-1737's projector routed at this sequence.
        if persisted.get(&judgment.sequence) != Some(judgment)
            || crate::skill_attribution::judgment_displaced(vault, judgment.sequence)?
        {
            continue;
        }
        let executor = receipt_executor(&receipt).map(str::to_owned);
        match batches
            .iter_mut()
            .find(|(id, model, _)| *id == subject && *model == executor)
        {
            Some((_, _, rows)) => rows.push(judgment),
            None => batches.push((subject, executor, vec![judgment])),
        }
    }

    #[cfg(test)]
    PRE_WRITE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
    let mut projected = Vec::with_capacity(batches.len());
    for (skill, executor, rows) in batches {
        let at = rows.iter().map(|row| row.at).max().unwrap_or_default();
        let prior = skill_reliability_prior(vault, &skill)?;
        vault.with_write_txn_grouped(|wtxn| {
            for row in &rows {
                // Close the TOCTOU window: a displacement can commit after the
                // pre-read but before this writer. Recheck under the same writer
                // lock as the ledger update and posterior fold.
                if crate::skill_attribution::judgment_displaced_in_txn(vault, wtxn, row.sequence)? {
                    continue;
                }
                // ONE judgment is ONE attributed outcome, so it writes ONE row.
                // `evidence_receipts` is a list because the type is general —
                // SK-04 emits a single receipt per routed outcome — and keying
                // on each element would turn one multi-cited outcome into
                // several losses.
                let receipt = row
                    .evidence_receipts
                    .first()
                    .ok_or(invalid("a reliability loss must cite a receipt"))?;
                record_outcome_positioned_in_txn(
                    vault,
                    wtxn,
                    &skill,
                    executor.as_deref(),
                    receipt,
                    false,
                    row.at,
                    output_positions.and_then(|positions| positions.get(&row.sequence)),
                )?;
            }
            project_in_txn(vault, wtxn, &skill, executor.as_deref(), prior, at)
        })?;
        projected.push(skill);
    }
    Ok(projected)
}

/// An unqualified projection cannot invent an executor or task placement.
pub fn project_skill_reliability_for(
    _vault: &Vault,
    _skill: &EntityId,
    _at: u64,
) -> Result<SkillReliabilityPosterior> {
    Err(invalid(
        "skill reliability projection requires an executor revision",
    ))
}

/// Re-projects this executor's attributed receipts into their separate typed cells.
pub fn project_skill_reliability_for_executor(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
    at: u64,
) -> Result<SkillReliabilityPosterior> {
    validate_executor(executor)?;
    let prior = skill_reliability_prior(vault, skill)?;
    vault.with_write_txn_grouped(|txn| project_in_txn(vault, txn, skill, Some(executor), prior, at))
}

pub(super) fn project_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
    prior: SkillReliabilityPosterior,
    at: u64,
) -> Result<SkillReliabilityPosterior> {
    let executor = executor.ok_or(invalid("skill reliability requires an executor revision"))?;
    validate_executor(executor)?;
    // A shell merged into the skill folds its history into the skill's cells
    // (FIX 7815): each receipt counts once, and a suppressed copy withdraws
    // it whichever subject holds it. The rows keep their stored skill.
    let subjects = redirect_equivalent_subjects_in_txn(vault, txn, skill)?;
    let mut folded = BTreeMap::new();
    for subject in &subjects {
        for (receipt, outcome) in projection_outcomes_in_txn(vault, txn, subject, executor)? {
            let held = folded.entry(receipt).or_insert(outcome);
            if outcome.is_none() {
                *held = None;
            }
        }
    }
    let outcomes: Vec<_> = folded.into_iter().collect();
    let managed: BTreeSet<_> = outcomes
        .iter()
        .map(|(receipt, _)| receipt.clone())
        .collect();
    let mut judges = BTreeMap::new();
    for judgment in crate::skill_attribution::attribution_judgments_in_txn(vault, txn)? {
        if judgment
            .subject
            .is_some_and(|subject| subjects.contains(&subject))
            && judgment.verdict == AttributionVerdict::SkillDefect
        {
            let judge =
                crate::skill_attribution::judgment_judge_in_txn(vault, txn, judgment.sequence)?;
            for receipt in judgment.evidence_receipts {
                judges.insert(receipt, judge.clone());
            }
        }
    }
    // The anchored-amendment join (FIX 10148, FIX 11673, FIX 11674): an
    // attempt with a native anchored pack outcome keeps that stable
    // observation as its one effective run, restated here under its
    // amendment's defect share. The scan covers every redirect-equivalent
    // subject, and the share reads across every arm.
    let amended = amended_receipt_shares_in_txn(vault, txn, skill)?;
    let anchored = anchored_rows_in_txn(vault, txn, &subjects, executor)?;
    let native_attempts: BTreeSet<&str> =
        anchored.iter().map(|held| held.attempt.as_str()).collect();
    let mut anchored_writes = Vec::new();
    let mut anchored_withdrawals = Vec::new();
    // The same anchored restatements under person cells (FIX 8968): the
    // attempt beside each write for the person, the held cell for its
    // coordinates, so the person's cell needs no re-read.
    let mut anchored_person_writes: Vec<(LearningCell, String, LearningEvidence)> = Vec::new();
    let mut anchored_person_withdrawals: Vec<(
        LearningCell,
        String,
        String,
        EntityId,
        EvidenceRow,
    )> = Vec::new();
    for held in &anchored {
        match effective_evidence_in_txn(vault, txn, held, &amended)? {
            AnchoredEffect::Stand => {}
            AnchoredEffect::Record(evidence) => {
                anchored_person_writes.push((
                    held.cell.clone(),
                    held.attempt.clone(),
                    evidence.clone(),
                ));
                anchored_writes.push((held.cell.clone(), evidence));
            }
            AnchoredEffect::Withdraw => {
                anchored_person_withdrawals.push((
                    held.cell.clone(),
                    held.receipt.clone(),
                    held.attempt.clone(),
                    held.subject,
                    held.row.clone(),
                ));
                anchored_withdrawals.push((held.cell.clone(), held.receipt.clone()));
            }
        }
    }
    let mut desired: BTreeMap<LearningCell, (SkillReliabilityQuery, Vec<LearningEvidence>)> =
        BTreeMap::new();
    let mut person_desired: BTreeMap<LearningCell, (SkillReliabilityQuery, Vec<LearningEvidence>)> =
        BTreeMap::new();
    for (receipt_ref, outcome) in &outcomes {
        let Some(outcome) = outcome else {
            continue;
        };
        // Its native anchored observation above is this attempt's one run.
        if native_attempts.contains(receipt_ref.as_str()) {
            continue;
        }
        let receipt = crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, receipt_ref)?
            .ok_or(invalid("skill reliability receipt disappeared"))?;
        let query = receipt_query(&receipt)?;
        let cell = query.cell(*skill, executor)?;
        // A routed failure or successful attempt alone is not an anchor.
        // Keep its attribution record, but mint no numerical claim from it.
        let Some(raw_anchor) = receipt.fields.get(FIELD_SKILL_LEARNING_ANCHOR) else {
            continue;
        };
        let anchor: Anchor = serde_json::from_str(raw_anchor)
            .map_err(|_| invalid("invalid skill receipt learning anchor"))?;
        let source = EvidenceSource::Anchored(anchor);
        if !source
            .admit()?
            .feeds(crate::claim::learning_predicate::LearningPredicate::Reliability)
        {
            return Err(invalid("skill reliability requires a performance anchor"));
        }
        let judge = judges
            .get(receipt_ref)
            .cloned()
            .flatten()
            .or_else(|| receipt.fields.get("judge").cloned());
        let mut evidence = LearningEvidence::anchored(
            receipt_ref.clone(),
            receipt.occurred_at,
            anchor,
            Observation::Success(outcome.win),
        );
        evidence.weight = if outcome.win {
            1.0
        } else {
            f64::from(outcome.loss)
        };
        evidence.on_judge_model =
            receipt.fields.get("judge.model").map(String::as_str) == Some(executor);
        evidence.judge = judge;
        // The revision frozen beside the outcome; a re-projection keeps it.
        evidence.goal_revision = receipt.fields.get(FIELD_SKILL_GOAL_REVISION).cloned();
        // The same outcome evidence under the person's own cell (FIX 8968):
        // a (task-type, person) fit fed by the runs the person drove.
        if let Some(person) = receipt
            .on_behalf_of
            .as_deref()
            .or(receipt.actor.as_deref())
            .and_then(|s| EntityId::from_hex(s).ok())
        {
            let person_cell =
                LearningCell::new(crate::learning::LearningPredicate::Reliability, person)
                    .executor(person.to_hex())
                    .type_ref(query.type_ref.clone())
                    .axis(query.axis.clone())
                    .project(query.project);
            person_cell.validate()?;
            person_desired
                .entry(person_cell)
                .or_insert_with(|| (query.clone(), Vec::new()))
                .1
                .push(evidence.clone());
        }
        desired
            .entry(cell)
            .or_insert_with(|| (query, Vec::new()))
            .1
            .push(evidence);
    }

    // Amendments and displaced verdicts replace an attempt's evidence, never
    // add a second run. Other learning producers' receipt rows are untouched.
    let mut changed = BTreeSet::new();
    for row in cells_for_subject_in_txn(vault, txn, skill)? {
        if row.cell.predicate != crate::claim::learning_predicate::LearningPredicate::Reliability
            || row.cell.executor.as_deref() != Some(executor)
        {
            continue;
        }
        let digest = row.cell.digest();
        for ((_, receipt), _) in EVIDENCE.scan_from(&vault.store, txn, &digest)? {
            if managed.contains(&receipt)
                && !desired
                    .get(&row.cell)
                    .is_some_and(|(_, rows)| rows.iter().any(|row| row.receipt == receipt))
            {
                let stale = EVIDENCE.get(&vault.store, txn, &(digest, receipt.clone()))?;
                EVIDENCE.delete(&vault.store, txn, &(digest, receipt.clone()))?;
                changed.insert(digest);
                // The same stale row under the person's cell (FIX 8968).
                if let Some(attempt) =
                    crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, &receipt)?
                    && let Some(person) = attempt
                        .on_behalf_of
                        .as_deref()
                        .or(attempt.actor.as_deref())
                        .and_then(|s| EntityId::from_hex(s).ok())
                    && let (Some(type_ref), Some(axis)) =
                        (row.cell.type_ref.clone(), row.cell.axis.clone())
                {
                    let person_cell =
                        LearningCell::new(crate::learning::LearningPredicate::Reliability, person)
                            .executor(person.to_hex())
                            .type_ref(type_ref)
                            .axis(axis)
                            .project(row.cell.project);
                    let person_digest = person_cell.digest();
                    let person_key = (person_digest, receipt.clone());
                    // A person row holding another observation than this
                    // skill's stale one survives (REVIEW-4322 P1): another
                    // skill's or the native-credit path's row is not this
                    // skill's to withdraw. Only a row with this skill's own
                    // stale observation leaves with it.
                    let keep = match (EVIDENCE.get(&vault.store, txn, &person_key)?, stale) {
                        (Some(stored), Some(old)) => {
                            stored.observation != old.observation || stored.weight != old.weight
                        }
                        _ => false,
                    };
                    if !keep {
                        EVIDENCE.delete(&vault.store, txn, &(person_digest, receipt))?;
                        changed.insert(person_digest);
                    }
                }
            }
        }
    }
    // The flipped-loss corner (FIX 11676): an amendment landing after its
    // attempt's standing credit moved to nothing has no anchored row to flip
    // and no desired row, so mint the flipped row from the sealed credit.
    {
        let desired_attempts: BTreeSet<&str> = desired
            .values()
            .flat_map(|(_, rows)| rows.iter().map(|row| row.receipt.as_str()))
            .collect();
        for (attempt, share) in &amended {
            if native_attempts.contains(attempt.as_str())
                || desired_attempts.contains(attempt.as_str())
            {
                continue;
            }
            let Some((cell, evidence)) =
                super::anchored_amendment::mint_flipped_from_credit_in_txn(
                    vault, txn, skill, executor, attempt, *share,
                )?
            else {
                continue;
            };
            crate::learning::record_evidence_in_txn(vault, txn, &cell, &evidence, at)?;
            changed.remove(&cell.digest());
            // The same flipped loss under the person's own cell (FIX 8968):
            // no anchored row exists in this corner, so mirror the minted
            // skill cell's coordinates and stable credit-receipt key.
            if let Some(attempt_receipt) =
                crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, attempt)?
                && let Some(person) = attempt_receipt
                    .on_behalf_of
                    .as_deref()
                    .or(attempt_receipt.actor.as_deref())
                    .and_then(|actor| EntityId::from_hex(actor).ok())
                && let (Some(type_ref), Some(axis)) = (cell.type_ref.clone(), cell.axis.clone())
            {
                let person_cell = crate::learning::LearningCell::new(
                    crate::learning::LearningPredicate::Reliability,
                    person,
                )
                .executor(person.to_hex())
                .type_ref(type_ref)
                .axis(axis)
                .project(cell.project);
                person_cell.validate()?;
                let parents: Vec<crate::learning::TypeRef> = attempt_receipt
                    .fields
                    .get("typeParents")
                    .map(|raw| serde_json::from_str(raw))
                    .transpose()
                    .map_err(|_| invalid("invalid skill receipt type parents"))?
                    .unwrap_or_default();
                crate::learning::prior::capture_borrowed_prior_in_txn(
                    vault,
                    txn,
                    &person_cell,
                    &parents,
                    crate::learning::EstimateForm::Beta,
                )?;
                let observation = match crate::skill_attribution::late_credit_receipt_in_txn(
                    vault,
                    txn,
                    &evidence.receipt,
                )? {
                    Some(credit) => match recomputed_person_observation(
                        vault, txn, &credit, attempt, *skill, None,
                    )? {
                        StandingCreditObservation::Credited(success, weight) => {
                            Some((success, weight))
                        }
                        StandingCreditObservation::Uncredited => None,
                        StandingCreditObservation::Unknown => continue,
                    },
                    None => None,
                };
                if let Some(observation) = observation {
                    record_recomputed_person_evidence_in_txn(
                        vault,
                        txn,
                        &person_cell,
                        &evidence,
                        observation,
                        at,
                        &mut changed,
                    )?;
                } else {
                    record_combined_person_evidence_in_txn(
                        vault,
                        txn,
                        &person_cell,
                        &evidence,
                        at,
                        &mut changed,
                    )?;
                }
            }
        }
    }
    for (cell, (query, evidence)) in desired {
        ensure_prior_in_txn(vault, txn, &cell, &query.type_parents)?;
        for row in evidence {
            crate::learning::record_evidence_in_txn(vault, txn, &cell, &row, at)?;
        }
        changed.remove(&cell.digest());
    }
    // The same desired evidence under person cells (FIX 8968). Persons start
    // from the shared borrowed/shipped prior, never a skill's provenance.
    for (cell, (query, evidence)) in person_desired {
        crate::learning::prior::capture_borrowed_prior_in_txn(
            vault,
            txn,
            &cell,
            &query.type_parents,
            crate::learning::EstimateForm::Beta,
        )?;
        for row in evidence {
            record_combined_person_evidence_in_txn(vault, txn, &cell, &row, at, &mut changed)?;
        }
    }
    // The anchored writes land in cells the credit recording already kept a
    // prior for; the stable key replaces the row in place.
    for (cell, evidence) in anchored_writes {
        crate::learning::record_evidence_in_txn(vault, txn, &cell, &evidence, at)?;
        changed.remove(&cell.digest());
    }
    // The same anchored restatements under person cells (FIX 8968): the
    // person comes from the attempt, the coordinates from the held credit
    // cell, and the recomputed observation across effective subjects stands.
    for (held, attempt_ref, evidence) in anchored_person_writes {
        let Some(attempt) =
            crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, &attempt_ref)?
        else {
            continue;
        };
        let Some(person) = attempt
            .on_behalf_of
            .as_deref()
            .or(attempt.actor.as_deref())
            .and_then(|s| EntityId::from_hex(s).ok())
        else {
            continue;
        };
        let query = receipt_query(&attempt)?;
        let Some(person_cell) = anchored_person_cell(&held, person) else {
            continue;
        };
        crate::learning::prior::capture_borrowed_prior_in_txn(
            vault,
            txn,
            &person_cell,
            &query.type_parents,
            crate::learning::EstimateForm::Beta,
        )?;
        let observation = match crate::skill_attribution::late_credit_receipt_in_txn(
            vault,
            txn,
            &evidence.receipt,
        )? {
            Some(credit) => match recomputed_person_observation(
                vault,
                txn,
                &credit,
                &attempt_ref,
                held.subject,
                None,
            )? {
                StandingCreditObservation::Credited(success, weight) => Some((success, weight)),
                StandingCreditObservation::Uncredited => None,
                StandingCreditObservation::Unknown => continue,
            },
            None => None,
        };
        if let Some(observation) = observation {
            record_recomputed_person_evidence_in_txn(
                vault,
                txn,
                &person_cell,
                &evidence,
                observation,
                at,
                &mut changed,
            )?;
        } else {
            record_combined_person_evidence_in_txn(
                vault,
                txn,
                &person_cell,
                &evidence,
                at,
                &mut changed,
            )?;
        }
    }
    for (cell, receipt) in anchored_withdrawals {
        crate::learning::evidence::withdraw_evidence_in_txn(vault, txn, &cell, &receipt, at)?;
        changed.remove(&cell.digest());
    }
    // The same anchored withdrawals under person cells (FIX 8968): the
    // person comes from the attempt, the coordinates from the held credit
    // cell, and a row another skill still stands on survives.
    for (held, receipt, attempt_ref, subject, row) in anchored_person_withdrawals {
        let Some(attempt) =
            crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, &attempt_ref)?
        else {
            continue;
        };
        let Some(person) = attempt
            .on_behalf_of
            .as_deref()
            .or(attempt.actor.as_deref())
            .and_then(|s| EntityId::from_hex(s).ok())
        else {
            continue;
        };
        let Some(person_cell) = anchored_person_cell(&held, person) else {
            continue;
        };
        let observation =
            match crate::skill_attribution::late_credit_receipt_in_txn(vault, txn, &receipt)? {
                Some(credit) => match recomputed_person_observation(
                    vault,
                    txn,
                    &credit,
                    &attempt_ref,
                    subject,
                    Some(&subject),
                )? {
                    StandingCreditObservation::Credited(success, weight) => Some((success, weight)),
                    StandingCreditObservation::Uncredited => None,
                    StandingCreditObservation::Unknown => continue,
                },
                None => None,
            };
        if let Some(observation) = observation {
            let mut restated = LearningEvidence::anchored(
                receipt.clone(),
                row.at,
                row.anchor,
                Observation::Success(observation.0),
            );
            restated.weight = observation.1;
            restated.judge.clone_from(&row.judge);
            restated.on_judge_model = row.on_judge_model;
            restated.outcome_label.clone_from(&row.outcome_label);
            restated.pack_attribution.clone_from(&row.pack_attribution);
            restated.goal_revision.clone_from(&row.goal_revision);
            restated
                .measurement_version
                .clone_from(&row.measurement_version);
            if person_row_current(
                vault,
                txn,
                &person_cell,
                &receipt,
                row.anchor,
                observation,
                row.at,
            )? {
                continue;
            }
            crate::learning::record_evidence_in_txn(vault, txn, &person_cell, &restated, at)?;
            changed.remove(&person_cell.digest());
        } else {
            crate::learning::evidence::withdraw_evidence_in_txn(
                vault,
                txn,
                &person_cell,
                &receipt,
                at,
            )?;
            changed.remove(&person_cell.digest());
        }
    }
    for digest in changed {
        project_cell_in_txn(vault, txn, &digest, at)?;
    }
    let estimate =
        resolved_estimate_in_txn(vault, txn, skill, Some(executor))?.map(|head| head.estimate);
    let posterior = estimate
        .as_ref()
        .map(posterior_from_estimate)
        .transpose()?
        .unwrap_or(prior);
    vault.refresh_skill_confidence_cache_in_txn(
        txn,
        skill,
        posterior.mean(),
        TimeRange { start: at, end: at },
        at,
    )?;
    super::floor::check_floor_cells_in_txn(vault, txn, skill, Some(executor), at)?;
    Ok(posterior)
}

/// The ROUTED judgments ONE-1737 persisted, keyed by sequence.
///
/// Read once per pass rather than once per judgment: the seam is a prefix scan,
/// and a batch of N judgments must not cost N scans.
fn persisted_judgments_by_sequence(vault: &Vault) -> Result<HashMap<u64, AttributionJudgment>> {
    Ok(attribution_judgments(vault)?
        .into_iter()
        .map(|judgment| (judgment.sequence, judgment))
        .collect())
}

#[cfg(test)]
thread_local! {
    static PRE_WRITE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn set_pre_write_hook(hook: Box<dyn FnOnce()>) {
    PRE_WRITE_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}
