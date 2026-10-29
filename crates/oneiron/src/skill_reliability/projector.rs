//! Project attributed skill outcomes into the shared learning.reliability cells.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::evidence::{EVIDENCE, cells_for_subject_in_txn};
use crate::learning::project::project_cell_in_txn;
use crate::learning::{Anchor, EvidenceSource, LearningCell, LearningEvidence, Observation};
use crate::receipt::ReceiptRecord;
use crate::skill_attribution::{AttributionJudgment, AttributionVerdict, attribution_judgments};
use crate::temporal::TimeRange;

use super::amended::amended_shares_in_txn;
use super::anchored_amendment::{anchored_rows_in_txn, effective_evidence_in_txn};
use super::codec::invalid;
use super::equivalent::redirect_equivalent_subjects_in_txn;
use super::ledger::{
    projection_outcomes_in_txn, receipt_executor, receipt_manifest_names_skill,
    record_outcome_in_txn,
};
use super::posterior::SkillReliabilityPosterior;
use super::priors::ensure_prior_in_txn;
use super::provenance::skill_reliability_prior;
use super::read::{
    SkillReliabilityQuery, posterior_from_estimate, resolved_estimate_in_txn, validate_executor,
};

pub const PREDICATE_SKILL_RELIABILITY: &str = crate::learning::PREDICATE_LEARNING_RELIABILITY;

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
                record_outcome_in_txn(
                    vault,
                    wtxn,
                    &skill,
                    executor.as_deref(),
                    receipt,
                    false,
                    row.at,
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
    // The anchored-amendment join (FIX 10148): an attempt with a native
    // anchored pack outcome keeps that stable observation as its one
    // effective run, restated here under its amendment's defect share.
    let amended = amended_shares_in_txn(vault, txn, skill, Some(executor))?;
    let anchored = anchored_rows_in_txn(vault, txn, skill, executor)?;
    let native_attempts: BTreeSet<&str> =
        anchored.iter().map(|held| held.attempt.as_str()).collect();
    let mut anchored_writes = Vec::new();
    for held in &anchored {
        if let Some(evidence) = effective_evidence_in_txn(vault, txn, skill, held, &amended)? {
            anchored_writes.push((held.cell.clone(), evidence));
        }
    }
    let mut desired: BTreeMap<LearningCell, (SkillReliabilityQuery, Vec<LearningEvidence>)> =
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
            .feeds(crate::learning::LearningPredicate::Reliability)
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
        if row.cell.predicate != crate::learning::LearningPredicate::Reliability
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
                EVIDENCE.delete(&vault.store, txn, &(digest, receipt))?;
                changed.insert(digest);
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
    // The anchored writes land in cells the credit recording already kept a
    // prior for; the stable key replaces the row in place.
    for (cell, evidence) in anchored_writes {
        crate::learning::record_evidence_in_txn(vault, txn, &cell, &evidence, at)?;
        changed.remove(&cell.digest());
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
    if let Some(estimate) = estimate {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let outcomes = estimate.runs as u32;
        super::floor::floor_check_in_txn(
            vault,
            txn,
            skill,
            Some(executor),
            posterior,
            outcomes,
            at,
        )?;
    }
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
