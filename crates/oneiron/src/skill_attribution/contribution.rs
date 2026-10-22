//! Contribution checks (ARCH-0037 #lineage-credit, ARCH-0053): whether one
//! loaded skill, or the source of one used derived-from edge, contributed to
//! a run's anchored outcome, measured on matched forks. The run's step is
//! regenerated with and without the target on the same pinned executor,
//! input snapshot, clock, seed and budget, and both forks are scored against
//! the same anchor. Loading, citing or succeeding proves nothing.
//!
//! A finished pair is measured only when the fork receipts the engine kept
//! for the run's credited outcome prove it; one they do not is recorded
//! unmatched, with why, and teaches nothing (FIX 3610,
//! [`super::contribution_admission`]).
//!
//! The forks run elsewhere (the Coach's contribution recipe, on a replay
//! capsule). This module samples the credited runs worth checking
//! ([`contribution_check_candidates_after`]), records a finished pair as one
//! immutable check ([`record_contribution_pair`]) and joins it to learning:
//! an outcome projected later reads the check
//! ([`super::project_anchored_pack_outcome`]), and an outcome already
//! credited is reconciled when the check lands ([`super::credit_join`]). The
//! run's frozen receipt is never rewritten.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::codec::{evidence_after, evidence_after_in_txn};
use super::contribution_admission::{ContributionAdmission, ContributionRecord, admit_pair_in_txn};
use super::contribution_targets::{CheckedEdge, ContributionTarget, Experiment, unchecked_edges};
use super::late_credit::CREDIT_RECEIPT;
use super::{AttemptOutcome, FollowedState, LateCreditReceipt, OutcomeEvidence};
use crate::entity_id::EntityId;
use crate::learning::{Anchor, EvidenceSource, LearningPredicate, TypeRef};
use crate::receipt::{
    ContributionCheck, PackAttributionFields, SkillContribution, attempt_pack_receipt,
};
use crate::side_table::{self, Named, SideTable};
use crate::{Error, Result, Vault};

/// Recorded checks, measured and unmatched. Key: attempt receipt NUL target
/// (a skill's 32 hex, or an edge's two joined by `>`) NUL a digest of the
/// experiment ([`Experiment::check_key`]).
pub(super) const CHECK: SideTable<String, ContributionAdmission, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_CONTRIBUTION_CHECK);

/// One fork of a matched pair: its receipt, and whether it passed the
/// anchor both forks were scored against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionFork {
    pub receipt: String,
    pub passed: bool,
}

/// A finished matched-fork pair for one target on one run's outcome axis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContributionPair {
    /// The original run's terminal receipt.
    pub attempt_receipt: String,
    /// The credited outcome the pair was checked for: its outcome receipt.
    pub outcome_receipt: String,
    /// The skill checked, or for a used edge's check the run's pattern,
    /// whose goal axis scored both forks; `None` once that skill is erased
    /// (FIX 8988).
    pub skill: Option<EntityId>,
    /// The used edge an ancestor check measured; `None` for a loaded
    /// skill's check.
    pub edge: Option<CheckedEdge>,
    pub axis: String,
    /// The goal revision the credited outcome was checked under; a check
    /// joins only an outcome of the same revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_revision: Option<String>,
    /// The correctness anchor both forks were scored against.
    pub anchor: Anchor,
    /// The fork with the target, as captured.
    pub with_skill: ContributionFork,
    /// The fork without the target's exposure.
    pub without_skill: ContributionFork,
    /// Unix seconds the pair finished.
    pub at: u64,
}

/// One measured check: the verdict and the pair it was read from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContributionCheckRecord {
    pub check: ContributionCheck,
    pub pair: ContributionPair,
}

/// A credited run's target a contribution check should measure: what a
/// recipe needs to regenerate its step with and without the target.
#[derive(Debug, Clone, PartialEq)]
pub struct ContributionCandidate {
    pub attempt_receipt: String,
    pub outcome_receipt: String,
    /// The skill whose goal axis scores both forks: the checked skill, or
    /// for a used edge the run's pattern.
    pub skill: EntityId,
    /// What the check measures.
    pub target: ContributionTarget,
    pub axis: String,
    /// The credit's frozen goal revision, for the pair to carry.
    pub goal_revision: Option<String>,
    pub anchor: Anchor,
    /// The pinned executor, `id@revision`.
    pub executor: String,
    pub type_ref: TypeRef,
}

/// The contribution rule: the fork with the target passed and the fork
/// without it failed. A tie or no improvement is no contribution.
#[must_use]
pub const fn contributed(with_skill: bool, without_skill: bool) -> bool {
    with_skill && !without_skill
}

/// Whether a routed evidence row says the run followed its skill and
/// succeeded, as the projector requires for a skill's direct win.
fn followed_success(row: &OutcomeEvidence) -> bool {
    row.outcome == AttemptOutcome::Succeeded
        && (matches!(row.followed_state, Some(FollowedState::Followed))
            || row.followed_state.is_none() && row.followed_skill == Some(true))
}

/// The skills each run followed to success, by attempt receipt.
fn followed_skills(vault: &Vault) -> Result<BTreeMap<String, BTreeSet<EntityId>>> {
    let mut out: BTreeMap<String, BTreeSet<EntityId>> = BTreeMap::new();
    for (_, row) in evidence_after(vault, 0)? {
        if let Some(skill) = row.skill
            && followed_success(&row)
        {
            out.entry(row.receipt_ref).or_default().insert(skill);
        }
    }
    Ok(out)
}

/// The skills the run `attempt_receipt` followed to success, read only
/// through `txn`.
pub(super) fn followed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_receipt: &str,
) -> Result<BTreeSet<EntityId>> {
    Ok(evidence_after_in_txn(vault, txn, 0)?
        .into_iter()
        .filter(|(_, row)| row.receipt_ref == attempt_receipt && followed_success(row))
        .filter_map(|(_, row)| row.skill)
        .collect())
}

/// Whether `skill` can earn a direct win on `credit`: a followed skill on a
/// successful outcome, or the team pattern once someone else won. A credit
/// whose attribution an erase cleared joins nothing (FIX 8988).
pub(super) fn joins(credit: &LateCreditReceipt, followed: bool, skill: EntityId) -> bool {
    let Some(attribution) = &credit.attribution else {
        return false;
    };
    credit.succeeded
        && !credit.direct_subjects.contains(&Some(skill))
        && if skill == attribution.pattern {
            !credit.direct_subjects.is_empty()
        } else {
            followed
        }
}

/// Every target a check could measure on `credit`, with the skill whose
/// goal axis scores it: each loaded skill the run followed to success and
/// the team pattern, then, once someone won directly, each used edge of its
/// effective attribution no check has measured, scored by the pattern.
fn targets_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    credit: &LateCreditReceipt,
    followed: Option<&BTreeSet<EntityId>>,
) -> Result<BTreeMap<ContributionTarget, EntityId>> {
    let Some(attribution) = &credit.attribution else {
        return Ok(BTreeMap::new());
    };
    let mut out: BTreeMap<_, _> = followed
        .into_iter()
        .flatten()
        .copied()
        .chain([attribution.pattern])
        .map(|skill| (ContributionTarget::LoadedSkill(skill), skill))
        .collect();
    if credit.succeeded && !credit.direct_subjects.is_empty() {
        let fields =
            super::credit_join::effective_fields_in_txn(vault, txn, credit, attribution.clone())?;
        out.extend(
            unchecked_edges(&fields)
                .into_iter()
                .map(|target| (target, attribution.pattern)),
        );
    }
    Ok(out)
}

/// Up to `limit` credited runs' targets a check should measure, in credit
/// order then target order, strictly after `after` (a credit key and a
/// target; `None` is the head): a followed skill or the team pattern that
/// has no direct win, or a used edge of a credit someone won, with no check
/// yet, sampled at the `contribution_check_rate` setting. Each comes with
/// its own credit key and target, so a pass can resume after the last one it
/// examined. A position whose credit is gone, or whose target that credit no
/// longer offers, starts at the head, so no candidate is skipped.
///
/// # Errors
///
/// Storage errors.
pub fn contribution_check_candidates_after(
    vault: &Vault,
    after: Option<&(String, ContributionTarget)>,
    limit: usize,
) -> Result<Vec<(String, ContributionTarget, ContributionCandidate)>> {
    let rate = crate::learning_setting::setting_value(
        vault,
        &crate::learning_setting::CONTRIBUTION_CHECK_RATE,
    )?;
    if rate <= 0.0 || limit == 0 {
        return Ok(Vec::new());
    }
    let followed = followed_skills(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    let after = match after {
        Some((key, target)) => match CREDIT_RECEIPT.get(&vault.store, &rtxn, key)? {
            Some(credit) => {
                targets_in_txn(vault, &rtxn, &credit, followed.get(&credit.attempt_receipt))?
                    .contains_key(target)
                    .then_some((key, *target))
            }
            None => None,
        },
        None => None,
    };
    let start = after.map_or(std::ops::Bound::Unbounded, |(key, _)| {
        std::ops::Bound::Included(key)
    });
    let mut out = Vec::new();
    for row in CREDIT_RECEIPT.iter_range(&vault.store, &rtxn, start, std::ops::Bound::Unbounded)? {
        let (key, credit) = row?;
        let run_followed = followed.get(&credit.attempt_receipt);
        // A credit whose attribution an erase cleared offers no candidate.
        let Some(attribution) = &credit.attribution else {
            continue;
        };
        for (target, skill) in targets_in_txn(vault, &rtxn, &credit, run_followed)? {
            if after.is_some_and(|(at, last)| *at == key && target <= last) {
                continue;
            }
            let candidate = ContributionCandidate {
                attempt_receipt: credit.attempt_receipt.clone(),
                outcome_receipt: credit.outcome_receipt.clone(),
                skill,
                target,
                axis: credit.axis.clone(),
                goal_revision: credit.goal_revision.clone(),
                anchor: credit.anchor,
                executor: attribution.executor.clone(),
                type_ref: attribution.type_ref.clone(),
            };
            let eligible = match target {
                ContributionTarget::LoadedSkill(skill) => joins(
                    &credit,
                    run_followed.is_some_and(|skills| skills.contains(&skill)),
                    skill,
                ),
                ContributionTarget::UsedEdge { .. } => true,
            };
            let experiment = Experiment::of_candidate(&candidate);
            if !eligible
                || !experiment.sampled(rate)
                || CHECK
                    .get(&vault.store, &rtxn, &experiment.check_key())?
                    .is_some()
            {
                continue;
            }
            out.push((key.clone(), target, candidate));
            if out.len() >= limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

/// Records one finished matched-fork pair (FIX 3610). It is measured, as an
/// immutable contribution check, only when the fork receipts the engine kept
/// for the run's credited outcome prove it, read in this write; a measured
/// check, whether it contributed or not, reconciles every outcome of the run
/// already credited ([`super::credit_join`]), and one on an adjacent used
/// edge fits `credit_decay` ([`super::decay_fit`]). A pair they do not prove
/// is recorded unmatched, with why, and teaches nothing; it may be measured
/// later, when its forks are kept. The same pair again answers its record; a
/// different pair beside a final measurement is kept as conflicting and
/// changes nothing.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a malformed reference or axis, forks that
/// share a receipt or reuse the run's, a pair naming no skill or a self
/// edge, an anchor that does not settle correctness, a run that is not a
/// scored stamped attempt, or a skill the run did not load; storage errors.
pub fn record_contribution_pair(
    vault: &Vault,
    pair: &ContributionPair,
    now: u64,
) -> Result<ContributionRecord> {
    let (Some(skill), Some(target)) = (pair.skill, pair.target()) else {
        return Err(Error::InvalidClaimBody(
            "a contribution check names its skill and target",
        ));
    };
    if let ContributionTarget::UsedEdge { derived, source } = target
        && derived == source
    {
        return Err(Error::InvalidClaimBody(
            "an ancestor check names an edge between two entities",
        ));
    }
    for text in [
        &pair.attempt_receipt,
        &pair.outcome_receipt,
        &pair.with_skill.receipt,
        &pair.without_skill.receipt,
    ] {
        crate::receipt::reference(text)?;
    }
    if pair.with_skill.receipt == pair.without_skill.receipt
        || pair.with_skill.receipt == pair.attempt_receipt
        || pair.without_skill.receipt == pair.attempt_receipt
    {
        return Err(Error::InvalidClaimBody(
            "a contribution check's two forks and the run are three receipts",
        ));
    }
    if pair.axis.is_empty() || pair.axis.len() > 256 || pair.axis.contains('\0') {
        return Err(Error::InvalidClaimBody(
            "a contribution check names its scored axis",
        ));
    }
    let anchor = EvidenceSource::Anchored(pair.anchor).admit()?;
    if !anchor.feeds(LearningPredicate::Reliability) {
        return Err(Error::InvalidClaimBody(
            "a contribution check's forks are scored against a correctness anchor",
        ));
    }
    let receipt = attempt_pack_receipt(vault, &pair.attempt_receipt)?.ok_or(
        Error::InvalidClaimBody("a contribution check names a stamped attempt"),
    )?;
    if !matches!(receipt.outcome.as_str(), "completed" | "failed") {
        return Err(Error::InvalidClaimBody(
            "cancelled or abandoned work is not checked",
        ));
    }
    vault.with_write_txn_grouped(|txn| {
        super::pack_learning::require_loaded_skill(vault, txn, &receipt, skill)?;
        admit_pair_in_txn(vault, txn, skill, target, pair, now)
    })
}

/// `fields` with `check` as `skill`'s contribution, unless the receipt froze
/// one already.
fn with_check(
    mut fields: PackAttributionFields,
    skill: EntityId,
    check: &ContributionCheck,
) -> PackAttributionFields {
    if !fields.contributions.iter().any(|c| c.skill == skill) {
        fields.contributions.push(SkillContribution {
            skill,
            check: check.clone(),
        });
    }
    fields
}

/// `fields` with `check` on the used edge `derived -> source`, unless the
/// receipt froze one on it already: the hop check that `check_every_hop`
/// credit reads (FIX 3241).
fn with_edge_check(
    mut fields: PackAttributionFields,
    derived: EntityId,
    source: EntityId,
    check: &ContributionCheck,
) -> PackAttributionFields {
    if let Some(edge) = fields
        .used_edges
        .iter_mut()
        .find(|edge| edge.derived == derived && edge.source == source && edge.check.is_none())
    {
        edge.check = Some(check.clone());
    }
    fields
}

/// `fields` with every check measured for `attempt_receipt`'s outcome
/// `outcome_receipt` on `axis` under `goal_revision` joined: a loaded
/// skill's as its contribution, a used edge's on that edge. The attribution
/// an outcome of that axis and revision projects.
///
/// # Errors
///
/// Storage errors.
pub(super) fn with_recorded_checks_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    attempt_receipt: &str,
    outcome_receipt: &str,
    axis: &str,
    goal_revision: Option<&str>,
    mut fields: PackAttributionFields,
) -> Result<PackAttributionFields> {
    let prefix = format!("{attempt_receipt}\0");
    // Only a measured check counts; an unmatched pair teaches nothing.
    for (_, admission) in CHECK.scan_from(store, txn, prefix.as_bytes())? {
        let Some(record) = admission.matched else {
            continue;
        };
        let pair = &record.pair;
        if pair.attempt_receipt != attempt_receipt
            || pair.outcome_receipt != outcome_receipt
            || pair.axis != axis
            || pair.goal_revision.as_deref() != goal_revision
        {
            continue;
        }
        fields = match pair.target() {
            Some(ContributionTarget::LoadedSkill(skill)) => {
                with_check(fields, skill, &record.check)
            }
            Some(ContributionTarget::UsedEdge { derived, source }) => {
                with_edge_check(fields, derived, source, &record.check)
            }
            None => fields,
        };
    }
    Ok(fields)
}
