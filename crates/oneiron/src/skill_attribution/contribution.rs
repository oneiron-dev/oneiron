//! Contribution checks (ARCH-0037 #lineage-credit, ARCH-0053): whether one
//! loaded skill contributed to a run's anchored outcome, measured on matched
//! forks. The run's step is regenerated with and without the skill on the
//! same pinned executor, input snapshot, clock, seed and budget, and both
//! forks are scored against the same anchor. Loading, citing or succeeding
//! proves nothing.
//!
//! The forks run elsewhere (the Coach's contribution recipe, on a replay
//! capsule). This module samples the credited runs worth checking
//! ([`contribution_check_candidates`]), records a finished pair as one
//! immutable check ([`record_contribution_pair`]) and joins it to learning:
//! an outcome projected later reads the check
//! ([`super::project_anchored_pack_outcome`]), and an outcome already
//! credited gains the skill's own win when the check lands. The run's frozen
//! receipt is never rewritten.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::codec::evidence_after;
use super::late_credit::CREDIT_RECEIPT;
use super::{AttemptOutcome, FollowedState, LateCreditReceipt, OutcomeEvidence};
use crate::entity_id::EntityId;
use crate::learning::{
    Anchor, EvidenceSource, LearningCell, LearningEvidence, LearningPredicate, Observation, TypeRef,
};
use crate::receipt::{
    ContributionCheck, PackAttributionFields, PackLearningContext, SkillContribution,
    attempt_pack_receipt,
};
use crate::side_table::{self, Named, SideTable};
use crate::{Error, Result, Vault};

/// Recorded checks. Key: attempt receipt NUL skill (32 hex) NUL axis.
const CHECK: SideTable<String, ContributionCheckRecord, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_CONTRIBUTION_CHECK);

/// One fork of a matched pair: its receipt, and whether it passed the
/// anchor both forks were scored against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionFork {
    pub receipt: String,
    pub passed: bool,
}

/// A finished matched-fork pair for one skill on one run's outcome axis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContributionPair {
    /// The original run's terminal receipt.
    pub attempt_receipt: String,
    pub skill: EntityId,
    pub axis: String,
    /// The correctness anchor both forks were scored against.
    pub anchor: Anchor,
    pub with_skill: ContributionFork,
    pub without_skill: ContributionFork,
    /// Unix seconds the pair finished.
    pub at: u64,
}

/// One recorded check: the verdict and the pair it was read from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContributionCheckRecord {
    pub check: ContributionCheck,
    pub pair: ContributionPair,
}

/// A credited run whose skill a contribution check should measure: what a
/// recipe needs to regenerate its step with and without the skill.
#[derive(Debug, Clone, PartialEq)]
pub struct ContributionCandidate {
    pub attempt_receipt: String,
    pub outcome_receipt: String,
    pub skill: EntityId,
    pub axis: String,
    pub anchor: Anchor,
    /// The pinned executor, `id@revision`.
    pub executor: String,
    pub type_ref: TypeRef,
}

/// The contribution rule: the fork with the skill passed and the fork
/// without it failed. A tie or no improvement is no contribution.
#[must_use]
pub const fn contributed(with_skill: bool, without_skill: bool) -> bool {
    with_skill && !without_skill
}

fn check_key(attempt_receipt: &str, skill: EntityId, axis: &str) -> String {
    format!("{attempt_receipt}\0{}\0{axis}", skill.to_hex())
}

/// The check's own receipt id: the run, the skill, the axis and both forks.
fn check_receipt(pair: &ContributionPair) -> String {
    let mut hash = blake3::Hasher::new_derive_key("oneiron contribution check v1");
    let skill = pair.skill.to_hex();
    for text in [
        pair.attempt_receipt.as_str(),
        skill.as_str(),
        pair.axis.as_str(),
        pair.with_skill.receipt.as_str(),
        pair.without_skill.receipt.as_str(),
    ] {
        hash.update(&(text.len() as u64).to_be_bytes());
        hash.update(text.as_bytes());
    }
    format!("contribution:{}", hash.finalize().to_hex())
}

/// Whether `(attempt, skill, axis)` falls in the sample at `rate`: a fixed
/// draw from the three, so a rerun samples the same runs.
fn sampled(attempt_receipt: &str, skill: EntityId, axis: &str, rate: f64) -> bool {
    let mut hash = blake3::Hasher::new_derive_key("oneiron contribution sample v1");
    for bytes in [
        attempt_receipt.as_bytes(),
        skill.as_bytes().as_slice(),
        axis.as_bytes(),
    ] {
        hash.update(&(bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let draw = hash.finalize();
    let mut head = [0_u8; 8];
    head.copy_from_slice(&draw.as_bytes()[..8]);
    #[allow(clippy::cast_precision_loss)]
    let unit = u64::from_be_bytes(head) as f64 / u64::MAX as f64;
    unit < rate
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

/// Whether `skill` can earn a direct win on `credit`: a followed skill on a
/// successful outcome, or the team pattern once someone else won.
fn joins(credit: &LateCreditReceipt, followed: bool, skill: EntityId) -> bool {
    credit.succeeded
        && !credit.direct_subjects.contains(&skill)
        && if skill == credit.attribution.pattern {
            !credit.direct_subjects.is_empty()
        } else {
            followed
        }
}

/// Up to `limit` credited runs whose skills a check should measure, in
/// credit order: a followed skill or the team pattern that has no direct win
/// and no check yet, sampled at the `contribution_check_rate` setting.
///
/// # Errors
///
/// Storage errors.
pub fn contribution_check_candidates(
    vault: &Vault,
    limit: usize,
) -> Result<Vec<ContributionCandidate>> {
    let rate = crate::learning_setting::setting_value(
        vault,
        &crate::learning_setting::CONTRIBUTION_CHECK_RATE,
    )?;
    if rate <= 0.0 || limit == 0 {
        return Ok(Vec::new());
    }
    let followed = followed_skills(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (_, credit) in CREDIT_RECEIPT.scan_from(&vault.store, &rtxn, &[])? {
        let run_followed = followed.get(&credit.attempt_receipt);
        let skills = run_followed
            .into_iter()
            .flatten()
            .copied()
            .chain([credit.attribution.pattern]);
        for skill in skills.collect::<BTreeSet<_>>() {
            let followed = run_followed.is_some_and(|skills| skills.contains(&skill));
            if !joins(&credit, followed, skill)
                || !sampled(&credit.attempt_receipt, skill, &credit.axis, rate)
                || CHECK
                    .get(
                        &vault.store,
                        &rtxn,
                        &check_key(&credit.attempt_receipt, skill, &credit.axis),
                    )?
                    .is_some()
            {
                continue;
            }
            out.push(ContributionCandidate {
                attempt_receipt: credit.attempt_receipt.clone(),
                outcome_receipt: credit.outcome_receipt.clone(),
                skill,
                axis: credit.axis.clone(),
                anchor: credit.anchor,
                executor: credit.attribution.executor.clone(),
                type_ref: credit.attribution.type_ref.clone(),
            });
            if out.len() >= limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

/// Records one finished matched-fork pair as an immutable contribution check
/// and joins it to learning: an outcome on the same run and axis that was
/// already credited without the skill gains the skill's own win now, once.
/// The same pair again returns its check; a different pair for the same run,
/// skill and axis fails.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a malformed reference or axis, forks that
/// share a receipt or reuse the run's, an anchor that does not settle
/// correctness, a run that is not a scored stamped attempt, a skill the run
/// did not load, or a second differing pair; storage errors.
pub fn record_contribution_pair(
    vault: &Vault,
    pair: &ContributionPair,
    now: u64,
) -> Result<ContributionCheck> {
    for text in [
        &pair.attempt_receipt,
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
    let check = ContributionCheck {
        receipt: check_receipt(pair),
        contributed: contributed(pair.with_skill.passed, pair.without_skill.passed),
    };
    let record = ContributionCheckRecord {
        check: check.clone(),
        pair: pair.clone(),
    };
    let followed = followed_skills(vault)?
        .get(&pair.attempt_receipt)
        .is_some_and(|skills| skills.contains(&pair.skill));
    let key = check_key(&pair.attempt_receipt, pair.skill, &pair.axis);
    vault.with_write_txn_grouped(|txn| {
        super::pack_learning::require_loaded_skill(vault, txn, &receipt, pair.skill)?;
        if let Some(previous) = CHECK.get(&vault.store, txn, &key)? {
            if previous != record {
                return Err(Error::InvalidClaimBody(
                    "a contribution check is final; another pair fails",
                ));
            }
            return Ok(previous.check);
        }
        CHECK.put(&vault.store, txn, &key, &record)?;
        if check.contributed {
            join_credited_in_txn(vault, txn, &record, followed, now)?;
        }
        Ok(check)
    })
}

/// The skill's own win on every outcome of the check's run and axis that
/// was credited before the check landed, recorded under a receipt naming
/// both the credit and the check. The credit receipt stays as sealed.
fn join_credited_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &ContributionCheckRecord,
    followed: bool,
    now: u64,
) -> Result<()> {
    let pair = &record.pair;
    let credits: Vec<LateCreditReceipt> = CREDIT_RECEIPT
        .scan_from(&vault.store, txn, &[])?
        .into_iter()
        .map(|(_, credit)| credit)
        .filter(|credit| {
            credit.attempt_receipt == pair.attempt_receipt
                && credit.axis == pair.axis
                && joins(credit, followed, pair.skill)
        })
        .collect();
    for credit in credits {
        let attribution = with_check(credit.attribution.clone(), pair.skill, &record.check);
        let cell = LearningCell::new(LearningPredicate::Reliability, pair.skill)
            .executor(attribution.executor.clone())
            .type_ref(attribution.type_ref.clone())
            .axis(credit.axis.clone());
        let mut learning = LearningEvidence::anchored(
            format!("{}+{}", credit.receipt_id, record.check.receipt),
            credit.at,
            credit.anchor,
            Observation::Success(true),
        );
        learning.judge = Some(attribution.judge.clone());
        learning.on_judge_model = attribution.executor == attribution.judge;
        learning.pack_attribution = Some(PackLearningContext {
            attempt_receipt: credit.attempt_receipt.clone(),
            outcome_receipt: credit.outcome_receipt.clone(),
            attribution,
        });
        crate::learning::record_evidence_in_txn(vault, txn, &cell, &learning, now)?;
    }
    Ok(())
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

/// `fields` with every check recorded for `attempt_receipt` on `axis` joined
/// as a contribution: the attribution an outcome on that axis projects.
///
/// # Errors
///
/// Storage errors.
pub(super) fn with_recorded_checks_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    attempt_receipt: &str,
    axis: &str,
    mut fields: PackAttributionFields,
) -> Result<PackAttributionFields> {
    let prefix = format!("{attempt_receipt}\0");
    for (_, record) in CHECK.scan_from(store, txn, prefix.as_bytes())? {
        if record.pair.attempt_receipt == attempt_receipt && record.pair.axis == axis {
            fields = with_check(fields, record.pair.skill, &record.check);
        }
    }
    Ok(fields)
}
