//! Contribution-check admission (FIX 3610, OF-542): every well-formed pair a
//! caller submits is recorded. It is measured only when the fork receipts
//! the engine kept for the run's credited outcome prove it, read in the
//! recording write ([`crate::code_run::matched_contribution_facts_in_txn`]);
//! otherwise it is recorded unmatched, with why, and teaches nothing. An
//! unmatched record is a record state, never a refusal: ARCH-0053 and
//! ARCH-0037 rule what may teach, not what may be recorded.

use serde::{Deserialize, Serialize};

use super::contribution::{
    CHECK, ContributionCandidate, ContributionCheckRecord, ContributionPair, check_key,
    check_receipt, contributed, join_credited_in_txn,
};
use super::late_credit::{CREDIT_RECEIPT, receipt_id};
use crate::code_run::{ForkMismatch, matched_contribution_facts_in_txn};
use crate::entity_id::EntityId;
use crate::receipt::ContributionCheck;
use crate::{Result, Vault};

/// What recording one contribution pair kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContributionRecord {
    /// The kept fork receipts proved the pair: its measurement.
    Matched(ContributionCheck),
    /// Recorded and not measured: why the kept fork receipts did not prove
    /// it. It teaches nothing, and is not "did not contribute".
    Unmatched { reasons: Vec<UnmatchedReason> },
}

/// Why a recorded pair is unmatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmatchedReason {
    /// No credited outcome of the run names the pair's outcome, axis, goal
    /// revision and anchor with a readable attribution.
    NoCredit,
    /// The run's kept forks do not prove the pair.
    Forks(ForkMismatch),
    /// The run's skill and axis already hold the final measurement of
    /// another pair; this one is kept beside it.
    Conflicting,
}

/// One submitted pair the kept forks did not prove, with why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct UnmatchedContribution {
    pub(crate) pair: ContributionPair,
    pub(crate) reasons: Vec<UnmatchedReason>,
}

/// One run's skill and axis, as recorded: the measurement of the pair the
/// kept forks proved, final once set, and each other pair submitted, once.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct ContributionAdmission {
    pub(crate) matched: Option<ContributionCheckRecord>,
    pub(crate) unmatched: Vec<UnmatchedContribution>,
}

/// Records `pair` for its live `skill` in `txn`: measured when the run's
/// kept forks prove it, else unmatched with why. A pair already measured
/// answers its measurement; another pair beside a final measurement is kept
/// as conflicting. A measured check that contributed joins learning
/// (`followed`: whether the run followed the skill to success).
///
/// # Errors
///
/// Storage errors.
pub(super) fn admit_pair_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    skill: EntityId,
    pair: &ContributionPair,
    followed: bool,
    now: u64,
) -> Result<ContributionRecord> {
    let key = check_key(&pair.attempt_receipt, skill, &pair.axis);
    let mut admission = CHECK.get(&vault.store, txn, &key)?.unwrap_or_default();
    let reasons = if let Some(matched) = &admission.matched {
        if same_pair(&matched.pair, pair) {
            return Ok(ContributionRecord::Matched(matched.check.clone()));
        }
        vec![UnmatchedReason::Conflicting]
    } else {
        match proved_in_txn(vault, txn, skill, pair)? {
            Ok(check) => {
                let record = ContributionCheckRecord {
                    check,
                    pair: pair.clone(),
                };
                // A pair kept unmatched before its forks were proved is now
                // the measurement.
                admission
                    .unmatched
                    .retain(|kept| !same_pair(&kept.pair, pair));
                admission.matched = Some(record.clone());
                CHECK.put(&vault.store, txn, &key, &admission)?;
                if record.check.contributed {
                    join_credited_in_txn(vault, txn, &record, skill, followed, now)?;
                }
                return Ok(ContributionRecord::Matched(record.check));
            }
            Err(reasons) => reasons,
        }
    };
    // Each pair is kept once, with the reasons it was last recorded for.
    match admission
        .unmatched
        .iter_mut()
        .find(|kept| same_pair(&kept.pair, pair))
    {
        Some(kept) => kept.reasons.clone_from(&reasons),
        None => admission.unmatched.push(UnmatchedContribution {
            pair: pair.clone(),
            reasons: reasons.clone(),
        }),
    }
    CHECK.put(&vault.store, txn, &key, &admission)?;
    Ok(ContributionRecord::Unmatched { reasons })
}

/// The check `pair` measures for `skill` when the run's credited outcome
/// names it and its kept forks prove it, read in `txn`; else why not.
fn proved_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: EntityId,
    pair: &ContributionPair,
) -> Result<std::result::Result<ContributionCheck, Vec<UnmatchedReason>>> {
    let Some(candidate) = credited_candidate_in_txn(vault, txn, skill, pair)? else {
        return Ok(Err(vec![UnmatchedReason::NoCredit]));
    };
    Ok(
        match matched_contribution_facts_in_txn(
            vault,
            txn,
            &candidate,
            &pair.with_skill,
            &pair.without_skill,
        )? {
            Ok(facts) => Ok(ContributionCheck {
                receipt: check_receipt(pair, skill),
                contributed: contributed(facts.with_skill_passed, facts.without_skill_passed),
            }),
            Err(mismatches) => Err(mismatches.into_iter().map(UnmatchedReason::Forks).collect()),
        },
    )
}

/// The candidate the run's credited outcome makes of `pair`: its outcome,
/// axis, goal revision and anchor resolved from the stored credit, never
/// taken from the caller. `None` when no credit names them, or an erase
/// cleared its attribution.
fn credited_candidate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: EntityId,
    pair: &ContributionPair,
) -> Result<Option<ContributionCandidate>> {
    let key = receipt_id(&pair.attempt_receipt, &pair.outcome_receipt, &pair.axis);
    let Some(credit) = CREDIT_RECEIPT.get(&vault.store, txn, &key)? else {
        return Ok(None);
    };
    let Some(attribution) = credit.attribution else {
        return Ok(None);
    };
    if credit.goal_revision != pair.goal_revision || credit.anchor != pair.anchor {
        return Ok(None);
    }
    Ok(Some(ContributionCandidate {
        attempt_receipt: credit.attempt_receipt,
        outcome_receipt: credit.outcome_receipt,
        skill,
        axis: credit.axis,
        goal_revision: credit.goal_revision,
        anchor: credit.anchor,
        executor: attribution.executor,
        type_ref: attribution.type_ref,
    }))
}

/// Whether two submissions assert the same pair, whenever each was made.
fn same_pair(kept: &ContributionPair, submitted: &ContributionPair) -> bool {
    ContributionPair {
        at: submitted.at,
        ..kept.clone()
    } == *submitted
}

/// Keeps every contribution check of erased skill `entity` in erased form
/// (FIX 8988): each pair it recorded, measured or unmatched, names no skill,
/// and the row moves to a key that no longer spells the skill's id, so the
/// run's other checks stay apart. The measurement and both fork outcomes
/// stay. A row that no longer decodes is deleted and counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_contribution_checks_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let spelled = format!("\0{}\0", entity.to_hex());
    for (key, mut admission) in super::skill_erase::erase_scan_in_txn(vault, wtxn, CHECK)? {
        let pairs = admission
            .matched
            .iter_mut()
            .map(|record| &mut record.pair)
            .chain(admission.unmatched.iter_mut().map(|kept| &mut kept.pair));
        let mut named = key.contains(spelled.as_str());
        for pair in pairs {
            if pair.skill == Some(*entity) {
                pair.skill = None;
                named = true;
            }
        }
        if !named {
            continue;
        }
        let mut erased = blake3::Hasher::new_derive_key("oneiron contribution check erased v1");
        erased.update(key.as_bytes());
        let moved = key.replacen(
            spelled.as_str(),
            &format!("\0erased:{}\0", erased.finalize().to_hex()),
            1,
        );
        CHECK.delete(&vault.store, wtxn, &key)?;
        CHECK.put(&vault.store, wtxn, &moved, &admission)?;
    }
    Ok(())
}
