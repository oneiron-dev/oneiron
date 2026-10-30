//! Contribution-check admission (FIX 3610, OF-542): every well-formed pair a
//! caller submits is recorded. It is measured only when the fork receipts
//! the engine kept for the run's credited outcome prove it, read in the
//! recording write ([`crate::code_run::matched_contribution_facts_in_txn`]);
//! otherwise it is recorded unmatched, with why, and teaches nothing. An
//! unmatched record is a record state, never a refusal: ARCH-0053 and
//! ARCH-0037 rule what may teach, not what may be recorded.

use serde::{Deserialize, Serialize};

use super::contribution::{
    CHECK, ContributionCandidate, ContributionCheckRecord, ContributionPair, contributed,
};
use super::contribution_targets::{ContributionTarget, Experiment};
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
    /// revision and anchor with a readable attribution; for a used edge's
    /// check, also one whose effective used chain holds the edge, scored by
    /// the run's pattern.
    NoCredit,
    /// The run's kept forks do not prove the pair.
    Forks(ForkMismatch),
    /// The run's outcome and target already hold the final measurement of
    /// another pair; this one is kept beside it.
    Conflicting,
    /// What would measure it could not be read or minted in this write (the
    /// credit's effective used chain, or the check's own id); the fault is
    /// logged, and the pair may be measured when it is submitted again.
    Unread,
}

/// One submitted pair the kept forks did not prove, with why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct UnmatchedContribution {
    pub(crate) pair: ContributionPair,
    pub(crate) reasons: Vec<UnmatchedReason>,
}

/// One experiment (the run, its outcome, goal revision and axis, and the
/// target), as recorded: the measurement of the pair the kept forks proved,
/// final once set, and each other pair submitted, once.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct ContributionAdmission {
    pub(crate) matched: Option<ContributionCheckRecord>,
    pub(crate) unmatched: Vec<UnmatchedContribution>,
}

/// Records `pair` on `target`, scored by its live `skill`, in `txn`:
/// measured when the run's kept forks prove it, else unmatched with why. A
/// pair already measured answers its measurement; another pair beside a
/// final measurement is kept as conflicting. A measured check, contributed
/// or not, fits `credit_decay` when it is an adjacent edge's
/// ([`super::decay_fit`]) and reconciles the run's credited outcomes
/// ([`super::credit_join`]); both are capture-only and never fail the
/// record.
///
/// # Errors
///
/// Storage errors.
pub(super) fn admit_pair_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    skill: EntityId,
    target: ContributionTarget,
    pair: &ContributionPair,
    now: u64,
) -> Result<ContributionRecord> {
    let experiment = Experiment::of_pair(pair, target);
    let key = experiment.check_key();
    let mut admission = CHECK.get(&vault.store, txn, &key)?.unwrap_or_default();
    let reasons = if let Some(matched) = &admission.matched {
        if same_pair(&matched.pair, pair) {
            return Ok(ContributionRecord::Matched(matched.check.clone()));
        }
        vec![UnmatchedReason::Conflicting]
    } else {
        match proved_in_txn(vault, txn, skill, &experiment, pair)? {
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
                super::decay_fit::record_ancestor_decay_check_in_txn(vault, txn, &record, now);
                super::credit_join::reconcile_credited_outcomes_in_txn(
                    vault,
                    txn,
                    &pair.attempt_receipt,
                    now,
                );
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

/// The check `pair` measures for `experiment` when the run's credited
/// outcome names it and its kept forks prove it, read in `txn`; else why
/// not.
fn proved_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: EntityId,
    experiment: &Experiment<'_>,
    pair: &ContributionPair,
) -> Result<std::result::Result<ContributionCheck, Vec<UnmatchedReason>>> {
    let candidate = match credited_candidate_in_txn(vault, txn, skill, experiment.target(), pair)? {
        Ok(candidate) => candidate,
        Err(reason) => return Ok(Err(vec![reason])),
    };
    let facts = match matched_contribution_facts_in_txn(
        vault,
        txn,
        &candidate,
        &pair.with_skill,
        &pair.without_skill,
    )? {
        Ok(facts) => facts,
        Err(mismatches) => {
            return Ok(Err(mismatches
                .into_iter()
                .map(UnmatchedReason::Forks)
                .collect()));
        }
    };
    // A fresh opaque id, kept with the measurement: no id the check names
    // derives it, so none confirms it once erased.
    let id = match vault.store.clock.ulid() {
        Ok(id) => id,
        Err(error) => {
            unread(&error);
            return Ok(Err(vec![UnmatchedReason::Unread]));
        }
    };
    Ok(Ok(ContributionCheck {
        receipt: format!("contribution:{}", crate::entity_id::bytes_to_hex_lower(&id)),
        contributed: contributed(facts.with_skill_passed, facts.without_skill_passed),
    }))
}

fn unread(error: &crate::Error) {
    tracing::warn!(
        kind = ?error.kind(),
        %error,
        "a contribution pair could not be measured in this write; it is kept unmatched"
    );
}

/// The candidate the run's credited outcome makes of `pair`: its outcome,
/// axis, goal revision and anchor resolved from the stored credit, never
/// taken from the caller. [`UnmatchedReason::NoCredit`] when no credit names
/// them, or an erase cleared its attribution; for a used edge, also when the
/// credit's effective used chain does not hold the edge or `skill` is not
/// the run's pattern, and [`UnmatchedReason::Unread`] when that chain could
/// not be read.
fn credited_candidate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: EntityId,
    target: ContributionTarget,
    pair: &ContributionPair,
) -> Result<std::result::Result<ContributionCandidate, UnmatchedReason>> {
    let key = receipt_id(&pair.attempt_receipt, &pair.outcome_receipt, &pair.axis);
    let Some(credit) = CREDIT_RECEIPT.get(&vault.store, txn, &key)? else {
        return Ok(Err(UnmatchedReason::NoCredit));
    };
    let Some(attribution) = credit.attribution.clone() else {
        return Ok(Err(UnmatchedReason::NoCredit));
    };
    if credit.goal_revision != pair.goal_revision || credit.anchor != pair.anchor {
        return Ok(Err(UnmatchedReason::NoCredit));
    }
    if let ContributionTarget::UsedEdge { derived, source } = target {
        let fields = match super::credit_join::effective_fields_in_txn(
            vault,
            txn,
            &credit,
            attribution.clone(),
        ) {
            Ok(fields) => fields,
            Err(error) => {
                unread(&error);
                return Ok(Err(UnmatchedReason::Unread));
            }
        };
        if skill != attribution.pattern
            || !fields
                .used_edges
                .iter()
                .any(|edge| edge.derived == derived && edge.source == source)
        {
            return Ok(Err(UnmatchedReason::NoCredit));
        }
    }
    Ok(Ok(ContributionCandidate {
        attempt_receipt: credit.attempt_receipt,
        outcome_receipt: credit.outcome_receipt,
        skill,
        target,
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

/// Keeps every contribution check naming erased `entity` in erased form
/// (FIX 8988): each pair it recorded, measured or unmatched, names no such
/// skill or edge end, and the row moves to its run's prefix and a fresh
/// opaque ULID in place of the target and the identity digest, which a known
/// id would confirm, so the run's other checks stay apart. A pair whose run
/// or outcome reference spells the id has those references rewritten to
/// opaque erased ids, and where the run itself spells it the row moves to a
/// fully opaque key (FIX 11359, CB2-B). The measurement and both fork
/// outcomes stay. A row that no longer decodes is deleted and counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_contribution_checks_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let spelled = entity.to_hex();
    let spelled_lower = spelled.to_ascii_lowercase();
    for (key, mut admission) in super::skill_erase::erase_scan_in_txn(vault, wtxn, CHECK)? {
        let (run, target) = key
            .split_once('\0')
            .map_or((key.as_str(), ""), |(run, rest)| {
                (
                    run,
                    rest.split_once('\0').map_or(rest, |(target, _)| target),
                )
            });
        let mut named =
            target.contains(spelled.as_str()) || run.to_ascii_lowercase().contains(&spelled_lower);
        for pair in admission
            .matched
            .iter_mut()
            .map(|record| &mut record.pair)
            .chain(admission.unmatched.iter_mut().map(|kept| &mut kept.pair))
        {
            if pair
                .attempt_receipt
                .to_ascii_lowercase()
                .contains(&spelled_lower)
                || pair
                    .outcome_receipt
                    .to_ascii_lowercase()
                    .contains(&spelled_lower)
            {
                named = true;
            }
            let mut ends = vec![&mut pair.skill];
            if let Some(edge) = &mut pair.edge {
                ends.extend([&mut edge.derived, &mut edge.source]);
            }
            for end in ends {
                if *end == Some(*entity) {
                    *end = None;
                    named = true;
                }
            }
        }
        if !named {
            continue;
        }
        let fresh = crate::entity_id::bytes_to_hex_lower(&vault.store.clock.ulid()?);
        let erased_ref = format!("erased:{fresh}");
        for pair in admission
            .matched
            .iter_mut()
            .map(|record| &mut record.pair)
            .chain(admission.unmatched.iter_mut().map(|kept| &mut kept.pair))
        {
            if pair
                .attempt_receipt
                .to_ascii_lowercase()
                .contains(&spelled_lower)
            {
                pair.attempt_receipt.clone_from(&erased_ref);
            }
            if pair
                .outcome_receipt
                .to_ascii_lowercase()
                .contains(&spelled_lower)
            {
                pair.outcome_receipt.clone_from(&erased_ref);
            }
        }
        let moved = if run.to_ascii_lowercase().contains(&spelled_lower) {
            format!("erased\0{fresh}")
        } else {
            format!("{run}\0erased:{fresh}")
        };
        CHECK.delete(&vault.store, wtxn, &key)?;
        CHECK.put(&vault.store, wtxn, &moved, &admission)?;
    }
    Ok(())
}
