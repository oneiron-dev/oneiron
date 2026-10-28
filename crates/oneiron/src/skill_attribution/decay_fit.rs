//! The `credit_decay` fit (FIX 2870, OF-542; ARCH-0037 #lineage-credit,
//! ARCH-0053). Canon has sampled contribution checks fit the lineage decay
//! from matched forks with and without the ancestor, and names no estimator.
//! This engine fits it by one policy, [`ANCESTOR_DECAY_FIT_POLICY`], a CALL
//! rather than canon: each matched check on one adjacent used edge of a
//! credited run is one observation, recorded as a `learning.setting` check
//! on the scope the shared resolver reads
//! ([`crate::learning_setting::setting_value_in_scope_in_txn`]): the run's
//! project when it names one, else the knob's vault-wide subject at the run's
//! task type. An owner's pin or seed over that scope wins over the fit, and
//! while no check is measured the decay stays as set.

use super::contribution::{ContributionCheckRecord, contributed};
use super::contribution_targets::ContributionTarget;
use super::late_credit::{CREDIT_RECEIPT, receipt_id};
use crate::learning_setting::{
    CREDIT_DECAY, SettingCheck, global_setting_subject, record_setting_check_in_txn,
};
use crate::{Result, Vault};

/// How a matched ancestor check observes `credit_decay`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecayFitPolicy {
    /// The binary positive marginal effect of one adjacent actually-used
    /// edge: a check on an edge whose derived end is a root of the run's
    /// credit (its output, or a skill that won it directly with a
    /// contributing check) observes `1.0` when the fork with the ancestor
    /// passed and the fork without it failed, else `0.0`, as one observation
    /// of unit weight. A check on any other edge observes nothing.
    AdjacentMarginal,
}

impl DecayFitPolicy {
    /// What one matched pair observes; `None` is no observation, never a
    /// zero.
    const fn observed(self, adjacent: bool, with_ancestor: bool, without: bool) -> Option<f64> {
        match self {
            Self::AdjacentMarginal if !adjacent => None,
            Self::AdjacentMarginal if contributed(with_ancestor, without) => Some(1.0),
            Self::AdjacentMarginal => Some(0.0),
        }
    }
}

/// The one policy `credit_decay` is fitted by (a CALL: canon names no
/// estimator, and no epsilon, sample floor or depth beyond one hop is
/// added).
const ANCESTOR_DECAY_FIT_POLICY: DecayFitPolicy = DecayFitPolicy::AdjacentMarginal;

/// Records `record`, a matched check just admitted in `wtxn`, as one
/// `credit_decay` observation when it is an ancestor check the policy
/// observes, under the check's own receipt, so a replay adds nothing.
/// Capture-only: an error drops the observation with a WARN and the check
/// stands.
pub(super) fn record_ancestor_decay_check_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &ContributionCheckRecord,
    now: u64,
) {
    let Some(ContributionTarget::UsedEdge { derived, .. }) = record.pair.target() else {
        return;
    };
    super::credit_join::capture_in_txn(&vault.store, wtxn, |txn| {
        observe_in_txn(vault, txn, record, derived, now)
    });
}

fn observe_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &ContributionCheckRecord,
    derived: crate::entity_id::EntityId,
    now: u64,
) -> Result<()> {
    let pair = &record.pair;
    let key = receipt_id(&pair.attempt_receipt, &pair.outcome_receipt, &pair.axis);
    let Some(credit) = CREDIT_RECEIPT.get(&vault.store, txn, &key)? else {
        return Ok(());
    };
    let Some(fields) = &credit.attribution else {
        return Ok(());
    };
    let adjacent = super::credit_join::credit_roots_in_txn(vault, txn, &credit)?.contains(&derived);
    let Some(observed) = ANCESTOR_DECAY_FIT_POLICY.observed(
        adjacent,
        pair.with_skill.passed,
        pair.without_skill.passed,
    ) else {
        return Ok(());
    };
    let subject = match fields.project {
        Some(project) => project,
        None => global_setting_subject(CREDIT_DECAY.key)?,
    };
    let check = SettingCheck {
        subject,
        key: CREDIT_DECAY.key.to_owned(),
        type_ref: fields.type_ref.clone(),
        observed,
        receipt: record.check.receipt.clone(),
        at: pair.at,
        anchor: pair.anchor,
    };
    record_setting_check_in_txn(vault, txn, &check, now)?;
    Ok(())
}
