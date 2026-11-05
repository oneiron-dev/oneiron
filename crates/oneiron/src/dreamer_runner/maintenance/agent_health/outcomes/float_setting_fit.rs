//! Exact-float dial fits for `long_wait` and `cost_spike` (FIX 8076): an owner's
//! verdict on a card whose finding froze the raw `(D, m)` pair becomes one
//! vault-wide `learning.setting` fitting check, or withdraws it. Only these
//! two reviewers fit here; every other reviewer is inert. Disjoint knob keys
//! from the integer fits, so both projections survive side by side.

use super::super::{AgentHealthOutcome, HEALTH_COST_SPIKE, HEALTH_WAIT_SHARE};
use super::HealthReviewReceipt;
use crate::learning::{Anchor, LearningCell, LearningPredicate, TypeRef};
use crate::learning_setting::{SettingCheck, SettingSpec, global_setting_subject};
use crate::{Result, Vault};

/// The float policy: the exact reviewer to its knob, and the fitted target.
/// `Some((spec, Some(target)))` records a fitting check; `Some((spec, None))`
/// withdraws the state's row; `None` is inert. Confirmed keeps `D`;
/// dismissed fits `m`, which suppresses under strict `>` exactly. Finite raw
/// pair, catalog-bounded `D`, witnessed `m > D`, and a finite catalog-bounded
/// target are required; no epsilon, no `+1`, no clamp, no reconstruction
/// from rounded fields.
fn float_setting_target(
    reviewer: &str,
    outcome: AgentHealthOutcome,
    by_owner: bool,
    exact_dial: Option<f64>,
    exact_measured: Option<f64>,
) -> Option<(&'static SettingSpec, Option<f64>)> {
    if !by_owner {
        return None;
    }
    let spec = match reviewer {
        "coach.agent_health.long_wait.v1" => &HEALTH_WAIT_SHARE,
        "coach.agent_health.cost_spike.v1" => &HEALTH_COST_SPIKE,
        _ => return None,
    };
    match outcome {
        AgentHealthOutcome::Open | AgentHealthOutcome::Unresolved => Some((spec, None)),
        AgentHealthOutcome::Confirmed | AgentHealthOutcome::Dismissed => {
            let (dial, measured) = match (exact_dial, exact_measured) {
                (Some(dial), Some(measured)) => (dial, measured),
                _ => return None,
            };
            if !dial.is_finite() || !measured.is_finite() {
                return None;
            }
            if dial < spec.min || dial > spec.max {
                return None;
            }
            if measured <= dial {
                return None;
            }
            let target = match outcome {
                AgentHealthOutcome::Confirmed => dial,
                AgentHealthOutcome::Dismissed => measured,
                AgentHealthOutcome::Open | AgentHealthOutcome::Unresolved => return None,
            };
            if !target.is_finite() || target < spec.min || target > spec.max {
                return None;
            }
            Some((spec, Some(target)))
        }
    }
}

/// Projects one owner receipt's float-dial effect in `txn`: a fitting check
/// on the knob's vault-wide cell, or a withdrawal of that cell's row for the
/// held receipt. Runs inside the settlement's savepoint; storage errors
/// propagate to the existing retry. A vault-wide subject that is not ready
/// passes over through the existing door.
pub(super) fn project_float_setting_fit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    held: &HealthReviewReceipt,
    now: u64,
) -> Result<()> {
    let Some((spec, target)) = float_setting_target(
        &held.reviewer,
        held.outcome,
        held.by_owner,
        held.exact_dial,
        held.exact_measured,
    ) else {
        return Ok(());
    };
    let subject = global_setting_subject(spec.key)?;
    match target {
        Some(observed) => {
            let check = SettingCheck {
                subject,
                project: None,
                key: spec.key.to_owned(),
                type_ref: TypeRef::root(0),
                observed,
                receipt: held.receipt.clone(),
                at: held.at,
                anchor: Anchor::FittingCheck,
            };
            let _ = crate::learning_setting::record_setting_check_in_txn(vault, txn, &check, now)?;
            Ok(())
        }
        None => {
            let cell = LearningCell::new(LearningPredicate::Setting, subject)
                .setting_key(spec.key)
                .type_ref(TypeRef::root(0))
                .project(None);
            let _ = crate::learning::evidence::withdraw_evidence_in_txn(
                vault,
                txn,
                &cell,
                &held.receipt,
                now,
            )?;
            Ok(())
        }
    }
}
