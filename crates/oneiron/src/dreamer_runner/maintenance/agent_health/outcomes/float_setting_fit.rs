//! Exact-float dial fits for `long_wait`, `cost_spike` and `silent` (FIX 8076):
//! an owner's verdict on a card whose finding froze the raw `(D, m)` pair
//! becomes one vault-wide `learning.setting` fitting check, or withdraws it.
//! Only these three reviewers fit here; every other reviewer is inert.
//! Disjoint knob keys from the integer fits, so both projections survive side
//! by side.

use super::super::{
    AgentHealthOutcome, HEALTH_COST_SPIKE, HEALTH_SILENT_MINUTES, HEALTH_WAIT_SHARE,
};
use super::HealthReviewReceipt;
use crate::learning::{Anchor, LearningCell, LearningPredicate, TypeRef};
use crate::learning_setting::{SettingCheck, SettingSpec, global_setting_subject};
use crate::{Result, Vault};

/// The float policy: the exact reviewer to its knob, and the fitted target.
/// `Some((spec, Some(target)))` records a fitting check; `Some((spec, None))`
/// withdraws the state's row; `None` is inert. For `long_wait` and
/// `cost_spike`, confirmed keeps `D` and dismissed fits `m`, which suppresses
/// under strict `>` exactly: no epsilon, no `+1`, no clamp, no reconstruction
/// from rounded fields. For `silent`, confirmed keeps the frozen actual `D`
/// minutes and dismissed fits the smallest next effective integer-second
/// threshold, canonically encoded back to minutes and validated through the
/// same native `round(T * 60)`. An owner verdict with no feasible target
/// withdraws any earlier fit of this same review state.
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
        "coach.agent_health.silent.v1" => &HEALTH_SILENT_MINUTES,
        _ => return None,
    };
    match outcome {
        AgentHealthOutcome::Open | AgentHealthOutcome::Unresolved => Some((spec, None)),
        AgentHealthOutcome::Confirmed | AgentHealthOutcome::Dismissed => {
            if spec.key == HEALTH_SILENT_MINUTES.key {
                return silent_setting_target(spec, outcome, exact_dial, exact_measured);
            }
            let (dial, measured) = match (exact_dial, exact_measured) {
                (Some(dial), Some(measured)) => (dial, measured),
                _ => return Some((spec, None)),
            };
            if !dial.is_finite() || !measured.is_finite() {
                return Some((spec, None));
            }
            if dial < spec.min || dial > spec.max {
                return Some((spec, None));
            }
            if measured <= dial {
                return Some((spec, None));
            }
            let target = match outcome {
                AgentHealthOutcome::Confirmed => dial,
                AgentHealthOutcome::Dismissed => measured,
                AgentHealthOutcome::Open | AgentHealthOutcome::Unresolved => {
                    return Some((spec, None));
                }
            };
            if !target.is_finite() || target < spec.min || target > spec.max {
                return Some((spec, None));
            }
            Some((spec, Some(target)))
        }
    }
}

/// The `silent` policy: the smallest next effective integer-second threshold,
/// canonically encoded back to minutes. The native predicate is inclusive
/// integer seconds (`quiet >= round(D * 60)`), so confirmed keeps the frozen
/// actual `D` minutes and dismissed fits `T = (quiet + 1) / 60`. Minimality is
/// over the integer-second grid only, never over continuous `f64` minutes.
/// Required: finite catalog-bounded `D` and `T`, exact nonnegative integral
/// `quiet`, the actual inclusive trigger, and the same native
/// `round(T * 60) > quiet` before recording a dismissal. Anything infeasible
/// withdraws the state's row; no clamp, no fake success.
fn silent_setting_target(
    spec: &'static SettingSpec,
    outcome: AgentHealthOutcome,
    exact_dial: Option<f64>,
    exact_measured: Option<f64>,
) -> Option<(&'static SettingSpec, Option<f64>)> {
    let (dial, measured) = match (exact_dial, exact_measured) {
        (Some(dial), Some(measured)) => (dial, measured),
        _ => return Some((spec, None)),
    };
    if !dial.is_finite() || !measured.is_finite() {
        return Some((spec, None));
    }
    if dial < spec.min || dial > spec.max {
        return Some((spec, None));
    }
    // The frozen quiet seconds stay within the producer's exact-integer range.
    if measured < 0.0 || measured.fract() != 0.0 || measured > (1u64 << f64::MANTISSA_DIGITS) as f64
    {
        return Some((spec, None));
    }
    let quiet = measured as u64;
    // The actual inclusive trigger, through the same native adaptation.
    if quiet < (dial * 60.0).round() as u64 {
        return Some((spec, None));
    }
    let target = match outcome {
        AgentHealthOutcome::Confirmed => dial,
        AgentHealthOutcome::Dismissed => (measured + 1.0) / 60.0,
        AgentHealthOutcome::Open | AgentHealthOutcome::Unresolved => return Some((spec, None)),
    };
    if !target.is_finite() || target < spec.min || target > spec.max {
        return Some((spec, None));
    }
    // A dismissal must suppress through the same native conversion: when
    // rounding leaves the integer-second grid unmoved, withdraw instead.
    if matches!(outcome, AgentHealthOutcome::Dismissed) && (target * 60.0).round() as u64 <= quiet {
        return Some((spec, None));
    }
    Some((spec, Some(target)))
}

/// Projects one owner receipt's float-dial effect in `txn`: a fitting check
/// on the knob's vault-wide cell, or a withdrawal of that cell's row for the
/// held receipt. `silent` fits minutes from frozen quiet seconds; its
/// dismissed target is minimal over the native integer-second grid. Runs
/// inside the settlement's savepoint; storage errors propagate to the
/// existing retry. A vault-wide subject that is not ready passes over through
/// the existing door.
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
