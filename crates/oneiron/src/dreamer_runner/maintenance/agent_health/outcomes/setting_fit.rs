//! Integer health-threshold checks derived from an owner's frozen card
//! label. The policy keeps the closest threshold consistent with that
//! label: retain an accepted dial, or move just above a dismissed count.
//! These are fitted targets, not independently observed optimal settings.

use super::{Effect, HealthReviewReceipt, review_effect};
use crate::dreamer_runner::maintenance::agent_health::{
    HEALTH_CHECK_FAILS, HEALTH_LOOP_REPEATS, HEALTH_WIDEN_DENIALS,
};
use crate::learning::{Anchor, LearningCell, LearningPredicate, TypeRef};
use crate::learning_setting::{
    SettingCheck, global_setting_subject, knob_bounds, record_setting_check_in_txn,
};
use crate::setting::Setting;
use crate::{Result, Vault};

pub(super) fn project_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    held: &HealthReviewReceipt,
    now: u64,
) -> Result<()> {
    let Some(knob) = threshold_spec(&held.reviewer) else {
        return Ok(());
    };
    let effect = review_effect(held.outcome, held.by_owner);
    if effect == Effect::Unscored {
        return Ok(());
    }
    let subject = global_setting_subject(knob.spec.name)?;
    let observed = match effect {
        Effect::Label(label) => target(knob, held.dial, held.measured, label),
        Effect::Withdraw | Effect::Unscored => None,
    };
    if let Some(observed) = observed {
        record_setting_check_in_txn(
            vault,
            txn,
            &SettingCheck {
                subject,
                project: None,
                key: knob.spec.name.to_owned(),
                type_ref: TypeRef::root(0),
                observed,
                receipt: held.receipt.clone(),
                at: held.at,
                anchor: Anchor::FittingCheck,
            },
            now,
        )?;
    } else {
        let cell = LearningCell::new(LearningPredicate::Setting, subject)
            .setting_key(knob.spec.name)
            .type_ref(TypeRef::root(0));
        crate::learning::evidence::withdraw_evidence_in_txn(vault, txn, &cell, &held.receipt, now)?;
    }
    Ok(())
}

/// Only families whose card carries the exact integer `count >= dial`
/// pair. Share and cost cards round away their native floating-point dials.
fn threshold_spec(reviewer: &str) -> Option<&'static Setting<f64>> {
    match reviewer {
        "coach.agent_health.loop.v1" => Some(&HEALTH_LOOP_REPEATS),
        "coach.agent_health.failed_check_repeat.v1" => Some(&HEALTH_CHECK_FAILS),
        "coach.agent_health.misalignment.v1" => Some(&HEALTH_WIDEN_DENIALS),
        _ => None,
    }
}

/// Minimizes the change to the frozen integer dial subject to reproducing
/// the owner's label on its count. A constant/non-knob dial (such as the
/// misalignment confession's zero), or an impossible target, fits nothing.
fn target(knob: &Setting<f64>, dial: i64, measured: i64, confirmed: bool) -> Option<f64> {
    if measured < dial || !knob_bounds(knob).contains(dial as f64) {
        return None;
    }
    let observed = if confirmed {
        dial
    } else {
        measured.checked_add(1)?
    } as f64;
    knob_bounds(knob).contains(observed).then_some(observed)
}
