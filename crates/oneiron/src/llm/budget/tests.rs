use super::*;
use crate::llm::{LlmInputUsage, LlmOutputUsage};
use serde_json::Value as JsonValue;

#[test]
fn admission_reserves_lease_and_exhaustion_denies_new_leases() {
    let guard = BudgetGuard::with_reserve_units("job", 10, 4, BudgetExhaustionPolicy::Suspend);

    let first = guard.admit().expect("first lease");
    assert_eq!(first.lease.id(), "job:metered:1");
    assert_eq!(first.read.reserved_units, 4);
    assert_eq!(first.read.remaining_units, 6);

    let second = guard.admit().expect("second lease");
    assert_eq!(second.lease.id(), "job:metered:2");
    assert_eq!(second.read.reserved_units, 8);
    assert_eq!(second.read.remaining_units, 2);

    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
}

#[test]
fn terminal_settlement_uses_absolute_counters_without_double_counting_retry() {
    let guard = BudgetGuard::with_reserve_units("job", 100, 20, BudgetExhaustionPolicy::Suspend);
    let first = guard.admit().expect("lease");

    let settlement = guard
        .settle_absolute(&first.lease, 30)
        .expect("terminal settlement");
    assert_eq!(settlement.read.used_units, 30);
    assert_eq!(settlement.read.reserved_units, 0);
    assert_eq!(settlement.read.remaining_units, 70);

    let duplicate = guard
        .settle_absolute(&first.lease, 60)
        .expect("duplicate terminal settlement is idempotent");
    assert_eq!(duplicate.read.used_units, 30);

    let retry = guard.admit().expect("retry lease");
    let retried = guard
        .settle_absolute(&retry.lease, 30)
        .expect("retry reports same absolute total");
    assert_eq!(retried.read.used_units, 30);
}

#[test]
fn admitted_call_is_not_killed_when_terminal_usage_overshoots() {
    let guard = BudgetGuard::with_reserve_units("job", 10, 8, BudgetExhaustionPolicy::Suspend);
    let admission = guard.admit().expect("lease before cap");

    let settlement = guard
        .settle_absolute(&admission.lease, 14)
        .expect("admitted call settles even after cap");
    assert_eq!(settlement.read.used_units, 14);
    assert_eq!(settlement.read.remaining_units, 0);
    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
}

#[test]
fn abort_refunds_reserved_units_without_spend() {
    let guard = BudgetGuard::with_reserve_units("job", 10, 8, BudgetExhaustionPolicy::Suspend);
    let admission = guard.admit().expect("lease");

    let aborted = guard.abort(&admission.lease).expect("abort");
    assert_eq!(aborted.read.used_units, 0);
    assert_eq!(aborted.read.reserved_units, 0);
    assert_eq!(aborted.read.remaining_units, 10);
    assert!(matches!(
        guard.settle_absolute(&admission.lease, 8),
        Err(BudgetDenied::LeaseInvalid)
    ));
}

#[test]
fn ladder_events_fire_once_and_use_only_steering_queue_delivery() {
    let guard = BudgetGuard::with_reserve_units("job", 100, 50, BudgetExhaustionPolicy::Suspend);

    let fifty = guard.admit().expect("50 percent");
    assert_eq!(fifty.ladder_events.len(), 1);
    assert_eq!(fifty.ladder_events[0].threshold, BudgetThreshold::Silent50);
    assert!(fifty.ladder_events[0].steering.is_none());

    let lease = guard.admit().expect("100 percent projected");
    let thresholds: Vec<_> = lease
        .ladder_events
        .iter()
        .map(|event| event.threshold)
        .collect();
    assert_eq!(
        thresholds,
        vec![BudgetThreshold::Plan80, BudgetThreshold::Land95]
    );
    for event in &lease.ladder_events {
        let steering = event.steering.as_ref().expect("80/95 steering signal");
        assert_eq!(
            steering.channel,
            BudgetSignalDeliveryChannel::SteeringQueueNextTurn
        );
    }

    let duplicate = guard
        .settle_absolute(&lease.lease, 100)
        .expect("settlement after thresholds");
    assert!(duplicate.ladder_events.is_empty());
}

#[test]
fn overdraft_policy_extends_admission_cap() {
    let suspend =
        BudgetGuard::with_reserve_units("suspend", 10, 11, BudgetExhaustionPolicy::Suspend);
    assert!(matches!(suspend.admit(), Err(BudgetDenied::Exhausted)));

    let overdraft = BudgetGuard::with_reserve_units(
        "overdraft",
        10,
        11,
        BudgetExhaustionPolicy::Overdraft { cap: 2 },
    );
    let admission = overdraft.admit().expect("overdraft cap admits");
    assert_eq!(admission.read.cap_units, 12);
    assert_eq!(admission.read.remaining_units, 1);
}

#[test]
fn continue_on_local_requires_explicit_unmetered_lease_after_exhaustion() {
    let guard =
        BudgetGuard::with_reserve_units("job", 10, 10, BudgetExhaustionPolicy::ContinueOnLocal);
    assert!(matches!(
        guard.admit_local(),
        Err(BudgetDenied::AdmissionDenied)
    ));

    let metered = guard.admit().expect("metered lease reaches cap");
    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));

    let local = guard.admit_local().expect("explicit local continuation");
    assert_eq!(local.lease.id(), "job:local:2");
    let settled = guard
        .settle_absolute(&local.lease, 99)
        .expect("local lease settles without paid spend");
    assert_eq!(settled.read.used_units, 0);
    assert_eq!(settled.read.reserved_units, 10);

    guard
        .settle_absolute(&metered.lease, 10)
        .expect("metered settlement");
    let after_metered = guard.read();
    assert_eq!(after_metered.used_units, 10);
    assert_eq!(after_metered.reserved_units, 0);
    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
}

#[test]
fn self_budget_read_reports_current_meter() {
    let guard =
        BudgetGuard::with_reserve_units("job", 100, 20, BudgetExhaustionPolicy::ContinueOnLocal);
    let admission = guard.admit().expect("lease");
    let usage = LlmUsage {
        input: LlmInputUsage {
            total: 12,
            cache_read: 2,
            cache_write: 1,
        },
        output: LlmOutputUsage {
            total: 8,
            text: 5,
            reasoning: 3,
        },
        raw_provider: JsonValue::Null,
    };
    guard
        .settle_terminal(&admission.lease, &usage)
        .expect("terminal settlement");

    let read = guard.self_budget();
    assert_eq!(read.job_id, "job");
    assert_eq!(read.used_units, 20);
    assert_eq!(read.reserved_units, 0);
    assert_eq!(read.remaining_units, 80);
    assert_eq!(
        read.on_budget_exhausted,
        BudgetExhaustionPolicy::ContinueOnLocal
    );
}

#[test]
fn prompt_templates_ship_as_data() {
    let ids: Vec<_> = BUDGET_PROMPT_TEMPLATES
        .iter()
        .map(|template| template.id)
        .collect();
    assert_eq!(
        ids,
        vec![
            BUDGET_PLAN_PROMPT_TEMPLATE_ID,
            BUDGET_LAND_PROMPT_TEMPLATE_ID,
            BUDGET_OWNER_DIGEST_PROMPT_TEMPLATE_ID,
            BUDGET_RESUME_PREAMBLE_PROMPT_TEMPLATE_ID,
        ]
    );
    assert!(BUDGET_LAND_PROMPT_TEMPLATE.contains("incomplete-but-honest"));
}
