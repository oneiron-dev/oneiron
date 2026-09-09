use super::*;

mod request_usage;
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, LlmInputUsage, LlmMessage, LlmMessageRole,
    LlmOutputUsage, ModelId, ModelTierRef, ResponseFormat, TierPrecedence,
};
use serde_json::Value as JsonValue;
use std::sync::{Arc, Barrier};
use std::thread;

mod per_call;

fn on_device_request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("test/model@r1").expect("model id"),
        envelope: CallEnvelope {
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence {
                per_call: None,
                vault_policy: None,
                purpose_default: None,
                global_default: ModelTierRef("default".to_owned()),
            },
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: Vec::new(),
        }],
        tools: Vec::new(),
        params: std::collections::BTreeMap::new(),
        provider_options: std::collections::BTreeMap::new(),
    }
}

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
fn concurrent_reservations_are_arithmetic_deterministic() {
    const LIMIT_UNITS: u64 = 1_000;
    const RESERVE_UNITS: u64 = 37;
    const THREADS: usize = 64;

    let guard = Arc::new(BudgetGuard::with_reserve_units(
        "job",
        LIMIT_UNITS,
        RESERVE_UNITS,
        BudgetExhaustionPolicy::Suspend,
    ));
    let start = Arc::new(Barrier::new(THREADS));
    // Eager collect is load-bearing: every thread must spawn before any
    // join, or the Barrier::new(THREADS) rendezvous deadlocks.
    #[expect(clippy::needless_collect)]
    let handles = (0..THREADS)
        .map(|_| {
            let guard = Arc::clone(&guard);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                guard.admit()
            })
        })
        .collect::<Vec<_>>();

    let admissions = handles
        .into_iter()
        .map(|handle| handle.join().expect("admission thread"))
        .collect::<Vec<_>>();
    let admitted = admissions
        .iter()
        .filter(|admission| admission.is_ok())
        .count() as u64;
    let expected = LIMIT_UNITS / RESERVE_UNITS;
    assert_eq!(admitted, expected);

    let read = guard.read();
    assert_eq!(read.reserved_units, admitted * RESERVE_UNITS);
    assert!(read.reserved_units <= read.cap_units);
}

#[test]
fn on_device_continuation_racing_abort_never_gets_transiently_denied() {
    for _ in 0..128 {
        let guard = Arc::new(BudgetGuard::with_reserve_units(
            "job",
            10,
            10,
            BudgetExhaustionPolicy::ContinueOnLocal,
        ));
        let metered = guard.admit().expect("initial lease");
        let request = Arc::new(on_device_request());
        let start = Arc::new(Barrier::new(2));

        let local_guard = Arc::clone(&guard);
        let local_request = Arc::clone(&request);
        let local_start = Arc::clone(&start);
        let local = thread::spawn(move || {
            local_start.wait();
            local_guard.admit_for_request(&local_request)
        });

        let abort_guard = Arc::clone(&guard);
        let abort_start = Arc::clone(&start);
        let lease = metered.lease.clone();
        let abort = thread::spawn(move || {
            abort_start.wait();
            abort_guard.abort(&lease)
        });

        let admission = local.join().expect("local admission thread");
        abort.join().expect("abort thread").expect("abort lease");
        assert!(
            admission.is_ok(),
            "local continuation was denied despite either free capacity or local policy: {admission:?}"
        );
    }
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
    assert_eq!(read.attempt_id, "job");
    assert_eq!(read.used_units, 20);
    assert_eq!(read.reserved_units, 0);
    assert_eq!(read.remaining_units, 80);
    assert_eq!(
        read.on_budget_exhausted,
        BudgetExhaustionPolicy::ContinueOnLocal
    );
}

// ---------------------------------------------------------------------------
// ONE-1348 `budget_policy` row-accounting tests.
//
// Fixed tiny units against the policy-aware constructor. The existing
// single-pool tests above stay untouched; the two regression tests below
// prove the empty/absent table is byte-for-byte the legacy meter.
// ---------------------------------------------------------------------------

fn policy_test_actor(seed: u8) -> WriteActor {
    WriteActor::new(
        EntityId::from_bytes([seed; 16]).expect("test actor id"),
        crate::edge::EdgeActorClass::Agent,
    )
}

fn purpose_row(purpose: CallPurpose, floor: Option<u64>, cap: Option<u64>) -> BudgetPolicyRow {
    BudgetPolicyRow::new(BudgetPolicySelector::Purpose(purpose), floor, cap)
}

fn actor_row(seed: u8, floor: Option<u64>, cap: Option<u64>) -> BudgetPolicyRow {
    BudgetPolicyRow::new(
        BudgetPolicySelector::Actor(EntityId::from_bytes([seed; 16]).expect("test actor id")),
        floor,
        cap,
    )
}

fn request_for(purpose: CallPurpose, locality: ModelLocality) -> LlmRequest {
    LlmRequest {
        model: ModelId::new("test/model@r1").expect("model id"),
        envelope: CallEnvelope {
            purpose,
            class: CallClass::BestEffort,
            tier: TierPrecedence {
                per_call: None,
                vault_policy: None,
                purpose_default: None,
                global_default: ModelTierRef("default".to_owned()),
            },
            response_format: ResponseFormat::Text,
            locality,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: Vec::new(),
        }],
        tools: Vec::new(),
        params: std::collections::BTreeMap::new(),
        provider_options: std::collections::BTreeMap::new(),
    }
}

/// Full internal bookkeeping snapshot: row tallies travel as
/// `(used, reserved, floor_used, floor_reserved)` in resolved row order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MeterSnapshot {
    used_units: u64,
    reserved_units: u64,
    shared_used_units: u64,
    shared_reserved_units: u64,
    rows: Vec<(u64, u64, u64, u64)>,
    open_leases: usize,
    total_leases: usize,
}

fn meter_snapshot(guard: &BudgetGuard) -> MeterSnapshot {
    let state = guard.state.lock().expect("meter snapshot");
    MeterSnapshot {
        used_units: state.used_units,
        reserved_units: state.reserved_units,
        shared_used_units: state.shared_used_units,
        shared_reserved_units: state.shared_reserved_units,
        rows: state
            .row_tallies
            .iter()
            .map(|tally| {
                (
                    tally.used_units,
                    tally.reserved_units,
                    tally.floor_used_units,
                    tally.floor_reserved_units,
                )
            })
            .collect(),
        open_leases: state
            .leases
            .values()
            .filter(|record| matches!(record.state, LeaseState::Open))
            .count(),
        total_leases: state.leases.len(),
    }
}

#[test]
fn budget_policy_empty_table_is_exact_single_pool_regression() {
    for policy in [
        BudgetExhaustionPolicy::Suspend,
        BudgetExhaustionPolicy::Overdraft { cap: 10 },
    ] {
        let legacy = BudgetGuard::with_reserve_units("job", 100, 40, policy);
        let policy_aware = BudgetGuard::with_policy_table(
            "job",
            100,
            40,
            policy,
            policy_test_actor(0x40),
            &BudgetPolicyTable::default(),
        );
        let mut identities = Vec::new();
        for guard in [&legacy, &policy_aware] {
            let first = guard.admit().expect("first admission");
            assert_eq!(first.read.used_units, 0);
            assert_eq!(first.read.reserved_units, 40);
            assert!(first.ladder_events.is_empty());

            let second = guard.admit().expect("second admission");
            assert_eq!(second.read.used_units, 0);
            assert_eq!(second.read.reserved_units, 80);
            assert_eq!(second.ladder_events.len(), 2);
            for (event, threshold) in second
                .ladder_events
                .iter()
                .zip([BudgetThreshold::Silent50, BudgetThreshold::Plan80])
            {
                assert_eq!(event.threshold, threshold);
                assert_eq!(event.row_index, None);
                match threshold {
                    BudgetThreshold::Silent50 => assert!(event.steering.is_none()),
                    BudgetThreshold::Plan80 => {
                        let signal = event.steering.as_ref().expect("plan steering");
                        assert_eq!(signal.threshold, BudgetThreshold::Plan80);
                        assert!(matches!(
                            signal.channel,
                            BudgetSignalDeliveryChannel::SteeringQueueNextTurn
                        ));
                        assert_eq!(signal.template_id, BUDGET_PLAN_PROMPT_TEMPLATE_ID);
                    }
                    BudgetThreshold::Land95 => unreachable!(),
                }
            }

            let settled = guard
                .settle_absolute(&first.lease, 50)
                .expect("settle first");
            assert_eq!(settled.read.used_units, 50);
            assert_eq!(settled.read.reserved_units, 40);
            assert!(settled.ladder_events.is_empty());
            let aborted = guard.abort(&second.lease).expect("abort second");
            assert_eq!(aborted.read.used_units, 50);
            assert_eq!(aborted.read.reserved_units, 0);
            assert!(aborted.ladder_events.is_empty());

            let third = guard.admit().expect("third admission");
            assert_eq!(third.read.used_units, 50);
            assert_eq!(third.read.reserved_units, 40);
            assert!(third.ladder_events.is_empty());
            let settled = guard
                .settle_absolute(&third.lease, 96)
                .expect("settle third");
            assert_eq!(settled.read.used_units, 96);
            assert_eq!(settled.read.reserved_units, 0);
            assert_eq!(settled.ladder_events.len(), 1);
            let event = &settled.ladder_events[0];
            assert_eq!(event.threshold, BudgetThreshold::Land95);
            assert_eq!(event.row_index, None);
            let signal = event.steering.as_ref().expect("land steering");
            assert_eq!(signal.threshold, BudgetThreshold::Land95);
            assert!(matches!(
                signal.channel,
                BudgetSignalDeliveryChannel::SteeringQueueNextTurn
            ));
            assert_eq!(signal.template_id, BUDGET_LAND_PROMPT_TEMPLATE_ID);

            assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
            let read = guard.read();
            assert_eq!(read.attempt_id, "job");
            assert_eq!(read.limit_units, 100);
            assert_eq!(read.cap_units, policy.admission_cap(100));
            assert_eq!(read.used_units, 96);
            assert_eq!(read.reserved_units, 0);
            assert_eq!(read.remaining_units, read.cap_units - 96);
            assert_eq!(read.on_budget_exhausted, policy);
            assert_eq!(
                read.fired_thresholds,
                vec![
                    BudgetThreshold::Silent50,
                    BudgetThreshold::Plan80,
                    BudgetThreshold::Land95,
                ],
            );
            assert_ne!(first.lease.id, second.lease.id);
            assert_ne!(second.lease.id, third.lease.id);
            assert_ne!(first.lease.id, third.lease.id);
            identities.push([first.lease.id, second.lease.id, third.lease.id]);
        }
        assert_eq!(identities[0], identities[1]);
    }
}

#[test]
fn budget_policy_floor_is_reserved_for_matching_purpose() {
    // T = 100, Consolidation floor 30, reserve 10: shared slice is 70.
    let table = BudgetPolicyTable::from_rows(vec![purpose_row(
        CallPurpose::Consolidation,
        Some(30),
        None,
    )]);
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x41),
        &table,
    );

    for _ in 0..7 {
        guard.admit().expect("shared-slice admission");
    }
    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 70);

    for _ in 0..3 {
        guard
            .admit_for_request(&request_for(
                CallPurpose::Consolidation,
                ModelLocality::ThirdParty,
            ))
            .expect("floor-backed consolidation admission");
    }
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        )),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 100);
}

#[test]
fn budget_policy_actor_floor_uses_engine_stamped_actor() {
    let table = BudgetPolicyTable::from_rows(vec![actor_row(0x50, Some(30), None)]);
    let matching = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x50),
        &table,
    );
    let other = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x51),
        &table,
    );

    for _ in 0..7 {
        other.admit().expect("other-actor shared admission");
    }
    assert!(matches!(other.admit(), Err(BudgetDenied::Exhausted)));
    assert_eq!(other.read().used_units, 0);
    assert_eq!(other.read().reserved_units, 70);

    let mut spoofed = request_for(CallPurpose::Voice, ModelLocality::ThirdParty);
    let owner_ref = EntityId::from_bytes([0x50; 16])
        .expect("owner actor id")
        .to_hex();
    spoofed
        .params
        .insert("actor".to_owned(), JsonValue::from(owner_ref.clone()));
    spoofed
        .provider_options
        .insert("actor_entity".to_owned(), JsonValue::from(owner_ref));
    assert!(matches!(
        other.admit_for_request(&spoofed),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!(other.read().used_units, 0);
    assert_eq!(other.read().reserved_units, 70);
    assert_eq!(other.read().remaining_units, 30);
    assert!(matches!(other.admit(), Err(BudgetDenied::Exhausted)));

    for _ in 0..10 {
        matching.admit().expect("matching-actor admission");
    }
    assert!(matches!(matching.admit(), Err(BudgetDenied::Exhausted)));
    assert_eq!(matching.read().used_units, 0);
    assert_eq!(matching.read().reserved_units, 100);
    assert_eq!(matching.read().remaining_units, 0);
}

#[test]
fn budget_policy_cap_denies_matching_row_only() {
    let table = BudgetPolicyTable::from_rows(vec![
        purpose_row(CallPurpose::Extraction, None, Some(30)),
        purpose_row(CallPurpose::Consolidation, None, Some(50)),
    ]);
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x52),
        &table,
    );

    for _ in 0..3 {
        guard
            .admit_for_request(&request_for(
                CallPurpose::Extraction,
                ModelLocality::ThirdParty,
            ))
            .expect("extraction admission under cap");
    }
    let before_denial = guard.read();
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty,
        )),
        Err(BudgetDenied::Exhausted)
    ));
    let after_denial = guard.read();
    assert_eq!(after_denial.used_units, before_denial.used_units);
    assert_eq!(after_denial.reserved_units, before_denial.reserved_units);
    assert_eq!(after_denial.remaining_units, before_denial.remaining_units);
    assert_eq!(
        after_denial.fired_thresholds,
        before_denial.fired_thresholds
    );

    guard
        .admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty))
        .expect("non-matching shared admission");
    guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("unrelated-row admission");
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 50);

    for _ in 0..4 {
        guard
            .admit_for_request(&request_for(
                CallPurpose::Consolidation,
                ModelLocality::ThirdParty,
            ))
            .expect("remaining consolidation capacity");
    }
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        )),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!(guard.read().reserved_units, 90);
    guard
        .admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty))
        .expect("remaining shared capacity");
    assert_eq!(guard.read().reserved_units, 100);
}

#[test]
fn budget_policy_purpose_and_actor_caps_are_conjunctive() {
    let table = BudgetPolicyTable::from_rows(vec![
        purpose_row(CallPurpose::Consolidation, None, Some(50)),
        actor_row(0x50, None, Some(20)),
    ]);
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x50),
        &table,
    );

    for _ in 0..2 {
        guard
            .admit_for_request(&request_for(
                CallPurpose::Consolidation,
                ModelLocality::ThirdParty,
            ))
            .expect("double-matched admission");
    }
    let before_denial = guard.read();
    assert_eq!(before_denial.used_units, 0);
    assert_eq!(before_denial.reserved_units, 20);

    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        )),
        Err(BudgetDenied::Exhausted)
    ));
    let read_after = guard.read();
    assert!(read_after.remaining_units > 0);
    assert_eq!(read_after.used_units, before_denial.used_units);
    assert_eq!(read_after.reserved_units, before_denial.reserved_units);
    assert_eq!(read_after.remaining_units, before_denial.remaining_units);
    assert_eq!(read_after.fired_thresholds, before_denial.fired_thresholds);
    assert!(matches!(
        guard.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty)),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!(guard.read().reserved_units, 20);
}

#[test]
fn budget_policy_multi_floor_match_allocates_in_manifest_order() {
    let table = BudgetPolicyTable::from_rows(vec![
        purpose_row(CallPurpose::Consolidation, Some(20), None),
        actor_row(0x50, Some(30), None),
        purpose_row(CallPurpose::Voice, Some(40), None),
    ]);
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        15,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x50),
        &table,
    );

    let first = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("first consolidation admission");
    assert_eq!(first.read.reserved_units, 15);
    // Generic admissions match only the actor: its 30 plus shared 10 remain.
    assert!(matches!(
        guard.admit_reserve(41),
        Err(BudgetDenied::Exhausted)
    ));
    let probe = guard.admit_reserve(40).expect("actor floor untouched");
    assert_eq!(probe.read.reserved_units, 55);
    let refunded = guard.abort(&probe.lease).expect("refund first probe");
    assert_eq!(refunded.read.reserved_units, 15);
    assert_eq!(refunded.read.used_units, 0);

    let second = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("second consolidation admission");
    assert_eq!(second.read.reserved_units, 30);
    assert!(matches!(
        guard.admit_reserve(31),
        Err(BudgetDenied::Exhausted)
    ));
    let probe = guard
        .admit_reserve(30)
        .expect("remaining actor and shared capacity");
    assert_eq!(probe.read.reserved_units, 60);
    assert_eq!(
        guard
            .abort(&probe.lease)
            .expect("refund second probe")
            .read
            .reserved_units,
        30,
    );

    guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("third consolidation admission");
    assert!(matches!(
        guard.admit_reserve(16),
        Err(BudgetDenied::Exhausted)
    ));
    let probe = guard
        .admit_reserve(15)
        .expect("last actor and shared capacity");
    assert_eq!(probe.read.reserved_units, 60);
    assert_eq!(
        guard
            .abort(&probe.lease)
            .expect("refund third probe")
            .read
            .reserved_units,
        45,
    );
    let fourth = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("fourth consolidation admission");
    assert_eq!(fourth.read.reserved_units, 60);
    assert!(matches!(
        guard.admit_reserve(1),
        Err(BudgetDenied::Exhausted)
    ));

    guard
        .admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty))
        .expect("voice admission");
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 75);
    guard
        .admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty))
        .expect("remaining full voice reserve");
    assert!(matches!(
        guard.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty)),
        Err(BudgetDenied::Exhausted)
    ));

    let settled = guard
        .settle_usage(&fourth.lease, 0)
        .expect("unused fourth reserve is refunded");
    assert_eq!(settled.read.used_units, 0);
    assert_eq!(settled.read.reserved_units, 75);
    assert!(matches!(
        guard.admit_reserve(16),
        Err(BudgetDenied::Exhausted)
    ));
    let probe = guard
        .admit_reserve(15)
        .expect("refunded actor and shared capacity");
    assert_eq!(probe.read.reserved_units, 90);
}

#[test]
fn budget_policy_row_ladder_uses_reduced_horizon_and_row_index() {
    // Row 1 is a background row: its horizon is bounded by its cap (20) and
    // reduced by the floor it can never draw (90) to min(20, 100 - 90) = 10.
    let table = || {
        BudgetPolicyTable::from_rows(vec![
            purpose_row(CallPurpose::Consolidation, Some(90), None),
            purpose_row(CallPurpose::Extraction, None, Some(20)),
        ])
    };
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        1,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x53),
        &table(),
    );

    let mut observed: Vec<(BudgetThreshold, Option<u16>)> = Vec::new();
    for admission in 1..=10 {
        let outcome = guard
            .admit_for_request(&request_for(
                CallPurpose::Extraction,
                ModelLocality::ThirdParty,
            ))
            .expect("extraction admission");
        for event in &outcome.ladder_events {
            // Row events keep the existing steering payload unchanged.
            assert_eq!(event.steering, steering_signal(event.threshold));
            observed.push((event.threshold, event.row_index));
        }
        if admission < 5 {
            assert!(outcome.ladder_events.is_empty());
        }
    }
    assert_eq!(
        observed,
        vec![
            (BudgetThreshold::Silent50, Some(1)),
            (BudgetThreshold::Plan80, Some(1)),
            (BudgetThreshold::Land95, Some(1)),
        ],
        "the row ladder crosses 50/80/95 against the reduced horizon of 10"
    );
    // The global meter stayed at 10% of T = 100: it never fired while the row
    // ladder reported full depletion on its own horizon.
    assert!(guard.read().fired_thresholds.is_empty());

    // The global ladder still uses T and fires first with row_index = None.
    let global_leg = BudgetGuard::with_policy_table(
        "job",
        100,
        55,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x53),
        &table(),
    );
    let admission = global_leg
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("floor-backed consolidation admission");
    let events: Vec<(BudgetThreshold, Option<u16>)> = admission
        .ladder_events
        .iter()
        .map(|event| (event.threshold, event.row_index))
        .collect();
    assert_eq!(
        events,
        vec![
            (BudgetThreshold::Silent50, None),
            (BudgetThreshold::Silent50, Some(0)),
        ]
    );
}

#[test]
fn budget_policy_row_ladder_fires_once_per_threshold_and_row() {
    let table = BudgetPolicyTable::from_rows(vec![
        purpose_row(CallPurpose::Consolidation, None, Some(30)),
        actor_row(0x50, None, Some(30)),
    ]);
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        15,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x50),
        &table,
    );

    // One multi-match call crosses 50 on both rows: two events, distinct
    // indices, fired once.
    let first = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("first admission");
    let first_events: Vec<(BudgetThreshold, Option<u16>)> = first
        .ladder_events
        .iter()
        .map(|event| (event.threshold, event.row_index))
        .collect();
    assert_eq!(
        first_events,
        vec![
            (BudgetThreshold::Silent50, Some(0)),
            (BudgetThreshold::Silent50, Some(1)),
        ]
    );

    // Settlement and later reads emit no duplicates.
    let settled = guard
        .settle_absolute(&first.lease, 15)
        .expect("first settlement");
    assert!(settled.ladder_events.is_empty());
    let _ = guard.read();

    // The next multi-match call crosses 80 and 95 on both rows, once each,
    // in row order.
    let second = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("second admission");
    let second_events: Vec<(BudgetThreshold, Option<u16>)> = second
        .ladder_events
        .iter()
        .map(|event| (event.threshold, event.row_index))
        .collect();
    assert_eq!(
        second_events,
        vec![
            (BudgetThreshold::Plan80, Some(0)),
            (BudgetThreshold::Land95, Some(0)),
            (BudgetThreshold::Plan80, Some(1)),
            (BudgetThreshold::Land95, Some(1)),
        ]
    );
    let settled = guard
        .settle_absolute(&second.lease, 15)
        .expect("second settlement");
    assert!(settled.ladder_events.is_empty());
}

#[test]
fn budget_policy_abort_refunds_row_floor_and_shared_reservations() {
    let table = BudgetPolicyTable::from_rows(vec![purpose_row(
        CallPurpose::Consolidation,
        Some(30),
        None,
    )]);
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x54),
        &table,
    );

    let mut floor_leases = Vec::new();
    for _ in 0..3 {
        floor_leases.push(
            guard
                .admit_for_request(&request_for(
                    CallPurpose::Consolidation,
                    ModelLocality::ThirdParty,
                ))
                .expect("floor-backed admission"),
        );
    }
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 30);

    let shared_one = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("first shared admission");
    let shared_two = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("second shared admission");
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 50);

    let refunded = guard.abort(&shared_one.lease).expect("abort shared one");
    assert_eq!(refunded.read.reserved_units, 40);
    assert_eq!(refunded.read.used_units, 0);
    let refunded = guard.abort(&shared_two.lease).expect("abort shared two");
    assert_eq!(refunded.read.reserved_units, 30);
    assert_eq!(refunded.read.used_units, 0);
    assert_eq!(refunded.read.remaining_units, 70);

    // All seven nonmatching reserves must be available again.
    let mut shared_probes = Vec::new();
    for _ in 0..7 {
        shared_probes.push(guard.admit().expect("refunded shared capacity"));
    }
    assert_eq!(guard.read().reserved_units, 100);
    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
    for probe in shared_probes {
        guard.abort(&probe.lease).expect("restore shared probe");
    }
    assert_eq!(guard.read().reserved_units, 30);

    guard
        .abort(&floor_leases[0].lease)
        .expect("abort floor lease");
    assert_eq!(guard.read().reserved_units, 20);
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().remaining_units, 80);
    assert!(matches!(
        guard.settle_absolute(&shared_one.lease, 10),
        Err(BudgetDenied::LeaseInvalid)
    ));

    for _ in 0..7 {
        guard.admit().expect("shared capacity remains separate");
    }
    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
    assert_eq!(guard.read().reserved_units, 90);
    let replacement = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("refunded floor capacity");
    assert_eq!(replacement.read.used_units, 0);
    assert_eq!(replacement.read.reserved_units, 100);
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        )),
        Err(BudgetDenied::Exhausted)
    ));
}

#[test]
fn budget_policy_settlement_overshoot_is_recorded_not_killed() {
    let table =
        BudgetPolicyTable::from_rows(vec![purpose_row(CallPurpose::Extraction, None, Some(20))]);
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x55),
        &table,
    );

    let first = guard
        .admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty,
        ))
        .expect("first extraction admission");
    let second = guard
        .admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty,
        ))
        .expect("second extraction admission");

    let settled = guard
        .settle_absolute(&first.lease, 30)
        .expect("overshoot settlement is recorded, not killed");
    assert_eq!(settled.read.used_units, 30);
    assert_eq!(settled.read.reserved_units, 10);
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty,
        )),
        Err(BudgetDenied::Exhausted)
    ));

    // Absolute usage retains the global watermark, not the sum of reports.
    let settled = guard
        .settle_absolute(&second.lease, 25)
        .expect("second settlement succeeds");
    assert_eq!(settled.read.used_units, 30);
    assert_eq!(settled.read.reserved_units, 0);
    assert_eq!(guard.read().used_units, 30);
    assert_eq!(guard.read().reserved_units, 0);
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty,
        )),
        Err(BudgetDenied::Exhausted)
    ));
}

#[test]
fn budget_policy_continue_on_local_and_admit_local_are_unchanged() {
    for attempt in ["legacy", "policy"] {
        let guard = if attempt == "legacy" {
            BudgetGuard::with_reserve_units("job", 10, 10, BudgetExhaustionPolicy::ContinueOnLocal)
        } else {
            BudgetGuard::with_policy_table(
                "job",
                10,
                10,
                BudgetExhaustionPolicy::ContinueOnLocal,
                policy_test_actor(0x56),
                &BudgetPolicyTable::default(),
            )
        };
        assert!(matches!(
            guard.admit_local(),
            Err(BudgetDenied::AdmissionDenied)
        ));
        let metered = guard.admit().expect("metered lease reaches cap");
        assert!(metered.lease.id().starts_with("job:metered:"));
        assert_eq!(metered.read.used_units, 0);
        assert_eq!(metered.read.reserved_units, 10);
        assert_eq!(metered.read.remaining_units, 0);
        assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));

        let local = guard.admit_local().expect("explicit local continuation");
        assert!(local.lease.id().starts_with("job:local:"));
        assert_ne!(local.lease.id(), metered.lease.id());
        assert!(local.ladder_events.is_empty());
        assert_eq!(local.read.used_units, 0);
        assert_eq!(local.read.reserved_units, 10);
        let settled = guard
            .settle_absolute(&local.lease, 99)
            .expect("local settlement is unmetered");
        assert!(settled.ladder_events.is_empty());
        assert_eq!(settled.read.used_units, 0);
        assert_eq!(settled.read.reserved_units, 10);
        assert_eq!(settled.read.remaining_units, 0);
        let settled = guard
            .settle_absolute(&metered.lease, 10)
            .expect("metered settlement");
        assert!(settled.ladder_events.is_empty());
        assert_eq!(settled.read.used_units, 10);
        assert_eq!(settled.read.reserved_units, 0);
        assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
        assert_eq!(guard.read().used_units, 10);
        assert_eq!(guard.read().reserved_units, 0);
        assert_eq!(guard.read().remaining_units, 0);
    }

    // Exhaust the shared slice while leaving the consolidation floor intact.
    let table = BudgetPolicyTable::from_rows(vec![purpose_row(
        CallPurpose::Consolidation,
        Some(30),
        None,
    )]);
    let gap = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::ContinueOnLocal,
        policy_test_actor(0x57),
        &table,
    );
    for _ in 0..7 {
        gap.admit().expect("shared-slice admission");
    }
    let local = gap
        .admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::OnDevice))
        .expect("policy-blocked OnDevice request gets the local lease");
    assert_eq!(local.lease.id(), "job:local:8");
    assert!(local.ladder_events.is_empty());
    assert_eq!(local.read.used_units, 0);
    assert_eq!(local.read.reserved_units, 70);
    assert_eq!(local.read.remaining_units, 30);

    let second_local = gap
        .admit_local()
        .expect("admit_local uses the same capacity predicate");
    assert_eq!(second_local.lease.id(), "job:local:9");
    assert_ne!(local.lease.id(), second_local.lease.id());
    assert!(second_local.ladder_events.is_empty());
    assert_eq!(second_local.read.used_units, 0);
    assert_eq!(second_local.read.reserved_units, 70);
    for lease in [&local.lease, &second_local.lease] {
        let settled = gap
            .settle_absolute(lease, 99)
            .expect("floor-gap local settlement is unmetered");
        assert!(settled.ladder_events.is_empty());
        assert_eq!(settled.read.used_units, 0);
        assert_eq!(settled.read.reserved_units, 70);
        assert_eq!(settled.read.remaining_units, 30);
    }

    let metered = gap
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::OnDevice,
        ))
        .expect("floor headroom admits a metered lease");
    assert!(metered.lease.id().starts_with("job:metered:"));
    assert_eq!(metered.read.reserved_units, 80);
    assert!(matches!(
        gap.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty)),
        Err(BudgetDenied::Exhausted)
    ));
    // Both remaining floor draws must still be paid admissions.
    for reserved in [90, 100] {
        let admission = gap
            .admit_for_request(&request_for(
                CallPurpose::Consolidation,
                ModelLocality::OnDevice,
            ))
            .expect("local calls left the entire floor available");
        assert!(admission.lease.id().starts_with("job:metered:"));
        assert_eq!(admission.read.used_units, 0);
        assert_eq!(admission.read.reserved_units, reserved);
    }

    let capped_purpose = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::ContinueOnLocal,
        policy_test_actor(0x58),
        &BudgetPolicyTable::from_rows(vec![
            purpose_row(CallPurpose::Consolidation, Some(30), None),
            purpose_row(CallPurpose::Voice, None, Some(0)),
        ]),
    );
    for _ in 0..7 {
        capped_purpose.admit().expect("shared-slice admission");
    }
    assert!(matches!(
        capped_purpose.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::OnDevice)),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!(capped_purpose.read().used_units, 0);
    assert_eq!(capped_purpose.read().reserved_units, 70);
    assert_eq!(capped_purpose.read().remaining_units, 30);
    let local = capped_purpose
        .admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::OnDevice,
        ))
        .expect("capacity block still yields the local lease");
    assert_eq!(local.lease.id(), "job:local:8");
    assert!(local.ladder_events.is_empty());
    let settled = capped_purpose
        .settle_absolute(&local.lease, 99)
        .expect("non-matching local lease remains unmetered");
    assert!(settled.ladder_events.is_empty());
    assert_eq!(settled.read.used_units, 0);
    assert_eq!(settled.read.reserved_units, 70);

    let capped_actor = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::ContinueOnLocal,
        policy_test_actor(0x59),
        &BudgetPolicyTable::from_rows(vec![actor_row(0x59, None, Some(0))]),
    );
    assert!(matches!(
        capped_actor.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::OnDevice)),
        Err(BudgetDenied::Exhausted)
    ));
    assert!(matches!(
        capped_actor.admit_for_request(&request_for(
            CallPurpose::AnswerGen,
            ModelLocality::OnDevice
        )),
        Err(BudgetDenied::Exhausted)
    ));
    assert!(matches!(
        capped_actor.admit_local(),
        Err(BudgetDenied::AdmissionDenied)
    ));
    assert_eq!(capped_actor.read().used_units, 0);
    assert_eq!(capped_actor.read().reserved_units, 0);
    assert_eq!(capped_actor.read().remaining_units, 100);
    assert!(capped_actor.read().fired_thresholds.is_empty());
}

#[test]
fn budget_policy_interactive_purposes_have_no_special_case() {
    // Under Suspend, interactive purposes on OnDevice requests are denied
    // like any other purpose; there is no mid-conversation suspension or
    // implicit local rescue.
    let suspend = BudgetGuard::with_policy_table(
        "job",
        10,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x5A),
        &BudgetPolicyTable::default(),
    );
    suspend.admit().expect("metered lease reaches cap");
    assert!(matches!(
        suspend.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::OnDevice)),
        Err(BudgetDenied::Exhausted)
    ));
    assert!(matches!(
        suspend.admit_for_request(&request_for(
            CallPurpose::AnswerGen,
            ModelLocality::OnDevice
        )),
        Err(BudgetDenied::Exhausted)
    ));

    // Under ContinueOnLocal the only special handling is the locality +
    // policy branch, and it is purpose-agnostic: Voice, AnswerGen, and
    // Extraction all get the same zero-unit local lease after exhaustion.
    let local = BudgetGuard::with_policy_table(
        "job",
        10,
        10,
        BudgetExhaustionPolicy::ContinueOnLocal,
        policy_test_actor(0x5B),
        &BudgetPolicyTable::default(),
    );
    local.admit().expect("metered lease reaches cap");
    for purpose in [
        CallPurpose::Voice,
        CallPurpose::AnswerGen,
        CallPurpose::Extraction,
    ] {
        let admission = local
            .admit_for_request(&request_for(purpose, ModelLocality::OnDevice))
            .expect("every purpose shares the same local fallback");
        assert!(admission.lease.id().starts_with("job:local:"));
        assert!(admission.ladder_events.is_empty());
    }
    // Locality, not interactivity, governs: remote interactive calls deny.
    assert!(matches!(
        local.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty)),
        Err(BudgetDenied::Exhausted)
    ));

    // Interactive purposes get no implicit floor either: only an explicit row
    // selects them, and then the row governs like any other purpose's row.
    let selected = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x5C),
        &BudgetPolicyTable::from_rows(vec![purpose_row(CallPurpose::Voice, None, Some(0))]),
    );
    assert!(matches!(
        selected.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::OnDevice)),
        Err(BudgetDenied::Exhausted)
    ));
    selected
        .admit_for_request(&request_for(
            CallPurpose::AnswerGen,
            ModelLocality::OnDevice,
        ))
        .expect("unselected interactive purpose uses the shared slice");
}

#[test]
fn budget_policy_row_tallies_are_per_lease_additive_across_interleaved_settlements() {
    let table =
        BudgetPolicyTable::from_rows(vec![purpose_row(CallPurpose::Extraction, None, Some(60))]);
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x5D),
        &table,
    );

    let a1 = guard
        .admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty,
        ))
        .expect("A1 admission");
    let non_matching = guard
        .admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty))
        .expect("non-matching admission");
    let a2 = guard
        .admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty,
        ))
        .expect("A2 admission");

    // A1 settles 30: row A is 30.
    guard.settle_absolute(&a1.lease, 30).expect("A1 settlement");
    assert_eq!(meter_snapshot(&guard).rows[0].0, 30);

    // A non-matching lease settles 50: row A is unchanged.
    guard
        .settle_absolute(&non_matching.lease, 50)
        .expect("non-matching settlement");
    assert_eq!(meter_snapshot(&guard).rows[0].0, 30);

    // A2 settles 40: row A is 70 — above cap 60, and settlement still
    // succeeds because an admitted call is never killed; the overshoot is
    // recorded and the next matching admission is denied.
    guard
        .settle_absolute(&a2.lease, 40)
        .expect("A2 settlement succeeds above the cap");
    let exhausted = meter_snapshot(&guard);
    assert_eq!(exhausted.rows[0], (70, 0, 0, 0));
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty
        )),
        Err(BudgetDenied::Exhausted)
    ));

    // Settling either A lease again adds zero.
    let read_before = guard.read();
    guard
        .settle_absolute(&a1.lease, 30)
        .expect("duplicate A1 settlement is idempotent");
    guard
        .settle_absolute(&a2.lease, 40)
        .expect("duplicate A2 settlement is idempotent");
    assert_eq!(meter_snapshot(&guard), exhausted);
    assert_eq!(guard.read(), read_before);
}

#[test]
fn budget_policy_generic_admit_respects_actor_rows() {
    let table = || {
        BudgetPolicyTable::from_rows(vec![
            purpose_row(CallPurpose::Extraction, None, Some(5)),
            actor_row(0x50, Some(20), Some(20)),
        ])
    };

    let bound = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x50),
        &table(),
    );
    bound.admit().expect("first generic admission draws floor");
    bound.admit().expect("second generic admission draws floor");
    assert_eq!(bound.read().used_units, 0);
    assert_eq!(bound.read().reserved_units, 20);
    assert_eq!(bound.read().remaining_units, 80);
    assert!(matches!(bound.admit(), Err(BudgetDenied::Exhausted)));
    assert!(matches!(
        bound.admit_reserve(10),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!(bound.read().used_units, 0);
    assert_eq!(bound.read().reserved_units, 20);
    assert_eq!(bound.read().remaining_units, 80);

    let unbound = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x51),
        &table(),
    );
    for _ in 0..8 {
        unbound
            .admit_reserve(10)
            .expect("shared-only generic admission");
    }
    assert!(matches!(
        unbound.admit_reserve(10),
        Err(BudgetDenied::Exhausted)
    ));
    assert!(matches!(unbound.admit(), Err(BudgetDenied::Exhausted)));
    assert_eq!(unbound.read().used_units, 0);
    assert_eq!(unbound.read().reserved_units, 80);
    assert_eq!(unbound.read().remaining_units, 20);

    // With no shared slice, success proves that generic calls can draw the
    // bound actor's floor rather than merely reserving shared capacity.
    let floor_only = BudgetGuard::with_policy_table(
        "job",
        20,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x50),
        &table(),
    );
    let first = floor_only.admit().expect("generic admit draws actor floor");
    assert_eq!(first.read.used_units, 0);
    assert_eq!(first.read.reserved_units, 10);
    let second = floor_only
        .admit_reserve(10)
        .expect("explicit reserve draws remaining actor floor");
    assert_eq!(second.read.used_units, 0);
    assert_eq!(second.read.reserved_units, 20);
    assert_eq!(second.read.remaining_units, 0);
    assert!(matches!(floor_only.admit(), Err(BudgetDenied::Exhausted)));
    assert!(matches!(
        floor_only.admit_reserve(10),
        Err(BudgetDenied::Exhausted)
    ));
}

#[test]
fn budget_policy_oversubscribed_floors_saturate_without_panic() {
    // Three floor-60 rows against T = 100 leave no shared capacity.
    let table = BudgetPolicyTable::from_rows(vec![
        purpose_row(CallPurpose::Extraction, Some(60), None),
        purpose_row(CallPurpose::Consolidation, Some(60), None),
        purpose_row(CallPurpose::Voice, Some(60), None),
    ]);
    let guard = BudgetGuard::with_policy_table(
        "job",
        100,
        10,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x5E),
        &table,
    );

    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::AnswerGen,
            ModelLocality::ThirdParty
        )),
        Err(BudgetDenied::Exhausted)
    ));

    let first = guard
        .admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty,
        ))
        .expect("first floor draw");
    let events: Vec<(BudgetThreshold, Option<u16>)> = first
        .ladder_events
        .iter()
        .map(|event| (event.threshold, event.row_index))
        .collect();
    let mut expected = Vec::new();
    for row_index in 0..3u16 {
        for threshold in [
            BudgetThreshold::Silent50,
            BudgetThreshold::Plan80,
            BudgetThreshold::Land95,
        ] {
            expected.push((threshold, Some(row_index)));
        }
    }
    assert_eq!(events, expected);

    for _ in 0..5 {
        guard
            .admit_for_request(&request_for(
                CallPurpose::Extraction,
                ModelLocality::ThirdParty,
            ))
            .expect("extraction floor draw");
    }
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 60);
    // Extraction cannot borrow another floor even with global headroom.
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty
        )),
        Err(BudgetDenied::Exhausted)
    ));
    for _ in 0..4 {
        guard
            .admit_for_request(&request_for(
                CallPurpose::Consolidation,
                ModelLocality::ThirdParty,
            ))
            .expect("consolidation floor draw");
    }
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty
        )),
        Err(BudgetDenied::Exhausted)
    ));
    assert!(matches!(
        guard.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty)),
        Err(BudgetDenied::Exhausted)
    ));

    let read = guard.read();
    assert_eq!(read.used_units, 0);
    assert_eq!(read.reserved_units, 100);
    assert_eq!(read.remaining_units, 0);
    assert_eq!(read.depleted_percent(), 100);
    assert_eq!(
        read.fired_thresholds,
        vec![
            BudgetThreshold::Silent50,
            BudgetThreshold::Plan80,
            BudgetThreshold::Land95,
        ]
    );
}
