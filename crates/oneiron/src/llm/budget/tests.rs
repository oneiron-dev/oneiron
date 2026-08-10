use super::*;
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, LlmInputUsage, LlmMessage, LlmMessageRole,
    LlmOutputUsage, ModelId, ModelTierRef, ResponseFormat, TierPrecedence,
};
use serde_json::Value as JsonValue;
use std::sync::{Arc, Barrier};
use std::thread;

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

/// The deterministic admit/settle/abort/read/ladder sequence any single-pool
/// meter must reproduce exactly, policy-aware-empty included.
fn single_pool_transcript(guard: &BudgetGuard) -> Vec<String> {
    let mut log = Vec::new();
    let first = guard.admit().expect("first admission");
    log.push(format!("first: {first:?}"));
    let second = guard.admit().expect("second admission");
    log.push(format!("second: {second:?}"));
    log.push(format!(
        "settle_first: {:?}",
        guard.settle_absolute(&first.lease, 50)
    ));
    log.push(format!("abort_second: {:?}", guard.abort(&second.lease)));
    let third = guard.admit().expect("third admission");
    log.push(format!("third: {third:?}"));
    log.push(format!(
        "settle_third: {:?}",
        guard.settle_absolute(&third.lease, 96)
    ));
    log.push(format!("over_cap_denial: {:?}", guard.admit()));
    log.push(format!("read: {:?}", guard.read()));
    log
}

/// The exact local-continuation flow pinned by
/// `continue_on_local_requires_explicit_unmetered_lease_after_exhaustion`.
fn local_continuation_transcript(guard: &BudgetGuard) -> Vec<String> {
    let mut log = Vec::new();
    log.push(format!("early_local: {:?}", guard.admit_local()));
    let metered = guard.admit().expect("metered lease reaches cap");
    log.push(format!("metered: {metered:?}"));
    log.push(format!("exhausted: {:?}", guard.admit()));
    let local = guard.admit_local().expect("explicit local continuation");
    log.push(format!("local: {local:?}"));
    log.push(format!(
        "settle_local: {:?}",
        guard.settle_absolute(&local.lease, 99)
    ));
    log.push(format!(
        "settle_metered: {:?}",
        guard.settle_absolute(&metered.lease, 10)
    ));
    log.push(format!("after_metered: {:?}", guard.admit()));
    log.push(format!("read: {:?}", guard.read()));
    log
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
        assert_eq!(
            single_pool_transcript(&legacy),
            single_pool_transcript(&policy_aware),
            "empty table must reproduce lease ids, reads, ladders, and denials exactly"
        );
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

    // Seven non-matching calls exhaust the shared slice; the floor is untouched.
    for _ in 0..7 {
        guard.admit().expect("shared-slice admission");
    }
    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
    let after_shared = meter_snapshot(&guard);
    assert_eq!(after_shared.rows, vec![(0, 0, 0, 0)]);
    assert_eq!(after_shared.shared_reserved_units, 70);
    assert_eq!(after_shared.reserved_units, 70);

    // Consolidation still admits three floor-backed reserves; the fourth is
    // denied even though the floor is the only slice it can draw.
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
            ModelLocality::ThirdParty
        )),
        Err(BudgetDenied::Exhausted)
    ));
    let after_floor = meter_snapshot(&guard);
    assert_eq!(after_floor.rows, vec![(0, 30, 0, 30)]);
    assert_eq!(after_floor.shared_reserved_units, 70);
    assert_eq!(after_floor.reserved_units, 100);
}

#[test]
fn budget_policy_actor_floor_uses_engine_stamped_actor() {
    // One actor-floor row; two guards share the table but bind different
    // engine-stamped actors.
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

    // The non-matching guard cannot touch the actor floor: it exhausts the
    // shared slice after seven admissions and is denied.
    for _ in 0..7 {
        other.admit().expect("other-actor shared admission");
    }
    assert!(matches!(other.admit(), Err(BudgetDenied::Exhausted)));
    let other_snapshot = meter_snapshot(&other);
    assert_eq!(other_snapshot.rows, vec![(0, 0, 0, 0)]);
    assert_eq!(other_snapshot.shared_reserved_units, 70);

    // Request payloads and provider options cannot impersonate the actor.
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
    assert_eq!(meter_snapshot(&other), other_snapshot);

    // The matching actor draws the floor first (three reserves), then the
    // shared slice (seven), and is denied only at the global total.
    for _ in 0..10 {
        matching.admit().expect("matching-actor admission");
    }
    assert!(matches!(matching.admit(), Err(BudgetDenied::Exhausted)));
    let matching_snapshot = meter_snapshot(&matching);
    assert_eq!(matching_snapshot.rows, vec![(0, 100, 0, 30)]);
    assert_eq!(matching_snapshot.shared_reserved_units, 70);
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
    let before_denial = (guard.read(), meter_snapshot(&guard));

    // The cap denial is final and mutates nothing.
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty
        )),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!((guard.read(), meter_snapshot(&guard)), before_denial);

    // A non-matching call still uses shared capacity; an unrelated row still
    // admits its own matching call.
    guard
        .admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty))
        .expect("non-matching shared admission");
    guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("unrelated-row admission");
    let after = meter_snapshot(&guard);
    assert_eq!(after.rows, vec![(0, 30, 0, 0), (0, 10, 0, 0)]);
    assert_eq!(after.shared_reserved_units, 50);
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

    // One request matches both rows and is charged to both.
    for _ in 0..2 {
        guard
            .admit_for_request(&request_for(
                CallPurpose::Consolidation,
                ModelLocality::ThirdParty,
            ))
            .expect("double-matched admission");
    }
    let before_denial = (guard.read(), meter_snapshot(&guard));

    // The smaller actor cap denies even though the purpose cap and the global
    // pool both have room; the denial leaves every meter untouched.
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty
        )),
        Err(BudgetDenied::Exhausted)
    ));
    let (read_after, snapshot_after) = (guard.read(), meter_snapshot(&guard));
    assert!(read_after.remaining_units > 0);
    assert_eq!(snapshot_after.rows, vec![(0, 20, 0, 0), (0, 20, 0, 0)]);
    assert_eq!(snapshot_after.shared_reserved_units, 20);
    assert_eq!((read_after, snapshot_after), before_denial);
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

    // A consolidation request matches rows 0 and 1: the purpose floor first.
    let first = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("first consolidation admission");
    {
        let state = guard.state.lock().expect("lease inspection");
        let record = state.leases.get(first.lease.id()).expect("lease record");
        assert_eq!(
            record.floor_allocations,
            vec![FloorAllocation {
                row_index: 0,
                units: 15,
            }]
        );
        assert_eq!(record.shared_reserved_units, 0);
    }

    // The second request drains the purpose floor's last 5, then draws 10
    // from the actor floor — matched floor headroom in resolved order.
    let second = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("second consolidation admission");
    {
        let state = guard.state.lock().expect("lease inspection");
        let record = state.leases.get(second.lease.id()).expect("lease record");
        assert_eq!(
            record.floor_allocations,
            vec![
                FloorAllocation {
                    row_index: 0,
                    units: 5,
                },
                FloorAllocation {
                    row_index: 1,
                    units: 10,
                },
            ]
        );
        assert_eq!(record.shared_reserved_units, 0);
    }

    // The third fits the actor floor; the fourth spills 10 into shared.
    guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("third consolidation admission");
    let fourth = guard
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::ThirdParty,
        ))
        .expect("fourth consolidation admission");
    {
        let state = guard.state.lock().expect("lease inspection");
        let record = state.leases.get(fourth.lease.id()).expect("lease record");
        assert_eq!(
            record.floor_allocations,
            vec![FloorAllocation {
                row_index: 1,
                units: 5,
            }]
        );
        assert_eq!(record.shared_reserved_units, 10);
    }

    // A voice request also matches the actor row (actor rows are
    // purpose-independent) but the actor floor is exhausted, so it draws only
    // its own purpose floor; every unmatched floor stays untouched.
    guard
        .admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty))
        .expect("voice admission");
    let snapshot = meter_snapshot(&guard);
    assert_eq!(
        snapshot.rows,
        vec![(0, 60, 0, 20), (0, 75, 0, 30), (0, 15, 0, 15)]
    );
    assert_eq!(snapshot.shared_reserved_units, 10);
    assert_eq!(snapshot.reserved_units, 75);
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

    // Three reserves consume the floor exactly; snapshot the steady state.
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
    let floor_only = meter_snapshot(&guard);
    assert_eq!(floor_only.rows, vec![(0, 30, 0, 30)]);
    assert_eq!(floor_only.shared_reserved_units, 0);

    // Two more reserves spill into the shared slice.
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
    let spilled = meter_snapshot(&guard);
    assert_eq!(spilled.rows, vec![(0, 50, 0, 30)]);
    assert_eq!(spilled.shared_reserved_units, 20);
    assert_eq!(spilled.reserved_units, 50);

    // Aborting the shared reserves refunds global, row, floor, and shared
    // reservations exactly back to the floor-only steady state (aborted
    // leases stay recorded as Aborted, so only open leases compare).
    guard.abort(&shared_one.lease).expect("abort shared one");
    guard.abort(&shared_two.lease).expect("abort shared two");
    let refunded_shared = meter_snapshot(&guard);
    assert_eq!(refunded_shared.rows, floor_only.rows);
    assert_eq!(refunded_shared.reserved_units, floor_only.reserved_units);
    assert_eq!(refunded_shared.used_units, floor_only.used_units);
    assert_eq!(
        refunded_shared.shared_reserved_units,
        floor_only.shared_reserved_units
    );
    assert_eq!(
        refunded_shared.shared_used_units,
        floor_only.shared_used_units
    );
    assert_eq!(refunded_shared.open_leases, floor_only.open_leases);

    // Aborting a floor reserve refunds its floor allocation.
    guard
        .abort(&floor_leases[0].lease)
        .expect("abort floor lease");
    let refunded = meter_snapshot(&guard);
    assert_eq!(refunded.rows, vec![(0, 20, 0, 20)]);
    assert_eq!(refunded.reserved_units, 20);
    assert_eq!(refunded.shared_reserved_units, 0);
    assert!(matches!(
        guard.settle_absolute(&shared_one.lease, 10),
        Err(BudgetDenied::LeaseInvalid)
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

    // Settling above the reserve and the row cap succeeds; the overshoot is
    // recorded in the row tally and the later matching admission is denied.
    let settled = guard
        .settle_absolute(&first.lease, 30)
        .expect("overshoot settlement is recorded, not killed");
    assert_eq!(settled.read.used_units, 30);
    let after_overshoot = meter_snapshot(&guard);
    assert_eq!(after_overshoot.rows, vec![(30, 10, 0, 0)]);
    assert_eq!(after_overshoot.shared_used_units, 30);

    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::ThirdParty
        )),
        Err(BudgetDenied::Exhausted)
    ));

    // The second lease settles normally above the already-exceeded cap.
    guard
        .settle_absolute(&second.lease, 25)
        .expect("second settlement succeeds");
    let after_second = meter_snapshot(&guard);
    assert_eq!(after_second.rows, vec![(55, 0, 0, 0)]);
}

#[test]
fn budget_policy_continue_on_local_and_admit_local_are_unchanged() {
    // The explicit zero-unit local lease, its settlement, and the no-event
    // behavior are byte-identical between the legacy constructor and a
    // policy-aware guard holding an empty table.
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
        let transcript = local_continuation_transcript(&guard);
        assert_eq!(
            transcript,
            local_continuation_transcript(&BudgetGuard::with_reserve_units(
                "job",
                10,
                10,
                BudgetExhaustionPolicy::ContinueOnLocal
            )),
            "{attempt} constructor must reproduce the local-continuation flow exactly"
        );
    }

    // Floor-gap fixture: T = 100, a consolidation floor of 30, and the shared
    // 70 exhausted. An OnDevice Voice request gets the zero-unit local lease
    // without row tallies or row events; admit_local succeeds under the same
    // policy-aware capacity predicate.
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
    let before_local = (gap.read(), meter_snapshot(&gap));

    let local = gap
        .admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::OnDevice))
        .expect("policy-blocked OnDevice request gets the local lease");
    assert_eq!(local.lease.id(), "job:local:8");
    assert!(local.ladder_events.is_empty());
    assert_eq!(local.read.reserved_units, 70);
    assert_eq!(gap.read(), before_local.0);
    let after_local = meter_snapshot(&gap);
    assert_eq!(after_local.rows, before_local.1.rows);
    assert_eq!(after_local.reserved_units, before_local.1.reserved_units);
    assert_eq!(
        after_local.shared_reserved_units,
        before_local.1.shared_reserved_units
    );
    assert_eq!(after_local.open_leases, before_local.1.open_leases + 1);

    let local = gap
        .admit_local()
        .expect("admit_local uses the same capacity predicate");
    assert_eq!(local.lease.id(), "job:local:9");
    assert!(local.ladder_events.is_empty());
    let after_second_local = meter_snapshot(&gap);
    assert_eq!(after_second_local.rows, before_local.1.rows);
    assert_eq!(
        after_second_local.open_leases,
        before_local.1.open_leases + 2
    );

    // A request that fits the untouched floor still admits metered.
    let metered = gap
        .admit_for_request(&request_for(
            CallPurpose::Consolidation,
            ModelLocality::OnDevice,
        ))
        .expect("floor headroom admits a metered lease");
    assert!(metered.lease.id().starts_with("job:metered:"));

    // A Remote request with no floor access is denied outright.
    assert!(matches!(
        gap.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::ThirdParty)),
        Err(BudgetDenied::Exhausted)
    ));

    // A matching cap: 0 row keeps the cap denial final on the purpose axis:
    // the capacity local-continuation branch never fires for it.
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
    let before_cap = (capped_purpose.read(), meter_snapshot(&capped_purpose));
    assert!(matches!(
        capped_purpose.admit_for_request(&request_for(CallPurpose::Voice, ModelLocality::OnDevice)),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!(
        (capped_purpose.read(), meter_snapshot(&capped_purpose)),
        before_cap,
        "cap denial issues no local lease and mutates nothing"
    );
    // A capacity-blocked non-matching request still gets the local lease.
    capped_purpose
        .admit_for_request(&request_for(
            CallPurpose::Extraction,
            ModelLocality::OnDevice,
        ))
        .expect("capacity block still yields the local lease");

    // A matching actor cap: 0 row keeps the denial final on BOTH paths:
    // admit_for_request never issues a local lease, and admit_local never
    // falls back either — the actor cap matches the purpose-less call too.
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
    assert_eq!(meter_snapshot(&capped_actor).total_leases, 0);
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

    // On the actor-bound guard, generic admit() matches the actor row: it
    // draws the matched actor floor and the matched actor cap binds. The
    // purpose cap never matches (a purpose cap of 5 would deny immediately).
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
    let bound_snapshot = meter_snapshot(&bound);
    assert_eq!(bound_snapshot.rows, vec![(0, 0, 0, 0), (0, 20, 0, 20)]);
    assert_eq!(bound_snapshot.shared_reserved_units, 0);
    assert!(matches!(bound.admit(), Err(BudgetDenied::Exhausted)));
    assert_eq!(meter_snapshot(&bound), bound_snapshot);

    // A guard bound to a different actor is shared-only for the same generic
    // call: the actor floor is never drawn, the purpose row still never
    // matches, and the shared slice is bounded by T - sum(floors) = 80.
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
    let unbound_snapshot = meter_snapshot(&unbound);
    assert_eq!(unbound_snapshot.rows, vec![(0, 0, 0, 0), (0, 0, 0, 0)]);
    assert_eq!(unbound_snapshot.shared_reserved_units, 80);
    assert_eq!(unbound_snapshot.reserved_units, 80);
}

#[test]
fn budget_policy_oversubscribed_floors_saturate_without_panic() {
    // Three floor-60 rows against T = 100 oversubscribe the total; the shared
    // slice saturates to zero and horizons saturate to zero (100% depleted).
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

    // A non-matching call is denied immediately: shared slice is zero.
    assert!(matches!(
        guard.admit_for_request(&request_for(
            CallPurpose::AnswerGen,
            ModelLocality::ThirdParty
        )),
        Err(BudgetDenied::Exhausted)
    ));

    // First-come floor draws saturate the zero horizons: every row reports
    // 50/80/95 with its own index on the first ladder evaluation.
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

    // Floor draws are first-come and bounded by the global total: extraction
    // fills its floor, consolidation draws four more, and admission stops at
    // T = 100 even though unmatched floor headroom remains.
    for _ in 0..5 {
        guard
            .admit_for_request(&request_for(
                CallPurpose::Extraction,
                ModelLocality::ThirdParty,
            ))
            .expect("extraction floor draw");
    }
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

    let snapshot = meter_snapshot(&guard);
    assert_eq!(
        snapshot.rows,
        vec![(0, 60, 0, 60), (0, 40, 0, 40), (0, 0, 0, 0)]
    );
    assert_eq!(snapshot.reserved_units, 100);
    assert_eq!(snapshot.shared_reserved_units, 0);
    {
        let state = guard.state.lock().expect("saturation inspection");
        assert_eq!(state.shared_slice_units(), 0);
        assert_eq!(state.shared_admission_ceiling(), 0);
    }
    // The global ladder still uses T: committed reached exactly 100% of T and
    // never above, so all three global thresholds fired with row_index = None.
    assert_eq!(
        guard.read().fired_thresholds,
        vec![
            BudgetThreshold::Silent50,
            BudgetThreshold::Plan80,
            BudgetThreshold::Land95,
        ]
    );
}
