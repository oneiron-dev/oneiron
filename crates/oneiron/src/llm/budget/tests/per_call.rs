use super::*;

fn usage(input: u64, output: u64) -> LlmUsage {
    let mut usage = LlmUsage::zero();
    usage.input.total = input;
    usage.output.total = output;
    usage
}

#[test]
fn distinct_calls_add_and_duplicate_settlements_do_not_release_other_reservations() {
    let guard = BudgetGuard::with_reserve_units("calls", 100, 10, BudgetExhaustionPolicy::Suspend);
    let first = guard.admit().unwrap();
    let second = guard.admit().unwrap();
    let settled = guard.settle_per_call(&first.lease, &usage(3, 4)).unwrap();
    assert_eq!(settled.read.used_units, 7);
    assert_eq!(settled.read.reserved_units, 10);
    let before_duplicate = meter_snapshot(&guard);
    let duplicate = guard.settle_per_call(&first.lease, &usage(90, 9)).unwrap();
    assert_eq!(duplicate.read, settled.read);
    assert!(duplicate.ladder_events.is_empty());
    assert_eq!(meter_snapshot(&guard), before_duplicate);
    guard.settle_absolute(&first.lease, 99).unwrap();
    assert_eq!(meter_snapshot(&guard), before_duplicate);

    let settled = guard.settle_per_call(&second.lease, &usage(3, 4)).unwrap();
    assert_eq!(settled.read.used_units, 14);
    assert_eq!(settled.read.reserved_units, 0);
    assert_eq!(settled.read.remaining_units, 86);
    assert_eq!(meter_snapshot(&guard).shared_used_units, 14);
    assert!(matches!(
        guard.abort(&second.lease),
        Err(BudgetDenied::LeaseInvalid)
    ));
}

#[test]
fn absolute_settlements_keep_their_watermark_semantics() {
    let guard = BudgetGuard::with_reserve_units("mixed", 100, 1, BudgetExhaustionPolicy::Suspend);
    let first = guard.admit().unwrap();
    guard.settle_terminal(&first.lease, &usage(3, 4)).unwrap();
    let second = guard.admit().unwrap();
    guard.settle_terminal(&second.lease, &usage(3, 4)).unwrap();
    assert_eq!(guard.read().used_units, 7);
    let before_duplicate = meter_snapshot(&guard);
    guard.settle_per_call(&second.lease, &usage(3, 4)).unwrap();
    assert_eq!(meter_snapshot(&guard), before_duplicate);
    let third = guard.admit().unwrap();
    guard.settle_per_call(&third.lease, &usage(3, 4)).unwrap();
    assert_eq!(guard.read().used_units, 14);
    let fourth = guard.admit().unwrap();
    guard.settle_absolute(&fourth.lease, 12).unwrap();
    assert_eq!(guard.read().used_units, 14);
}

#[test]
fn unknown_foreign_and_aborted_leases_cannot_charge_or_refund() {
    let guard = BudgetGuard::with_reserve_units("owner", 100, 10, BudgetExhaustionPolicy::Suspend);
    let foreign =
        BudgetGuard::with_reserve_units("foreign", 100, 10, BudgetExhaustionPolicy::Suspend);
    let foreign_lease = foreign.admit().unwrap();
    let aborted = guard.admit().unwrap();
    guard.abort(&aborted.lease).unwrap();
    let open = guard.admit().unwrap();
    let before = (guard.read(), meter_snapshot(&guard));
    for lease in [
        foreign_lease.lease,
        aborted.lease,
        BudgetLease::for_test("unknown"),
    ] {
        assert!(matches!(
            guard.settle_per_call(&lease, &usage(3, 4)),
            Err(BudgetDenied::LeaseInvalid)
        ));
        assert_eq!((guard.read(), meter_snapshot(&guard)), before);
    }
    guard.settle_per_call(&open.lease, &usage(3, 4)).unwrap();
    assert_eq!(guard.read().used_units, 7);
    assert_eq!(foreign.read().reserved_units, 10);
}

#[test]
fn same_textual_ids_from_independent_guards_are_not_authority() {
    let table = BudgetPolicyTable::from_rows(vec![actor_row(0x64, Some(6), Some(100))]);
    for policy_aware in [false, true] {
        let make_guard = || {
            if policy_aware {
                BudgetGuard::with_policy_table(
                    "same-attempt",
                    100,
                    10,
                    BudgetExhaustionPolicy::Suspend,
                    policy_test_actor(0x64),
                    &table,
                )
            } else {
                BudgetGuard::with_reserve_units(
                    "same-attempt",
                    100,
                    10,
                    BudgetExhaustionPolicy::Suspend,
                )
            }
        };
        let guard = make_guard();
        let foreign = make_guard();
        let local = guard.admit().unwrap().lease;
        let other = foreign.admit().unwrap().lease;
        assert_eq!(local.id(), "same-attempt:metered:1");
        assert_eq!(local.id(), other.id());
        assert_eq!(format!("{local:?}"), format!("{other:?}"));
        assert_ne!(local, other);
        let leases = std::collections::HashSet::from([local.clone(), local.clone(), other.clone()]);
        assert_eq!(leases.len(), 2);
        let before = (guard.read(), meter_snapshot(&guard));
        let foreign_before = (foreign.read(), meter_snapshot(&foreign));
        for lease in [&other, &BudgetLease::for_test(local.id())] {
            assert_eq!(
                guard.settle_per_call(lease, &usage(90, 9)),
                Err(BudgetDenied::LeaseInvalid)
            );
            assert_eq!((guard.read(), meter_snapshot(&guard)), before);
            assert_eq!(
                guard.settle_absolute(lease, 99),
                Err(BudgetDenied::LeaseInvalid)
            );
            assert_eq!((guard.read(), meter_snapshot(&guard)), before);
            assert_eq!(
                guard.settle_terminal(lease, &usage(90, 9)),
                Err(BudgetDenied::LeaseInvalid)
            );
            assert_eq!((guard.read(), meter_snapshot(&guard)), before);
            assert_eq!(guard.abort(lease), Err(BudgetDenied::LeaseInvalid));
            assert_eq!((guard.read(), meter_snapshot(&guard)), before);
        }
        assert_eq!((foreign.read(), meter_snapshot(&foreign)), foreign_before);
        guard.settle_per_call(&local, &usage(3, 4)).unwrap();
        let settled = (guard.read(), meter_snapshot(&guard));
        assert_eq!(settled.0.used_units, 7);
        assert_eq!(settled.0.reserved_units, 0);
        // A settled record must not turn foreign settlement into a duplicate no-op.
        assert_eq!(
            guard.settle_per_call(&other, &usage(3, 4)),
            Err(BudgetDenied::LeaseInvalid)
        );
        assert_eq!(
            guard.settle_absolute(&other, 7),
            Err(BudgetDenied::LeaseInvalid)
        );
        assert_eq!((guard.read(), meter_snapshot(&guard)), settled);
        foreign.abort(&other).unwrap();
        assert_eq!(foreign.read().used_units, 0);
        assert_eq!(foreign.read().reserved_units, 0);
    }
}

#[test]
fn guard_and_lease_clones_share_settlement_and_abort_authority() {
    let guard = BudgetGuard::with_reserve_units("clones", 100, 10, BudgetExhaustionPolicy::Suspend);
    let clone = guard.clone();
    let first = guard.admit().unwrap().lease;
    let copied = first.clone();
    assert_eq!(first, copied);
    clone.settle_per_call(&copied, &usage(3, 4)).unwrap();
    let settled = meter_snapshot(&guard);
    assert_eq!(settled.used_units, 7);
    guard.settle_terminal(&first, &usage(90, 9)).unwrap();
    clone.settle_per_call(&copied, &usage(90, 9)).unwrap();
    assert_eq!(meter_snapshot(&guard), settled);

    let second = clone.admit().unwrap().lease;
    guard.settle_absolute(&second, 12).unwrap();
    clone.settle_per_call(&second, &usage(90, 9)).unwrap();
    assert_eq!(guard.read().used_units, 12);
    let third = guard.admit().unwrap().lease;
    let third_copy = third.clone();
    clone.settle_terminal(&third_copy, &usage(3, 4)).unwrap();
    guard.settle_absolute(&third, 99).unwrap();
    assert_eq!(
        guard.read().used_units,
        12,
        "absolute usage is still a watermark"
    );

    let original = clone.admit().unwrap().lease;
    let aborted = original.clone();
    drop(original);
    guard.abort(&aborted).unwrap();
    let after_abort = meter_snapshot(&guard);
    clone.abort(&aborted).unwrap();
    assert_eq!(meter_snapshot(&guard), after_abort);
    assert_eq!(guard.read().reserved_units, 0);
    assert_eq!(
        clone.settle_per_call(&aborted, &usage(3, 4)),
        Err(BudgetDenied::LeaseInvalid)
    );
}

#[test]
fn out_of_order_calls_conserve_rows_floors_shared_and_caps() {
    let table = BudgetPolicyTable::from_rows(vec![
        purpose_row(CallPurpose::Extraction, Some(6), Some(14)),
        actor_row(0x60, Some(4), Some(25)),
        purpose_row(CallPurpose::Voice, Some(10), None),
    ]);
    let guard = BudgetGuard::with_policy_table(
        "rows",
        40,
        4,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x60),
        &table,
    );
    let extraction = request_for(CallPurpose::Extraction, ModelLocality::ThirdParty);
    let voice = request_for(CallPurpose::Voice, ModelLocality::ThirdParty);
    let first = guard.admit_for_request(&extraction).unwrap();
    let other = guard.admit_for_request(&voice).unwrap();
    let second = guard.admit_for_request(&extraction).unwrap();

    // The second call cannot consume floor headroom reserved by the first
    // extraction or by the voice call. Its overshoot spills into shared.
    guard.settle_per_call(&second.lease, &usage(3, 4)).unwrap();
    let pending = meter_snapshot(&guard);
    assert_eq!(pending.used_units, 7);
    assert_eq!(pending.reserved_units, 8);
    assert_eq!(pending.rows, vec![(7, 4, 2, 4), (7, 8, 0, 4), (0, 4, 0, 0)]);
    assert_eq!(pending.shared_used_units, 5);
    assert_eq!(pending.shared_reserved_units, 0);
    guard.settle_per_call(&second.lease, &usage(9, 9)).unwrap();
    assert_eq!(meter_snapshot(&guard), pending);

    guard.settle_per_call(&other.lease, &usage(1, 2)).unwrap();
    guard.settle_per_call(&first.lease, &usage(3, 4)).unwrap();
    let settled = meter_snapshot(&guard);
    assert_eq!(settled.used_units, 17);
    assert_eq!(settled.reserved_units, 0);
    assert_eq!(
        settled.rows,
        vec![(14, 0, 6, 0), (17, 0, 4, 0), (3, 0, 0, 0)]
    );
    assert_eq!(settled.shared_used_units, 7);
    assert_eq!(settled.shared_reserved_units, 0);
    assert_eq!(settled.open_leases, 0);
    assert_eq!(
        settled.used_units,
        settled.shared_used_units + settled.rows.iter().map(|r| r.2).sum::<u64>()
    );
    assert_eq!(guard.read().remaining_units, 23);

    // A matching cap denial creates no lease and changes no accounting.
    let before_denial = (guard.read(), meter_snapshot(&guard));
    assert!(matches!(
        guard.admit_for_request(&extraction),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!((guard.read(), meter_snapshot(&guard)), before_denial);
    let allowed = guard.admit_for_request(&voice).unwrap();
    guard.settle_per_call(&allowed.lease, &usage(3, 5)).unwrap();
    let settled = meter_snapshot(&guard);
    assert_eq!(settled.used_units, 25);
    assert_eq!(
        settled.rows,
        vec![(14, 0, 6, 0), (25, 0, 4, 0), (11, 0, 8, 0)]
    );
    assert_eq!(settled.shared_used_units, 7);
    assert!(matches!(
        guard.admit_for_request(&voice),
        Err(BudgetDenied::Exhausted)
    ));
    assert_eq!(meter_snapshot(&guard), settled);
}

#[test]
fn concurrent_distinct_and_duplicate_calls_charge_once_under_shared_mutex() {
    const CALLS: usize = 32;
    let table = BudgetPolicyTable::from_rows(vec![
        purpose_row(CallPurpose::Extraction, Some(100), Some(1_000)),
        actor_row(0x61, Some(50), Some(1_000)),
    ]);
    let guard = BudgetGuard::with_policy_table(
        "concurrent",
        1_000,
        1,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x61),
        &table,
    );
    let request = request_for(CallPurpose::Extraction, ModelLocality::ThirdParty);
    let leases: Vec<_> = (0..CALLS)
        .map(|_| guard.admit_for_request(&request).unwrap().lease)
        .collect();
    let start = Arc::new(Barrier::new(CALLS * 2));
    let mut handles = Vec::new();
    // Spawn every contender before joining. Each real lease races its clone.
    for lease in leases.iter().rev().chain(leases.iter()) {
        let guard = guard.clone();
        let lease = lease.clone();
        let start = Arc::clone(&start);
        handles.push(thread::spawn(move || {
            start.wait();
            guard.settle_per_call(&lease, &usage(3, 4)).unwrap();
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let settled = meter_snapshot(&guard);
    assert_eq!(settled.used_units, 224);
    assert_eq!(settled.reserved_units, 0);
    assert_eq!(settled.rows, vec![(224, 0, 100, 0), (224, 0, 50, 0)]);
    assert_eq!(settled.shared_used_units, 74);
    assert_eq!(settled.shared_reserved_units, 0);
    assert_eq!(settled.open_leases, 0);
    assert_eq!(settled.total_leases, CALLS);
}

#[test]
fn per_call_usage_and_tallies_saturate_and_admitted_overshoot_still_settles() {
    let table =
        BudgetPolicyTable::from_rows(vec![purpose_row(CallPurpose::Extraction, None, Some(10))]);
    let guard = BudgetGuard::with_policy_table(
        "overflow",
        10,
        1,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x62),
        &table,
    );
    let request = request_for(CallPurpose::Extraction, ModelLocality::ThirdParty);
    let first = guard.admit_for_request(&request).unwrap();
    let second = guard.admit_for_request(&request).unwrap();
    guard.settle_per_call(&first.lease, &usage(3, 4)).unwrap();
    let settled = guard
        .settle_per_call(&second.lease, &usage(u64::MAX - 2, 5))
        .unwrap();
    assert_eq!(settled.read.used_units, u64::MAX);
    assert_eq!(settled.read.remaining_units, 0);
    let snapshot = meter_snapshot(&guard);
    assert_eq!(snapshot.rows, vec![(u64::MAX, 0, 0, 0)]);
    assert_eq!(snapshot.shared_used_units, u64::MAX);
    assert_eq!(snapshot.reserved_units, 0);
    assert!(matches!(
        guard.admit_for_request(&request),
        Err(BudgetDenied::Exhausted)
    ));
    guard.settle_per_call(&second.lease, &usage(1, 1)).unwrap();
    assert_eq!(meter_snapshot(&guard), snapshot);
}

#[test]
fn explicit_local_continuation_stays_unmetered() {
    let guard =
        BudgetGuard::with_reserve_units("local", 10, 10, BudgetExhaustionPolicy::ContinueOnLocal);
    let metered = guard.admit().unwrap();
    let local = guard.admit_local().unwrap();
    let foreign =
        BudgetGuard::with_reserve_units("local", 10, 10, BudgetExhaustionPolicy::ContinueOnLocal);
    let _foreign_metered = foreign.admit().unwrap();
    let foreign_local = foreign.admit_local().unwrap();
    assert_eq!(local.lease.id(), foreign_local.lease.id());
    let snapshot = meter_snapshot(&guard);
    assert_eq!(
        guard.settle_per_call(&foreign_local.lease, &usage(3, 4)),
        Err(BudgetDenied::LeaseInvalid)
    );
    assert_eq!(
        guard.settle_absolute(&foreign_local.lease, 7),
        Err(BudgetDenied::LeaseInvalid)
    );
    assert_eq!(
        guard.abort(&foreign_local.lease),
        Err(BudgetDenied::LeaseInvalid)
    );
    assert_eq!(meter_snapshot(&guard), snapshot);
    let before = guard.read();
    let cloned_guard = guard.clone();
    drop(guard);
    let guard = cloned_guard;
    guard.settle_per_call(&local.lease, &usage(3, 4)).unwrap();
    assert_eq!(guard.read(), before);
    guard.settle_per_call(&metered.lease, &usage(3, 4)).unwrap();
    assert_eq!(guard.read().used_units, 7);
    assert_eq!(guard.read().reserved_units, 0);
    let settled = meter_snapshot(&guard);
    guard
        .settle_per_call(&local.lease, &usage(u64::MAX, 1))
        .unwrap();
    assert_eq!(meter_snapshot(&guard), settled);
}

#[test]
fn zero_usage_refunds_all_partitions_and_additive_ladders_fire_once() {
    let table = BudgetPolicyTable::from_rows(vec![purpose_row(
        CallPurpose::Extraction,
        Some(3),
        Some(10),
    )]);
    let guard = BudgetGuard::with_policy_table(
        "ladder",
        10,
        4,
        BudgetExhaustionPolicy::Suspend,
        policy_test_actor(0x63),
        &table,
    );
    let request = request_for(CallPurpose::Extraction, ModelLocality::ThirdParty);
    let unused = guard.admit_for_request(&request).unwrap();
    let reserved = meter_snapshot(&guard);
    assert_eq!(reserved.rows, vec![(0, 4, 0, 3)]);
    assert_eq!(reserved.shared_reserved_units, 1);
    guard.settle_per_call(&unused.lease, &usage(0, 0)).unwrap();
    let refunded = meter_snapshot(&guard);
    assert_eq!(refunded.rows, vec![(0, 0, 0, 0)]);
    assert_eq!(refunded.used_units, 0);
    assert_eq!(refunded.reserved_units, 0);
    assert_eq!(refunded.shared_used_units, 0);
    assert_eq!(refunded.shared_reserved_units, 0);

    let first = guard.admit_for_request(&request).unwrap();
    let second = guard.admit_for_request(&request).unwrap();
    let settled = guard.settle_per_call(&second.lease, &usage(3, 4)).unwrap();
    let events: Vec<_> = settled
        .ladder_events
        .iter()
        .map(|event| (event.threshold, event.row_index))
        .collect();
    assert_eq!(
        events,
        vec![
            (BudgetThreshold::Land95, None),
            (BudgetThreshold::Land95, Some(0)),
        ]
    );
    guard.settle_per_call(&first.lease, &usage(3, 4)).unwrap();
    assert_eq!(guard.read().used_units, 14);
    let before = meter_snapshot(&guard);
    let duplicate = guard.settle_per_call(&second.lease, &usage(3, 4)).unwrap();
    assert!(duplicate.ladder_events.is_empty());
    assert_eq!(meter_snapshot(&guard), before);
}
