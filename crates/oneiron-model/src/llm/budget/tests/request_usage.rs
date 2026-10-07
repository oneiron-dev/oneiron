use super::*;

#[test]
fn retrieval_depth_request_usage_is_additive_and_idempotent_out_of_order() {
    let guard =
        BudgetGuard::with_reserve_units("requests", 34, 17, BudgetExhaustionPolicy::Suspend);
    let first = guard.admit().expect("first request");
    let second = guard.admit().expect("second concurrent request");
    guard
        .settle_usage(&second.lease, 17)
        .expect("second finishes first");
    assert_eq!(guard.read().used_units, 17);
    assert_eq!(guard.read().reserved_units, 17);
    guard
        .settle_usage(&first.lease, 17)
        .expect("first finishes");
    assert_eq!(guard.read().used_units, 34);
    assert_eq!(guard.read().reserved_units, 0);
    guard
        .settle_usage(&second.lease, 90)
        .expect("duplicate settlement");
    assert_eq!(guard.read().used_units, 34);
    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
}

#[test]
fn retrieval_depth_request_usage_settlements_are_atomic_across_threads() {
    const REQUESTS: usize = 8;
    let guard =
        BudgetGuard::with_reserve_units("requests", 100, 10, BudgetExhaustionPolicy::Suspend);
    let admissions = (0..REQUESTS).map(|_| guard.admit().unwrap());
    let start = Arc::new(Barrier::new(REQUESTS));
    // Spawn every worker before joining: they rendezvous on the same barrier.
    let handles: Vec<_> = admissions
        .map(|admission| {
            let guard = guard.clone();
            let start = start.clone();
            thread::spawn(move || {
                start.wait();
                guard.settle_usage(&admission.lease, 7).unwrap();
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("settlement thread");
    }
    assert_eq!(guard.read().used_units, 56);
    assert_eq!(guard.read().reserved_units, 0);
}

#[test]
fn retrieval_depth_request_usage_records_overspend_and_rejects_aborted_leases() {
    let guard = BudgetGuard::with_reserve_units("requests", 10, 8, BudgetExhaustionPolicy::Suspend);
    let canceled = guard.admit().unwrap();
    guard.abort(&canceled.lease).unwrap();
    assert!(matches!(
        guard.settle_usage(&canceled.lease, 3),
        Err(BudgetDenied::LeaseInvalid)
    ));
    let admitted = guard.admit().unwrap();
    guard
        .settle_usage(&admitted.lease, 14)
        .expect("actual usage, not a hard cap");
    assert_eq!(guard.read().used_units, 14);
    assert_eq!(guard.read().reserved_units, 0);
    assert!(matches!(guard.admit(), Err(BudgetDenied::Exhausted)));
}
