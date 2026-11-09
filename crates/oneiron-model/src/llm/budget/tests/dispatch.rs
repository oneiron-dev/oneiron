use super::*;

use crate::llm::{
    DispatchBinding, DispatchRefused, FAILED_RUNGS_KEY, answered_units, answered_units_wide,
};

const ROUTE: &str = "fake@https://model.test:443";

fn binding(model: &str, locality: ModelLocality) -> DispatchBinding {
    DispatchBinding {
        subject: model.to_owned(),
        route: ROUTE.to_owned(),
        locality,
        offer: "customer-key".to_owned(),
        request_digest: None,
    }
}

fn small() -> DispatchBinding {
    binding("fake/small@v1", ModelLocality::ThirdParty)
}

fn guard(limit: u64) -> BudgetGuard {
    BudgetGuard::with_reserve_units("run", limit, 6, BudgetExhaustionPolicy::Suspend)
}

fn bound_lease(guard: &BudgetGuard) -> BudgetLease {
    guard
        .admit_reserve_bound(6, binding("fake/small@v1", ModelLocality::ThirdParty))
        .expect("bound admission")
        .lease
}

#[test]
fn two_threads_racing_one_permit_start_exactly_one_call() {
    for _ in 0..64 {
        let guard = Arc::new(guard(20));
        let lease = bound_lease(&guard);
        let start = Arc::new(Barrier::new(2));
        let racers: [_; 2] = std::array::from_fn(|_| {
            let guard = Arc::clone(&guard);
            let lease = lease.clone();
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                guard.begin_dispatch(&lease, &small())
            })
        });
        let started = racers
            .into_iter()
            .map(|racer| racer.join().expect("racer"))
            .filter(Result::is_ok)
            .count();
        assert_eq!(started, 1);
    }
}

#[test]
fn settled_aborted_and_unbound_leases_start_nothing() {
    let guard = guard(40);
    let settled = bound_lease(&guard);
    guard.settle_usage(&settled, 4).expect("settle");
    let aborted = bound_lease(&guard);
    guard.abort(&aborted).expect("abort");
    let unbound = guard.admit().expect("plain admission").lease;
    for (lease, refusal) in [
        (&settled, DispatchRefused::Closed),
        (&aborted, DispatchRefused::Closed),
        (&unbound, DispatchRefused::Unbound),
    ] {
        assert_eq!(guard.begin_dispatch(lease, &small()), Err(refusal));
    }
}

#[test]
fn an_abort_after_dispatch_charges_the_reservation_and_an_abort_before_releases_it() {
    let guard = guard(20);
    let untouched = bound_lease(&guard);
    guard.abort(&untouched).expect("abort before dispatch");
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 0);

    let started = bound_lease(&guard);
    guard.begin_dispatch(&started, &small()).expect("dispatch");
    guard.abort(&started).expect("abort after dispatch");
    assert_eq!(guard.read().used_units, 6);
    assert_eq!(guard.read().reserved_units, 0);
    // The charge is a settlement: a later completion is not charged again.
    guard
        .settle_usage(&started, 4)
        .expect("duplicate completion");
    assert_eq!(guard.read().used_units, 6);
}

#[test]
fn a_line_at_u64_max_never_admits_past_its_limit() {
    let guard = guard(u64::MAX);
    let binding = || binding("fake/small@v1", ModelLocality::ThirdParty);
    let whole = guard
        .admit_reserve_bound(u64::MAX, binding())
        .expect("the whole line")
        .lease;
    assert_eq!(
        guard.admit_reserve_bound(1, binding()),
        Err(BudgetDenied::Exhausted)
    );
    guard.abort(&whole).expect("release unsent");
    let one = guard.admit_reserve_bound(1, binding()).expect("one unit");
    assert_eq!(guard.read().reserved_units, 1);
    guard.settle_usage(&one.lease, u64::MAX).expect("overrun");
    assert_eq!(
        guard.admit_reserve_bound(1, binding()),
        Err(BudgetDenied::Exhausted)
    );
}

