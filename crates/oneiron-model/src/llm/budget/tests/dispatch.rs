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
    }
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
fn a_bound_lease_starts_one_call_and_its_clone_starts_none() {
    let guard = guard(20);
    let lease = bound_lease(&guard);
    let clone = lease.clone();
    assert_eq!(guard.begin_dispatch(&lease, "fake/small@v1", ROUTE), Ok(()));
    assert_eq!(
        guard.begin_dispatch(&clone, "fake/small@v1", ROUTE),
        Err(DispatchRefused::AlreadyDispatched)
    );
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
                guard.begin_dispatch(&lease, "fake/small@v1", ROUTE)
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
fn a_lease_from_another_meter_with_the_same_textual_id_starts_nothing() {
    let ours = guard(20);
    let theirs = guard(20);
    let foreign = bound_lease(&theirs);
    let _own = bound_lease(&ours);
    assert_eq!(
        ours.begin_dispatch(&foreign, "fake/small@v1", ROUTE),
        Err(DispatchRefused::ForeignLease)
    );
    assert_eq!(
        ours.begin_dispatch(&BudgetLease::for_test(foreign.id()), "fake/small@v1", ROUTE),
        Err(DispatchRefused::ForeignLease)
    );
    assert_eq!(ours.read().used_units, 0);
    assert_eq!(theirs.read().used_units, 0);
    assert_eq!(theirs.read().reserved_units, 6);
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
        assert_eq!(
            guard.begin_dispatch(lease, "fake/small@v1", ROUTE),
            Err(refusal)
        );
    }
}

#[test]
fn a_call_that_swapped_its_model_or_route_does_not_spend_the_permit() {
    let guard = guard(20);
    let lease = bound_lease(&guard);
    assert_eq!(
        guard.begin_dispatch(&lease, "fake/large@v1", ROUTE),
        Err(DispatchRefused::SubjectMismatch)
    );
    assert_eq!(
        guard.begin_dispatch(&lease, "fake/small@v1", "fake@https://paid.test:443"),
        Err(DispatchRefused::RouteMismatch)
    );
    assert_eq!(guard.begin_dispatch(&lease, "fake/small@v1", ROUTE), Ok(()));
}

#[test]
fn an_abort_after_dispatch_charges_the_reservation_and_an_abort_before_releases_it() {
    let guard = guard(20);
    let untouched = bound_lease(&guard);
    guard.abort(&untouched).expect("abort before dispatch");
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 0);

    let started = bound_lease(&guard);
    guard
        .begin_dispatch(&started, "fake/small@v1", ROUTE)
        .expect("dispatch");
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
fn an_unmetered_lease_needs_an_on_device_route() {
    let guard = guard(20);
    assert_eq!(
        guard.admit_unmetered(binding("fake/small@v1", ModelLocality::OwnServer)),
        Err(BudgetDenied::AdmissionDenied)
    );
    let lease = guard
        .admit_unmetered(binding("local/small@v1", ModelLocality::OnDevice))
        .expect("local lease")
        .lease;
    guard
        .begin_dispatch(&lease, "local/small@v1", ROUTE)
        .expect("dispatch");
    guard.settle_usage(&lease, 99).expect("settle");
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.reserved_for(&lease), Some(0));
}

#[test]
fn a_paid_reservation_is_bound_and_settles_its_actual_units() {
    let guard = guard(20);
    let lease = guard
        .admit_reserve_bound(
            3,
            DispatchBinding {
                subject: "search".to_owned(),
                route: "paid@https://paid.test:443".to_owned(),
                locality: ModelLocality::ThirdParty,
            },
        )
        .expect("paid admission")
        .lease;
    assert_eq!(guard.reserved_for(&lease), Some(3));
    assert_eq!(
        guard.begin_dispatch(&lease, "search", ROUTE),
        Err(DispatchRefused::RouteMismatch)
    );
    guard
        .begin_dispatch(&lease, "search", "paid@https://paid.test:443")
        .expect("dispatch");
    guard.settle_usage(&lease, 3).expect("settle");
    assert_eq!(guard.read().used_units, 3);
}

#[test]
fn an_answer_is_charged_its_tokens_or_the_floor_plus_a_floor_per_failed_rung() {
    let mut usage = LlmUsage::zero();
    assert_eq!(answered_units(&usage, 8), 8);
    usage.input.total = 3;
    usage.output.total = 1;
    assert_eq!(answered_units(&usage, 8), 4);
    usage.raw_provider = serde_json::json!({ FAILED_RUNGS_KEY: 2 });
    assert_eq!(answered_units(&usage, 8), 20);
    // Wide, nothing is lost before a caller converts it; narrow, it clamps.
    usage.input.total = u64::MAX;
    usage.output.total = u64::MAX;
    let wide = u128::from(u64::MAX) * 2 + 16;
    assert_eq!(answered_units_wide(&usage, 8), wide);
    assert_eq!(answered_units(&usage, 8), u64::MAX);
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

#[test]
fn a_revised_line_moves_the_limit_and_keeps_its_spend() {
    let guard = guard(12);
    let spent = bound_lease(&guard);
    guard.settle_usage(&spent, 6).expect("settle");
    let read = guard.revise_line(6, 6);
    assert_eq!((read.limit_units, read.used_units), (6, 6));
    assert_eq!(
        guard.admit_reserve_bound(6, binding("fake/small@v1", ModelLocality::ThirdParty)),
        Err(BudgetDenied::Exhausted)
    );
    guard.revise_line(30, 6);
    let lease = bound_lease(&guard);
    assert_eq!(guard.dispatched(&lease), Some(false));
    guard
        .begin_dispatch(&lease, "fake/small@v1", ROUTE)
        .expect("dispatch");
    assert_eq!(guard.dispatched(&lease), Some(true));
    assert_eq!(guard.read().used_units, 6);
}
