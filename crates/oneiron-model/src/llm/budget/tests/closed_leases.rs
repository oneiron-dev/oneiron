//! FIX BUDGET-LINE-LEASE-TABLE-UNBOUNDED: a meter keeps a record for its open
//! leases only, while every handle of a closed lease still answers as before.

use super::*;

use crate::llm::{DispatchBinding, DispatchRefused};

const DIGEST: &str = "sha256:request";

fn call() -> DispatchBinding {
    DispatchBinding {
        subject: "fake/small@v1".to_owned(),
        route: "fake@https://model.test:443".to_owned(),
        locality: ModelLocality::ThirdParty,
        offer: "customer-key".to_owned(),
        request_digest: Some(DIGEST.to_owned()),
    }
}

fn guard() -> BudgetGuard {
    BudgetGuard::with_reserve_units("run", 10_000, 6, BudgetExhaustionPolicy::Suspend)
}

fn bound_lease(guard: &BudgetGuard) -> BudgetLease {
    guard
        .admit_reserve_bound(6, call())
        .expect("bound admission")
        .lease
}

#[test]
fn the_meter_keeps_only_its_open_leases() {
    let guard = guard();
    for _ in 0..64 {
        let settled = bound_lease(&guard);
        guard.begin_dispatch(&settled, &call()).expect("dispatch");
        guard.settle_usage(&settled, 1).expect("settle");
        let aborted = guard.admit_local().expect("local admission").lease;
        guard.abort(&aborted).expect("abort");
        let started = bound_lease(&guard);
        guard.begin_dispatch(&started, &call()).expect("dispatch");
        guard.abort(&started).expect("abort after dispatch");
    }
    assert_eq!(guard.read().used_units, 64 * 7);
    let open = bound_lease(&guard);
    assert_eq!(guard.lock_state().leases.len(), 1);
    guard.settle_reserved(&open).expect("settle the open lease");
    assert_eq!(guard.lock_state().leases.len(), 0);
}

#[test]
fn a_settled_lease_answers_through_every_handle() {
    let guard = guard();
    let lease = bound_lease(&guard);
    let early = lease.clone();
    guard.begin_dispatch(&lease, &call()).expect("dispatch");
    guard.settle_usage(&lease, 4).expect("settle");
    let late = lease.clone();
    for handle in [&lease, &early, &late] {
        assert_eq!(guard.lease_open(handle), Some(false));
        assert_eq!(guard.dispatched(handle), Some(true));
        assert_eq!(guard.reserved_for(handle), Some(6));
        assert_eq!(
            guard.admitted_request_digest(handle).as_deref(),
            Some(DIGEST)
        );
        assert_eq!(
            guard.begin_dispatch(handle, &call()),
            Err(DispatchRefused::Closed)
        );
        assert!(matches!(
            guard.mark_unsent(handle),
            Err(BudgetDenied::LeaseInvalid)
        ));
        // A second settlement on any API charges nothing; an abort is refused.
        guard.settle_usage(handle, 9).expect("repeat settle");
        guard
            .settle_absolute(handle, 99)
            .expect("repeat absolute settle");
        guard
            .settle_reserved(handle)
            .expect("repeat reserved settle");
        assert!(matches!(
            guard.abort(handle),
            Err(BudgetDenied::LeaseInvalid)
        ));
    }
    assert_eq!(guard.read().used_units, 4);
    assert_eq!(guard.read().reserved_units, 0);
}

#[test]
fn an_aborted_lease_answers_through_every_handle() {
    let guard = guard();
    let lease = bound_lease(&guard);
    let early = lease.clone();
    guard.abort(&lease).expect("abort");
    let late = lease.clone();
    for handle in [&lease, &early, &late] {
        assert_eq!(guard.lease_open(handle), Some(false));
        assert_eq!(guard.dispatched(handle), Some(false));
        assert_eq!(guard.reserved_for(handle), Some(6));
        assert_eq!(
            guard.admitted_request_digest(handle).as_deref(),
            Some(DIGEST)
        );
        assert_eq!(
            guard.begin_dispatch(handle, &call()),
            Err(DispatchRefused::Closed)
        );
        assert!(matches!(
            guard.mark_unsent(handle),
            Err(BudgetDenied::LeaseInvalid)
        ));
        // A second abort releases nothing; a settlement is refused.
        guard.abort(handle).expect("repeat abort");
        assert!(matches!(
            guard.settle_usage(handle, 1),
            Err(BudgetDenied::LeaseInvalid)
        ));
        assert!(matches!(
            guard.settle_absolute(handle, 1),
            Err(BudgetDenied::LeaseInvalid)
        ));
        assert!(matches!(
            guard.settle_reserved(handle),
            Err(BudgetDenied::LeaseInvalid)
        ));
    }
    assert_eq!(guard.read().used_units, 0);
    assert_eq!(guard.read().reserved_units, 0);
}

#[test]
fn a_started_abort_closes_as_a_settlement() {
    let guard = guard();
    let lease = bound_lease(&guard);
    guard.begin_dispatch(&lease, &call()).expect("dispatch");
    guard.abort(&lease).expect("abort after dispatch");
    assert_eq!(guard.read().used_units, 6);
    assert_eq!(guard.dispatched(&lease), Some(true));
    assert!(matches!(
        guard.abort(&lease),
        Err(BudgetDenied::LeaseInvalid)
    ));
    guard.settle_usage(&lease, 4).expect("later completion");
    assert_eq!(guard.read().used_units, 6);
    assert_eq!(guard.read().reserved_units, 0);
}

#[test]
fn a_foreign_lease_with_a_closed_leases_id_stays_foreign() {
    let guard = guard();
    let foreign = self::guard();
    let ours = bound_lease(&guard);
    let theirs = bound_lease(&foreign);
    assert_eq!(ours.id(), theirs.id());
    guard.settle_usage(&ours, 2).expect("settle");
    assert_eq!(guard.lease_open(&theirs), None);
    assert_eq!(guard.dispatched(&theirs), None);
    assert_eq!(guard.reserved_for(&theirs), None);
    assert_eq!(guard.admitted_request_digest(&theirs), None);
    assert_eq!(
        guard.begin_dispatch(&theirs, &call()),
        Err(DispatchRefused::ForeignLease)
    );
    assert!(matches!(
        guard.settle_reserved(&theirs),
        Err(BudgetDenied::LeaseInvalid)
    ));
    assert_eq!(foreign.lease_open(&theirs), Some(true));
}

#[test]
fn a_lease_observation_reads_a_closed_lease_through_its_handle() {
    let guard = guard();
    let foreign = self::guard();
    let settled = bound_lease(&guard);
    let theirs = bound_lease(&foreign);
    guard.begin_dispatch(&settled, &call()).expect("dispatch");
    assert_eq!(
        guard.lease_observation(&settled),
        Some(BudgetLeaseState::Open {
            reserve_units: 6,
            dispatched: true,
        })
    );
    guard.settle_usage(&settled, 4).expect("settle");
    let aborted = bound_lease(&guard);
    guard.abort(&aborted).expect("abort");
    for handle in [&settled, &settled.clone()] {
        assert_eq!(
            guard.lease_observation(handle),
            Some(BudgetLeaseState::Settled { used_units: 4 })
        );
    }
    assert_eq!(
        guard.lease_observation(&aborted),
        Some(BudgetLeaseState::Aborted)
    );
    // Another meter's lease with the same id is not this meter's lease.
    assert_eq!(theirs.id(), settled.id());
    assert_eq!(guard.lease_observation(&theirs), None);
    assert_eq!(
        foreign.lease_observation(&theirs),
        Some(BudgetLeaseState::Open {
            reserve_units: 6,
            dispatched: false,
        })
    );
}

/// A meter whose lease sequence is spent issues no second lease under the
/// last id: closing one would remove the other's record (review P1 of
/// #9388). The refusal comes before any reservation is planned.
#[test]
fn a_spent_lease_sequence_issues_no_second_lease_under_one_id() {
    let mut checkpoint =
        serde_json::to_value(guard().checkpoint().expect("checkpoint")).expect("checkpoint json");
    checkpoint["next_lease_seq"] = serde_json::json!(u64::MAX - 1);
    let guard =
        BudgetGuard::from_checkpoint(serde_json::from_value(checkpoint).expect("checkpoint"))
            .expect("restore");
    let last = guard.admit_local().expect("the last lease id").lease;
    assert_eq!(
        guard.admit_local().map(|_| ()),
        Err(BudgetDenied::AdmissionDenied)
    );
    assert_eq!(
        guard.admit_reserve_bound(6, call()).map(|_| ()),
        Err(BudgetDenied::AdmissionDenied)
    );
    assert_eq!(guard.read().reserved_units, 0);
    guard.settle_usage(&last, 1).expect("settle the last lease");
    assert_eq!(guard.lease_open(&last), Some(false));
    guard
        .settle_usage(&last, 1)
        .expect("a repeated settlement changes nothing");
    assert_eq!(guard.lock_state().leases.len(), 0);
}
