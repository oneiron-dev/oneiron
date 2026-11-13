//! FIX BUDGET-LEASE: a call's lease, once a physical attempt began under it,
//! can never be marked unsent. The meter reads that send evidence from its own
//! lease record (the counter the lease's transports write), so a caller's
//! unsent claim never clears the dispatch mark of a call that sent bytes: the
//! lease does not start again, and its abort charges the reservation.
//!
//! Public API only, so this file builds against the `oneiron-model` lib alone:
//! `cargo test --locked -p oneiron-model --all-features --test budget_unsent_evidence`.

use oneiron_model::llm::{
    BudgetAdmission, BudgetExhaustionPolicy, BudgetGuard, BudgetLease, DispatchBinding,
    DispatchRefused, ModelLocality,
};

/// The reservation one call holds on the 100-unit meter.
const RESERVE: u64 = 10;

fn binding() -> DispatchBinding {
    DispatchBinding {
        subject: "model:budget-unsent-evidence".into(),
        route: "provider:budget-unsent-evidence".into(),
        locality: ModelLocality::ThirdParty,
        offer: "offer:budget-unsent-evidence".into(),
        request_digest: None,
    }
}

/// A 100-unit meter with one bound lease of `RESERVE` units, started.
fn started_lease() -> (BudgetGuard, BudgetLease) {
    let meter = BudgetGuard::with_reserve_units(
        "budget-unsent-evidence",
        100,
        RESERVE,
        BudgetExhaustionPolicy::Suspend,
    );
    let BudgetAdmission { lease, .. } = meter
        .admit_reserve_bound(RESERVE, binding())
        .expect("the meter admits one bound call");
    meter
        .begin_dispatch(&lease, &binding())
        .expect("the bound call starts");
    (meter, lease)
}

#[test]
fn a_physical_attempt_cannot_be_reclassified_as_unsent() {
    let (meter, lease) = started_lease();
    lease.begin_physical_attempt();
    assert_eq!(lease.physical_attempts(), 1);
    assert!(
        meter.mark_unsent(&lease).is_err(),
        "physical-send evidence must forbid the unsent transition"
    );
}

#[test]
fn a_sent_lease_cannot_start_again() {
    let (meter, lease) = started_lease();
    lease.begin_physical_attempt();
    // The caller's unsent claim is refused, so the dispatch mark stays.
    let _refused = meter.mark_unsent(&lease);
    assert_eq!(
        meter.begin_dispatch(&lease, &binding()),
        Err(DispatchRefused::AlreadyDispatched),
        "a lease good for one call never starts a second after it sent"
    );
}

#[test]
fn a_sent_lease_abort_charges_its_reservation() {
    let (meter, lease) = started_lease();
    lease.begin_physical_attempt();
    let _refused = meter.mark_unsent(&lease);
    let settled = meter.abort(&lease).expect("the open lease settles");
    assert_eq!(
        (settled.read.used_units, settled.read.reserved_units),
        (RESERVE, 0),
        "a call that sent bytes pays its reservation as unknown usage"
    );
}

/// A pin: the unsent path a call that sent nothing takes is unchanged.
#[test]
fn an_unsent_lease_with_no_attempt_releases_its_reservation() {
    let (meter, lease) = started_lease();
    assert_eq!(lease.physical_attempts(), 0);
    meter
        .mark_unsent(&lease)
        .expect("a started call that sent nothing may be marked unsent");
    let settled = meter.abort(&lease).expect("the open lease settles");
    assert_eq!(
        (settled.read.used_units, settled.read.reserved_units),
        (0, 0),
        "an unsent call's reservation is released untouched"
    );
}
