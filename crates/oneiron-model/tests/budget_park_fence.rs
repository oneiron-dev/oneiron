//! FIX BUDGET-PARK: parking a workflow's budget fences every handle of the
//! original meter. `BudgetGuard::park` takes the settled checkpoint and, in the
//! same lock, sets a Parked phase that every clone of the meter shares, so no
//! handle of it admits again: unmetered and free work included. A plain
//! `checkpoint` stays a snapshot, and the resumed meter
//! (`BudgetGuard::from_checkpoint`) admits as before.
//!
//! Public API only, so this file builds against the `oneiron-model` lib alone:
//! `cargo test --locked -p oneiron-model --all-features --test budget_park_fence`.

use oneiron_model::llm::{BudgetExhaustionPolicy, BudgetGuard, DispatchBinding, ModelLocality};

/// The reservation of one call on the 10-unit meter.
const RESERVE: u64 = 2;

fn meter() -> BudgetGuard {
    BudgetGuard::with_reserve_units(
        "budget-park-fence",
        10,
        RESERVE,
        BudgetExhaustionPolicy::Suspend,
    )
}

fn binding(locality: ModelLocality) -> DispatchBinding {
    DispatchBinding {
        subject: "model:budget-park-fence".into(),
        route: "provider:budget-park-fence".into(),
        locality,
        offer: "offer:budget-park-fence".into(),
        request_digest: None,
    }
}

/// One call of `RESERVE` units, settled, so the meter carries spend.
fn spend_once(meter: &BudgetGuard) {
    let admission = meter.admit().expect("the meter admits one call");
    meter
        .settle_reserved(&admission.lease)
        .expect("the call settles");
}

#[test]
fn parking_a_budget_fences_every_handle_to_the_original_meter() {
    let meter = meter();
    let old_handle = meter.clone();
    spend_once(&meter);
    let checkpoint = meter.park().expect("a settled meter parks");
    let resumed = BudgetGuard::from_checkpoint(checkpoint).expect("the checkpoint restores");
    resumed.admit().expect("the resumed meter admits");
    assert!(
        old_handle.admit().is_err(),
        "a handle of the parked meter must not admit again"
    );
}

#[test]
fn a_parked_meter_refuses_every_admission() {
    let meter = meter();
    spend_once(&meter);
    meter.park().expect("a settled meter parks");
    let admitted: Vec<&str> = [
        ("admit", meter.admit().is_ok()),
        ("admit_reserve", meter.admit_reserve(RESERVE).is_ok()),
        ("admit_local", meter.admit_local().is_ok()),
        (
            "admit_unmetered",
            meter
                .admit_unmetered(binding(ModelLocality::OnDevice))
                .is_ok(),
        ),
        (
            "admit_free_work",
            meter
                .admit_free_work(binding(ModelLocality::OwnServer), true)
                .is_ok(),
        ),
        (
            "admit_reserve_bound",
            meter
                .admit_reserve_bound(RESERVE, binding(ModelLocality::ThirdParty))
                .is_ok(),
        ),
    ]
    .into_iter()
    .filter_map(|(door, ok)| ok.then_some(door))
    .collect();
    assert!(
        admitted.is_empty(),
        "these doors admitted on a parked meter: {admitted:?}"
    );
}

/// A pin: a plain checkpoint is a snapshot and fences nothing.
#[test]
fn a_plain_checkpoint_leaves_the_meter_open() {
    let meter = meter();
    spend_once(&meter);
    meter.checkpoint().expect("a settled meter checkpoints");
    assert!(
        meter.admit().is_ok(),
        "a snapshot must leave its meter admitting"
    );
}

/// A pin: a park refused for an open lease fences nothing.
#[test]
fn a_refused_park_leaves_the_meter_open() {
    let meter = meter();
    let open = meter.admit().expect("the meter admits one call");
    assert!(meter.park().is_err(), "an open lease refuses the park");
    meter
        .settle_reserved(&open.lease)
        .expect("the call settles");
    assert!(
        meter.admit().is_ok(),
        "a refused park must leave its meter admitting"
    );
}

/// A pin: a second park, with nothing between, answers the same checkpoint.
#[test]
fn a_second_park_answers_the_same_checkpoint() {
    let meter = meter();
    spend_once(&meter);
    let first = meter.park().expect("a settled meter parks");
    let second = meter.park().expect("a parked meter parks again");
    assert_eq!(first, second);
}
