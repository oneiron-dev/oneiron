//! Done-means for the pass's schedule: a restart in the middle of a pass
//! resumes the right sweeps, with no early re-run and none skipped forever;
//! a failing or panicking sweep is reported and retried and never stops the
//! others.

use std::cell::Cell;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use super::{HousekeepingBudget, HousekeepingReport, HousekeepingSweep, SweepOutcome};
use crate::Vault;
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::ports::ManualClock;

/// What the pass does at one sweep, in place of running it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Injected {
    /// The process dies after the start marker committed.
    Crash,
    Fail,
    Panic,
}

thread_local! {
    static INJECT: Cell<Option<(HousekeepingSweep, Injected)>> = const { Cell::new(None) };
}

/// The injection armed for `sweep`, consumed.
pub(super) fn injected(sweep: HousekeepingSweep) -> Option<Injected> {
    INJECT.with(|armed| match armed.get() {
        Some((at, what)) if at == sweep => {
            armed.set(None);
            Some(what)
        }
        _ => None,
    })
}

fn inject(sweep: HousekeepingSweep, what: Injected) {
    INJECT.with(|armed| armed.set(Some((sweep, what))));
}

const T0: u64 = 1_800_000_000;

const ENGINE_SWEEPS: [HousekeepingSweep; 10] = [
    HousekeepingSweep::SecretLeaseExpiry,
    HousekeepingSweep::CriticalConfirmExpiry,
    HousekeepingSweep::SymbolLeaseExpiry,
    HousekeepingSweep::VoicePrintRetention,
    HousekeepingSweep::EsignExpiry,
    HousekeepingSweep::EsignSealBackstop,
    HousekeepingSweep::CommitmentLapse,
    HousekeepingSweep::GateDecisionRetention,
    HousekeepingSweep::HardEraseSweep,
    HousekeepingSweep::PprCacheEviction,
];

fn open(dir: &std::path::Path, clock: &Arc<ManualClock>) -> Vault {
    Vault::open(
        dir,
        VaultConfig {
            store_clock: clock.bundle(),
            ..VaultConfig::device()
        },
    )
    .expect("open vault")
}

fn pass(vault: &Vault) -> HousekeepingReport {
    vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("the schedule reads")
}

fn outcome(report: &HousekeepingReport, sweep: HousekeepingSweep) -> &SweepOutcome {
    report.sweep(sweep).expect("every sweep has a row")
}

fn ran(report: &HousekeepingReport, sweep: HousekeepingSweep) -> bool {
    matches!(outcome(report, sweep), SweepOutcome::Ran { .. })
}

fn not_due(report: &HousekeepingReport, sweep: HousekeepingSweep) -> bool {
    matches!(outcome(report, sweep), SweepOutcome::NotDue { .. })
}

#[test]
fn a_restart_in_the_middle_of_a_pass_resumes_the_unfinished_sweeps_and_reruns_none_early() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    {
        let vault = open(dir.path(), &clock);
        inject(HousekeepingSweep::VoicePrintRetention, Injected::Crash);
        let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            vault.housekeeping(HousekeepingBudget::unbounded())
        }));
        assert!(crashed.is_err(), "the injected crash ends the pass");
    }

    clock.set(T0 + 1);
    let vault = open(dir.path(), &clock);
    let report = pass(&vault);
    for sweep in [
        HousekeepingSweep::SecretLeaseExpiry,
        HousekeepingSweep::CriticalConfirmExpiry,
        HousekeepingSweep::SymbolLeaseExpiry,
    ] {
        assert!(
            not_due(&report, sweep),
            "{sweep:?} finished before the crash and ran again early: {report:#?}"
        );
    }
    for sweep in [
        HousekeepingSweep::EsignExpiry,
        HousekeepingSweep::EsignSealBackstop,
        HousekeepingSweep::CommitmentLapse,
        HousekeepingSweep::GateDecisionRetention,
        HousekeepingSweep::HardEraseSweep,
        HousekeepingSweep::PprCacheEviction,
    ] {
        assert!(
            ran(&report, sweep),
            "{sweep:?} never started before the crash and did not run: {report:#?}"
        );
    }
    // The interrupted run counts as a failure: retried after the first
    // backoff rather than first at every restart, and never dropped.
    assert_eq!(
        outcome(&report, HousekeepingSweep::VoicePrintRetention),
        &SweepOutcome::NotDue { due_at: T0 + 60 }
    );

    clock.set(T0 + 60);
    let report = pass(&vault);
    assert!(
        ran(&report, HousekeepingSweep::VoicePrintRetention),
        "the interrupted sweep was skipped: {report:#?}"
    );
    assert!(
        not_due(&report, HousekeepingSweep::HardEraseSweep),
        "{report:#?}"
    );

    // Once it finished, it waits its whole cadence again.
    clock.set(T0 + 61);
    let report = pass(&vault);
    assert_eq!(
        outcome(&report, HousekeepingSweep::VoicePrintRetention),
        &SweepOutcome::NotDue {
            due_at: T0 + 60 + 15 * 60
        }
    );
}

#[test]
fn a_failing_or_panicking_sweep_is_reported_and_retried_and_never_stops_the_others() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let vault = open(dir.path(), &clock);

    inject(HousekeepingSweep::EsignExpiry, Injected::Fail);
    let report = pass(&vault);
    assert_eq!(
        outcome(&report, HousekeepingSweep::EsignExpiry),
        &SweepOutcome::Failed {
            kind: ErrorKind::InvariantViolation
        }
    );
    assert_eq!(report.failed(), 1, "{report:#?}");
    for sweep in ENGINE_SWEEPS {
        if sweep != HousekeepingSweep::EsignExpiry {
            assert!(
                ran(&report, sweep),
                "{sweep:?} did not run beside a failure: {report:#?}"
            );
        }
    }
    for sweep in HousekeepingSweep::ALL {
        if !ENGINE_SWEEPS.contains(&sweep) {
            assert!(
                matches!(outcome(&report, sweep), SweepOutcome::HostOnly { .. }),
                "{sweep:?} is the host's: {report:#?}"
            );
        }
    }

    // Retried after the first backoff, well before its 15-minute cadence.
    clock.set(T0 + 60);
    let report = pass(&vault);
    assert!(ran(&report, HousekeepingSweep::EsignExpiry), "{report:#?}");
    assert!(
        not_due(&report, HousekeepingSweep::EsignSealBackstop),
        "{report:#?}"
    );

    // The owner's "now" runs every engine sweep, due or not.
    inject(HousekeepingSweep::HardEraseSweep, Injected::Panic);
    let report = vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("the schedule reads");
    assert_eq!(
        outcome(&report, HousekeepingSweep::HardEraseSweep),
        &SweepOutcome::Panicked
    );
    assert_eq!(report.ran(), ENGINE_SWEEPS.len() - 1, "{report:#?}");
}

#[test]
fn the_owners_run_now_left_over_by_its_budget_runs_on_the_next_pass() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let vault = open(dir.path(), &clock);
    let report = pass(&vault);
    assert_eq!(report.ran(), ENGINE_SWEEPS.len(), "{report:#?}");

    // Nothing is due; the owner asks for everything with no time to spare.
    clock.set(T0 + 1);
    let report = vault
        .housekeeping_all(HousekeepingBudget::within(std::time::Duration::ZERO))
        .expect("the schedule reads");
    assert_eq!(report.ran(), 1, "{report:#?}");
    let left: Vec<_> = ENGINE_SWEEPS
        .into_iter()
        .filter(|&sweep| matches!(outcome(&report, sweep), SweepOutcome::OutOfBudget))
        .collect();
    assert_eq!(left.len(), ENGINE_SWEEPS.len() - 1, "{report:#?}");

    clock.set(T0 + 2);
    let report = pass(&vault);
    for sweep in left {
        assert!(
            ran(&report, sweep),
            "{sweep:?} was asked for and dropped: {report:#?}"
        );
    }
}
