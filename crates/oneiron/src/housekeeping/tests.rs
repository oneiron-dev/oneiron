//! Done-means for the pass's schedule: a restart in the middle of a pass
//! resumes the right sweeps, with no early re-run and none skipped forever;
//! a failing or panicking sweep is reported and retried and never stops the
//! others.

use std::cell::Cell;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use super::{HousekeepingBudget, HousekeepingReport, HousekeepingSweep, SweepOutcome};
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::ports::ManualClock;
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};

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
            due_at: T0 + 60 + 60 * 60
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

const ACTOR: [u8; 16] = [0x20; 16];
const SUBJECT: [u8; 16] = [0x21; 16];

/// The writer and the subject of [`critical_writes`].
fn seed_people(vault: &Vault) {
    for id in [ACTOR, SUBJECT] {
        let id = EntityId::from_bytes(id).expect("id");
        let when = TimeRange { start: T0, end: T0 };
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                when,
                T0,
                b"person",
            )
            .expect("seed");
    }
}

/// `count` critical writes learned at `at`, each awaiting its confirm for
/// the engine's 300 s.
fn critical_writes(vault: &Vault, at: u64, count: usize) -> Vec<EntityId> {
    let actor = EntityId::from_bytes(ACTOR).expect("id");
    let subject = EntityId::from_bytes(SUBJECT).expect("id");
    let when = TimeRange { start: at, end: at };
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("housekeeping test")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    (0..count)
        .map(|n| {
            let claim = EntityId::now();
            let candidate = ClaimCandidate::new(
                "health.allergy",
                ClaimSubject::Entity(subject),
                rmpv::Value::from(format!("allergen {at} {n}")),
                1.0,
            )
            .with_scope(rmpv::Value::Map(vec![(
                rmpv::Value::from("sensitivity"),
                rmpv::Value::from("public"),
            )]));
            vault
                .batch()
                .claim_candidate(&claim, candidate, &envelope, when, at)
                .commit()
                .expect("critical write");
            claim
        })
        .collect()
}

/// Sol R3 F5: a confirm walk that outlasts a bounded pass goes on in the
/// next from where it was, rather than starting over, so it ends; once it
/// has, the deadline it covered no longer wakes the vault.
#[test]
fn a_confirm_walk_that_spans_passes_ends_and_retires_the_deadline_it_covered() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let vault = open(dir.path(), &clock);
    seed_people(&vault);
    // One confirm whose window closes at T0 + 300, ahead of pages of
    // confirms still open past it.
    let overdue = critical_writes(&vault, T0, 1)[0];
    clock.set(T0 + 200);
    critical_writes(&vault, T0 + 200, 600);
    clock.set(T0 + 301);

    // A pass with no time to spare runs one sweep, and a walk one page.
    let mut passes = 0;
    while vault.housekeeping_wake_at().expect("wake") < Some(T0 + 500) {
        assert!(passes < 60, "the covered deadline still wakes the vault");
        vault
            .housekeeping(HousekeepingBudget::within(std::time::Duration::ZERO))
            .expect("the schedule reads");
        passes += 1;
    }
    let approval = vault
        .get_claim(&overdue)
        .expect("read")
        .expect("claim")
        .approval;
    assert_eq!(
        approval,
        ClaimApprovalStatus::Proposed,
        "the overdue write was demoted"
    );
}

/// Sol R4 F2 (#1456): an owner's erasure run cut short before it compacts is
/// still the owner's when the next pass retries it, so the retry compacts the
/// history the owner asked to drop, with no obligation due. A scheduled run
/// would leave it.
#[cfg(feature = "sync")]
#[test]
fn an_owners_erasure_run_cut_short_is_retried_as_the_owners() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let config = || VaultConfig {
        store_clock: clock.bundle(),
        ..crate::test_util::embedding_test_config()
    };
    {
        let vault = Vault::open(dir.path(), config()).expect("open vault");
        // A persisted window, and no obligation left: an erasure the owner's
        // own sweep has already discharged.
        let erased = EntityId::now();
        vault
            .batch()
            .put(
                &erased,
                1,
                TimeRange { start: T0, end: T0 },
                T0,
                b"window-history",
            )
            .commit()
            .expect("put");
        vault
            .delete_entity_with_reason(&erased, crate::deletion::DeleteReason::GdprDelete)
            .expect("delete");
        let discharged = crate::sweep::run_hard_erase_sweep(&vault).expect("erase");
        assert_eq!(discharged.jobs_processed, 1);
        inject(HousekeepingSweep::HardEraseSweep, Injected::Crash);
        let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            vault.housekeeping_all(HousekeepingBudget::unbounded())
        }));
        assert!(crashed.is_err(), "the injected crash ends the owner's pass");
    }

    clock.set(T0 + 3_600);
    let vault = Vault::open(dir.path(), config()).expect("reopen vault");
    let report = pass(&vault);

    assert!(
        matches!(
            outcome(&report, HousekeepingSweep::HardEraseSweep),
            SweepOutcome::Ran {
                work: super::SweepWork::HardErase(super::HardEraseWork {
                    windows_compacted: 1..,
                    ..
                }),
                ..
            }
        ),
        "{report:#?}"
    );
}

/// Engine edge on Sol R4 F2 (#1456): a window a caller holds when the
/// owner's erasure run comes is left out of it, and the run stays the
/// owner's. Once the window is free, the retry compacts it, with no
/// obligation due.
#[cfg(feature = "sync")]
#[test]
fn a_window_held_through_the_owners_erasure_run_is_compacted_on_its_retry() {
    use crate::sync::bridge::Materializer;
    use crate::sync::manager::WindowManager;
    use crate::sync::types::WindowKey;

    let erase_work =
        |report: &HousekeepingReport| match outcome(report, HousekeepingSweep::HardEraseSweep) {
            SweepOutcome::Ran {
                work: super::SweepWork::HardErase(work),
                ..
            } => *work,
            other => panic!("the erasure sweep did not run: {other:?}"),
        };
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let vault = Arc::new(
        Vault::open(
            dir.path(),
            VaultConfig {
                store_clock: clock.bundle(),
                ..crate::test_util::embedding_test_config()
            },
        )
        .expect("open vault"),
    );
    // A persisted window, and no obligation left.
    let erased = EntityId::now();
    vault
        .batch()
        .put(
            &erased,
            1,
            TimeRange { start: T0, end: T0 },
            T0,
            b"window-history",
        )
        .commit()
        .expect("put");
    vault
        .delete_entity_with_reason(&erased, crate::deletion::DeleteReason::GdprDelete)
        .expect("delete");
    let discharged = crate::sweep::run_hard_erase_sweep(&vault).expect("erase");
    assert_eq!(discharged.jobs_processed, 1);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "held-window-test",
    ));
    let held = manager
        .open_window(&WindowKey::from_timestamp(T0))
        .expect("open window");

    let owners = vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("the schedule reads");
    let work = erase_work(&owners);
    assert_eq!(work.windows_compacted, 0);
    assert!(work.windows_deferred_live >= 1, "{work:?}");

    drop(held);
    clock.set(T0 + 3_600);
    let work = erase_work(&pass(&vault));
    assert!(work.windows_unloaded >= 1, "{work:?}");
    assert!(work.windows_compacted >= 1, "the retry was the owner's");
}
