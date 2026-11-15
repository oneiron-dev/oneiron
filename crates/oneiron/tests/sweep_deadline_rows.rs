//! DESIGN 15-setting-primitive, stage 5b-1: a deadline a door notes for a retirement sweep is a
//! row of that sweep's deadline job (`housekeeping.<sweep>.deadline`), a one-time job at the
//! deadline, and the schedule's due index is the only index of them.
//! - each note is its own row, due at the deadline, and a stopped vault wakes for it;
//! - the run of the sweep that covers a deadline disarms its rows, and the sweep goes on a cadence
//!   after it, with no run more;
//! - a deadline whose time comes while its sweep backs off waits for the sweep's retry, and the
//!   sweep's run then disarms it;
//! - the annotation follow sweep's deadlines never wake a stopped vault.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test sweep_deadline_rows`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::housekeeping::{
    HousekeepingBudget, HousekeepingReport, HousekeepingSweep, SweepOutcome,
};
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::schedule::{due_at, note_sweep_deadline, plant_start_marker};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

const LIST: &str = "vault.schedules.list";
const T0: u64 = 1_790_000_000;
const MINUTE: u64 = 60;
const HOUR: u64 = 3_600;

struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            clock,
            _dir: dir,
            owner,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn at(&self, now: u64) {
        self.clock.set(now);
    }

    /// One host pass with no time bound.
    fn pass(&self) -> HousekeepingReport {
        self.vault
            .housekeeping(HousekeepingBudget::unbounded())
            .expect("the housekeeping pass")
    }

    /// When `sweep`'s job is next due, or `None` when it is not armed.
    fn due(&self, sweep: HousekeepingSweep) -> Option<u64> {
        due_at(&self.vault, &sweep_job(sweep), None).expect("the due time")
    }

    /// The due time of every armed row of `sweep`'s deadline job, as the owner lists them,
    /// earliest first.
    fn deadlines(&self, sweep: HousekeepingSweep) -> Vec<u64> {
        let listed = invoke(
            &self.as_owner(),
            LIST,
            json!({ "job": format!("{}.deadline", sweep_job(sweep)) }),
        )
        .expect("the owner lists the schedules");
        let mut due: Vec<u64> = listed["schedules"]
            .as_array()
            .expect("schedules")
            .iter()
            .map(|view| view["due_at"].as_u64().expect("due_at"))
            .collect();
        due.sort_unstable();
        due
    }

    fn wake(&self) -> Option<u64> {
        self.vault.housekeeping_wake_at().expect("the wake time")
    }
}

fn sweep_job(sweep: HousekeepingSweep) -> String {
    format!("housekeeping.{}", sweep.code())
}

fn ran_to_its_end(report: &HousekeepingReport, sweep: HousekeepingSweep) -> bool {
    matches!(
        report.sweep(sweep),
        Some(SweepOutcome::Ran { complete: true, .. })
    )
}

#[test]
fn each_noted_deadline_is_a_row_due_then_and_the_run_that_covers_it_disarms_it() {
    let fx = Fixture::rooted();
    let sweep = HousekeepingSweep::SecretLeaseExpiry;
    fx.pass();
    assert_eq!(fx.due(sweep), Some(T0 + HOUR));
    assert!(fx.deadlines(sweep).is_empty(), "no deadline before a note");

    let deadline = T0 + 10 * MINUTE;
    note_sweep_deadline(&fx.vault, sweep, deadline).expect("a door notes a deadline");
    note_sweep_deadline(&fx.vault, sweep, deadline).expect("a second door notes the same one");
    note_sweep_deadline(&fx.vault, sweep, T0 + 2 * HOUR).expect("a door notes a later one");
    assert_eq!(
        fx.deadlines(sweep),
        vec![deadline, deadline, T0 + 2 * HOUR],
        "each note is its own row, due at its deadline"
    );
    assert_eq!(
        fx.due(sweep),
        Some(deadline),
        "the note makes the sweep due then"
    );
    assert!(
        fx.wake().is_some_and(|at| at <= deadline),
        "a stopped vault wakes by the deadline: {:?}",
        fx.wake()
    );

    fx.at(deadline);
    let report = fx.pass();
    assert!(ran_to_its_end(&report, sweep), "{report:#?}");
    assert_eq!(
        fx.deadlines(sweep),
        vec![T0 + 2 * HOUR],
        "the run disarmed the deadlines it covered and kept the later one"
    );
    assert_eq!(
        fx.due(sweep),
        Some(deadline + HOUR),
        "the sweep goes on a cadence after the run, with no run more"
    );
}

#[test]
fn a_deadline_that_comes_while_its_sweep_backs_off_waits_for_the_run_that_covers_it() {
    let fx = Fixture::rooted();
    let sweep = HousekeepingSweep::SecretLeaseExpiry;
    fx.pass();

    // A run of the sweep, due at a first deadline, starts and never ends: the process stopped.
    let first = T0 + 9 * MINUTE;
    note_sweep_deadline(&fx.vault, sweep, first).expect("a door notes a deadline");
    let started = first + 50;
    fx.at(started);
    plant_start_marker(&fx.vault, &sweep_job(sweep), None, started).expect("a start marker");
    // A second deadline, noted while that run is in flight: its pull is refused.
    let second = T0 + 10 * MINUTE;
    note_sweep_deadline(&fx.vault, sweep, second).expect("a door notes a second deadline");
    assert_eq!(fx.deadlines(sweep), vec![first, second]);

    // The next pass finds the run interrupted: the sweep backs off until the first retry after
    // its start, which is after both deadlines. Each deadline runs, finds the sweep backing off,
    // and is due again at the sweep's retry, never sooner than a minute after its own run.
    fx.at(second);
    let report = fx.pass();
    assert!(!ran_to_its_end(&report, sweep), "{report:#?}");
    let retry = started + MINUTE;
    assert_eq!(fx.due(sweep), Some(retry), "the sweep backs off");
    assert_eq!(
        fx.deadlines(sweep),
        vec![second + MINUTE, second + MINUTE],
        "both deadlines wait for the run that covers them"
    );
    assert!(
        fx.wake().is_some_and(|at| at <= second + MINUTE),
        "a stopped vault wakes for them: {:?}",
        fx.wake()
    );

    // The sweep's retry walks from the start after both deadlines: it covers and disarms them.
    fx.at(second + MINUTE);
    let report = fx.pass();
    assert!(ran_to_its_end(&report, sweep), "{report:#?}");
    assert!(
        fx.deadlines(sweep).is_empty(),
        "the covering run disarmed both deadlines"
    );
    assert_eq!(
        fx.due(sweep),
        Some(retry + HOUR),
        "the sweep goes on a cadence after the retry it ran at"
    );
}

#[test]
fn an_annotation_follow_deadline_never_wakes_a_stopped_vault() {
    let fx = Fixture::rooted();
    let sweep = HousekeepingSweep::AnnotationBodyAnchors;
    fx.pass();
    let before = fx.wake();

    let deadline = T0 + 30 * MINUTE;
    note_sweep_deadline(&fx.vault, sweep, deadline).expect("a live-body edit notes the sweep");
    assert_eq!(fx.deadlines(sweep), vec![deadline], "the note is a row");
    assert_eq!(fx.wake(), before, "it does not wake a stopped vault");
}
