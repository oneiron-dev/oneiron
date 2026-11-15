//! DESIGN 15-setting-primitive, stage 5a-2: the engine's 19 sweeps are jobs of the one runner, and
//! their cadences are 19 Setting keys.
//! - each sweep has a key `housekeeping.<sweep>.every` at the cadence the code held before, and
//!   each sweep's job takes its cadence from its key and is armed by the engine alone;
//! - a handle's first pass arms and runs every engine sweep, and reports the host-only ones; the
//!   next pass finds each due a cadence later;
//! - a job that starts once a pass, as a sweep does, goes on at the next pass when it stopped at
//!   its bound;
//! - a cadence row this build cannot read never fails the pass: its sweep is armed from the
//!   key's default;
//! - queuing an erasure obligation makes the erasure sweep due an hour after its last run, or at
//!   once when that hour has passed;
//! - the owner sets a cadence: its job is armed again in that write and goes on from now, and a
//!   cadence that can never fire is refused;
//! - the owner's `housekeeping_all` runs every engine sweep now, and each goes on from now;
//! - a deadline a door notes makes its sweep due then, a stopped vault wakes for it, and the run
//!   that covers it goes on a cadence after it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test housekeeping_sweep_jobs`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::housekeeping::{
    HousekeepingBudget, HousekeepingReport, HousekeepingSweep, SweepOutcome,
};
use oneiron::memory::Memory;
use oneiron::schedule::Trigger;
use oneiron::setting::SettingScope;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::schedule::{
    arm_as_engine, cadence_jobs, cadence_jobs_not_engine_armed, due_at, note_sweep_deadline,
    pull_for_queued_erase_obligation, seen,
};
use oneiron::test_doors::setting::plant_undecodable_row;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const SET: &str = "vault.settings.set";
const GET: &str = "vault.settings.get";
const T0: u64 = 1_790_000_000;
const MINUTE: u64 = 60;
const HOUR: u64 = 3_600;
const DAY: u64 = 24 * HOUR;

/// Every engine sweep, and the cadence the code held for it before stage 5a.
const CADENCES: [(HousekeepingSweep, u64); 19] = [
    (HousekeepingSweep::SecretLeaseExpiry, HOUR),
    (HousekeepingSweep::CriticalConfirmExpiry, HOUR),
    (HousekeepingSweep::SymbolLeaseExpiry, 5 * MINUTE),
    (HousekeepingSweep::VoicePrintRetention, HOUR),
    (HousekeepingSweep::EsignExpiry, 15 * MINUTE),
    (HousekeepingSweep::EsignSealBackstop, 15 * MINUTE),
    (HousekeepingSweep::CommitmentLapse, 15 * MINUTE),
    (HousekeepingSweep::GateDecisionRetention, HOUR),
    (HousekeepingSweep::HardEraseSweep, DAY),
    (HousekeepingSweep::PprCacheEviction, DAY),
    (HousekeepingSweep::SharedActMaturity, HOUR),
    (HousekeepingSweep::SecretLiftHistory, 15 * MINUTE),
    (HousekeepingSweep::ClaimVadDebt, 15 * MINUTE),
    (HousekeepingSweep::FoundKeyNotices, 15 * MINUTE),
    (HousekeepingSweep::BodyLineIndexRebuild, 15 * MINUTE),
    (HousekeepingSweep::AnnotationBodyAnchors, MINUTE),
    (HousekeepingSweep::DrafterCorpusSweep, DAY),
    (HousekeepingSweep::ModelPackRetirement, MINUTE),
    (HousekeepingSweep::OAuthExpiry, HOUR),
];

/// The engine sweeps that run to their end with nothing failed on a new vault, so each is next
/// due exactly a cadence after its run.
const QUIET_ON_A_NEW_VAULT: [(HousekeepingSweep, u64); 10] = [
    (HousekeepingSweep::SecretLeaseExpiry, HOUR),
    (HousekeepingSweep::CriticalConfirmExpiry, HOUR),
    (HousekeepingSweep::SymbolLeaseExpiry, 5 * MINUTE),
    (HousekeepingSweep::VoicePrintRetention, HOUR),
    (HousekeepingSweep::EsignExpiry, 15 * MINUTE),
    (HousekeepingSweep::EsignSealBackstop, 15 * MINUTE),
    (HousekeepingSweep::CommitmentLapse, 15 * MINUTE),
    (HousekeepingSweep::GateDecisionRetention, HOUR),
    (HousekeepingSweep::HardEraseSweep, DAY),
    (HousekeepingSweep::PprCacheEviction, DAY),
];

/// The sweeps only a host runs.
const HOST_ONLY: [HousekeepingSweep; 6] = [
    HousekeepingSweep::EsignReminders,
    HousekeepingSweep::ConsultSettlement,
    HousekeepingSweep::PolicyHoldPrune,
    HousekeepingSweep::TaskAttribution,
    HousekeepingSweep::AttemptLeaseReclaim,
    HousekeepingSweep::SelfHealDetectorRuns,
];

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
        due_at(&self.vault, &format!("housekeeping.{}", sweep.code()), None).expect("the due time")
    }

    /// The owner sets `sweep`'s cadence at the vault.
    fn set_cadence(&self, sweep: HousekeepingSweep, trigger: Value) -> Result<Value, String> {
        invoke(
            &self.as_owner(),
            SET,
            json!({ "key": key(sweep), "scope": { "kind": "vault" }, "value": trigger }),
        )
        .map_err(|error| format!("{error:?}"))
    }

    /// `sweep`'s cadence in force at the vault.
    fn cadence(&self, sweep: HousekeepingSweep) -> Value {
        invoke(
            &self.as_owner(),
            GET,
            json!({ "key": key(sweep), "at": [] }),
        )
        .expect("the owner reads the cadence")["value"]
            .clone()
    }
}

fn key(sweep: HousekeepingSweep) -> String {
    format!("housekeeping.{}.every", sweep.code())
}

fn outcome(report: &HousekeepingReport, sweep: HousekeepingSweep) -> &SweepOutcome {
    report.sweep(sweep).expect("every sweep has a row")
}

/// When a sweep of cadence `secs` whose run ended at `end` with `outcome` is next due: at once
/// when it stopped at its bound (the next pass goes on), after the first retry when it left
/// items, else a cadence later.
fn due_after(outcome: &SweepOutcome, end: u64, secs: u64) -> u64 {
    match outcome {
        SweepOutcome::Ran {
            complete: false, ..
        } => end,
        SweepOutcome::Ran { work, .. } if work.items_failed() > 0 => end + MINUTE,
        _ => end + secs,
    }
}

#[test]
fn each_engine_sweep_has_a_cadence_key_at_the_cadence_it_ran_at() {
    let fx = Fixture::rooted();
    for (sweep, secs) in CADENCES {
        let cadence = fx.cadence(sweep);
        assert_eq!(
            (&cadence["kind"], &cadence["secs"]),
            (&json!("every"), &json!(secs)),
            "{}: {cadence}",
            sweep.code()
        );
    }
}

#[test]
fn a_first_pass_runs_every_engine_sweep_and_the_next_finds_each_due_a_cadence_later() {
    let fx = Fixture::rooted();
    for (sweep, _) in CADENCES {
        assert_eq!(fx.due(sweep), None, "{}: not armed before", sweep.code());
    }
    let first = fx.pass();
    assert_eq!(first.sweeps.len(), 25, "{first:#?}");
    for (sweep, secs) in CADENCES {
        let ran = outcome(&first, sweep);
        assert!(
            matches!(ran, SweepOutcome::Ran { .. }),
            "{}: the first pass runs it: {first:#?}",
            sweep.code()
        );
        assert_eq!(
            fx.due(sweep),
            Some(due_after(ran, T0, secs)),
            "{}: armed, and due as its run left it: {ran:?}",
            sweep.code()
        );
    }
    for sweep in HOST_ONLY {
        assert!(
            matches!(outcome(&first, sweep), SweepOutcome::HostOnly { .. }),
            "{}: {first:#?}",
            sweep.code()
        );
    }
    for (sweep, secs) in QUIET_ON_A_NEW_VAULT {
        assert!(
            matches!(
                outcome(&first, sweep),
                SweepOutcome::Ran { complete: true, .. }
            ),
            "{}: {first:#?}",
            sweep.code()
        );
        assert_eq!(fx.due(sweep), Some(T0 + secs), "{}", sweep.code());
    }

    let second = fx.pass();
    for (sweep, secs) in CADENCES {
        let due = due_after(outcome(&first, sweep), T0, secs);
        if due > T0 {
            assert_eq!(
                outcome(&second, sweep),
                &SweepOutcome::NotDue { due_at: due },
                "{}: the same handle's next pass runs nothing early: {second:#?}",
                sweep.code()
            );
        } else {
            assert!(
                matches!(outcome(&second, sweep), SweepOutcome::Ran { .. }),
                "{}: a sweep that stopped at its bound goes on at the next pass: {second:#?}",
                sweep.code()
            );
        }
    }
}

#[test]
fn the_owner_sets_a_cadence_and_its_sweep_goes_on_from_now_at_that_cadence() {
    let fx = Fixture::rooted();
    let sweep = HousekeepingSweep::SymbolLeaseExpiry;
    fx.pass();
    assert_eq!(fx.due(sweep), Some(T0 + 5 * MINUTE));

    fx.at(T0 + MINUTE);
    fx.set_cadence(sweep, json!({ "kind": "every", "secs": 2 * HOUR }))
        .expect("the owner sets the cadence");
    assert_eq!(
        fx.due(sweep),
        Some(T0 + MINUTE),
        "the write that set the cadence armed the job again, from now"
    );
    let report = fx.pass();
    assert!(
        matches!(
            outcome(&report, sweep),
            SweepOutcome::Ran { complete: true, .. }
        ),
        "{report:#?}"
    );
    assert_eq!(fx.due(sweep), Some(T0 + MINUTE + 2 * HOUR));

    let zero = fx
        .set_cadence(sweep, json!({ "kind": "every", "secs": 0 }))
        .expect_err("a cadence that never fires is refused");
    assert!(zero.contains("can never fire"), "{zero}");
    let cadence = fx.cadence(sweep);
    assert_eq!(&cadence["secs"], &json!(2 * HOUR), "{cadence}");
    assert_eq!(fx.due(sweep), Some(T0 + MINUTE + 2 * HOUR), "nothing moved");
}

#[test]
fn the_owners_run_now_runs_every_engine_sweep_and_each_goes_on_from_now() {
    let fx = Fixture::rooted();
    fx.pass();
    let now = T0 + 10 * MINUTE;
    fx.at(now);
    let report = fx
        .vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("the owner's run now");
    for (sweep, secs) in CADENCES {
        let ran = outcome(&report, sweep);
        assert!(
            matches!(ran, SweepOutcome::Ran { .. }),
            "{}: due or not, it runs: {report:#?}",
            sweep.code()
        );
        assert_eq!(
            fx.due(sweep),
            Some(due_after(ran, now, secs)),
            "{}: goes on from now: {ran:?}",
            sweep.code()
        );
    }
    for (sweep, secs) in QUIET_ON_A_NEW_VAULT {
        assert_eq!(fx.due(sweep), Some(now + secs), "{}", sweep.code());
    }
}

#[test]
fn a_noted_deadline_makes_its_sweep_due_then_and_a_stopped_vault_wakes_for_it() {
    let fx = Fixture::rooted();
    let sweep = HousekeepingSweep::SecretLeaseExpiry;
    fx.pass();
    assert_eq!(fx.due(sweep), Some(T0 + HOUR));

    let deadline = T0 + 10 * MINUTE;
    note_sweep_deadline(&fx.vault, sweep, deadline).expect("a door notes a deadline");
    assert_eq!(fx.due(sweep), Some(deadline), "due when the deadline comes");
    let wake = fx.vault.housekeeping_wake_at().expect("the wake time");
    assert!(
        wake.is_some_and(|at| at <= deadline),
        "a stopped vault wakes by the deadline: {wake:?}"
    );

    fx.at(deadline);
    let report = fx.pass();
    assert!(
        matches!(
            outcome(&report, sweep),
            SweepOutcome::Ran { complete: true, .. }
        ),
        "{report:#?}"
    );
    assert_eq!(
        fx.due(sweep),
        Some(deadline + HOUR),
        "the run covered the deadline and goes on a cadence after it"
    );
}

#[test]
fn each_sweep_job_takes_its_cadence_key_and_only_the_engine_arms_it() {
    let cadence = cadence_jobs();
    for (sweep, _) in CADENCES {
        let job = format!("housekeeping.{}", sweep.code());
        assert!(
            cadence.iter().any(|code| *code == job),
            "{job}: {cadence:?}"
        );
    }
    for sweep in HOST_ONLY {
        let job = format!("housekeeping.{}", sweep.code());
        assert!(
            !cadence.iter().any(|code| *code == job),
            "{job}: a host runs it: {cadence:?}"
        );
    }
    assert_eq!(cadence_jobs_not_engine_armed(), Vec::<&str>::new());
}

#[test]
fn a_job_that_starts_once_a_pass_goes_on_at_the_next_pass() {
    let fx = Fixture::rooted();
    arm_as_engine(
        &fx.vault,
        "test.once",
        None,
        Trigger::Every {
            secs: HOUR,
            first_at: None,
        },
    )
    .expect("the engine arms a drain that starts once a pass");
    fx.pass();
    assert_eq!(
        seen(&fx.vault, "test.once").len(),
        1,
        "it stopped at its bound and is due again at once, but the pass starts it once"
    );
    assert_eq!(
        due_at(&fx.vault, "test.once", None).expect("the due time"),
        Some(T0),
        "due again at once"
    );
    fx.pass();
    assert_eq!(
        seen(&fx.vault, "test.once").len(),
        2,
        "the next pass goes on"
    );
}

#[test]
fn a_cadence_row_this_build_cannot_read_arms_its_sweep_from_the_default() {
    let fx = Fixture::rooted();
    let sweep = HousekeepingSweep::SymbolLeaseExpiry;
    plant_undecodable_row(&fx.vault, &key(sweep), SettingScope::Vault)
        .expect("a row this build cannot read");
    let report = fx.pass();
    assert!(
        matches!(
            outcome(&report, sweep),
            SweepOutcome::Ran { complete: true, .. }
        ),
        "{report:#?}"
    );
    assert_eq!(
        fx.due(sweep),
        Some(T0 + 5 * MINUTE),
        "armed from the key's default, five minutes"
    );
    for (other, _) in CADENCES {
        assert!(fx.due(other).is_some(), "{}: armed", other.code());
    }
}

#[test]
fn a_queued_erasure_makes_its_sweep_due_an_hour_after_its_last_run_or_at_once() {
    let sweep = HousekeepingSweep::HardEraseSweep;

    let soon = Fixture::rooted();
    soon.pass();
    assert_eq!(soon.due(sweep), Some(T0 + DAY));
    soon.at(T0 + 10 * MINUTE);
    pull_for_queued_erase_obligation(&soon.vault).expect("the queuing write");
    assert_eq!(
        soon.due(sweep),
        Some(T0 + HOUR),
        "ten minutes after a run: an hour after that run"
    );

    let late = Fixture::rooted();
    late.pass();
    late.at(T0 + 3 * HOUR);
    pull_for_queued_erase_obligation(&late.vault).expect("the queuing write");
    assert_eq!(
        late.due(sweep),
        Some(T0 + 3 * HOUR),
        "three hours after a run: at once"
    );
}
