//! DESIGN 15-setting-primitive, stage 5a-1: what the Schedule runner gains so the engine's sweeps
//! can be its jobs.
//! - a cadence key's job is armed from the key's value in force, and the write that changes the
//!   key arms it again; a trigger that can never fire, or names an unknown zone, refuses the
//!   change; arming again with the same trigger keeps the due time;
//! - a walk that ends with items left backs off and starts again from the beginning;
//! - an engine "run now" makes the jobs it names due at once, and the run answers it; a requested
//!   run that fails stays requested on its retry, and a run that ends done clears it;
//! - one job runs alone, now, while another is due;
//! - a door pulls a due time forward, but not while the job backs off;
//! - a run's `due_by` makes its job due before its next occurrence;
//! - a pass whose budget is spent still starts one due job; a stopped pass starts none.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test schedule_runner_sweeps`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use oneiron::authority::MachineRole;
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::Memory;
use oneiron::schedule::{JobOutcome, Trigger};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::schedule::{
    SeenRun, arm_as_engine, arm_cadence_jobs, due_at, pull_due_forward, request_at_open_runs,
    request_cadence_runs, run_job_now, seen, set_cadence_due_by,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const SET: &str = "vault.settings.set";
const GET: &str = "vault.settings.get";
const CADENCE_KEY: &str = "test.job_cadence";
const T0: u64 = 1_790_000_000;
const MINUTE: u64 = 60;
const HOUR: u64 = 3_600;
const DAY: u64 = 24 * HOUR;

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

    /// One runner pass; the jobs it ran and their outcomes.
    fn run_due(&self) -> Vec<(String, JobOutcome)> {
        self.vault
            .run_due(HousekeepingBudget::unbounded())
            .expect("the runner")
            .runs
            .into_iter()
            .map(|run| (run.job, run.outcome))
            .collect()
    }

    fn due(&self, job: &str) -> Option<u64> {
        due_at(&self.vault, job, None).expect("the due time")
    }

    fn arm(&self, job: &str, trigger: Trigger) {
        arm_as_engine(&self.vault, job, None, trigger).expect("the engine arms the job");
    }

    /// The owner sets the test cadence key at the vault.
    fn set_cadence(&self, trigger: Value) -> Result<Value, String> {
        invoke(
            &self.as_owner(),
            SET,
            json!({ "key": CADENCE_KEY, "scope": { "kind": "vault" }, "value": trigger }),
        )
        .map_err(|error| format!("{error:?}"))
    }

    fn cadence(&self) -> Value {
        invoke(
            &self.as_owner(),
            GET,
            json!({ "key": CADENCE_KEY, "at": [] }),
        )
        .expect("the owner reads the cadence")["value"]
            .clone()
    }
}

fn every(secs: u64) -> Trigger {
    Trigger::Every {
        secs,
        first_at: None,
    }
}

fn ran(job: &str, outcome: JobOutcome) -> (String, JobOutcome) {
    (job.to_owned(), outcome)
}

fn requested(runs: &[SeenRun]) -> Vec<bool> {
    runs.iter().map(|run| run.requested).collect()
}

#[test]
fn a_cadence_key_arms_its_job_and_a_change_rearms_it_in_the_same_write() {
    let fx = Fixture::rooted();
    assert_eq!(fx.due("test.cadence"), None, "nothing armed it yet");
    arm_cadence_jobs(&fx.vault).expect("the engine arms the cadence jobs");
    assert_eq!(
        fx.due("test.cadence"),
        Some(T0),
        "the key's default is daily, from now"
    );
    assert_eq!(fx.run_due(), vec![ran("test.cadence", JobOutcome::Done)]);
    assert_eq!(fx.due("test.cadence"), Some(T0 + DAY));

    fx.at(T0 + 100);
    let applied = fx
        .set_cadence(json!({ "kind": "every", "secs": HOUR }))
        .expect("the owner sets the cadence");
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(
        fx.due("test.cadence"),
        Some(T0 + 100),
        "the new trigger is armed in the write that set it, due from now"
    );
    assert_eq!(fx.run_due(), vec![ran("test.cadence", JobOutcome::Done)]);
    assert_eq!(fx.due("test.cadence"), Some(T0 + 100 + HOUR));

    fx.set_cadence(json!({ "kind": "every", "secs": 0 }))
        .expect_err("an interval of zero never fires");
    fx.set_cadence(json!({
        "kind": "civil", "hour": 9, "minute": 0, "zone": "Nowhere/Atlantis"
    }))
    .expect_err("the engine knows no such zone: the arming refuses the change");
    let cadence = fx.cadence();
    assert_eq!(
        (&cadence["kind"], &cadence["secs"]),
        (&json!("every"), &json!(HOUR)),
        "{cadence}"
    );
    assert_eq!(
        fx.due("test.cadence"),
        Some(T0 + 100 + HOUR),
        "nothing moved"
    );
}

#[test]
fn arming_again_with_the_same_trigger_keeps_the_due_time() {
    let fx = Fixture::rooted();
    arm_cadence_jobs(&fx.vault).expect("first arming");
    assert_eq!(fx.run_due(), vec![ran("test.cadence", JobOutcome::Done)]);
    fx.at(T0 + HOUR);
    arm_cadence_jobs(&fx.vault).expect("the next handle's arming");
    assert_eq!(fx.due("test.cadence"), Some(T0 + DAY));
    assert!(
        fx.run_due().is_empty(),
        "not due before its next occurrence"
    );
}

#[test]
fn a_walk_that_ends_with_items_left_backs_off_and_starts_again_from_the_beginning() {
    let fx = Fixture::rooted();
    fx.arm("test.items", every(DAY));
    assert_eq!(
        fx.run_due(),
        vec![
            ran("test.items", JobOutcome::More),
            ran("test.items", JobOutcome::ItemsFailed),
        ]
    );
    assert_eq!(fx.due("test.items"), Some(T0 + MINUTE), "the first retry");
    fx.at(T0 + MINUTE);
    assert_eq!(
        fx.run_due(),
        vec![
            ran("test.items", JobOutcome::More),
            ran("test.items", JobOutcome::ItemsFailed),
        ]
    );
    assert_eq!(
        fx.due("test.items"),
        Some(T0 + 3 * MINUTE),
        "the second retry waits twice as long"
    );
    let cursors: Vec<_> = seen(&fx.vault, "test.items")
        .into_iter()
        .map(|run| run.cursor)
        .collect();
    assert_eq!(cursors, vec![None, Some(vec![1]), None, Some(vec![1])]);
}

#[test]
fn an_engine_request_runs_the_jobs_it_names_at_once_and_the_run_answers_it() {
    let fx = Fixture::rooted();
    fx.arm("test.open", every(DAY));
    arm_cadence_jobs(&fx.vault).expect("arming");
    assert_eq!(fx.run_due().len(), 2, "both are due at their arming");
    fx.at(T0 + HOUR);
    assert!(fx.run_due().is_empty());

    assert_eq!(request_at_open_runs(&fx.vault).expect("request"), 1);
    assert_eq!(fx.run_due(), vec![ran("test.open", JobOutcome::Done)]);
    assert_eq!(requested(&seen(&fx.vault, "test.open")), vec![false, true]);
    assert_eq!(
        fx.due("test.open"),
        Some(T0 + HOUR + DAY),
        "it goes on from now"
    );

    assert_eq!(request_cadence_runs(&fx.vault).expect("request"), 1);
    assert_eq!(fx.run_due(), vec![ran("test.cadence", JobOutcome::Done)]);
    assert_eq!(
        requested(&seen(&fx.vault, "test.cadence")),
        vec![false, true]
    );
}

#[test]
fn a_requested_run_that_fails_stays_requested_on_its_retry_and_one_that_ends_done_clears_it() {
    let fx = Fixture::rooted();
    fx.arm("test.answer", every(DAY));
    assert!(matches!(
        run_job_now(&fx.vault, "test.answer", None).expect("run now"),
        Some(JobOutcome::Failed { .. })
    ));
    assert_eq!(fx.due("test.answer"), Some(T0 + MINUTE), "it backs off");
    fx.at(T0 + MINUTE);
    assert_eq!(fx.run_due(), vec![ran("test.answer", JobOutcome::Done)]);
    fx.at(T0 + MINUTE + DAY);
    assert_eq!(fx.run_due(), vec![ran("test.answer", JobOutcome::Done)]);
    assert_eq!(
        requested(&seen(&fx.vault, "test.answer")),
        vec![true, true, false],
        "the retry still answers the request; the run after a done one does not"
    );
}

#[test]
fn one_job_runs_alone_now_while_another_is_due() {
    let fx = Fixture::rooted();
    fx.arm("test.open", every(DAY));
    fx.arm("test.answer", every(DAY));
    assert!(matches!(
        run_job_now(&fx.vault, "test.answer", None).expect("run now"),
        Some(JobOutcome::Failed { .. })
    ));
    assert!(
        seen(&fx.vault, "test.open").is_empty(),
        "the other job did not run"
    );
    assert_eq!(fx.due("test.open"), Some(T0), "and is still due");
    assert_eq!(
        run_job_now(&fx.vault, "test.items", None).expect("run now"),
        None,
        "a job that is not armed does not run"
    );
}

#[test]
fn a_door_pulls_a_due_time_forward_but_not_while_the_job_backs_off() {
    let fx = Fixture::rooted();
    fx.arm("test.open", every(DAY));
    assert_eq!(fx.run_due(), vec![ran("test.open", JobOutcome::Done)]);
    assert_eq!(fx.due("test.open"), Some(T0 + DAY));
    pull_due_forward(&fx.vault, "test.open", None, T0 + HOUR).expect("pull");
    assert_eq!(fx.due("test.open"), Some(T0 + HOUR));
    pull_due_forward(&fx.vault, "test.open", None, T0 + 2 * HOUR).expect("pull");
    assert_eq!(
        fx.due("test.open"),
        Some(T0 + HOUR),
        "a later time moves nothing"
    );
    fx.at(T0 + HOUR);
    assert_eq!(fx.run_due(), vec![ran("test.open", JobOutcome::Done)]);

    fx.arm("test.answer", every(DAY));
    assert!(matches!(
        fx.run_due()[..],
        [(ref job, JobOutcome::Failed { .. })] if job == "test.answer"
    ));
    assert_eq!(fx.due("test.answer"), Some(T0 + HOUR + MINUTE));
    pull_due_forward(&fx.vault, "test.answer", None, T0 + HOUR + 10).expect("pull");
    assert_eq!(
        fx.due("test.answer"),
        Some(T0 + HOUR + MINUTE),
        "a job that backs off waits out its backoff"
    );
}

#[test]
fn a_runs_due_by_makes_its_job_due_before_its_next_occurrence() {
    let fx = Fixture::rooted();
    arm_cadence_jobs(&fx.vault).expect("arming");
    set_cadence_due_by(&fx.vault, Some(T0 + HOUR));
    assert_eq!(fx.run_due(), vec![ran("test.cadence", JobOutcome::Done)]);
    assert_eq!(fx.due("test.cadence"), Some(T0 + HOUR));
    set_cadence_due_by(&fx.vault, None);
    fx.at(T0 + HOUR);
    assert_eq!(fx.run_due(), vec![ran("test.cadence", JobOutcome::Done)]);
    assert_eq!(
        fx.due("test.cadence"),
        Some(T0 + HOUR + DAY),
        "with no due_by it goes on a cadence after the occurrence it served"
    );
}

#[test]
fn a_pass_whose_budget_is_spent_starts_one_due_job_and_a_stopped_pass_starts_none() {
    let fx = Fixture::rooted();
    fx.arm("test.count", every(DAY));
    fx.arm("test.open", every(DAY));
    let stop = Arc::new(AtomicBool::new(true));
    let stopped = fx
        .vault
        .run_due(HousekeepingBudget::unbounded().stop_when(Arc::clone(&stop)))
        .expect("the runner");
    assert!(stopped.runs.is_empty(), "a stopped pass starts nothing");
    let spent = fx
        .vault
        .run_due(HousekeepingBudget::within(Duration::ZERO))
        .expect("the runner");
    assert_eq!(
        spent.runs.len(),
        1,
        "a pass whose budget is spent still starts one due job"
    );
    assert_eq!(fx.run_due().len(), 1, "the other waits for the next pass");
}
