//! DESIGN 15-setting-primitive, stage 5b-3: the watcher TASKs' ticks and the actors' timer turn
//! programs are armed jobs of the schedule's runner (OPUS-SETTING's answers to ASK
//! SETTING-SCHEDULE-5B2-HOME-NODE-JOBS):
//! - a TASK with a due time arms a row of `runtime_hooks.task_tick` about it, due then;
//! - an actor's timer programs arm one row of `dreamer_runner.program_timer` about the actor, due
//!   at the earliest of their due times, and moved by each run to the new earliest;
//! - the fact-hook runner's pass runs the due rows of those two jobs alone, sooner than the
//!   housekeeping tick, and runs nothing while a housekeeping pass holds the runner;
//! - only the node that releases the vault's ticks runs them: a node that is not the elected home
//!   steps over the rows, which stay due there and never wake it, and the home ticks each, late,
//!   once.
//! - a run's result lands only on the row it started on: a row armed again while its run runs (a
//!   TASK rewrite that moves a waiting tick's due time) keeps its new arming (OPUS-SETTING's
//!   review F2 of 5b-3).
//!
//! Red before 5b-3: no tick or timer row is ever armed, and the hook pass releases ticks without
//! the runner.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test task_tick_timer_due_jobs`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::dreamer_runner::{
    ArmTurnProgram, DreamerHomeNodeCandidate, DreamerRunnerStore, ProgramTrigger,
};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::runtime_hooks::{
    FactHookRunner, HOOK_PASS_ENTRIES, HookBodyRun, HookBodyRuntime, HookRunContext,
};
use oneiron::schedule::Trigger;
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::schedule::{
    TEST_REARM_AFTER_SECS, arm_as_engine, due_at, runs, task_tick_waiting,
    while_a_pass_holds_the_runner,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value as RmpValue;

/// The instant every test opens at, in vault-clock seconds.
const T0: u64 = 4_000_000_000;
/// The job a waiting watcher tick arms.
const TICK_JOB: &str = "runtime_hooks.task_tick";
/// The job an actor's timer programs arm.
const TIMER_JOB: &str = "dreamer_runner.program_timer";
/// A node id no vault in these tests mints for itself.
const OTHER_NODE: u64 = 7;

/// A hook body runtime that never runs: no fact binding is enabled in these tests.
struct NoBodies;

impl HookBodyRuntime for NoBodies {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        panic!("no hook body runs: no fact binding is enabled")
    }
}

/// A vault on a clock the test moves, opened as an embedded owner opens it.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let clock = ManualClock::new(T0);
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        config.store_clock = clock.bundle();
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open_owned(dir.path(), config).expect("open vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        Self {
            vault,
            clock,
            owner,
            _dir: dir,
        }
    }

    fn at(&self, now: u64) {
        self.clock.set(now);
    }

    /// One fact-hook runner pass, as the host's hook runner makes on its tick.
    fn hook_pass(&self) {
        FactHookRunner::new()
            .run_pass(&self.vault, &NoBodies, HOOK_PASS_ENTRIES)
            .expect("hook pass");
    }

    /// One housekeeping pass, as the host's tick runs it.
    fn pass(&self) {
        self.vault
            .housekeeping(HousekeepingBudget::unbounded())
            .expect("housekeeping");
    }

    /// When `job`'s row about `subject` is next due, or `None` when it is not armed.
    fn armed(&self, job: &str, subject: EntityId) -> Option<u64> {
        due_at(&self.vault, job, Some(subject)).expect("schedule")
    }

    /// When `task`'s tick is due while it waits for it.
    fn waiting(&self, task: EntityId) -> Option<u64> {
        task_tick_waiting(&self.vault, task).expect("tick record")
    }

    /// The owner's watch TASK, ticking at `due`.
    fn watcher(&self, title: &str, due: u64) -> EntityId {
        let now = self.vault.now_recorded_at();
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .tasks_create(
                &TaskCreateSpec::new(RmpValue::from(title), None, None, Some(now))
                    .with_due_at(due)
                    .with_watch(true),
            )
            .expect("create the watch TASK")
            .task_ref
            .expect("the watch TASK is minted")
    }

    /// The owner's timer program on `skill`, first due at `first_at`, repeating every
    /// `every_secs` (0: once).
    fn timer(&self, skill: EntityId, first_at: u64, every_secs: u64) -> EntityId {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .arm_turn_program(&ArmTurnProgram {
                skill,
                executor: "fixture.executor@1".into(),
                args: serde_json::json!({"value": 41}),
                conversation: None,
                trigger: ProgramTrigger::Timer {
                    first_at,
                    every_secs,
                },
            })
            .expect("arm the timer program")
            .registration
    }

    /// Elects `candidate` the vault's MACRO home.
    fn elect(&self, candidate: DreamerHomeNodeCandidate) {
        DreamerRunnerStore::new(&self.vault)
            .elect_home_node(&[candidate], self.vault.now_recorded_at())
            .expect("elect the home");
    }

    /// This node, as a candidate for the home.
    fn this_node(&self) -> DreamerHomeNodeCandidate {
        DreamerRunnerStore::new(&self.vault)
            .local_home_node_candidate(true, true, true)
            .expect("this node's candidacy")
    }
}

/// An active callable SKILL, enough to arm: arming pins the record and never loads its source.
fn active_callable_skill(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let files: [(&str, &[u8]); 2] = [
        (
            "SKILL.md",
            b"---\nname: fixture.callable\ndescription: Increment a number\nversion: 1\nrole: callable\ncall:\n  reference: scripts/call.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n---\nAn executable fixture.\n",
        ),
        (
            "scripts/call.js",
            b"finish(JSON.stringify({result:skillArgs.value + 1}));",
        ),
    ];
    let hash = canonical_skill_tree_hash(files).expect("hash the fixture tree");
    let mut record = SkillRecord::new(
        "fixture.callable",
        "Increment a number",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: "scripts/call.js".into(),
            arguments: serde_json::json!({"value": "integer"}),
            returns: serde_json::json!({"result": "integer"}),
        }),
    )
    .with_content_hash(hash);
    vault
        .put_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)
        .expect("put the callable candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &record, TimeRange { start: 2, end: 2 }, 2)
        .expect("activate the callable");
    id
}

/// A watch TASK arms its tick as a row due at its due time, and the hook pass alone ticks it
/// then: the row goes and the tick no longer waits.
#[test]
fn a_watch_task_arms_a_tick_row_that_the_hook_pass_ticks_at_its_due_time() {
    let fx = Fixture::open();
    let task = fx.watcher("watch the build", T0 + 60);
    assert_eq!(
        fx.armed(TICK_JOB, task),
        Some(T0 + 60),
        "the TASK's tick is armed at its due time"
    );
    assert_eq!(fx.waiting(task), Some(T0 + 60));
    assert_eq!(
        fx.vault.housekeeping_wake_at().expect("wake"),
        Some(T0 + 60),
        "a stopped vault wakes for the tick"
    );

    fx.at(T0 + 59);
    fx.hook_pass();
    assert_eq!(fx.waiting(task), Some(T0 + 60), "not before its due time");

    fx.at(T0 + 60);
    fx.hook_pass();
    assert_eq!(fx.waiting(task), None, "the hook pass ticked it");
    assert_eq!(fx.armed(TICK_JOB, task), None, "its row went with the tick");
}

/// While a housekeeping pass holds the runner, the hook pass runs no tick; the next one does.
#[test]
fn a_hook_pass_runs_no_tick_while_a_housekeeping_pass_holds_the_runner() {
    let fx = Fixture::open();
    let task = fx.watcher("watch the inbox", T0 + 60);
    fx.at(T0 + 60);
    while_a_pass_holds_the_runner(&fx.vault, || fx.hook_pass());
    assert_eq!(
        fx.waiting(task),
        Some(T0 + 60),
        "a held runner runs nothing"
    );
    assert_eq!(fx.armed(TICK_JOB, task), Some(T0 + 60));

    fx.hook_pass();
    assert_eq!(fx.waiting(task), None, "the free runner ticks it");
}

/// A node that is not the elected home steps over a due tick row: it stays due, is never run by
/// a hook or housekeeping pass there, and wakes nothing; once the node is elected, it ticks the
/// row, late, once.
#[test]
fn a_node_that_is_not_home_steps_over_tick_rows_until_it_is_elected() {
    let fx = Fixture::open();
    fx.elect(DreamerHomeNodeCandidate::always_on_local(OTHER_NODE));
    let task = fx.watcher("watch the deploy", T0 + 60);
    assert_eq!(
        fx.armed(TICK_JOB, task),
        Some(T0 + 60),
        "every node arms the tick"
    );

    fx.at(T0 + 120);
    fx.hook_pass();
    fx.pass();
    assert_eq!(
        fx.waiting(task),
        Some(T0 + 60),
        "a node not home never ticks it"
    );
    assert_eq!(
        fx.armed(TICK_JOB, task),
        Some(T0 + 60),
        "its row stays due there, unrun"
    );
    assert_ne!(
        fx.vault.housekeeping_wake_at().expect("wake"),
        Some(T0 + 60),
        "a node not home never wakes for the tick"
    );

    fx.elect(fx.this_node());
    fx.hook_pass();
    assert_eq!(fx.waiting(task), None, "the home ticks it, late");
    assert_eq!(fx.armed(TICK_JOB, task), None);
}

/// An actor's timer programs are one row about the actor, due at the earliest of their due
/// times; a run moves it to the new earliest within seconds, and it goes with the last timer.
#[test]
fn an_actors_timers_are_one_row_due_at_their_earliest_due_time() {
    let fx = Fixture::open();
    let skill = active_callable_skill(&fx.vault);
    let hourly = fx.timer(skill, T0 + 120, 3_600);
    assert_eq!(fx.armed(TIMER_JOB, fx.owner), Some(T0 + 120));
    fx.timer(skill, T0 + 130, 0);
    assert_eq!(
        fx.armed(TIMER_JOB, fx.owner),
        Some(T0 + 120),
        "a later timer leaves the row at the earliest"
    );
    assert_eq!(
        fx.vault.housekeeping_wake_at().expect("wake"),
        Some(T0 + 120),
        "a stopped vault wakes for the earliest timer"
    );

    fx.at(T0 + 120);
    fx.hook_pass();
    assert_eq!(
        fx.armed(TIMER_JOB, fx.owner),
        Some(T0 + 130),
        "the run moves the row to the next timer, ten seconds on, not a minute"
    );

    fx.at(T0 + 130);
    fx.hook_pass();
    assert_eq!(
        fx.armed(TIMER_JOB, fx.owner),
        Some(T0 + 120 + 3_600),
        "the one-time timer is spent; the hourly one is next"
    );

    assert!(
        fx.vault
            .memory(fx.owner, EdgeActorClass::Human)
            .disarm_turn_program(hourly)
            .expect("disarm")
    );
    assert_eq!(
        fx.armed(TIMER_JOB, fx.owner),
        None,
        "no timer left: the row goes in the disarm's write"
    );
}

/// A row armed again while its run runs keeps the new arming, and runs then: the run's result
/// write lands only on the row the run started on (OPUS-SETTING's review F2 of 5b-3). Here the
/// test job's first run arms its own row an hour on, in its own write, and answers done with no
/// `due_by`, which ends the row it started on. Red before the fix: that answer took the new
/// arming too, and the row went.
#[test]
fn a_row_armed_again_while_its_run_runs_keeps_its_new_arming() {
    const JOB: &str = "test.rearm";
    let fx = Fixture::open();
    let subject = EntityId::from_bytes([0x5B; 16]).expect("subject");
    arm_as_engine(&fx.vault, JOB, Some(subject), Trigger::At { at: T0 + 10 }).expect("armed");

    fx.at(T0 + 10);
    fx.pass();
    assert_eq!(runs(JOB, Some(subject)), 1, "the row ran at its due time");
    assert_eq!(
        fx.armed(JOB, subject),
        Some(T0 + 10 + TEST_REARM_AFTER_SECS),
        "the arming its run made stands"
    );

    fx.at(T0 + 10 + TEST_REARM_AFTER_SECS);
    fx.pass();
    assert_eq!(
        runs(JOB, Some(subject)),
        2,
        "the new arming ran at its time"
    );
    assert_eq!(
        fx.armed(JOB, subject),
        None,
        "the second run ended the row it started on"
    );
}
