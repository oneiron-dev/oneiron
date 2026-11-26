//! CG-2 row 9's scheduled read (owner COMPUTE-CG = AA, 25 Nov 22:56: "A drained machine clears
//! itself once its readiness check passes; you hear only when the check keeps failing"; FIX
//! CG2-ROW9-UNDEMANDED-MACHINES-UNOBSERVED). The job worker's pass asks `Node` only of the
//! machines an open order wants. After each pass the worker also starts a read, beside its next
//! passes, that asks each machine the vault's grants admit on the job protocol once that
//! machine's `jobs.readiness.every_secs` has passed since its last ask, and acts on the answer's
//! readiness fact as the pass does. So an idle machine whose check keeps failing reaches the
//! owner with no order open (pass 34, 7.3 and 16, practice 6). REVIEW-10544 round 1: the
//! enabled issuer's worker starts with no job work; the worker never waits for the read, and
//! one read runs at a time; each ask is dated when it is sent; a period longer than a day
//! outlives the readings' one-day drop. Round 2: the pass dates its asks when sent too and
//! records each before it is sent, so the read never repeats a request already out; a granted
//! machine's readings outlive the one-day drop; nothing is read before the mesh is bound.
//!
//! A, B and C share one home. A is the vault's issuer of vault machine jobs with the section
//! enabled, and C names A as the issuer too. A's vault grants B the job protocol and C the
//! status protocol alone. Every node call A's worker makes is answered by a script that counts
//! the asks per machine.
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features \
//!     --test issuer_readiness_scheduled_read
//! ```
#![cfg(all(oneiron_test_support, feature = "mesh"))]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::Duration;

use engine_stack::on_engine_stack;
use mesh_machines::{Machines, TestResult, at};
use oneiron::machine_policy::machine_item;
use oneiron::machine_readiness::ReadinessEscalation;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::steward;
use oneiron::{EntityId, Vault};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::gpu_execution_node::issuer::guard::ReadinessReads;
use oneiron_server::gpu_execution_node::issuer::{JobNodeClient, NodeCallError};
use oneiron_server::gpu_execution_node::wire::{
    JOB_ALPN, JOB_STATUS_ALPN, JobAnswer, JobRequest, JobStatusAnswer, JobStatusRequest,
    NodeAnswer, NodeReadiness, ReadinessCheck, ReadinessResult, ReadinessState,
};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::gpu_backend::{
    gpu_job_worker_starts, run_gpu_job_worker_tick, use_job_nodes,
};
use oneiron_server::test_doors::work_order_host::{run_readiness_read_at, worker_pass_asks};
use serde_json::{Value, json};

const A: usize = 0;
const B: usize = 1;
const C: usize = 2;

/// 26 Nov 2026 12:00 UTC on the issuer's clock: the first scheduled read in these tests.
const READ_AT_MS: u64 = 1_795_694_400_000;
/// `jobs.readiness.every_secs`, its default, in milliseconds.
const PERIOD_MS: u64 = 900_000;
/// The node's newest check, on its own clock.
const CHECKED_AT_MS: u64 = 1_795_690_000_000;
const READINESS_EVERY_SECS: &str = "jobs.readiness.every_secs";
/// How long a held answer waits for the test to release it.
const HOLD_LIMIT: Duration = Duration::from_secs(30);

/// What the script answers a machine's `Node` ask.
#[derive(Clone)]
enum Script {
    /// A `Node` answer with this readiness fact, or with none (a node that reports none).
    Answers(Option<NodeReadiness>),
    /// No answer: the call times out.
    Unreachable,
}

/// One machine's answer held until the test releases it.
struct Hold {
    machine: EntityId,
    asked: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

/// The machines A's worker calls, by script. A machine with no script does not answer.
#[derive(Default)]
struct ScriptedMachines {
    scripts: Mutex<BTreeMap<EntityId, Script>>,
    asks: Mutex<Vec<EntityId>>,
    /// The issuer's clock as the scheduled read dates its asks in a test that passes it.
    clock_ms: AtomicU64,
    /// How long the next ask takes, on that clock.
    next_ask_takes_ms: AtomicU64,
    hold: Mutex<Option<Hold>>,
    /// A held answer was never released within `HOLD_LIMIT`.
    hold_expired: AtomicBool,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl ScriptedMachines {
    fn script(&self, machine: EntityId, script: Script) {
        locked(&self.scripts).insert(machine, script);
    }

    /// The `Node` asks of `machine` so far.
    fn asks_of(&self, machine: EntityId) -> usize {
        locked(&self.asks)
            .iter()
            .filter(|asked| **asked == machine)
            .count()
    }

    /// Every `Node` ask so far, in order.
    fn asked(&self) -> Vec<EntityId> {
        locked(&self.asks).clone()
    }

    fn asks(&self) -> usize {
        locked(&self.asks).len()
    }

    fn now_ms(&self) -> u64 {
        self.clock_ms.load(Ordering::SeqCst)
    }

    /// Holds `machine`'s next answer until the test sends on the returned sender; the returned
    /// receiver hears when that ask arrives.
    fn hold(&self, machine: EntityId) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (asked, heard) = mpsc::channel();
        let (release, released) = mpsc::channel();
        *locked(&self.hold) = Some(Hold {
            machine,
            asked,
            release: released,
        });
        (heard, release)
    }
}

impl JobNodeClient for ScriptedMachines {
    fn job(&self, node: EntityId, request: &JobRequest) -> Result<JobAnswer, NodeCallError> {
        assert!(
            matches!(request, JobRequest::Node),
            "the worker asks an idle machine nothing but Node"
        );
        locked(&self.asks).push(node);
        let takes = self.next_ask_takes_ms.swap(0, Ordering::SeqCst);
        self.clock_ms.fetch_add(takes, Ordering::SeqCst);
        let hold = {
            let mut hold = locked(&self.hold);
            if hold.as_ref().is_some_and(|hold| hold.machine == node) {
                hold.take()
            } else {
                None
            }
        };
        if let Some(hold) = hold {
            hold.asked.send(()).ok();
            if hold.release.recv_timeout(HOLD_LIMIT).is_err() {
                self.hold_expired.store(true, Ordering::SeqCst);
            }
        }
        let script = locked(&self.scripts)
            .get(&node)
            .cloned()
            .unwrap_or(Script::Unreachable);
        match script {
            Script::Answers(readiness) => Ok(JobAnswer::Node(NodeAnswer {
                readiness,
                ..idle()
            })),
            Script::Unreachable => Err(NodeCallError::Timeout),
        }
    }

    fn job_status(
        &self,
        _node: EntityId,
        _request: &JobStatusRequest,
    ) -> Result<JobStatusAnswer, NodeCallError> {
        Err(NodeCallError::Unreachable {
            reason: "the scheduled read asks no status".to_owned(),
        })
    }
}

/// An idle node's answer: enabled, nothing running, no readiness fact.
fn idle() -> NodeAnswer {
    NodeAnswer {
        enabled: true,
        paused: None,
        drained: None,
        templates: Vec::new(),
        scopes: Vec::new(),
        disk_free_bytes: 200 << 30,
        disk_reserved_bytes: 0,
        disk_reserve_bytes: 50 << 30,
        epoch: None,
        swept: true,
        boot_id: "boot-1".to_owned(),
        engine_version: "0.0.0-test".to_owned(),
        readiness: None,
    }
}

/// The node's fact after a passed check at `at_ms`, on its own clock.
fn passed(at_ms: u64) -> NodeReadiness {
    NodeReadiness {
        state: ReadinessState::Ready,
        checked_at_ms: Some(at_ms),
        failed_in_a_row: 0,
        failing_since_ms: None,
        results: vec![ReadinessResult {
            at_ms,
            state: ReadinessState::Ready,
        }],
    }
}

/// The node's fact at the `failed`th failed check of a run, one period apart, the newest at
/// `CHECKED_AT_MS`.
fn failing(failed: u32) -> NodeReadiness {
    let not_ready = ReadinessState::NotReady {
        check: ReadinessCheck::Devices,
        why: "driver not answering".to_owned(),
    };
    let at = |index: u32| CHECKED_AT_MS - u64::from(failed - 1 - index) * PERIOD_MS;
    NodeReadiness {
        state: not_ready.clone(),
        checked_at_ms: Some(at(failed - 1)),
        failed_in_a_row: failed,
        failing_since_ms: Some(at(0)),
        results: (0..failed)
            .map(|index| ReadinessResult {
                at_ms: at(index),
                state: not_ready.clone(),
            })
            .collect(),
    }
}

/// A, B and C as the module doc says, with A's node calls answered by `script`.
async fn issuer_with(script: &Arc<ScriptedMachines>) -> TestResult<Machines> {
    let mesh = Machines::start_with(3, |index, machines| {
        let mut config = SyncServerConfig::default();
        if index != B {
            config.gpu_jobs.vault_machine.issuer = Some(machines[A]);
        }
        config.gpu_jobs.vault_machine.enabled = index == A;
        config
    })
    .await?;
    mesh.grant(A, B, &[JOB_ALPN])?;
    mesh.grant(A, C, &[JOB_STATUS_ALPN])?;
    let nodes: Arc<dyn JobNodeClient> = Arc::clone(script) as Arc<dyn JobNodeClient>;
    if !use_job_nodes(&mesh.machine(A).served.server, nodes) {
        return Err("FIXTURE: A's loop made its own node client before the script".into());
    }
    Ok(mesh)
}

/// A's scheduled read after a pass begun at `now_ms`, every ask dated `now_ms`, off the runtime
/// as the worker runs it.
fn read_at(server: &Arc<SyncServer>, now_ms: u64) {
    tokio::task::block_in_place(|| run_readiness_read_at(server, now_ms, &|| now_ms));
}

/// The owner sets `jobs.readiness.every_secs` for `machine` on `vault`.
fn owner_sets_every_secs(vault: &Vault, machine: EntityId, value: Value) -> TestResult {
    let owner = steward::owner(vault).map_err(at("the owner's proof"))?;
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(&owner),
            SetSetting {
                item: Some(machine_item(machine)),
                ..SetSetting::vault_value(READINESS_EVERY_SECS, value)
            },
        )
        .map_err(at("the owner sets the period"))?;
    if !matches!(outcome, SetSettingOutcome::Applied { .. }) {
        return Err(format!("the owner's period applies: {outcome:?}").into());
    }
    Ok(())
}

/// A machine is due the scheduled read a whole period after the worker last asked it, whatever
/// that ask brought. A machine asked since the pass began is not due, whatever the period, so a
/// period of 0 asks once a pass. It is due at once when the issuer's clock steps back past its
/// last ask. A last ask is kept past the readings' one-day drop, so a period of two days counts
/// in full, until the grants no longer admit the machine.
#[test]
fn a_machine_is_due_the_scheduled_read_a_period_after_its_last_ask() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut config = oneiron::VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Vault::open(dir.path(), config).map_err(at("open the vault"))?;
    let machine = EntityId::now();
    let mut reads = ReadinessReads::default();
    let due = |reads: &ReadinessReads, now: u64, every: u64| reads.due(machine, now, every, now);
    assert!(
        due(&reads, READ_AT_MS, PERIOD_MS),
        "a machine never asked is due"
    );

    reads.asked(machine, READ_AT_MS);
    assert!(
        !reads.due(machine, READ_AT_MS, PERIOD_MS, READ_AT_MS),
        "asked since the pass began: not due"
    );
    assert!(
        !reads.due(machine, READ_AT_MS + PERIOD_MS, 0, READ_AT_MS),
        "asked since the pass began: not due, whatever the period"
    );
    assert!(!due(&reads, READ_AT_MS + PERIOD_MS - 1, PERIOD_MS));
    assert!(due(&reads, READ_AT_MS + PERIOD_MS, PERIOD_MS));
    assert!(
        due(&reads, READ_AT_MS + 1, 0),
        "a period of 0: due at the next pass"
    );
    assert!(
        due(&reads, READ_AT_MS - 1, PERIOD_MS),
        "the issuer's clock stepped back past the ask"
    );

    let two_days = 2 * ReadinessReads::IDLE_MS;
    let day_after = READ_AT_MS + ReadinessReads::IDLE_MS + 3_600_000;
    let fact = passed(CHECKED_AT_MS);
    reads.observe(&vault, EntityId::now(), None, None, &fact, day_after);
    assert!(
        !due(&reads, day_after, two_days),
        "a two-day period outlives the readings' one-day drop"
    );
    assert!(due(&reads, READ_AT_MS + two_days, two_days));

    reads.keep_granted(&[machine]);
    assert!(
        !due(&reads, day_after, two_days),
        "a granted machine's ask is kept"
    );
    reads.keep_granted(&[]);
    assert!(
        due(&reads, day_after, two_days),
        "an ask of a machine the grants no longer admit is dropped"
    );

    let mut reads = ReadinessReads::default();
    let granted = EntityId::now();
    reads.observe(&vault, granted, None, None, &fact, READ_AT_MS);
    reads.keep_granted(&[granted]);
    reads.observe(&vault, EntityId::now(), None, None, &fact, day_after);
    assert_eq!(
        reads.len(),
        2,
        "a granted machine's readings outlive the one-day drop"
    );
    reads.keep_granted(&[]);
    reads.observe(&vault, EntityId::now(), None, None, &fact, day_after);
    assert_eq!(
        reads.len(),
        2,
        "once the grants no longer admit it, the idle machine's readings are dropped"
    );
    Ok(())
}

/// An idle machine whose check keeps failing: no order wants it, so no pass asks it. A tick of
/// the worker starts the scheduled read, which asks B and queues the owner's one ask for the
/// run. C, which holds the status grant alone, is never asked. The next tick's read, inside the
/// period, asks nothing. The enabled issuer's worker starts with no offer, job or order.
async fn idle_failing_machine_reaches_the_owner() -> TestResult {
    let script = Arc::new(ScriptedMachines::default());
    let mesh = issuer_with(&script).await?;
    let server = Arc::clone(&mesh.machine(A).served.server);
    let vault = Arc::clone(&mesh.machine(A).device.vault);
    let b = mesh.machine(B).device.machine;
    let c = mesh.machine(C).device.machine;
    let run = failing(3);
    script.script(b, Script::Answers(Some(run.clone())));
    script.script(c, Script::Answers(Some(run.clone())));

    let read = run_gpu_job_worker_tick(&server)
        .await
        .ok_or("the tick starts the scheduled read")?;
    read.await?;
    assert_eq!(script.asks_of(b), 1, "the worker asks the idle machine B");
    assert_eq!(script.asks_of(c), 0, "C holds no job grant: never asked");
    let streak = run
        .streak(b)
        .ok_or("FIXTURE: three failed checks make a streak")?;
    let escalation = vault
        .raise_machine_readiness_ask(&streak)
        .map_err(at("find the run's ask"))?;
    assert!(
        matches!(
            escalation,
            ReadinessEscalation::Asked {
                queued_now: false,
                ..
            }
        ),
        "the worker's read queued the run's one ask: {escalation:?}"
    );

    let read = run_gpu_job_worker_tick(&server)
        .await
        .ok_or("the next tick starts a read too")?;
    read.await?;
    assert_eq!(
        script.asks(),
        1,
        "inside the period the next read asks nothing"
    );
    assert!(
        gpu_job_worker_starts(&server),
        "the enabled issuer's worker starts with no offer, job or order"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn the_issuers_worker_reads_an_idle_machine_and_its_failing_run_reaches_the_owner() -> TestResult {
    on_engine_stack(idle_failing_machine_reaches_the_owner)
}

/// The worker never waits for its scheduled read: while B's answer is held, the tick that
/// started the read has returned, and the next tick runs its pass and starts no second read.
/// Once the read ends, the next tick starts one again.
async fn read_runs_beside_the_worker_one_at_a_time() -> TestResult {
    let script = Arc::new(ScriptedMachines::default());
    let mesh = issuer_with(&script).await?;
    let server = Arc::clone(&mesh.machine(A).served.server);
    let b = mesh.machine(B).device.machine;
    script.script(b, Script::Answers(Some(passed(CHECKED_AT_MS))));
    let (heard, release) = script.hold(b);

    let read = run_gpu_job_worker_tick(&server)
        .await
        .ok_or("the tick starts the scheduled read")?;
    tokio::task::block_in_place(|| heard.recv_timeout(HOLD_LIMIT))
        .map_err(at("the read asks B"))?;
    assert!(
        run_gpu_job_worker_tick(&server).await.is_none(),
        "the next tick starts no second read while one runs"
    );
    release.send(()).map_err(at("release B's answer"))?;
    read.await?;
    assert!(
        !script.hold_expired.load(Ordering::SeqCst),
        "the tick returned while B's answer was held"
    );
    assert_eq!(script.asks_of(b), 1);

    let read = run_gpu_job_worker_tick(&server)
        .await
        .ok_or("the read ended: the next tick starts one")?;
    read.await?;
    assert_eq!(
        script.asks_of(b),
        1,
        "inside the period B is not asked again"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn the_worker_never_waits_for_its_readiness_read_and_runs_one_at_a_time() -> TestResult {
    on_engine_stack(read_runs_beside_the_worker_one_at_a_time)
}

/// The scheduled read asks B at most once per B's `jobs.readiness.every_secs`, counted from the
/// worker's last ask of it: 900 s by default, then the owner's 60 s for B, then 0 (once a pass).
async fn machine_is_asked_once_a_period() -> TestResult {
    let script = Arc::new(ScriptedMachines::default());
    let mesh = issuer_with(&script).await?;
    let server = Arc::clone(&mesh.machine(A).served.server);
    let vault = Arc::clone(&mesh.machine(A).device.vault);
    let b = mesh.machine(B).device.machine;
    script.script(b, Script::Answers(Some(passed(CHECKED_AT_MS))));

    read_at(&server, READ_AT_MS);
    assert_eq!(script.asks_of(b), 1, "the first read asks B");
    read_at(&server, READ_AT_MS);
    read_at(&server, READ_AT_MS + PERIOD_MS - 1);
    assert_eq!(script.asks_of(b), 1, "inside 900 s B is not asked again");
    read_at(&server, READ_AT_MS + PERIOD_MS);
    assert_eq!(
        script.asks_of(b),
        2,
        "900 s after its last ask B is asked again"
    );

    owner_sets_every_secs(&vault, b, json!(60))?;
    let last = READ_AT_MS + PERIOD_MS;
    read_at(&server, last + 59_999);
    assert_eq!(script.asks_of(b), 2, "inside the owner's 60 s");
    read_at(&server, last + 60_000);
    assert_eq!(script.asks_of(b), 3, "the owner's 60 s period for B");

    owner_sets_every_secs(&vault, b, json!(0))?;
    let last = last + 60_000;
    read_at(&server, last);
    assert_eq!(
        script.asks_of(b),
        3,
        "a period of 0 asks no machine twice for one pass"
    );
    read_at(&server, last + 1);
    assert_eq!(
        script.asks_of(b),
        4,
        "a period of 0 asks at every later pass"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn the_scheduled_read_asks_a_machine_again_only_after_its_every_secs() -> TestResult {
    on_engine_stack(machine_is_asked_once_a_period)
}

/// Each ask is dated when it is sent. The read's first ask takes 70 s; the machine asked after
/// it is dated 70 s later than the pass, so with a 60 s period it is not due again 100 s after
/// the pass, while the first one is.
async fn asks_are_dated_when_sent() -> TestResult {
    let script = Arc::new(ScriptedMachines::default());
    let mesh = issuer_with(&script).await?;
    mesh.grant(A, C, &[JOB_ALPN])?;
    let server = Arc::clone(&mesh.machine(A).served.server);
    let vault = Arc::clone(&mesh.machine(A).device.vault);
    for index in [B, C] {
        let machine = mesh.machine(index).device.machine;
        script.script(machine, Script::Answers(Some(passed(CHECKED_AT_MS))));
        owner_sets_every_secs(&vault, machine, json!(60))?;
    }
    let clock = || script.now_ms();

    script.clock_ms.store(READ_AT_MS, Ordering::SeqCst);
    script.next_ask_takes_ms.store(70_000, Ordering::SeqCst);
    tokio::task::block_in_place(|| run_readiness_read_at(&server, READ_AT_MS, &clock));
    let order = script.asked();
    let [first, second] = order.as_slice() else {
        return Err(format!("FIXTURE: the first read asks B and C once each: {order:?}").into());
    };

    let later = READ_AT_MS + 100_000;
    script.clock_ms.store(later, Ordering::SeqCst);
    tokio::task::block_in_place(|| run_readiness_read_at(&server, later, &clock));
    assert_eq!(
        script.asks_of(*first),
        2,
        "asked at the pass, 100 s ago: due"
    );
    assert_eq!(
        script.asks_of(*second),
        1,
        "asked 70 s after the pass, 30 s ago: not due"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn each_ask_is_dated_when_it_is_sent() -> TestResult {
    on_engine_stack(asks_are_dated_when_sent)
}

/// A machine that does not answer, or answers with no readiness fact, is asked once a period
/// too: the worker records each ask, so such a machine costs one call a period, not one a pass.
async fn silent_machine_is_asked_once_a_period() -> TestResult {
    let script = Arc::new(ScriptedMachines::default());
    let mesh = issuer_with(&script).await?;
    let server = Arc::clone(&mesh.machine(A).served.server);
    let b = mesh.machine(B).device.machine;

    script.script(b, Script::Unreachable);
    read_at(&server, READ_AT_MS);
    read_at(&server, READ_AT_MS + 1_000);
    assert_eq!(script.asks_of(b), 1, "an unanswered ask waits its period");
    read_at(&server, READ_AT_MS + PERIOD_MS);
    assert_eq!(script.asks_of(b), 2, "a period later B is asked again");

    script.script(b, Script::Answers(None));
    read_at(&server, READ_AT_MS + 2 * PERIOD_MS);
    read_at(&server, READ_AT_MS + 2 * PERIOD_MS + 1_000);
    assert_eq!(
        script.asks_of(b),
        3,
        "an answer with no readiness fact waits its period"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_machine_that_brings_no_readiness_fact_is_asked_once_a_period() -> TestResult {
    on_engine_stack(silent_machine_is_asked_once_a_period)
}

/// Only the vault's issuer of vault machine jobs reads: C, a replica that names A as the issuer
/// and holds B's job grant too, asks nothing. And A reads only machines whose job grant it still
/// holds: once A withdraws B's grant, B is not asked again.
async fn only_issuer_reads_job_granted_machines() -> TestResult {
    let script = Arc::new(ScriptedMachines::default());
    let mesh = issuer_with(&script).await?;
    let server = Arc::clone(&mesh.machine(A).served.server);
    let b = mesh.machine(B).device.machine;
    script.script(b, Script::Answers(Some(failing(3))));

    mesh.grant(C, B, &[JOB_ALPN])?;
    let replica_script = Arc::new(ScriptedMachines::default());
    replica_script.script(b, Script::Answers(Some(failing(3))));
    let replica = Arc::clone(&mesh.machine(C).served.server);
    let replica_nodes: Arc<dyn JobNodeClient> =
        Arc::clone(&replica_script) as Arc<dyn JobNodeClient>;
    if !use_job_nodes(&replica, replica_nodes) {
        return Err("FIXTURE: C's loop made its own node client before the script".into());
    }
    read_at(&replica, READ_AT_MS);
    assert_eq!(
        replica_script.asks(),
        0,
        "a replica that is not the issuer asks nothing"
    );

    read_at(&server, READ_AT_MS);
    assert_eq!(script.asks_of(b), 1, "the issuer asks B");
    mesh.revoke(A, B, &[JOB_ALPN])?;
    read_at(&server, READ_AT_MS + PERIOD_MS);
    assert_eq!(
        script.asks_of(b),
        1,
        "B's job grant withdrawn: B is not asked"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn only_the_issuer_reads_and_only_machines_it_holds_a_job_grant_for() -> TestResult {
    on_engine_stack(only_issuer_reads_job_granted_machines)
}

/// The pass dates each ask when it is sent: its first ask takes 70 s, so the machine it asks
/// next is dated 70 s into the pass, and with a 60 s period the read 100 s after the pass asks
/// only the first one again (REVIEW-10544 round 2).
async fn pass_dates_asks_when_sent() -> TestResult {
    let script = Arc::new(ScriptedMachines::default());
    let mesh = issuer_with(&script).await?;
    mesh.grant(A, C, &[JOB_ALPN])?;
    let server = Arc::clone(&mesh.machine(A).served.server);
    let vault = Arc::clone(&mesh.machine(A).device.vault);
    let b = mesh.machine(B).device.machine;
    let c = mesh.machine(C).device.machine;
    for machine in [b, c] {
        script.script(machine, Script::Answers(Some(passed(CHECKED_AT_MS))));
        owner_sets_every_secs(&vault, machine, json!(60))?;
    }
    let clock = || script.now_ms();

    script.clock_ms.store(READ_AT_MS, Ordering::SeqCst);
    script.next_ask_takes_ms.store(70_000, Ordering::SeqCst);
    tokio::task::block_in_place(|| worker_pass_asks(&server, READ_AT_MS, &clock, &[b, c]));
    assert_eq!(script.asked(), vec![b, c], "the pass asks B, then C");

    let later = READ_AT_MS + 100_000;
    script.clock_ms.store(later, Ordering::SeqCst);
    tokio::task::block_in_place(|| run_readiness_read_at(&server, later, &clock));
    assert_eq!(script.asks_of(b), 2, "asked at the pass, 100 s ago: due");
    assert_eq!(
        script.asks_of(c),
        1,
        "asked 70 s into the pass, 30 s ago: not due"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn the_pass_dates_each_ask_when_it_is_sent() -> TestResult {
    on_engine_stack(pass_dates_asks_when_sent)
}

/// The pass records each ask before it sends it, so a read running while a request to B is out
/// does not send B another one (REVIEW-10544 round 2).
async fn read_skips_a_request_already_out() -> TestResult {
    let script = Arc::new(ScriptedMachines::default());
    let mesh = issuer_with(&script).await?;
    let server = Arc::clone(&mesh.machine(A).served.server);
    let b = mesh.machine(B).device.machine;
    script.script(b, Script::Answers(Some(passed(CHECKED_AT_MS))));
    script.clock_ms.store(READ_AT_MS, Ordering::SeqCst);
    let (heard, release) = script.hold(b);

    let pass_server = Arc::clone(&server);
    let pass_script = Arc::clone(&script);
    let pass = tokio::task::spawn_blocking(move || {
        let clock = || pass_script.now_ms();
        worker_pass_asks(&pass_server, READ_AT_MS, &clock, &[b]);
    });
    tokio::task::block_in_place(|| heard.recv_timeout(HOLD_LIMIT))
        .map_err(at("the pass asks B"))?;
    // A read that began just before that pass, while the pass waits on B's answer.
    tokio::task::block_in_place(|| {
        run_readiness_read_at(&server, READ_AT_MS - 1, &|| READ_AT_MS);
    });
    assert_eq!(
        script.asks_of(b),
        1,
        "the read sends B no second request while one is out"
    );
    release.send(()).map_err(at("release B's answer"))?;
    pass.await?;
    assert!(!script.hold_expired.load(Ordering::SeqCst));
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_read_never_repeats_a_request_already_out() -> TestResult {
    on_engine_stack(read_skips_a_request_already_out)
}

/// Before the issuer's mesh listener is bound, no node call can start, so the read asks nothing
/// and records nothing (REVIEW-10544 round 2). A second server on A's vault that no listener
/// serves stands in for A before its bind.
async fn nothing_is_read_before_the_mesh_is_bound() -> TestResult {
    let script = Arc::new(ScriptedMachines::default());
    let mesh = issuer_with(&script).await?;
    let vault = Arc::clone(&mesh.machine(A).device.vault);
    let a = mesh.machine(A).device.machine;
    let b = mesh.machine(B).device.machine;
    let mut config = SyncServerConfig::default();
    config.auth_secret = Some("issuer-readiness-scheduled-read-unbound".to_owned());
    config.gpu_jobs.vault_machine.enabled = true;
    config.gpu_jobs.vault_machine.issuer = Some(a);
    let unbound = SyncServer::new(vault, config).map_err(at("the unbound server"))?;
    let unbound = Arc::new(unbound);
    let unbound_script = Arc::new(ScriptedMachines::default());
    unbound_script.script(b, Script::Answers(Some(failing(3))));
    let nodes: Arc<dyn JobNodeClient> = Arc::clone(&unbound_script) as Arc<dyn JobNodeClient>;
    if !use_job_nodes(&unbound, nodes) {
        return Err("FIXTURE: the unbound server made its own node client".into());
    }

    read_at(&unbound, READ_AT_MS);
    assert_eq!(
        unbound_script.asks(),
        0,
        "before the mesh listener is bound the read asks nothing"
    );
    drop(unbound);
    mesh.stop().await;
    Ok(())
}

#[test]
fn nothing_is_read_before_the_issuers_mesh_listener_is_bound() -> TestResult {
    on_engine_stack(nothing_is_read_before_the_mesh_is_bound)
}
