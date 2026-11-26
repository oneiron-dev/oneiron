//! CG-2 row 9's scheduled read (owner COMPUTE-CG = AA, 25 Nov 22:56: "A drained machine clears
//! itself once its readiness check passes; you hear only when the check keeps failing"; FIX
//! CG2-ROW9-UNDEMANDED-MACHINES-UNOBSERVED). The job worker's pass asks `Node` only of the
//! machines an open order wants. After each pass the worker also asks each machine the vault's
//! grants admit on the job protocol once that machine's `jobs.readiness.every_secs` has passed
//! since its last ask, and acts on the answer's readiness fact as the pass does. So an idle
//! machine whose check keeps failing reaches the owner with no order open (pass 34, 7.3 and 16,
//! practice 6).
//!
//! A, B and C share one home. A is the vault's issuer of vault machine jobs, and C names A as
//! the issuer too. A's vault grants B the job protocol and C the status protocol alone. Every
//! node call A's worker makes is answered by a script that counts the asks per machine.
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
use std::sync::{Arc, Mutex, MutexGuard};

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
use oneiron_server::test_doors::gpu_backend::{run_gpu_job_worker_pass, use_job_nodes};
use oneiron_server::test_doors::work_order_host::run_readiness_read_at;
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

/// What the script answers a machine's `Node` ask.
#[derive(Clone)]
enum Script {
    /// A `Node` answer with this readiness fact, or with none (a node that reports none).
    Answers(Option<NodeReadiness>),
    /// No answer: the call times out.
    Unreachable,
}

/// The machines A's worker calls, by script. A machine with no script does not answer.
#[derive(Default)]
struct ScriptedMachines {
    scripts: Mutex<BTreeMap<EntityId, Script>>,
    asks: Mutex<Vec<EntityId>>,
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

    /// Every `Node` ask so far.
    fn asks(&self) -> usize {
        locked(&self.asks).len()
    }
}

impl JobNodeClient for ScriptedMachines {
    fn job(&self, node: EntityId, request: &JobRequest) -> Result<JobAnswer, NodeCallError> {
        assert!(
            matches!(request, JobRequest::Node),
            "the worker asks an idle machine nothing but Node"
        );
        locked(&self.asks).push(node);
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

/// A's scheduled read at `now_ms`, off the runtime as the worker runs it.
fn read_at(server: &Arc<SyncServer>, now_ms: u64) {
    tokio::task::block_in_place(|| run_readiness_read_at(server, now_ms));
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

/// A machine is due the scheduled read a whole period after the worker last asked it, whether
/// that ask brought a reading or none. It is never asked twice at one time, so a period of 0
/// (`every_secs = 0`) means every pass, and it is due at once when the issuer's clock steps back
/// past its last ask.
#[test]
fn a_machine_is_due_the_scheduled_read_a_period_after_its_last_ask() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut config = oneiron::VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Vault::open(dir.path(), config)
        .map_err(at("open the vault"))?;
    let read = EntityId::now();
    let unanswered = EntityId::now();
    let mut reads = ReadinessReads::default();
    assert!(
        reads.due(read, READ_AT_MS, PERIOD_MS),
        "a machine never asked is due"
    );

    let fact = passed(CHECKED_AT_MS);
    reads.observe(&vault, read, None, None, &fact, READ_AT_MS);
    reads.asked(unanswered, READ_AT_MS);
    for (machine, what) in [(read, "a read"), (unanswered, "an ask with no reading")] {
        assert!(
            !reads.due(machine, READ_AT_MS, PERIOD_MS),
            "{what} at this time: not due"
        );
        assert!(
            !reads.due(machine, READ_AT_MS + PERIOD_MS - 1, PERIOD_MS),
            "{what}: not due inside the period"
        );
        assert!(
            reads.due(machine, READ_AT_MS + PERIOD_MS, PERIOD_MS),
            "{what}: due a period later"
        );
        assert!(
            !reads.due(machine, READ_AT_MS, 0),
            "{what}: a period of 0 never asks twice at one time"
        );
        assert!(
            reads.due(machine, READ_AT_MS + 1, 0),
            "{what}: a period of 0 asks at every later pass"
        );
        assert!(
            reads.due(machine, READ_AT_MS - 1, PERIOD_MS),
            "{what}: due once the issuer's clock steps back past it"
        );
    }
    Ok(())
}

/// An idle machine whose check keeps failing: no order wants it, so no pass asks it. The worker's
/// scheduled read asks it and queues the owner's one ask for the run. C, which holds the status
/// grant alone, is never asked. The next worker pass, inside the period, asks nothing.
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

    tokio::task::block_in_place(|| run_gpu_job_worker_pass(&server));
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

    tokio::task::block_in_place(|| run_gpu_job_worker_pass(&server));
    assert_eq!(
        script.asks(),
        1,
        "inside the period the next pass asks nothing"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn the_worker_reads_an_idle_granted_machine_and_its_failing_run_reaches_the_owner() -> TestResult {
    on_engine_stack(idle_failing_machine_reaches_the_owner)
}

/// The scheduled read asks B at most once per B's `jobs.readiness.every_secs`, counted from the
/// worker's last ask of it: 900 s by default, then the owner's 60 s for B, then 0 (every pass,
/// never twice at one time).
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
        "a period of 0 never asks twice at one time"
    );
    read_at(&server, last + 1);
    assert_eq!(
        script.asks_of(b),
        4,
        "a period of 0 asks at every later read"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn the_scheduled_read_asks_a_machine_again_only_after_its_every_secs() -> TestResult {
    on_engine_stack(machine_is_asked_once_a_period)
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
