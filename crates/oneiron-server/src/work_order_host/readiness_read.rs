//! The job worker's readiness read (CG-2 row 9; FIX CG2-ROW9-UNDEMANDED-MACHINES-UNOBSERVED): the
//! worker's `Node` ask that acts on a machine's readiness fact, by its pass and by its scheduled
//! read of the machines no open order wants, and the readings it keeps between asks.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::EntityId;

use super::OrderLoop;
use crate::gpu_execution_node::issuer::{
    JobNodeClient, NodeCallError, VAULT_MACHINE_BACKEND, not_the_issuer,
};
use crate::gpu_execution_node::wire::{JOB_ALPN, JobAnswer, JobRequest};
use crate::server::SyncServer;

/// The mark of the worker's scheduled readiness read while it runs
/// ([`OrderLoop::begin_readiness_read`]). Dropping it, however the read ends, lets the next one
/// start.
pub(crate) struct ReadinessReadRunning(Arc<AtomicBool>);

impl Drop for ReadinessReadRunning {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl OrderLoop {
    /// The worker's `Node` ask of `machine` through `nodes`, sent at `now_ms`, by its pass or by
    /// its scheduled read, acting on the answer's readiness fact
    /// (`issuer::guard::ReadinessReads::observe`). The issuer's guard row is read before the
    /// request is sent, so a check the answer shows as newer than an earlier one ran after that
    /// read; the node's own drain comes from the same answer. An answer that repeats the sample
    /// this loop last acted on changes nothing and takes no write. A reading whose store call
    /// failed is acted on again at the next answer. Every ask is recorded at `now_ms` before the
    /// request is sent, whatever comes back (`ReadinessReads::asked`), so the scheduled read
    /// counts the machine's period from it and never repeats a request already out. The
    /// readings' lock is not held while the node answers, so a pass and the scheduled read that
    /// runs beside it wait on each other only for a reading's own writes.
    pub(crate) fn ask_node_observing(
        &self,
        vault: &oneiron::Vault,
        nodes: &dyn JobNodeClient,
        machine: EntityId,
        now_ms: u64,
    ) -> Result<JobAnswer, NodeCallError> {
        let guard_before = vault.machine_job_guard(machine).unwrap_or_else(|error| {
            tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the machine's job guard not read; its readiness clear waits");
            None
        });
        self.readiness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .asked(machine, now_ms);
        let answer = nodes.job(machine, &JobRequest::Node);
        let mut reads = self
            .readiness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Ok(JobAnswer::Node(node)) = &answer
            && let Some(readiness) = &node.readiness
        {
            reads.observe(
                vault,
                machine,
                guard_before.as_ref(),
                node.drained.as_deref(),
                readiness,
                now_ms,
            );
        }
        answer
    }

    /// Whether `machine` is due the scheduled read after the pass begun at `pass_at_ms`, at
    /// `now_ms`, `every_ms` after its last ask, recording the read's ask when it is, in one step
    /// under the readings' lock (`issuer::guard::ReadinessReads::claim`).
    fn claim_readiness_read(
        &self,
        machine: EntityId,
        now_ms: u64,
        every_ms: u64,
        pass_at_ms: u64,
    ) -> bool {
        self.readiness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .claim(machine, now_ms, every_ms, pass_at_ms)
    }

    /// Records the machines the vault's grants admit now
    /// (`issuer::guard::ReadinessReads::keep_granted`).
    fn keep_granted(&self, machines: &[EntityId]) {
        self.readiness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keep_granted(machines);
    }

    /// Marks the worker's scheduled readiness read as running, or `None` while one runs.
    pub(crate) fn begin_readiness_read(&self) -> Option<ReadinessReadRunning> {
        (!self.reading.swap(true, Ordering::AcqRel))
            .then(|| ReadinessReadRunning(Arc::clone(&self.reading)))
    }
}

/// Whether `server`'s mesh listener is bound: before it is, every node call answers
/// `Unreachable` without dialing (`issuer::MeshJobNodeClient`).
#[cfg(feature = "mesh")]
pub(super) fn mesh_bound(server: &SyncServer) -> bool {
    server.mesh_transport.get().is_some()
}

/// A server built without the mesh calls no machines.
#[cfg(not(feature = "mesh"))]
pub(super) fn mesh_bound(_server: &SyncServer) -> bool {
    false
}

/// The job worker's pass's `Node` asks of `machines` on `server`, as its pass at `now_ms` sends
/// them, each dated by `clock`, for `tests/issuer_readiness_scheduled_read.rs`.
#[cfg(oneiron_test_support)]
pub(crate) fn worker_pass_asks(
    server: &Arc<SyncServer>,
    now_ms: u64,
    clock: &dyn Fn() -> u64,
    machines: &[EntityId],
) {
    use super::ServerOrderHost;
    use oneiron::work_order::OrderHost as _;

    let nodes = server.gpu_jobs.orders().nodes(server);
    let host = ServerOrderHost {
        clock,
        ..ServerOrderHost::new(server, nodes.as_ref(), now_ms)
    }
    .observing();
    drop(host.machine_facts(machines));
}

/// The job worker's scheduled readiness read after its pass begun at `pass_at_ms`, on the
/// issuer's clock `clock` (FIX CG2-ROW9-UNDEMANDED-MACHINES-UNOBSERVED). The pass asks only the
/// machines an open order wants, so an idle machine would keep a drain, and its run of failed
/// checks would reach no owner, until demand came back. This asks each machine the vault's
/// grants admit on the job protocol once its `jobs.readiness.every_secs` (default 900 s) has
/// passed since the worker last asked it, and acts on its readiness fact as the pass does
/// ([`OrderLoop::ask_node_observing`]): a passed check clears the issuer's drain, and a run of
/// failed checks reaches the owner as the run's one ask (pass 34, 7.3 and 16, practice 6).
/// - Each ask is dated by `clock` when it is sent, so a slow answer before it delays no
///   machine's period (REVIEW-10544 round 1 P1).
/// - A machine asked since `pass_at_ms`, by the pass or by a later one, is not asked again, nor
///   one a request is already out to: each check and its record are one step.
/// - The last asks of machines the grants no longer admit are dropped; the readings of those
///   they admit are kept however long their period (REVIEW-10544 round 2 P1).
/// - Nothing is read before the mesh listener is bound: no request could start, and none is
///   recorded (REVIEW-10544 round 2 P1).
///
/// Only the vault's issuer of vault machine jobs reads, as only its pass acts on what it reads
/// ([`ServerOrderHost::observing`]). The worker runs it beside its passes and never waits for it
/// (`gpu_host::spawn_gpu_job_steps`), off the pass's lock; each ask is bounded by
/// `[gpu_jobs.vault_machine] call_timeout_secs`. It writes only what a reading writes.
///
/// [`ServerOrderHost::observing`]: super::ServerOrderHost::observing
pub(crate) fn run_readiness_read(
    server: &Arc<SyncServer>,
    pass_at_ms: u64,
    clock: &dyn Fn() -> u64,
) {
    if not_the_issuer(server, VAULT_MACHINE_BACKEND).is_err() || !mesh_bound(server) {
        return;
    }
    let machines = match server.vault.mesh_machines_granted(JOB_ALPN) {
        Ok(machines) => machines,
        Err(error) => {
            tracing::warn!(%error, "vault_machine: the job-granted machines not read; the scheduled readiness read waits");
            return;
        }
    };
    let orders = server.gpu_jobs.orders();
    orders.keep_granted(&machines);
    let nodes = orders.nodes(server);
    for machine in machines {
        let every_secs = match server.vault.machine_policy(machine, &[], &[]) {
            Ok(policy) => policy.readiness_every_secs,
            Err(error) => {
                tracing::warn!(machine = %machine.to_hex(), %error, "vault_machine: the machine's policy not read; its scheduled readiness read waits");
                continue;
            }
        };
        let now_ms = clock();
        let every_ms = every_secs.saturating_mul(1_000);
        if !orders.claim_readiness_read(machine, now_ms, every_ms, pass_at_ms) {
            continue;
        }
        let asked = orders.ask_node_observing(&server.vault, nodes.as_ref(), machine, now_ms);
        if let Err(error) = asked {
            tracing::debug!(machine = %machine.to_hex(), %error, "vault_machine: the scheduled readiness read got no answer");
        }
    }
}
