//! Door for `tests/work_orders.rs` (FIX row WORK-ORDER-NODES-CACHED-OFF-RUNTIME): one call
//! through the node client the work-order loop calls machines through. Door for
//! `tests/issuer_readiness_drain.rs`: whether the worker's pass acts on readiness facts. Door for
//! `tests/issuer_readiness_scheduled_read.rs`: the worker's scheduled readiness read on a given
//! clock.

use std::sync::Arc;

use oneiron::EntityId;

use crate::gpu_execution_node::issuer::{JobNodeClient, NodeCallError};
use crate::gpu_execution_node::wire::{JobAnswer, JobRequest};
use crate::server::SyncServer;

/// One `Node` call to `machine` through the client the loop's passes call through now.
///
/// # Errors
///
/// The client's [`NodeCallError`].
pub fn node_call_now(
    server: &Arc<SyncServer>,
    machine: EntityId,
) -> Result<JobAnswer, NodeCallError> {
    let nodes = server.gpu_jobs.orders().nodes(server);
    JobNodeClient::job(nodes.as_ref(), machine, &JobRequest::Node)
}

/// Whether the job worker's work-order pass on `server` acts on the readiness facts it reads:
/// only on the vault's issuer of vault machine jobs (REVIEW-10518 round 2).
#[must_use]
pub fn worker_pass_observes(server: &SyncServer) -> bool {
    crate::work_order_host::worker_pass_observes(server)
}

/// The job worker's scheduled readiness read on `server` after a pass begun at `pass_at_ms`,
/// each ask dated by `clock` (FIX CG2-ROW9-UNDEMANDED-MACHINES-UNOBSERVED; the worker starts it
/// after each pass, `gpu_host::worker_tick`).
pub fn run_readiness_read_at(server: &Arc<SyncServer>, pass_at_ms: u64, clock: &dyn Fn() -> u64) {
    crate::work_order_host::run_readiness_read(server, pass_at_ms, clock);
}

/// The job worker's pass's `Node` asks of `machines` on `server`, as its pass at `now_ms` sends
/// them (acting on each readiness fact), each dated by `clock` (REVIEW-10544 round 2).
pub fn worker_pass_asks(
    server: &Arc<SyncServer>,
    now_ms: u64,
    clock: &dyn Fn() -> u64,
    machines: &[EntityId],
) {
    crate::work_order_host::worker_pass_asks(server, now_ms, clock, machines);
}
