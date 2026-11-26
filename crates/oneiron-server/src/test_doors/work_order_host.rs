//! Door for `tests/work_orders.rs` (FIX row WORK-ORDER-NODES-CACHED-OFF-RUNTIME): one call
//! through the node client the work-order loop calls machines through. Door for
//! `tests/issuer_readiness_drain.rs`: whether the worker's pass acts on readiness facts. Door for
//! `tests/issuer_readiness_scheduled_read.rs`: the worker's scheduled readiness read at a given
//! time.

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

/// The job worker's scheduled readiness read on `server` at `now_ms`, on the issuer's clock
/// (FIX CG2-ROW9-UNDEMANDED-MACHINES-UNOBSERVED; `gpu_host::worker_pass` runs it after each
/// pass at the pass's time).
pub fn run_readiness_read_at(server: &Arc<SyncServer>, now_ms: u64) {
    crate::work_order_host::run_readiness_read(server, now_ms);
}
