//! Door for `tests/work_orders.rs` (FIX row WORK-ORDER-NODES-CACHED-OFF-RUNTIME): one call
//! through the node client the work-order loop calls machines through.

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
