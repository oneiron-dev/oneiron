//! This machine's execution node on the mesh listener (pass 33): its two
//! job protocols, its tick, and on Linux its job service, which opens and
//! attaches before the listener serves (row R3a).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::host::{MeshRoutes, MeshTick};
use crate::gpu_execution_node::wire::{JOB_ALPN, JOB_STATUS_ALPN};
use crate::gpu_execution_node::{ExecutionNode, JobService, JobStatusService};

/// This machine's execution node, served by the listener: the node of
/// its `[execution_node]` file, and on Linux its job service (row R3a's
/// journal, opened and attached before the listener serves).
pub(crate) struct ServedNode {
    node: ExecutionNode,
    #[cfg(target_os = "linux")]
    jobs: crate::gpu_execution_node::jobs::ServedNodeJobs,
}

impl ServedNode {
    /// The node when the machine's `[execution_node]` file enables it as
    /// the listener starts (T3), else `None`. On Linux its job service
    /// opens here and attaches to it, so no request reaches an enabled
    /// node before its journal does; one that does not open yet (its
    /// writer lock held, its `state_dir` not writable, no MACHINE id) is
    /// tried again at each tick, and the node answers `NotEnabled` until
    /// it opens. It blocks: the listener calls it on a blocking thread.
    pub(crate) fn open(server: &crate::server::SyncServer) -> Option<Self> {
        let file = server.config.execution_node_file.clone()?;
        let node = ExecutionNode::new(
            file,
            Arc::clone(&server.vault),
            Arc::clone(&server.gpu_slots),
        );
        if !node.serves() {
            return None;
        }
        #[cfg(target_os = "linux")]
        let jobs = {
            let jobs = crate::gpu_execution_node::jobs::ServedNodeJobs::new(
                node.clone(),
                Arc::clone(&server.vault),
                Arc::clone(&server.gpu_slots),
                Arc::new(crate::machine::OrganFloor(server.memory.clone())),
            );
            if let Err(why) = jobs.open() {
                tracing::warn!(%why, "the execution node's job service did not open; the node's tick tries again");
            }
            jobs
        };
        Some(Self {
            node,
            #[cfg(target_os = "linux")]
            jobs,
        })
    }

    /// One pass of the node's tick. It blocks.
    fn tick(&self) {
        self.node.authority_tick();
        #[cfg(target_os = "linux")]
        self.jobs.tick();
    }
}

/// This machine's job protocols (pass 33, EM-1 = A): new work on one,
/// the keys it holds on the other, each its own grant. They are served
/// only when the machine's `[execution_node]` file enables it as the
/// listener starts (T3), so a machine that runs no jobs refuses both at
/// the handshake. With them comes the node's tick.
pub(crate) fn job_routes(routes: MeshRoutes, node: Option<ServedNode>) -> MeshRoutes {
    let Some(served) = node else {
        return routes;
    };
    let node = served.node.clone();
    routes
        .route(JOB_ALPN, Arc::new(JobService::new(node.clone())))
        .route(JOB_STATUS_ALPN, Arc::new(JobStatusService::new(node)))
        .tick(node_tick(served))
}

/// The node's tick on a blocking thread: its authority tick (its own
/// fold read for its own job grant and its issuer's, and the revoke
/// handed to its keys, EN-4 A), then one step of its job service (row
/// R3a: the end handling, the release checks and the receipts it keeps;
/// an open that failed is tried again). It runs on the listener's tick,
/// under its stop, and holds the job service until the listener is gone.
fn node_tick(served: ServedNode) -> MeshTick {
    let served = Arc::new(served);
    Arc::new(move || -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let served = Arc::clone(&served);
        Box::pin(async move {
            if tokio::task::spawn_blocking(move || served.tick())
                .await
                .is_err()
            {
                tracing::warn!("the execution node's tick did not finish");
            }
        })
    })
}
