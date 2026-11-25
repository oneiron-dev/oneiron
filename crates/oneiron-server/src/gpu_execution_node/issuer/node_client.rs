//! How the issuer asks a node (pass 33 section 7.1): one request and one answer per call, on
//! [`JOB_ALPN`] for new work and on [`JOB_STATUS_ALPN`] for the keys the node holds. The calls
//! block, as the GPU job connector's do: the host steps its jobs on its blocking pool.
//! [`MeshJobNodeClient`] carries them over the vault's mesh; a test answers them by script.
use oneiron::EntityId;

use crate::gpu_execution_node::wire::{JobAnswer, JobRequest, JobStatusAnswer, JobStatusRequest};

/// Why a call to a node got no answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeCallError {
    /// No answer in time: the request may have reached the node.
    #[error("the machine did not answer in time")]
    Timeout,
    /// The node could not be reached, or the answer could not be read; the request may have
    /// reached it.
    #[error("the machine could not be reached: {reason}")]
    Unreachable { reason: String },
}

/// The issuer's calls to a node, one per protocol.
pub trait JobNodeClient: Send + Sync {
    /// One request on [`JOB_ALPN`] to `node`.
    ///
    /// # Errors
    ///
    /// [`NodeCallError`] when no answer arrived.
    fn job(&self, node: EntityId, request: &JobRequest) -> Result<JobAnswer, NodeCallError>;

    /// One request on [`JOB_STATUS_ALPN`] to `node`.
    ///
    /// # Errors
    ///
    /// [`NodeCallError`] when no answer arrived.
    fn job_status(
        &self,
        node: EntityId,
        request: &JobStatusRequest,
    ) -> Result<JobStatusAnswer, NodeCallError>;
}

#[cfg(feature = "mesh")]
pub use mesh::MeshJobNodeClient;

#[cfg(feature = "mesh")]
mod mesh {
    use std::sync::{Arc, Weak};
    use std::time::Duration;

    use oneiron::EntityId;
    use oneiron_mesh_transport::MeshTransport;
    use oneiron_mesh_transport::message::exchange;
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use tokio::runtime::{Handle, RuntimeFlavor};

    use super::{JobNodeClient, NodeCallError};
    use crate::gpu_execution_node::wire::{
        JOB_ALPN, JOB_PROTOCOL, JOB_STATUS_ALPN, JobAnswer, JobRequest, JobStatusAnswer,
        JobStatusRequest,
    };
    use crate::server::SyncServer;

    /// The issuer's calls over the vault's mesh: each dials the node on the protocol, sends one
    /// message on a fresh stream and reads one back, on the serving runtime. The listener's
    /// transport is read at each call, so the client answers `Unreachable` until it is bound.
    pub struct MeshJobNodeClient {
        server: Weak<SyncServer>,
        runtime: Handle,
        timeout: Duration,
    }

    impl MeshJobNodeClient {
        /// A client of `server`'s mesh listener, whose calls run on `runtime` and wait at most
        /// `timeout` each.
        #[must_use]
        pub fn new(server: Weak<SyncServer>, runtime: Handle, timeout: Duration) -> Self {
            Self {
                server,
                runtime,
                timeout,
            }
        }

        fn ask<Q, A>(
            &self,
            node: EntityId,
            alpn: &'static [u8],
            request: &Q,
        ) -> Result<A, NodeCallError>
        where
            Q: Serialize + Sync,
            A: DeserializeOwned + Send,
        {
            let server = self
                .server
                .upgrade()
                .ok_or_else(|| NodeCallError::Unreachable {
                    reason: "the server is stopping".to_owned(),
                })?;
            let transport: Arc<dyn MeshTransport> = server
                .mesh_transport
                .get()
                .cloned()
                .ok_or_else(|| NodeCallError::Unreachable {
                    reason: "no mesh listener is bound".to_owned(),
                })?;
            let call = async move {
                let connection = transport.dial(node, alpn).await.map_err(unreachable)?;
                let answer = exchange(JOB_PROTOCOL, connection.as_ref(), request).await;
                connection.close();
                answer.map_err(unreachable)
            };
            let timeout = self.timeout;
            run_on(&self.runtime, async move {
                tokio::time::timeout(timeout, call)
                    .await
                    .map_err(|_| NodeCallError::Timeout)?
            })?
        }
    }

    impl JobNodeClient for MeshJobNodeClient {
        fn job(&self, node: EntityId, request: &JobRequest) -> Result<JobAnswer, NodeCallError> {
            self.ask(node, JOB_ALPN, request)
        }

        fn job_status(
            &self,
            node: EntityId,
            request: &JobStatusRequest,
        ) -> Result<JobStatusAnswer, NodeCallError> {
            self.ask(node, JOB_STATUS_ALPN, request)
        }
    }

    fn unreachable(error: impl std::fmt::Display) -> NodeCallError {
        NodeCallError::Unreachable {
            reason: error.to_string(),
        }
    }

    /// Runs `future` on `runtime` from a blocking caller. On a thread of a multi-thread
    /// runtime it leaves the worker first, so the runtime goes on serving; a single-thread
    /// runtime cannot serve the call it would wait on, so it refuses there.
    fn run_on<F: std::future::Future>(
        runtime: &Handle,
        future: F,
    ) -> Result<F::Output, NodeCallError> {
        match Handle::try_current() {
            Err(_) => Ok(runtime.block_on(future)),
            Ok(current) if current.runtime_flavor() == RuntimeFlavor::MultiThread => {
                Ok(tokio::task::block_in_place(|| runtime.block_on(future)))
            }
            Ok(_) => Err(NodeCallError::Unreachable {
                reason: "a job call from inside a single-thread runtime".to_owned(),
            }),
        }
    }
}
