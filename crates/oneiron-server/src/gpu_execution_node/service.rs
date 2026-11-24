//! The node's two mesh services (section 7.1): [`JobService`] on
//! [`JOB_ALPN`] and [`JobStatusService`] on [`JOB_STATUS_ALPN`]. The mesh
//! listener admits a connection on either only from a machine the vault
//! grants that protocol, checked at the handshake and at every stream; each
//! stream then carries one request and one answer in the organ codec.
//!
//! Row R0 serves the protocols with no `[execution_node]` behind them yet:
//! the node answers `Node` as not enabled, and refuses every other request
//! as `NotEnabled`, writing nothing. Row R1 adds the configuration, the
//! enabled gate on both routes, and the serving side's own peer, issuer and
//! grant checks.

use std::future::Future;

use oneiron_mesh_transport::message::{decode_message, encode_message};
use oneiron_mesh_transport::{MeshConnection, MeshFuture, MeshService};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::wire::{
    JOB_ALPN, JOB_PROTOCOL, JOB_STATUS_ALPN, JobAnswer, JobRefusal, JobRequest, JobStatusAnswer,
    JobStatusRequest, NodeAnswer,
};

/// Where Linux names this boot.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Serves [`JOB_ALPN`]: new work.
#[derive(Debug, Default)]
pub struct JobService;

impl JobService {
    /// The answer to one request.
    #[must_use]
    pub fn answer(&self, request: &JobRequest) -> JobAnswer {
        match request {
            JobRequest::Node => JobAnswer::Node(not_enabled_node()),
            JobRequest::Reserve(_) | JobRequest::Release { .. } | JobRequest::Submit(_) => {
                JobAnswer::Refused(JobRefusal::NotEnabled)
            }
        }
    }
}

impl MeshService for JobService {
    fn serve(&self, connection: Box<dyn MeshConnection>) -> MeshFuture<'_, ()> {
        Box::pin(async move {
            if connection.alpn() == JOB_ALPN {
                serve_each_stream(connection.as_ref(), |request: JobRequest| {
                    std::future::ready(self.answer(&request))
                })
                .await;
            }
            connection.close();
            Ok(())
        })
    }
}

/// Serves [`JOB_STATUS_ALPN`]: the keys this node holds.
#[derive(Debug, Default)]
pub struct JobStatusService;

impl JobStatusService {
    /// The answer to one request.
    #[must_use]
    pub fn answer(&self, request: &JobStatusRequest) -> JobStatusAnswer {
        match request {
            JobStatusRequest::Find { .. }
            | JobStatusRequest::Status { .. }
            | JobStatusRequest::Signal { .. }
            | JobStatusRequest::Stop { .. }
            | JobStatusRequest::Keys { .. }
            | JobStatusRequest::Fetch { .. }
            | JobStatusRequest::Ack { .. } => JobStatusAnswer::Refused(JobRefusal::NotEnabled),
        }
    }
}

impl MeshService for JobStatusService {
    fn serve(&self, connection: Box<dyn MeshConnection>) -> MeshFuture<'_, ()> {
        Box::pin(async move {
            if connection.alpn() == JOB_STATUS_ALPN {
                serve_each_stream(connection.as_ref(), |request: JobStatusRequest| {
                    std::future::ready(self.answer(&request))
                })
                .await;
            }
            connection.close();
            Ok(())
        })
    }
}

/// What a node with no `[execution_node]` answers to `Node`.
fn not_enabled_node() -> NodeAnswer {
    NodeAnswer {
        enabled: false,
        paused: None,
        drained: None,
        templates: Vec::new(),
        disk_free_bytes: 0,
        disk_reserved_bytes: 0,
        disk_reserve_bytes: 0,
        epoch: None,
        swept: false,
        boot_id: boot_id(),
        engine_version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

/// This boot's id, empty where the system names none.
fn boot_id() -> String {
    std::fs::read_to_string(BOOT_ID_PATH)
        .map(|id| id.trim().to_owned())
        .unwrap_or_default()
}

/// Serves `conn` until it ends: each stream it accepts carries one request,
/// which `answer` answers on the same stream. A stream whose request does
/// not decode gets no answer.
async fn serve_each_stream<Q, A, F, Fut>(conn: &dyn MeshConnection, mut answer: F)
where
    Q: DeserializeOwned,
    A: Serialize,
    F: FnMut(Q) -> Fut,
    Fut: Future<Output = A>,
{
    while let Ok(mut stream) = conn.accept_stream().await {
        let Ok(bytes) = stream.recv().await else {
            continue;
        };
        let Ok(request) = decode_message::<Q>(JOB_PROTOCOL, &bytes) else {
            continue;
        };
        let reply = answer(request).await;
        let Ok(reply) = encode_message(JOB_PROTOCOL, &reply) else {
            continue;
        };
        if stream.send(&reply).await.is_err() {
            break;
        }
    }
}
