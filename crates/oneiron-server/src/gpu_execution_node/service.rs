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
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use oneiron_mesh_transport::message::{decode_message, encode_message};
use oneiron_mesh_transport::{MeshConnection, MeshFuture, MeshService, MeshStream};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::wire::{
    JOB_ALPN, JOB_PROTOCOL, JOB_STATUS_ALPN, JobAnswer, JobRefusal, JobRequest, JobStatusAnswer,
    JobStatusRequest, NodeAnswer,
};

/// Where Linux names this boot.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// How long a stream may take to bring its whole request. A job request is
/// a few KiB (a pin's arguments are at most 4 KiB together), so this bounds
/// a stream that stalls or never finishes its request, not a slow link: at
/// the deadline the stream is dropped, which frees its slot among the
/// connection's streams. A wire bound, not a policy.
pub const REQUEST_READ_DEADLINE: Duration = Duration::from_secs(10);

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
/// which `answer` answers on the same stream. The streams are served side by
/// side, so a stream whose request never finishes, or whose peer stops
/// reading its answer, loses only itself; the next stream is still accepted
/// and answered. A stream whose request is not whole by
/// [`REQUEST_READ_DEADLINE`] is dropped, so unfinished requests never hold
/// all of the connection's stream slots. Each accept checks the peer's live
/// grant, and the loop ends when the connection closes or the grant ends; a
/// request still in flight then ends with it.
async fn serve_each_stream<Q, A, F, Fut>(conn: &dyn MeshConnection, answer: F)
where
    Q: DeserializeOwned,
    A: Serialize,
    F: Fn(Q) -> Fut,
    Fut: Future<Output = A>,
{
    let answer = &answer;
    let mut streams = FuturesUnordered::new();
    loop {
        tokio::select! {
            Some(()) = streams.next(), if !streams.is_empty() => {}
            accepted = conn.accept_stream() => match accepted {
                Ok(stream) => streams.push(serve_stream::<Q, A, F, Fut>(stream, answer)),
                Err(_) => break,
            },
        }
    }
}

/// One stream's request and its answer. A stream whose request is not whole
/// by [`REQUEST_READ_DEADLINE`], or does not decode, gets no answer; a
/// failure ends this stream alone.
async fn serve_stream<Q, A, F, Fut>(mut stream: Box<dyn MeshStream>, answer: &F)
where
    Q: DeserializeOwned,
    A: Serialize,
    F: Fn(Q) -> Fut,
    Fut: Future<Output = A>,
{
    let Ok(Ok(bytes)) = tokio::time::timeout(REQUEST_READ_DEADLINE, stream.recv()).await else {
        return;
    };
    let Ok(request) = decode_message::<Q>(JOB_PROTOCOL, &bytes) else {
        return;
    };
    let reply = answer(request).await;
    let Ok(reply) = encode_message(JOB_PROTOCOL, &reply) else {
        return;
    };
    // A peer that stopped reading loses this answer; it asks again on a new
    // stream.
    drop(stream.send(&reply).await);
}
