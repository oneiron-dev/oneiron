//! The node's two mesh services (section 7.1): [`JobService`] on
//! [`JOB_ALPN`] and [`JobStatusService`] on [`JOB_STATUS_ALPN`]. The mesh
//! listener serves them only on a machine whose `[execution_node]` file
//! enables it when the listener starts (row R1, T3), and admits a
//! connection on either only from a machine the vault grants that protocol,
//! checked at the handshake. Each stream then carries one request and one
//! answer in the organ codec, and every request first passes the node's own
//! gate ([`ExecutionNode::gate`]): the peer is proven for the protocol now
//! and is one of the node's `issuers`, and a request that admits work also
//! needs the node's own job grant live in its own fold.
//!
//! `Node` is answered to an issuer the file names, enabled or not (it says
//! which); `Availability` and every request that names a key need the node
//! enabled. `Node` and `Availability` are answered here. A request that names a key
//! goes to the node's keys (row R3a's journal, [`super::node::NodeKeys`])
//! once they are attached; until then it is refused as `NotEnabled`, and
//! nothing is written. The status side (row R4) goes there the same way:
//! `Find`, `Status`, `Stop`, `Keys`, `Signal`, `Fetch` and `Ack`.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use oneiron_mesh_transport::message::{decode_message, encode_message};
use oneiron_mesh_transport::{MeshConnection, MeshFuture, MeshService, MeshStream};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::node::{ExecutionNode, GateAsk};
use super::wire::{
    JOB_ALPN, JOB_PROTOCOL, JOB_STATUS_ALPN, JobAnswer, JobRefusal, JobRequest, JobStatusAnswer,
    JobStatusRequest,
};

/// How long a `Busy` answer asks the issuer to wait when the node could
/// not answer now (the engine stopping).
const BUSY_RETRY_AFTER_MS: u64 = 2_000;

/// How long a stream may take to bring its whole request. A job request is
/// a few KiB (a pin's arguments are at most 4 KiB together), so this bounds
/// a stream that stalls or never finishes its request, not a slow link: at
/// the deadline the stream is reset, which frees its slot among the
/// connection's streams. A wire bound, not a policy.
pub const REQUEST_READ_DEADLINE: Duration = Duration::from_secs(10);

/// How long a stream may take to take its whole answer. An answer is a few
/// KiB, so this bounds a peer that gives the answer no flow-control credit,
/// not a slow link: at the deadline the stream is reset, which drops the
/// unsent answer and frees its slot among the connection's streams. A wire
/// bound, not a policy.
pub const REPLY_WRITE_DEADLINE: Duration = Duration::from_secs(10);

/// Serves [`JOB_ALPN`]: new work.
#[derive(Debug, Clone)]
pub struct JobService {
    node: ExecutionNode,
}

impl JobService {
    /// The job service of `node`.
    #[must_use]
    pub fn new(node: ExecutionNode) -> Self {
        Self { node }
    }

    /// The answer to one `request` from the peer behind `endpoint_key`. The
    /// gate's fold reads and the journal's writes block, so both run on a
    /// blocking thread.
    pub async fn answer(&self, endpoint_key: [u8; 32], request: JobRequest) -> JobAnswer {
        let node = self.node.clone();
        tokio::task::spawn_blocking(move || answer_job(&node, endpoint_key, request))
            .await
            .unwrap_or(JobAnswer::Busy {
                retry_after_ms: BUSY_RETRY_AFTER_MS,
            })
    }
}

/// The node's answer to `request` on [`JOB_ALPN`].
fn answer_job(node: &ExecutionNode, endpoint_key: [u8; 32], request: JobRequest) -> JobAnswer {
    let ask = match &request {
        JobRequest::Node => GateAsk::Offer,
        JobRequest::Availability | JobRequest::Release { .. } => GateAsk::Read,
        JobRequest::Reserve(_) | JobRequest::Submit(_) => GateAsk::Admit,
    };
    let (peer, snapshot) = match node.gate(endpoint_key, JOB_ALPN, ask) {
        Ok(passed) => passed,
        Err(refusal) => return JobAnswer::Refused(refusal),
    };
    let keys = node.keys();
    match request {
        JobRequest::Node => JobAnswer::Node(node.node_answer_from(&snapshot)),
        JobRequest::Availability => match node.availability_from(&snapshot, now_ms()) {
            Ok(availability) => JobAnswer::Availability(availability),
            Err(why) => JobAnswer::Refused(JobRefusal::DevicesUnreadable { why }),
        },
        JobRequest::Reserve(reserve) => {
            keys.map_or_else(not_enabled, |keys| keys.reserve(peer, reserve))
        }
        JobRequest::Release { key } => {
            keys.map_or_else(not_enabled, |keys| keys.release(peer, &key))
        }
        JobRequest::Submit(signed) => {
            keys.map_or_else(not_enabled, |keys| keys.submit(peer, signed))
        }
    }
}

fn not_enabled() -> JobAnswer {
    JobAnswer::Refused(JobRefusal::NotEnabled)
}

impl MeshService for JobService {
    fn serve(&self, connection: Box<dyn MeshConnection>) -> MeshFuture<'_, ()> {
        Box::pin(async move {
            if connection.alpn() == JOB_ALPN {
                let endpoint_key = connection.endpoint_key();
                serve_each_stream(connection.as_ref(), |request: JobRequest| {
                    self.answer(endpoint_key, request)
                })
                .await;
            }
            connection.close();
            Ok(())
        })
    }
}

/// Serves [`JOB_STATUS_ALPN`]: the keys this node holds.
#[derive(Debug, Clone)]
pub struct JobStatusService {
    node: ExecutionNode,
}

impl JobStatusService {
    /// The status service of `node`.
    #[must_use]
    pub fn new(node: ExecutionNode) -> Self {
        Self { node }
    }

    /// The answer to one `request` from the peer behind `endpoint_key`. A
    /// disabled node still passes its issuer, so the receipts of the jobs it
    /// stopped stay collectable.
    pub async fn answer(
        &self,
        endpoint_key: [u8; 32],
        request: JobStatusRequest,
    ) -> JobStatusAnswer {
        let node = self.node.clone();
        tokio::task::spawn_blocking(move || answer_status(&node, endpoint_key, &request))
            .await
            .unwrap_or(JobStatusAnswer::Busy {
                retry_after_ms: BUSY_RETRY_AFTER_MS,
            })
    }
}

/// The node's answer to `request` on [`JOB_STATUS_ALPN`].
fn answer_status(
    node: &ExecutionNode,
    endpoint_key: [u8; 32],
    request: &JobStatusRequest,
) -> JobStatusAnswer {
    let (peer, _snapshot) = match node.gate(endpoint_key, JOB_STATUS_ALPN, GateAsk::Status) {
        Ok(passed) => passed,
        Err(refusal) => return JobStatusAnswer::Refused(refusal),
    };
    let Some(keys) = node.keys() else {
        return JobStatusAnswer::Refused(JobRefusal::NotEnabled);
    };
    match request {
        JobStatusRequest::Find { key } | JobStatusRequest::Status { key } => keys.find(peer, key),
        JobStatusRequest::Stop { key } => keys.stop(peer, key),
        JobStatusRequest::Keys { after } => keys.keys_page(peer, after.as_deref()),
        JobStatusRequest::Signal { key, signal } => keys.signal(peer, key, signal),
        JobStatusRequest::Fetch { key, name } => keys.fetch(peer, key, name),
        JobStatusRequest::Ack { key } => keys.acknowledge(peer, key),
        JobStatusRequest::Tail(request) => keys.tail(peer, request),
    }
}

impl MeshService for JobStatusService {
    fn serve(&self, connection: Box<dyn MeshConnection>) -> MeshFuture<'_, ()> {
        Box::pin(async move {
            if connection.alpn() == JOB_STATUS_ALPN {
                let endpoint_key = connection.endpoint_key();
                serve_each_stream(connection.as_ref(), |request: JobStatusRequest| {
                    self.answer(endpoint_key, request)
                })
                .await;
            }
            connection.close();
            Ok(())
        })
    }
}

/// Milliseconds since the Unix epoch now.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Serves `conn` until it ends: each stream it accepts carries one request,
/// which `answer` answers on the same stream. The streams are served side by
/// side, so a stream whose request never finishes, or whose peer stops
/// reading its answer, loses only itself; the next stream is still accepted
/// and answered. A stream whose request is not whole by
/// [`REQUEST_READ_DEADLINE`], or whose answer is not written by
/// [`REPLY_WRITE_DEADLINE`], is reset, so stalled streams never hold all of
/// the connection's stream slots. Each accept checks the peer's live
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
/// by [`REQUEST_READ_DEADLINE`], or does not decode, gets no answer, and an
/// answer not written by [`REPLY_WRITE_DEADLINE`] is abandoned: either way
/// the stream is reset, and the failure ends this stream alone.
async fn serve_stream<Q, A, F, Fut>(mut stream: Box<dyn MeshStream>, answer: &F)
where
    Q: DeserializeOwned,
    A: Serialize,
    F: Fn(Q) -> Fut,
    Fut: Future<Output = A>,
{
    let read = tokio::time::timeout(REQUEST_READ_DEADLINE, stream.recv()).await;
    let Ok(Ok(bytes)) = read else {
        stream.reset();
        return;
    };
    let Ok(request) = decode_message::<Q>(JOB_PROTOCOL, &bytes) else {
        stream.reset();
        return;
    };
    let reply = answer(request).await;
    let Ok(reply) = encode_message(JOB_PROTOCOL, &reply) else {
        stream.reset();
        return;
    };
    // A peer that stopped reading loses this answer; it asks again on a new
    // stream.
    let sent = tokio::time::timeout(REPLY_WRITE_DEADLINE, stream.send(&reply)).await;
    if !matches!(sent, Ok(Ok(()))) {
        stream.reset();
    }
}
