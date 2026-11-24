#![cfg(feature = "mesh")]
//! The job service answers each stream of a connection on its own (review
//! round 1 of #10407): a stream whose request never finishes, or whose peer
//! stops reading its answer, costs only that stream, and the next stream on
//! the same connection is still answered.
//!
//! The connection is an in-process stand-in for the mesh seam
//! (`MeshConnection`), so the test needs no grant: each stream it hands the
//! service is scripted as a request that never finishes, a request whose
//! answer cannot be sent, or a request whose answer is read. The service's
//! node (row R1) has a fresh vault of its own, which proves no stand-in peer,
//! so every answered stream is the gate's refusal: what counts is that the
//! second stream is answered at all.
//!
//! Run with: `cargo test --locked -p oneiron-server --features mesh --test
//! job_service_streams`.

use std::sync::Arc;
use std::time::Duration;

use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_mesh_transport::message::{decode_message, encode_message};
use oneiron_mesh_transport::{
    MachineId, MeshConnection, MeshDuplex, MeshError, MeshFuture, MeshService, MeshStream,
};
use oneiron_server::gpu_execution_node::wire::{
    JOB_ALPN, JOB_PROTOCOL, JobAnswer, JobRefusal, JobRequest,
};
use oneiron_server::gpu_execution_node::{
    ExecutionNode, GpuDeviceOffer, GpuSlotTable, JobService, NvidiaSmiProbe,
};
use tokio::sync::{Mutex, mpsc, oneshot};

/// How long the test waits for the answer it expects.
const ANSWER_WAIT: Duration = Duration::from_secs(30);

/// One stream as the peer drives it.
struct ScriptedStream {
    /// The request's bytes; `None` is a request that never finishes.
    request: Option<Vec<u8>>,
    /// Where the peer reads the answer; `None` is a peer that stopped
    /// reading, so sending the answer fails.
    answer: Option<oneshot::Sender<Vec<u8>>>,
}

impl MeshStream for ScriptedStream {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> MeshFuture<'a, ()> {
        Box::pin(async move {
            let reader = self
                .answer
                .take()
                .ok_or_else(|| MeshError::Io("the peer stopped reading".to_owned()))?;
            reader
                .send(bytes.to_vec())
                .map_err(|_| MeshError::Io("the peer is gone".to_owned()))
        })
    }

    fn recv(&mut self) -> MeshFuture<'_, Vec<u8>> {
        Box::pin(async move {
            match self.request.take() {
                Some(bytes) => Ok(bytes),
                None => std::future::pending().await,
            }
        })
    }
}

/// A connection on [`JOB_ALPN`] whose peer opens the streams the test
/// queues, in order.
struct ScriptedConnection {
    machine: MachineId,
    streams: Mutex<mpsc::UnboundedReceiver<ScriptedStream>>,
}

impl MeshConnection for ScriptedConnection {
    fn machine(&self) -> MachineId {
        self.machine
    }

    fn alpn(&self) -> &[u8] {
        JOB_ALPN
    }

    fn endpoint_key(&self) -> [u8; 32] {
        [0x4b; 32]
    }

    fn open_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async { Err(MeshError::Unavailable) })
    }

    fn accept_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async move {
            let next = self.streams.lock().await.recv().await;
            next.map(|stream| Box::new(stream) as Box<dyn MeshStream>)
                .ok_or(MeshError::Unavailable)
        })
    }

    fn open_duplex(&self) -> MeshFuture<'_, Box<dyn MeshDuplex>> {
        Box::pin(async { Err(MeshError::Unavailable) })
    }

    fn accept_duplex(&self) -> MeshFuture<'_, Box<dyn MeshDuplex>> {
        Box::pin(async { Err(MeshError::Unavailable) })
    }

    fn close(&self) {}
}

fn scripted_connection() -> (mpsc::UnboundedSender<ScriptedStream>, ScriptedConnection) {
    let (opens, streams) = mpsc::unbounded_channel();
    let machine = EntityId::from_bytes([0x4d; 16]).expect("machine id");
    (
        opens,
        ScriptedConnection {
            machine,
            streams: Mutex::new(streams),
        },
    )
}

fn node_request() -> Vec<u8> {
    encode_message(JOB_PROTOCOL, &JobRequest::Node).expect("encode the Node request")
}

/// Serves `connection` until the answer on `answer` arrives, and decodes it.
/// Fails if the service ends first or no answer comes within
/// [`ANSWER_WAIT`].
async fn answer_while_serving(
    connection: ScriptedConnection,
    answer: oneshot::Receiver<Vec<u8>>,
) -> JobAnswer {
    let dir = tempfile::tempdir().expect("a directory for the node's vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open the node's vault");
    let service = JobService::new(ExecutionNode::new(
        dir.path().join("execution-node.toml"),
        Arc::new(vault),
        Arc::new(GpuSlotTable::new(
            Arc::new(NvidiaSmiProbe),
            GpuDeviceOffer::default(),
        )),
    ));
    let bytes = tokio::select! {
        served = service.serve(Box::new(connection)) => {
            panic!("the service closed the connection before the second stream was answered: {served:?}")
        }
        bytes = tokio::time::timeout(ANSWER_WAIT, answer) => bytes
            .expect("the second stream is answered while the first one is still open")
            .expect("the service sent an answer"),
    };
    decode_message(JOB_PROTOCOL, &bytes).expect("decode the answer")
}

fn assert_gate_refusal(answer: &JobAnswer) {
    assert_eq!(
        answer,
        &JobAnswer::Refused(JobRefusal::PeerNotProven),
        "the node's vault proves no stand-in peer"
    );
}

#[tokio::test]
async fn a_request_that_never_finishes_holds_up_no_later_stream() {
    let (opens, connection) = scripted_connection();
    opens
        .send(ScriptedStream {
            request: None,
            answer: None,
        })
        .expect("queue the unfinished stream");
    let (reader, answer) = oneshot::channel();
    opens
        .send(ScriptedStream {
            request: Some(node_request()),
            answer: Some(reader),
        })
        .expect("queue the second stream");

    let answered = answer_while_serving(connection, answer).await;
    assert_gate_refusal(&answered);
    drop(opens);
}

#[tokio::test]
async fn a_peer_that_stops_reading_one_answer_still_gets_the_next() {
    let (opens, connection) = scripted_connection();
    opens
        .send(ScriptedStream {
            request: Some(node_request()),
            answer: None,
        })
        .expect("queue the stream whose answer cannot be sent");
    let (reader, answer) = oneshot::channel();
    opens
        .send(ScriptedStream {
            request: Some(node_request()),
            answer: Some(reader),
        })
        .expect("queue the second stream");

    let answered = answer_while_serving(connection, answer).await;
    assert_gate_refusal(&answered);
    drop(opens);
}
