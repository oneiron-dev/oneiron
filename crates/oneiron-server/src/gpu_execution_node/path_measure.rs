//! The path measurement of the first job's step 2 (pass 33,
//! `33-exec-node/DESIGN.md` section 12, "R6 in five steps"): the control
//! round trip and a result fetch between the issuer and a node, as samples
//! and byte counts, not a link rating. Both ends run the engine's own iroh
//! transport and its message codec on the direct path only (no relay map),
//! under keys that only the two measuring processes know: no vault is
//! opened, no grant is read, and no engine serves the protocol. A listener
//! admits the one dialer key it was given and stops at its deadline.
//!
//! Byte counts are message bytes, as the job protocols' messages count
//! them; QUIC's framing and encryption add their own on the wire.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use oneiron::EntityId;
use oneiron_mesh_transport::iroh_transport::IrohTransport;
use oneiron_mesh_transport::message::{decode_message, encode_message};
use oneiron_mesh_transport::transport_key::TransportKey;
use oneiron_mesh_transport::{
    AcceptPolicy, MachineGrants, MachineId, MachineRoster, MeshConnection, MeshError,
    MeshMachineAddress, MeshPathDirection, MeshPathReceipt, MeshTransport, PathReceipts,
};
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, timeout, timeout_at};

use super::wire::FETCH_MAX_BYTES;

/// The protocol the two measuring processes speak. No engine serves it.
pub const PATH_MEASURE_ALPN: &[u8] = b"oneiron/path-measure/1";

/// The protocol's name in a codec error.
const PATH_MEASURE_PROTOCOL: &str = "path measure";

/// One measuring request: its answer carries `answer_bytes` bytes, and the
/// request itself carries `padding`, so both directions take the size of
/// the message they stand for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasureRequest {
    pub sample: u32,
    pub answer_bytes: u64,
    #[serde(with = "serde_bytes")]
    pub padding: Vec<u8>,
}

/// The answer to a [`MeasureRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MeasureAnswer {
    Body {
        sample: u32,
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
    },
    /// The request asked more bytes back, or carried more, than one fetch
    /// answer holds.
    TooLarge { most: u64 },
}

/// A measuring process's key: the seed of a device signer, from which the
/// transport key is derived as an engine derives its own.
pub struct MeasurerKey(SigningKey);

impl MeasurerKey {
    /// A new key from the system's random source.
    #[must_use]
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut rand_core::OsRng))
    }

    /// The key whose seed is `seed`.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The seed, for the key file.
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The endpoint key the other end admits.
    #[must_use]
    pub fn endpoint(&self) -> [u8; 32] {
        TransportKey::derive(&self.0).endpoint_key()
    }
}

/// The one peer a measuring endpoint knows: its roster and its grants.
#[derive(Debug)]
struct OnePeer {
    machine: MachineId,
    address: MeshMachineAddress,
}

impl MachineRoster for OnePeer {
    fn by_machine(&self, machine: MachineId) -> Result<Option<MeshMachineAddress>, MeshError> {
        Ok((machine == self.machine).then(|| self.address.clone()))
    }

    fn by_endpoint(
        &self,
        endpoint_key: [u8; 32],
    ) -> Result<Option<(MachineId, MeshMachineAddress)>, MeshError> {
        Ok((endpoint_key == self.address.endpoint_key)
            .then(|| (self.machine, self.address.clone())))
    }
}

impl MachineGrants for OnePeer {
    fn permits(&self, machine: MachineId, key: [u8; 32], alpn: &[u8]) -> Result<bool, MeshError> {
        Ok(
            machine == self.machine
                && key == self.address.endpoint_key
                && alpn == PATH_MEASURE_ALPN,
        )
    }
}

/// The path receipts a measuring endpoint leaves: which path each
/// connection used, written as it opens and again as it closes.
#[derive(Debug, Default)]
pub struct PathReceiptLog(Mutex<Vec<MeshPathReceipt>>);

impl PathReceipts for PathReceiptLog {
    fn record(&self, receipt: &MeshPathReceipt) -> Option<String> {
        let mut receipts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let mut receipt = receipt.clone();
        if receipt.id.is_empty() {
            receipt.id = format!("{:016x}", receipts.len());
        }
        let id = receipt.id.clone();
        receipts.push(receipt);
        Some(id)
    }
}

impl PathReceiptLog {
    /// The newest receipt of a connection in `direction` that has closed.
    #[must_use]
    pub fn closed(&self, direction: MeshPathDirection) -> Option<MeshPathReceipt> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .rev()
            .find(|receipt| receipt.direction == direction && receipt.closed_at_ms.is_some())
            .cloned()
    }

    /// Waits up to `wait` for a closed connection's receipt in `direction`.
    pub async fn wait_closed(
        &self,
        direction: MeshPathDirection,
        wait: Duration,
    ) -> Option<MeshPathReceipt> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(receipt) = self.closed(direction) {
                return Some(receipt);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Binds a measuring endpoint at `bind` that admits and dials `peer` alone,
/// on [`PATH_MEASURE_ALPN`] alone, on the direct path only, and leaves its
/// path receipts in `receipts`. Returns the endpoint and the id it knows
/// the peer by.
///
/// # Errors
///
/// The endpoint could not be bound.
pub async fn bind_measurer(
    key: &MeasurerKey,
    peer: MeshMachineAddress,
    bind: SocketAddr,
    receipts: Arc<PathReceiptLog>,
) -> Result<(IrohTransport, MachineId), MeshError> {
    let machine = EntityId::now();
    let roster = Arc::new(OnePeer {
        machine,
        address: peer,
    });
    let policy = AcceptPolicy {
        roster: Arc::clone(&roster) as Arc<dyn MachineRoster>,
        grants: roster,
    };
    let transport = IrohTransport::bind_paired(
        TransportKey::derive(&key.0),
        policy,
        vec![PATH_MEASURE_ALPN.to_vec()],
        bind,
        None,
        receipts,
    )
    .await?;
    Ok((transport, machine))
}

/// What a listener served.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServeTally {
    pub connections: u32,
    pub answers: u32,
    pub received_bytes: u64,
    pub sent_bytes: u64,
}

/// Answers the measuring requests of each connection `transport` admits,
/// one connection at a time, until `deadline`, or until `connections`
/// connections have ended.
///
/// # Errors
///
/// The transport stopped accepting.
pub async fn serve_measurements(
    transport: &dyn MeshTransport,
    deadline: Instant,
    connections: u32,
) -> Result<ServeTally, MeshError> {
    let mut tally = ServeTally::default();
    while tally.connections < connections {
        let Ok(accepted) = timeout_at(deadline, transport.accept()).await else {
            break;
        };
        let connection = accepted?;
        tally.connections += 1;
        serve_connection(connection.as_ref(), deadline, &mut tally).await;
    }
    Ok(tally)
}

/// What a listener served, and the path its newest closed connection took.
#[derive(Debug)]
pub struct ListenOutcome {
    pub served: Result<ServeTally, MeshError>,
    pub path: Option<MeshPathReceipt>,
}

/// Serves as [`serve_measurements`] does, then reads the inbound path
/// receipt of the newest closed connection from `receipts`. The transport
/// writes a connection's closed receipt in a task of its own after the
/// connection closes, so serving can end first: once a connection was
/// served, the read waits up to `receipt_wait` for that receipt.
pub async fn serve_measurements_with_path(
    transport: &dyn MeshTransport,
    receipts: &PathReceiptLog,
    deadline: Instant,
    connections: u32,
    receipt_wait: Duration,
) -> ListenOutcome {
    let served = serve_measurements(transport, deadline, connections).await;
    let path = match &served {
        Ok(tally) if tally.connections > 0 => {
            receipts
                .wait_closed(MeshPathDirection::Inbound, receipt_wait)
                .await
        }
        _ => receipts.closed(MeshPathDirection::Inbound),
    };
    ListenOutcome { served, path }
}

/// Answers each stream of `connection` until it ends or `deadline` passes.
async fn serve_connection(
    connection: &dyn MeshConnection,
    deadline: Instant,
    tally: &mut ServeTally,
) {
    while let Ok(Ok(mut stream)) = timeout_at(deadline, connection.accept_stream()).await {
        let Ok(Ok(request)) = timeout_at(deadline, stream.recv()).await else {
            stream.reset();
            break;
        };
        let Some(answer) = answer_to(&request) else {
            stream.reset();
            break;
        };
        let sent = timeout_at(deadline, async {
            stream.send(&answer).await?;
            stream.delivered().await
        })
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            stream.reset();
            break;
        }
        tally.answers += 1;
        tally.received_bytes += byte_count(request.len());
        tally.sent_bytes += byte_count(answer.len());
    }
    connection.close();
}

/// The encoded answer to the encoded `request`; `None` when it does not
/// decode.
fn answer_to(request: &[u8]) -> Option<Vec<u8>> {
    let request: MeasureRequest = decode_message(PATH_MEASURE_PROTOCOL, request).ok()?;
    let answer = match usize::try_from(request.answer_bytes) {
        Ok(bytes)
            if request.answer_bytes <= FETCH_MAX_BYTES
                && byte_count(request.padding.len()) <= FETCH_MAX_BYTES =>
        {
            MeasureAnswer::Body {
                sample: request.sample,
                body: vec![0; bytes],
            }
        }
        _ => MeasureAnswer::TooLarge {
            most: FETCH_MAX_BYTES,
        },
    };
    encode_message(PATH_MEASURE_PROTOCOL, &answer).ok()
}

/// `len` as a byte count.
fn byte_count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// What a dialer measures, in order: the control round trips, then the
/// fetches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasurePlan {
    pub control_samples: u32,
    /// The size a control request stands for (a `Node` or `Status`).
    pub control_request_bytes: u64,
    /// The size a control answer stands for.
    pub control_answer_bytes: u64,
    pub fetch_samples: u32,
    /// The size of one fetched result, at most [`FETCH_MAX_BYTES`], as one
    /// `Fetch` answers it.
    pub fetch_bytes: u64,
    /// The longest the dial or one sample may take.
    pub call_timeout: Duration,
}

/// Which message a sample stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleKind {
    Control,
    Fetch,
}

impl SampleKind {
    /// The name the report prints.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Fetch => "fetch",
        }
    }
}

/// One round trip: a fresh stream, one request out, one answer back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub kind: SampleKind,
    /// Counted from 0 over every sample of the run.
    pub index: u32,
    pub elapsed: Duration,
    pub sent_bytes: u64,
    pub received_bytes: u64,
}

/// A dialer's run: the dial's own time, then each sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasureReport {
    pub connect: Duration,
    pub samples: Vec<Sample>,
}

/// Why a measurement stopped.
#[derive(Debug, thiserror::Error)]
pub enum MeasureError {
    #[error("the {what} took longer than {secs} s")]
    Timeout { what: &'static str, secs: u64 },
    #[error("a measuring message holds at most {most} bytes")]
    TooLarge { most: u64 },
    #[error("sample {sample} came back with other bytes than it asked for")]
    WrongAnswer { sample: u32 },
    #[error("the mesh: {0}")]
    Mesh(#[from] MeshError),
}

/// Dials `peer` on `transport` and takes `plan`'s samples, each on a fresh
/// stream as the job protocols send each request, then closes the
/// connection.
///
/// # Errors
///
/// A size above [`FETCH_MAX_BYTES`] (before anything is sent), a dial or
/// sample past the plan's timeout, a refused or failed connection, or an
/// answer that is not the one asked for.
pub async fn measure_path(
    transport: &dyn MeshTransport,
    peer: MachineId,
    plan: &MeasurePlan,
) -> Result<MeasureReport, MeasureError> {
    let sizes = [
        plan.control_request_bytes,
        plan.control_answer_bytes,
        plan.fetch_bytes,
    ];
    if sizes.iter().any(|bytes| *bytes > FETCH_MAX_BYTES) {
        return Err(MeasureError::TooLarge {
            most: FETCH_MAX_BYTES,
        });
    }
    let started = Instant::now();
    let connection = timeout(plan.call_timeout, transport.dial(peer, PATH_MEASURE_ALPN))
        .await
        .map_err(|_| timed_out("dial", plan.call_timeout))??;
    let connect = started.elapsed();
    let runs = [
        (
            SampleKind::Control,
            plan.control_samples,
            plan.control_answer_bytes,
        ),
        (SampleKind::Fetch, plan.fetch_samples, plan.fetch_bytes),
    ];
    let mut samples = Vec::new();
    let mut index = 0;
    for (kind, count, answer_bytes) in runs {
        for _ in 0..count {
            let ask = Ask {
                kind,
                index,
                request_bytes: plan.control_request_bytes,
                answer_bytes,
            };
            let sample = take_sample(connection.as_ref(), &ask, plan.call_timeout).await;
            if sample.is_err() {
                connection.close();
            }
            samples.push(sample?);
            index += 1;
        }
    }
    connection.close();
    Ok(MeasureReport { connect, samples })
}

/// One sample's request.
struct Ask {
    kind: SampleKind,
    index: u32,
    request_bytes: u64,
    answer_bytes: u64,
}

/// One round trip on a fresh stream of `connection`.
async fn take_sample(
    connection: &dyn MeshConnection,
    ask: &Ask,
    call_timeout: Duration,
) -> Result<Sample, MeasureError> {
    let too_large = || MeasureError::TooLarge {
        most: FETCH_MAX_BYTES,
    };
    let request = MeasureRequest {
        sample: ask.index,
        answer_bytes: ask.answer_bytes,
        padding: vec![0; usize::try_from(ask.request_bytes).map_err(|_| too_large())?],
    };
    let request = encode_message(PATH_MEASURE_PROTOCOL, &request)?;
    let started = Instant::now();
    let answer = timeout(call_timeout, async {
        let mut stream = connection.open_stream().await?;
        stream.send(&request).await?;
        stream.recv().await
    })
    .await
    .map_err(|_| timed_out("sample", call_timeout))??;
    let elapsed = started.elapsed();
    match decode_message(PATH_MEASURE_PROTOCOL, &answer)? {
        MeasureAnswer::Body { sample, body }
            if sample == ask.index && byte_count(body.len()) == ask.answer_bytes =>
        {
            Ok(Sample {
                kind: ask.kind,
                index: ask.index,
                elapsed,
                sent_bytes: byte_count(request.len()),
                received_bytes: byte_count(answer.len()),
            })
        }
        MeasureAnswer::TooLarge { .. } => Err(too_large()),
        MeasureAnswer::Body { .. } => Err(MeasureError::WrongAnswer { sample: ask.index }),
    }
}

/// The timeout error of `what`.
fn timed_out(what: &'static str, call_timeout: Duration) -> MeasureError {
    MeasureError::Timeout {
        what,
        secs: call_timeout.as_secs(),
    }
}

/// The samples of one kind, summed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleSummary {
    pub count: usize,
    pub min: Duration,
    /// The median, by nearest rank.
    pub p50: Duration,
    /// The 95th percentile, by nearest rank (never interpolated).
    pub p95: Duration,
    pub max: Duration,
    pub sent_bytes: u64,
    pub received_bytes: u64,
}

/// The summary of the samples of `kind`; `None` when there is none.
#[must_use]
pub fn summarize(samples: &[Sample], kind: SampleKind) -> Option<SampleSummary> {
    let of_kind: Vec<&Sample> = samples.iter().filter(|s| s.kind == kind).collect();
    let mut times: Vec<Duration> = of_kind.iter().map(|s| s.elapsed).collect();
    times.sort_unstable();
    let rank = |percent: usize| {
        let at = (times.len() * percent).div_ceil(100).saturating_sub(1);
        times.get(at).copied()
    };
    Some(SampleSummary {
        count: times.len(),
        min: *times.first()?,
        p50: rank(50)?,
        p95: rank(95)?,
        max: *times.last()?,
        sent_bytes: of_kind.iter().map(|s| s.sent_bytes).sum(),
        received_bytes: of_kind.iter().map(|s| s.received_bytes).sum(),
    })
}

/// The report's lines, as `measure-path dial` prints them: the dial, each
/// sample, each kind's summary, and the path the connection used.
#[must_use]
pub fn report_lines(report: &MeasureReport, path: Option<&MeshPathReceipt>) -> Vec<String> {
    let secs = |at: Duration| format!("{:.6}", at.as_secs_f64());
    let mut lines = vec![format!("## CONNECT secs={}", secs(report.connect))];
    for sample in &report.samples {
        lines.push(format!(
            "## SAMPLE kind={} n={} secs={} sent={} received={}",
            sample.kind.label(),
            sample.index + 1,
            secs(sample.elapsed),
            sample.sent_bytes,
            sample.received_bytes
        ));
    }
    for kind in [SampleKind::Control, SampleKind::Fetch] {
        if let Some(summary) = summarize(&report.samples, kind) {
            lines.push(format!(
                "## SUMMARY kind={} n={} min_secs={} p50_secs={} p95_secs={} max_secs={} sent_bytes={} received_bytes={}",
                kind.label(),
                summary.count,
                secs(summary.min),
                secs(summary.p50),
                secs(summary.p95),
                secs(summary.max),
                summary.sent_bytes,
                summary.received_bytes
            ));
        }
    }
    lines.push(path_line(path));
    lines
}

/// The path line of a connection's closed receipt.
#[must_use]
pub fn path_line(path: Option<&MeshPathReceipt>) -> String {
    match path {
        Some(receipt) => format!(
            "## PATH paths={} used_direct={} used_relay={} direct_addr={}",
            format!("{:?}", receipt.paths).to_lowercase(),
            receipt.used_direct,
            receipt.used_relay,
            receipt.direct_addr.as_deref().unwrap_or("-")
        ),
        None => "## PATH unknown (no receipt of the closed connection)".to_owned(),
    }
}
