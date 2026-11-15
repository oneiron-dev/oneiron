//! An organ's mesh ask and its answer past the transport's 1 MiB message
//! (FIX 8023): a big ask is offered from the serving node's connection
//! staging for the asking node to get in pieces, and a big answer is staged
//! the same way, so neither rides as one oversized transport message.
//!
//! On main both ride as one message (`Forward::ask` sends the whole encoded
//! ask, `client::answer` the whole encoded answer) and the transport refuses
//! them, so the organ reads a `failed` refusal. The pair below refuses a
//! message over 1 MiB exactly as the real transport does, so the first two
//! tests fail on main and pass with the fix. The third pins the small case:
//! one message each way, no staging exchange.
#![cfg(unix)]

use std::collections::VecDeque;
use std::sync::{
    Arc, LazyLock, Mutex, PoisonError,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_mesh_transport::{
    MachineId, MeshConnection, MeshDuplex, MeshError, MeshFuture, MeshStream, MeshTransport,
};
use oneiron_organ_host::{
    Answered, AskGrant, AskHandler, AskHandlers, AskReceipt, AskRequest, CallClass, CallReceipt,
    HostConfig, OrganCall, OrganHost, OrganNodes, OrganOutcome, OrganRouter, OrganService,
    OrganSpec, RanOn, Routed,
};
use oneiron_organ_protocol::{AskRefusal, Value};
use tokio::sync::{Notify, mpsc, oneshot};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");
const ASK_VERB: &str = "probe.answer";
const CALL_VERB: &str = "probe.ask";

/// Bytes past which one transport message fails: the real transport's
/// `MAX_MESSAGE`, mirrored by the pair below.
const MESSAGE_MAX: usize = 1024 * 1024;
/// A value past it: the ask or answer the fix stages.
const BIG: usize = 2 * 1024 * 1024;

fn serving_id() -> EntityId {
    EntityId::from_bytes_unchecked([0x51; 16])
}

fn asking_id() -> EntityId {
    EntityId::from_bytes_unchecked([0x41; 16])
}

/// Answers with the ask's own value: a big ask comes back as a big answer.
struct Echo;

impl AskHandler for Echo {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        Ok(Answered {
            value: ask.value.clone(),
            data: None,
            fetch: None,
        })
    }
}

/// Answers a small ask with a big value.
struct BigAnswer;

impl AskHandler for BigAnswer {
    fn answer(&self, _ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        Ok(Answered {
            value: Value::String(BIG_TEXT.clone()),
            data: None,
            fetch: None,
        })
    }
}

static ECHO: Echo = Echo;
static BIG_ANSWER: BigAnswer = BigAnswer;
static BIG_TEXT: LazyLock<String> = LazyLock::new(|| "b".repeat(BIG));

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn spec() -> OrganSpec {
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.verbs = vec!["organ.echo".into(), CALL_VERB.into()];
    spec.asks = vec![AskGrant::new(ASK_VERB, 4)];
    spec
}

fn ask_call(value: Value) -> OrganCall {
    OrganCall {
        organ: "probe".into(),
        verb: CALL_VERB.into(),
        schema: 1,
        args: Value::Map(vec![
            ("verb".into(), ASK_VERB.into()),
            ("value".into(), value),
            ("times".into(), 1u64.into()),
        ]),
        body: None,
        inputs: Vec::new(),
        class: CallClass::Agent,
        deadline: Duration::from_secs(30),
        grant: "g".into(),
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

fn lines(report: &Value) -> &[Value] {
    report.as_array().expect("one line per ask")
}

/// The receipt lines for the organ's own ask.
fn functional(receipt: &CallReceipt) -> Vec<&AskReceipt> {
    receipt
        .asks
        .iter()
        .filter(|line| line.verb == ASK_VERB)
        .collect()
}

/// What one in-memory connection pair shares: whether it is closed, and the
/// bell its ends wait on.
struct Link {
    closed: AtomicBool,
    bell: Notify,
}

impl Link {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            bell: Notify::new(),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.bell.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// The streams the pair's ends opened for each other, each way.
struct Pair {
    a_in: Mutex<VecDeque<FakeStream>>,
    b_in: Mutex<VecDeque<FakeStream>>,
    link: Arc<Link>,
}

/// One message each way: the mesh sends once and receives once per stream.
struct FakeStream {
    tx: Option<oneshot::Sender<Vec<u8>>>,
    rx: Option<oneshot::Receiver<Vec<u8>>>,
    link: Arc<Link>,
}

fn stream_pair(link: &Arc<Link>) -> (FakeStream, FakeStream) {
    let (a_tx, a_rx) = oneshot::channel();
    let (b_tx, b_rx) = oneshot::channel();
    (
        FakeStream {
            tx: Some(a_tx),
            rx: Some(b_rx),
            link: Arc::clone(link),
        },
        FakeStream {
            tx: Some(b_tx),
            rx: Some(a_rx),
            link: Arc::clone(link),
        },
    )
}

impl MeshStream for FakeStream {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> MeshFuture<'a, ()> {
        Box::pin(async move {
            if self.link.is_closed() {
                return Err(MeshError::Io("the connection closed".into()));
            }
            let Some(tx) = self.tx.take() else {
                return Err(MeshError::Io("the stream already sent".into()));
            };
            // As the real transport: a message past 1 MiB fails, and nothing
            // arrives; the peer's receive ends with the stream.
            if bytes.len() > MESSAGE_MAX {
                return Err(MeshError::Unavailable);
            }
            tx.send(bytes.to_vec())
                .map_err(|_| MeshError::Io("the stream broke".into()))
        })
    }

    fn recv(&mut self) -> MeshFuture<'_, Vec<u8>> {
        Box::pin(async move {
            let Some(rx) = self.rx.take() else {
                return Err(MeshError::Io("the stream already received".into()));
            };
            tokio::select! {
                received = rx => received.map_err(|_| MeshError::Io("the stream broke".into())),
                () = self.link.bell.notified() => Err(MeshError::Io("the connection closed".into())),
            }
        })
    }
}

/// One end of an in-memory connection: which queue is its own decides it.
struct FakeConn {
    pair: Arc<Pair>,
    own: Side,
    machine: EntityId,
    alpn: Vec<u8>,
    accepted: Arc<AtomicUsize>,
}

#[derive(Clone, Copy)]
enum Side {
    Asking,
    Serving,
}

impl FakeConn {
    fn inbox(&self) -> &Mutex<VecDeque<FakeStream>> {
        match self.own {
            Side::Asking => &self.pair.a_in,
            Side::Serving => &self.pair.b_in,
        }
    }

    fn peer_inbox(&self) -> &Mutex<VecDeque<FakeStream>> {
        match self.own {
            Side::Asking => &self.pair.b_in,
            Side::Serving => &self.pair.a_in,
        }
    }

    fn take_incoming(&self) -> Option<FakeStream> {
        self.inbox()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    fn push_incoming(&self, stream: FakeStream) {
        self.peer_inbox()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(stream);
        self.pair.link.bell.notify_one();
    }

    async fn accept(&self) -> Result<FakeStream, MeshError> {
        loop {
            if self.pair.link.is_closed() {
                return Err(MeshError::Io("the connection closed".into()));
            }
            if let Some(stream) = self.take_incoming() {
                self.accepted.fetch_add(1, Ordering::SeqCst);
                return Ok(stream);
            }
            self.pair.link.bell.notified().await;
        }
    }
}

impl MeshConnection for FakeConn {
    fn machine(&self) -> MachineId {
        self.machine
    }

    fn alpn(&self) -> &[u8] {
        &self.alpn
    }

    fn endpoint_key(&self) -> [u8; 32] {
        [0; 32]
    }

    fn open_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async move {
            if self.pair.link.is_closed() {
                return Err(MeshError::Io("the connection closed".into()));
            }
            let (own, peer) = stream_pair(&self.pair.link);
            self.push_incoming(peer);
            Ok(Box::new(own) as Box<dyn MeshStream>)
        })
    }

    fn accept_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async move {
            self.accept()
                .await
                .map(|stream| Box::new(stream) as Box<dyn MeshStream>)
        })
    }

    fn open_duplex(&self) -> MeshFuture<'_, Box<dyn MeshDuplex>> {
        Box::pin(async move { Err(MeshError::Unavailable) })
    }

    fn accept_duplex(&self) -> MeshFuture<'_, Box<dyn MeshDuplex>> {
        Box::pin(async move { Err(MeshError::Unavailable) })
    }

    fn close(&self) {
        self.pair.link.close();
    }
}

/// Dials in-memory pairs: the asking end returns, the serving end waits for
/// the test's serving task.
struct FakeTransport {
    serving_tx: mpsc::UnboundedSender<Box<dyn MeshConnection>>,
    serving_accepted: Arc<AtomicUsize>,
}

impl MeshTransport for FakeTransport {
    fn dial(&self, machine: MachineId, alpn: &[u8]) -> MeshFuture<'_, Box<dyn MeshConnection>> {
        let link = Arc::new(Link::new());
        let pair = Arc::new(Pair {
            a_in: Mutex::new(VecDeque::new()),
            b_in: Mutex::new(VecDeque::new()),
            link: Arc::clone(&link),
        });
        let serving = FakeConn {
            pair: Arc::clone(&pair),
            own: Side::Serving,
            machine: asking_id(),
            alpn: alpn.to_vec(),
            accepted: Arc::clone(&self.serving_accepted),
        };
        let handed = self
            .serving_tx
            .send(Box::new(serving) as Box<dyn MeshConnection>)
            .is_ok();
        let asking = FakeConn {
            pair,
            own: Side::Asking,
            machine,
            alpn: alpn.to_vec(),
            accepted: Arc::new(AtomicUsize::new(0)),
        };
        Box::pin(async move {
            if handed {
                Ok(Box::new(asking) as Box<dyn MeshConnection>)
            } else {
                Err(MeshError::Io("no serving task waits".into()))
            }
        })
    }

    fn accept(&self) -> MeshFuture<'_, Box<dyn MeshConnection>> {
        Box::pin(async move { Err(MeshError::Unavailable) })
    }
}

/// The owner's other node: the serving one.
struct OneNode(MachineId);

impl OrganNodes for OneNode {
    fn nodes(&self) -> Result<Vec<MachineId>, String> {
        Ok(vec![self.0])
    }
}

/// Runs one `probe.ask` call on the serving node over the in-memory pair: the
/// router asks, the serving host runs the probe, `handler` answers the
/// organ's ask back on this node. Returns the outcome and how many streams
/// the serving end accepted.
async fn run_over_mesh(value: Value, handler: &'static dyn AskHandler) -> (OrganOutcome, u64) {
    let (_ask_dir, asking_vault) = vault();
    let asking_vault = Arc::new(asking_vault);
    let (_serve_dir, serving_vault) = vault();
    let serving_host = Arc::new({
        let host = OrganHost::new(HostConfig::default());
        host.install(spec());
        host
    });
    let service = OrganService::new(Arc::clone(&serving_host), Arc::new(serving_vault));
    let (serving_tx, mut serving_rx) = mpsc::unbounded_channel::<Box<dyn MeshConnection>>();
    let serving_accepted = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(FakeTransport {
        serving_tx,
        serving_accepted: Arc::clone(&serving_accepted),
    });
    let nodes = Arc::new(OneNode(serving_id()));
    let asks = AskHandlers::none().with(ASK_VERB, handler);
    let call = ask_call(value);
    // The router blocks on the mesh runtime from the call's thread, while
    // this runtime serves the other end.
    let calling = tokio::task::spawn_blocking(move || {
        let mesh = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("the mesh runtime builds");
        let router = OrganRouter::new().with_mesh(transport, nodes, mesh.handle().clone());
        router.call_with(&asking_vault, call, Vec::new(), &asks)
    });
    let serving = serving_rx.recv().await.expect("the router dials");
    let served = tokio::spawn(async move {
        service.serve_connection(serving).await;
    });
    let outcome = match calling.await.expect("the call ends") {
        Ok(Routed::Done { outcome, ran_on }) => {
            assert_eq!(
                ran_on,
                RanOn::Node(serving_id()),
                "the call runs over the mesh"
            );
            outcome
        }
        Ok(Routed::Waiting(wait)) => {
            let reason = wait.reason;
            panic!("the call waits: {reason}");
        }
        Err(err) => panic!("the call fails: {err}"),
    };
    tokio::time::timeout(Duration::from_secs(30), served)
        .await
        .expect("serving ends")
        .expect("the serving task ends");
    (outcome, serving_accepted.load(Ordering::SeqCst))
}

#[tokio::test]
async fn an_ask_past_one_mib_is_answered_whole() {
    let big = "a".repeat(BIG);
    let encoded = oneiron_organ_protocol::encoded_len(&Value::String(big.clone()))
        .expect("the ask value encodes");
    assert!(
        encoded > MESSAGE_MAX as u64,
        "the ask must clear one message: {encoded} bytes"
    );
    let (outcome, _) = run_over_mesh(Value::String(big.clone()), &ECHO).await;
    let seen = lines(&outcome.report);
    assert_eq!(seen.len(), 1, "the probe asks once");
    assert_eq!(
        field(&seen[0], "answered").and_then(Value::as_str),
        Some(big.as_str()),
        "the big ask comes back answered, not refused"
    );
    let asked = functional(&outcome.receipt);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].refused, None);
}

#[tokio::test]
async fn an_answer_past_one_mib_comes_back_whole() {
    assert!(
        BIG_TEXT.len() > MESSAGE_MAX,
        "the answer must clear one message"
    );
    let (outcome, _) = run_over_mesh(Value::String("a small ask".into()), &BIG_ANSWER).await;
    let seen = lines(&outcome.report);
    assert_eq!(seen.len(), 1, "the probe asks once");
    assert_eq!(
        field(&seen[0], "answered").and_then(Value::as_str),
        Some(BIG_TEXT.as_str()),
        "the big answer comes back whole, not refused"
    );
    let asked = functional(&outcome.receipt);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].refused, None);
}

#[tokio::test]
async fn a_small_ask_still_rides_inline() {
    let (outcome, accepted) = run_over_mesh(Value::String("a small ask".into()), &ECHO).await;
    let seen = lines(&outcome.report);
    assert_eq!(seen.len(), 1, "the probe asks once");
    assert_eq!(
        field(&seen[0], "answered").and_then(Value::as_str),
        Some("a small ask")
    );
    // The asking end opens one stream for the offers and one for the call;
    // past either bound it would stage pieces over Put and Get streams.
    assert_eq!(accepted, 2, "no staging exchange for a small ask");
}
