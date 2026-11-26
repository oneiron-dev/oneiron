//! An organ's mesh ask and its answer past the transport's 1 MiB message
//! (FIX 8023): a big ask is offered from the serving node's connection
//! staging for the asking node to get in pieces, and a big answer is staged
//! the same way, so neither rides as one oversized transport message.
//!
//! Without the fix both ride as one message (`Forward::ask` sends the whole
//! encoded ask, `client::answer` the whole encoded answer) and the transport
//! refuses them, so the organ reads a `failed` refusal. The pair below
//! refuses a message over 1 MiB exactly as the real transport does, so the
//! first two tests fail without the fix and pass with it. The third pins the
//! small case: one message each way, no staging exchange.
//!
//! The serving node signs each successful call's receipt with its machine
//! key, and the asking node checks it against the machine its handshake
//! proved (Engine ruling ORGAN-MESH-RECEIPT-SIGNATURE). So both ends are real
//! installs: the asking node is the owner's home, and the serving node a
//! device of it, enrolled as `oneiron device enrol` enrols one, its mesh
//! identity bound on the home and granted `oneiron/organ/1` in the same
//! redemption. The in-memory pair presents the serving device's endpoint key
//! to the asking end, as the real handshake would. The last six tests pin the
//! signature: the serving node's receipt verifies as its own, and a receipt a
//! machine other than the one the connection proved signed is refused. The
//! serving end can rewrite its replies as a node that breaks the protocol
//! would: a receipt an earlier call earned, a report or a body other than
//! the ones the receipt names, and a result that does not decode are each
//! refused as a broken rule, never taken and never tried on another node
//! (blind-review P1s on #10409). It can also sign again what it changed, as
//! a node that signs what it should not would: a receipt naming the lent
//! input as a vault version is refused, and a report the JSON writer cannot
//! render leaves the signed receipt whole where a proposal keeps it. A
//! staged result or output whose pieces the serving node then refuses ends
//! the call as that node's failure, never as an absent node to run it again
//! on (round-2 blind-review P1s on #10409).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-organ-host --test mesh_ask_carried` (the home's owner proof is a
//! test door).
#![cfg(all(unix, oneiron_test_support))]

use std::collections::VecDeque;
use std::pin::pin;
use std::sync::{
    Arc, LazyLock, Mutex, PoisonError,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, MachineOwnership, MachineRole, MeshEnrolment, MeshEnrolmentAsk, PairingPrincipal,
    pairing_binding_transcript_pinned,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::test_doors::steward;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_mesh_transport::{
    MachineId, MeshConnection, MeshDuplex, MeshError, MeshFuture, MeshStream, MeshTransport,
};
use oneiron_organ_host::{
    Answered, AskGrant, AskHandler, AskHandlers, AskReceipt, AskRequest, CallClass, CallReceipt,
    HostConfig, HostError, LentInput, ORGAN_ALPN, OrganCall, OrganHost, OrganNodes, OrganOutcome,
    OrganRouter, OrganService, OrganSpec, RanOn, Routed,
};
use oneiron_organ_protocol::{AskRefusal, Value, from_slice, to_vec};
use tokio::sync::{Notify, mpsc, oneshot};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");
const ASK_VERB: &str = "probe.answer";
const CALL_VERB: &str = "probe.ask";
const OUTPUTS_VERB: &str = "probe.outputs";
/// The media type of the bytes a call lends; the probe's install grants it.
const LENT_MEDIA_TYPE: &str = "text/plain";
/// An output past the organ service's 64 KiB inline bound: the serving node
/// stages it.
const STAGED_OUTPUT_BYTES: u64 = 128 * 1024;

/// Bytes past which one transport message fails: the real transport's
/// `MAX_MESSAGE`, mirrored by the pair below.
const MESSAGE_MAX: usize = 1024 * 1024;
/// A value past it: the ask or answer the fix stages.
const BIG: usize = 2 * 1024 * 1024;

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

/// The owner's home, the asking node: a rooted carrier install the owner
/// answered as his own machine.
struct Home {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
}

/// A device of the home, the serving node: its own install, enrolled on the
/// home with its mesh identity bound there and granted organ calls.
struct Device {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    machine: EntityId,
    endpoint_key: [u8; 32],
}

fn home() -> Home {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = steward::open_owner_carrier_vault(dir.path()).expect("the home's vault");
    let owner = steward::owner(&vault).expect("the home's owner proof");
    let machine = vault
        .local_machine()
        .expect("the home's install")
        .expect("the home's install has a machine")
        .id;
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner answers the home is his");
    Home {
        _dir: dir,
        vault: Arc::new(vault),
        owner,
    }
}

impl Home {
    /// A device that copies the home's vault and enrols on it as the
    /// owner's own machine: the owner's machine pairing link, redeemed with
    /// the device's holder key (seeded by `holder_seed`), its enrolment
    /// request, its machine key's possession proof and its mesh identity,
    /// which the home binds and grants `oneiron/organ/1` in that redemption.
    fn enrol(&self, holder_seed: u8) -> Device {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the device's vault");
        vault
            .import_signed_authority_history(
                &self
                    .vault
                    .export_signed_authority_history()
                    .expect("the home's authority history"),
            )
            .expect("the device takes the home's authority history");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let vault_id = vault
            .authority_vault_id()
            .expect("the device's vault id")
            .expect("the device's copy has a vault id");
        let request = vault
            .machine_enrolment_request(
                vault_id,
                vault
                    .machine_encryption_key(vault_id)
                    .expect("the device's encryption key"),
            )
            .expect("the device's enrolment request");
        let device_owner = steward::owner(&vault).expect("the device's owner proof");
        let identity = vault
            .mesh_binding_identity_as_owner(&device_owner)
            .expect("the device's mesh identity");
        let issuer = test_host_issuer();
        let link = self
            .vault
            .issue_machine_pairing_link(
                &issuer,
                &self.owner,
                ActSurface::ThisInstall,
                Scope::top(),
                3600,
                PairingPrincipal::default(),
                MachineOwnership::Yours,
            )
            .expect("the owner's machine pairing link");
        let holder = SigningKey::from_bytes(&[holder_seed; 32]);
        let binding_key = holder.verifying_key().to_bytes();
        let holder_ref = request.machine.to_hex();
        let transcript = pairing_binding_transcript_pinned(
            &link.code,
            &binding_key,
            &holder_ref,
            link.pin.as_ref(),
        )
        .expect("the pairing transcript");
        let possession = vault
            .machine_possession_proof(&request, &transcript)
            .expect("the machine key's possession proof");
        let redeemed = self
            .vault
            .redeem_pairing_link_with_mesh(
                &issuer,
                &link.code,
                &holder_ref,
                binding_key,
                &holder.sign(&transcript).to_bytes(),
                &request,
                Some(&possession),
                // The binding's pairing covers the organ protocol it is
                // granted (MESH-PAIRING-CEILING = A); this crate does not
                // see the server's list of every protocol it serves.
                MeshEnrolmentAsk {
                    identity: &identity,
                    granted: ORGAN_ALPN,
                    ceiling: &[ORGAN_ALPN],
                },
            )
            .expect("the home redeems the device's enrolment");
        assert!(
            matches!(redeemed.mesh, Some(MeshEnrolment::Bound { .. })),
            "the home must bind the device's mesh identity: {:?}",
            redeemed.mesh
        );
        Device {
            _dir: dir,
            vault: Arc::new(vault),
            machine: request.machine,
            endpoint_key: identity.endpoint_key,
        }
    }
}

fn spec() -> OrganSpec {
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.verbs = vec!["organ.echo".into(), CALL_VERB.into(), OUTPUTS_VERB.into()];
    spec.asks = vec![AskGrant::new(ASK_VERB, 4)];
    spec.media_types = vec![LENT_MEDIA_TYPE.into()];
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

/// A `probe.outputs` call: `count` outputs of `bytes` bytes each.
fn outputs_call(count: u64, bytes: u64) -> OrganCall {
    OrganCall {
        verb: OUTPUTS_VERB.into(),
        args: Value::Map(vec![
            ("count".into(), count.into()),
            ("bytes".into(), bytes.into()),
        ]),
        ..ask_call(Value::Nil)
    }
}

/// `bytes`, lent to the call.
fn lent(bytes: &[u8]) -> Vec<LentInput> {
    vec![LentInput {
        media_type: LENT_MEDIA_TYPE.into(),
        bytes: bytes.to_vec(),
    }]
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
/// bell only the close rings. A stream's arrival rings its own inbox's bell,
/// so a waiter never reads an arrival as the close.
struct Link {
    closed: AtomicBool,
    closing: Notify,
}

impl Link {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            closing: Notify::new(),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.closing.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Ends once the pair is closed. The waiter registers before it reads
    /// the flag: `notify_waiters` keeps no permit for a later waiter, so a
    /// close between the read and the wait would otherwise go unseen.
    async fn closed(&self) {
        let mut closing = pin!(self.closing.notified());
        closing.as_mut().enable();
        if self.is_closed() {
            return;
        }
        closing.await;
    }
}

/// The streams one end has not accepted yet, and the bell that rings when
/// the other end opens one. The bell keeps a permit when no accept waits, so
/// an arrival between the queue read and the wait still wakes it.
struct Inbox {
    streams: Mutex<VecDeque<FakeStream>>,
    arrived: Notify,
}

impl Inbox {
    fn new() -> Self {
        Self {
            streams: Mutex::new(VecDeque::new()),
            arrived: Notify::new(),
        }
    }
}

/// The streams the pair's ends opened for each other, each way.
struct Pair {
    a_in: Inbox,
    b_in: Inbox,
    link: Arc<Link>,
}

/// Rewrites one message the serving end sends, as a node that breaks the
/// protocol would.
type Rewrite = Arc<dyn Fn(Vec<u8>) -> Vec<u8> + Send + Sync>;

/// One message each way: the mesh sends once and receives once per stream.
struct FakeStream {
    tx: Option<oneshot::Sender<Vec<u8>>>,
    rx: Option<oneshot::Receiver<Vec<u8>>>,
    link: Arc<Link>,
    /// What the serving end's sends go through, if anything.
    rewrite: Option<Rewrite>,
}

fn stream_pair(link: &Arc<Link>) -> (FakeStream, FakeStream) {
    let (a_tx, a_rx) = oneshot::channel();
    let (b_tx, b_rx) = oneshot::channel();
    (
        FakeStream {
            tx: Some(a_tx),
            rx: Some(b_rx),
            link: Arc::clone(link),
            rewrite: None,
        },
        FakeStream {
            tx: Some(b_tx),
            rx: Some(a_rx),
            link: Arc::clone(link),
            rewrite: None,
        },
    )
}

/// `value`'s entry under `key`, when `value` is a map that holds one.
fn entry_mut<'a>(value: &'a mut Value, key: &str) -> Option<&'a mut Value> {
    match value {
        Value::Map(entries) => entries
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// A rewrite that hands `change` the outcome in each call reply the serving
/// end sends (`{"call": {"inline": <{"done": outcome}>}}`), and passes every
/// other message through.
fn rewrite_done(change: impl Fn(&mut Value) + Send + Sync + 'static) -> Rewrite {
    Arc::new(move |bytes: Vec<u8>| {
        let Ok(mut reply) = from_slice::<Value>(&bytes) else {
            return bytes;
        };
        let Some(Value::Binary(inner)) =
            entry_mut(&mut reply, "call").and_then(|call| entry_mut(call, "inline"))
        else {
            return bytes;
        };
        let Ok(mut result) = from_slice::<Value>(inner) else {
            return bytes;
        };
        let Some(done) = entry_mut(&mut result, "done") else {
            return bytes;
        };
        change(done);
        *inner = to_vec(&result).expect("the rewritten result encodes");
        to_vec(&reply).expect("the rewritten reply encodes")
    })
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
            let bytes = match &self.rewrite {
                Some(rewrite) => rewrite(bytes.to_vec()),
                None => bytes.to_vec(),
            };
            // As the real transport: a message past 1 MiB fails, and nothing
            // arrives; the peer's receive ends with the stream.
            if bytes.len() > MESSAGE_MAX {
                return Err(MeshError::Unavailable);
            }
            tx.send(bytes)
                .map_err(|_| MeshError::Io("the stream broke".into()))
        })
    }

    fn recv(&mut self) -> MeshFuture<'_, Vec<u8>> {
        Box::pin(async move {
            let Some(rx) = self.rx.take() else {
                return Err(MeshError::Io("the stream already received".into()));
            };
            // As the real transport: a message sent before the close still
            // arrives.
            tokio::select! {
                biased;
                received = rx => received.map_err(|_| MeshError::Io("the stream broke".into())),
                () = self.link.closed() => Err(MeshError::Io("the connection closed".into())),
            }
        })
    }
}

/// One end of an in-memory connection: which queue is its own decides it.
struct FakeConn {
    pair: Arc<Pair>,
    own: Side,
    machine: EntityId,
    /// The key the handshake authenticated for the other end.
    endpoint_key: [u8; 32],
    alpn: Vec<u8>,
    accepted: Arc<AtomicUsize>,
    /// What the replies on the streams this end accepts go through.
    rewrite: Option<Rewrite>,
}

#[derive(Clone, Copy)]
enum Side {
    Asking,
    Serving,
}

impl FakeConn {
    fn inbox(&self) -> &Inbox {
        match self.own {
            Side::Asking => &self.pair.a_in,
            Side::Serving => &self.pair.b_in,
        }
    }

    fn peer_inbox(&self) -> &Inbox {
        match self.own {
            Side::Asking => &self.pair.b_in,
            Side::Serving => &self.pair.a_in,
        }
    }

    fn take_incoming(&self) -> Option<FakeStream> {
        self.inbox()
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    fn push_incoming(&self, stream: FakeStream) {
        let inbox = self.peer_inbox();
        inbox
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(stream);
        inbox.arrived.notify_one();
    }

    async fn accept(&self) -> Result<FakeStream, MeshError> {
        loop {
            if self.pair.link.is_closed() {
                return Err(MeshError::Io("the connection closed".into()));
            }
            if let Some(mut stream) = self.take_incoming() {
                self.accepted.fetch_add(1, Ordering::SeqCst);
                stream.rewrite.clone_from(&self.rewrite);
                return Ok(stream);
            }
            tokio::select! {
                () = self.inbox().arrived.notified() => {}
                () = self.pair.link.closed() => {}
            }
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
        self.endpoint_key
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
    /// The endpoint key the asking end's handshake proves for the node it
    /// dialed.
    presented_key: [u8; 32],
    /// What the serving end's replies go through.
    rewrite: Option<Rewrite>,
}

impl MeshTransport for FakeTransport {
    fn dial(&self, machine: MachineId, alpn: &[u8]) -> MeshFuture<'_, Box<dyn MeshConnection>> {
        let link = Arc::new(Link::new());
        let pair = Arc::new(Pair {
            a_in: Inbox::new(),
            b_in: Inbox::new(),
            link: Arc::clone(&link),
        });
        let serving = FakeConn {
            pair: Arc::clone(&pair),
            own: Side::Serving,
            machine: asking_id(),
            endpoint_key: [0; 32],
            alpn: alpn.to_vec(),
            accepted: Arc::clone(&self.serving_accepted),
            rewrite: self.rewrite.clone(),
        };
        let handed = self
            .serving_tx
            .send(Box::new(serving) as Box<dyn MeshConnection>)
            .is_ok();
        let asking = FakeConn {
            pair,
            own: Side::Asking,
            machine,
            endpoint_key: self.presented_key,
            alpn: alpn.to_vec(),
            accepted: Arc::new(AtomicUsize::new(0)),
            rewrite: None,
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

/// Runs `call` from the home over the in-memory pair, lending it `lent`:
/// the router dials `dialed`, whose endpoint key the asking end's handshake
/// proves, while `serving`'s host runs the probe, its replies going through
/// `rewrite`, and `handler` answers the organ's ask back on the home.
/// Returns what the router said and how many streams the serving end
/// accepted.
async fn run_on(
    home: &Home,
    dialed: &Device,
    serving: &Device,
    (call, lent): (OrganCall, Vec<LentInput>),
    handler: &'static dyn AskHandler,
    rewrite: Option<Rewrite>,
) -> (Result<Routed, HostError>, usize) {
    let serving_host = Arc::new({
        let host = OrganHost::new(HostConfig::default());
        host.install(spec());
        host
    });
    let service = OrganService::new(Arc::clone(&serving_host), Arc::clone(&serving.vault));
    let (serving_tx, mut serving_rx) = mpsc::unbounded_channel::<Box<dyn MeshConnection>>();
    let serving_accepted = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(FakeTransport {
        serving_tx,
        serving_accepted: Arc::clone(&serving_accepted),
        presented_key: dialed.endpoint_key,
        rewrite,
    });
    let nodes = Arc::new(OneNode(dialed.machine));
    let asks = AskHandlers::none().with(ASK_VERB, handler);
    let asking_vault = Arc::clone(&home.vault);
    // The router blocks on this runtime from the call's thread, while this
    // thread drives it: the serving end, and the timers of the mesh's
    // timeouts. A runtime of the call's own, entered only through
    // `Handle::block_on`, would drive no timer, so a stalled call would
    // hang the test rather than end it.
    let runtime = tokio::runtime::Handle::current();
    let calling = tokio::task::spawn_blocking(move || {
        let router = OrganRouter::new().with_mesh(transport, nodes, runtime);
        router.call_with(&asking_vault, call, lent, &asks)
    });
    let serving_conn = serving_rx.recv().await.expect("the router dials");
    let served = tokio::spawn(async move {
        service.serve_connection(serving_conn).await;
    });
    let routed = calling.await.expect("the call ends");
    tokio::time::timeout(Duration::from_secs(30), served)
        .await
        .expect("serving ends")
        .expect("the serving task ends");
    (routed, serving_accepted.load(Ordering::SeqCst))
}

/// Runs one `probe.ask` call on a device of the home over the in-memory
/// pair ([`run_on`]), the device both dialed and serving. Returns the
/// outcome, how many streams the serving end accepted, and the two installs.
async fn run_over_mesh_on(
    value: Value,
    handler: &'static dyn AskHandler,
) -> (OrganOutcome, usize, Home, Device) {
    let home = home();
    let serving = home.enrol(0x51);
    let called = (ask_call(value), Vec::new());
    let (routed, accepted) = run_on(&home, &serving, &serving, called, handler, None).await;
    let outcome = match routed {
        Ok(Routed::Done { outcome, ran_on }) => {
            assert_eq!(
                ran_on,
                RanOn::Node(serving.machine),
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
    (outcome, accepted, home, serving)
}

/// [`run_over_mesh_on`]'s outcome and stream count.
async fn run_over_mesh(value: Value, handler: &'static dyn AskHandler) -> (OrganOutcome, usize) {
    let (outcome, accepted, _, _) = run_over_mesh_on(value, handler).await;
    (outcome, accepted)
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

#[tokio::test]
async fn the_serving_nodes_receipt_is_signed_by_its_machine() {
    let (outcome, _, home, serving) =
        run_over_mesh_on(Value::String("a small ask".into()), &ECHO).await;
    let signed = outcome
        .receipt
        .signed_by
        .as_ref()
        .expect("the serving node signs its receipt");
    assert_eq!(signed.machine, serving.machine.to_hex());
    assert_eq!(
        outcome.receipt.signer(&*home.vault),
        Ok(serving.machine),
        "the receipt the asking node holds verifies as the serving machine's, against its MACHINE row"
    );
}

#[tokio::test]
async fn a_receipt_signed_by_another_machine_than_the_one_proved_is_refused() {
    let home = home();
    let serving = home.enrol(0x51);
    let proved = home.enrol(0x52);
    // The handshake proves `proved`, the machine the router dialed; the host
    // that answers and signs is `serving`'s.
    let called = (ask_call(Value::String("a small ask".into())), Vec::new());
    let (routed, _) = run_on(&home, &proved, &serving, called, &ECHO, None).await;
    match routed {
        Err(HostError::ReplyInvalid(why)) => assert!(
            why.contains(&serving.machine.to_hex()),
            "the refusal must name the machine that signed: {why}"
        ),
        Ok(Routed::Done { ran_on, .. }) => {
            panic!("the asking node took a receipt another machine signed, as run on {ran_on:?}")
        }
        Ok(Routed::Waiting(wait)) => panic!("the call waits: {}", wait.reason),
        Err(err) => panic!("the call fails otherwise: {err}"),
    }
}

/// One `probe.ask` call from the home on `serving`, its replies going
/// through `rewrite`: what the router said.
async fn run_rewritten(
    home: &Home,
    serving: &Device,
    value: &str,
    rewrite: Rewrite,
) -> Result<Routed, HostError> {
    let called = (ask_call(Value::String(value.into())), Vec::new());
    run_on(home, serving, serving, called, &ECHO, Some(rewrite))
        .await
        .0
}

/// Why the asking node refused a reply as a broken rule; any other end
/// fails the test.
fn refused(routed: Result<Routed, HostError>) -> String {
    match routed {
        Err(HostError::ReplyInvalid(why)) => why,
        Ok(Routed::Done { ran_on, .. }) => {
            panic!("the asking node took the rewritten reply, as run on {ran_on:?}")
        }
        Ok(Routed::Waiting(wait)) => {
            panic!("the call waits, as for an absent node: {}", wait.reason)
        }
        Err(err) => panic!("the call fails otherwise: {err}"),
    }
}

#[tokio::test]
async fn a_receipt_an_earlier_call_earned_is_refused_for_a_later_call() {
    let home = home();
    let serving = home.enrol(0x51);
    let earlier: Arc<Mutex<Option<Value>>> = Arc::default();
    let kept = Arc::clone(&earlier);
    let first = run_rewritten(
        &home,
        &serving,
        "the earlier call",
        rewrite_done(move |done| {
            *kept.lock().unwrap_or_else(PoisonError::into_inner) = Some(done.clone());
        }),
    )
    .await;
    assert!(
        matches!(first, Ok(Routed::Done { .. })),
        "the earlier call must run as it is"
    );
    let replayed = earlier
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .expect("the earlier call's outcome was kept");
    // The serving node answers a later call, with other args, with the
    // earlier call's signed outcome, outputs and all.
    let why = refused(
        run_rewritten(
            &home,
            &serving,
            "a later call",
            rewrite_done(move |done| *done = replayed.clone()),
        )
        .await,
    );
    assert!(
        why.contains("another call"),
        "the refusal must say the receipt answers another call: {why}"
    );
}

#[tokio::test]
async fn a_report_other_than_the_one_the_receipt_names_is_refused() {
    let home = home();
    let serving = home.enrol(0x51);
    let why = refused(
        run_rewritten(
            &home,
            &serving,
            "a small ask",
            rewrite_done(|done| {
                *entry_mut(done, "report").expect("the outcome holds its report") =
                    Value::from("a report the node never signed");
            }),
        )
        .await,
    );
    assert!(
        why.contains("report"),
        "the refusal must name the report: {why}"
    );
}

#[tokio::test]
async fn a_body_other_than_the_one_the_receipt_names_is_refused() {
    let home = home();
    let serving = home.enrol(0x51);
    let why = refused(
        run_rewritten(
            &home,
            &serving,
            "a small ask",
            rewrite_done(|done| {
                *entry_mut(done, "body").expect("the outcome holds its body") = Value::Map(vec![
                    ("kind".into(), "text".into()),
                    ("schema".into(), 1_u64.into()),
                    ("value".into(), "a body the node never signed".into()),
                ]);
            }),
        )
        .await,
    );
    assert!(
        why.contains("body"),
        "the refusal must name the body: {why}"
    );
}

#[tokio::test]
async fn a_result_that_does_not_decode_is_refused_not_tried_on_another_node() {
    let home = home();
    let serving = home.enrol(0x51);
    // The call ran on the serving node; its result's signature is a number.
    let why = refused(
        run_rewritten(
            &home,
            &serving,
            "a small ask",
            rewrite_done(|done| {
                let signed = entry_mut(done, "receipt")
                    .and_then(|receipt| entry_mut(receipt, "signed_by"))
                    .expect("the receipt carries its signature");
                *entry_mut(signed, "signature").expect("the signature's bytes") =
                    Value::from(7_u64);
            }),
        )
        .await,
    );
    assert!(
        why.contains("does not decode"),
        "the refusal must say the result does not decode: {why}"
    );
}

/// A rewrite that hands `change` the outcome in each call reply the serving
/// end sends, with its receipt, then signs that receipt again as `serving`'s
/// machine, over the call's nonce and the report the outcome then holds:
/// the word of a node that signs what it should not, which the signature
/// check alone takes.
fn resigned(
    serving: &Device,
    change: impl Fn(&mut Value, &mut CallReceipt) + Send + Sync + 'static,
) -> Rewrite {
    let signer = Arc::clone(&serving.vault);
    rewrite_done(move |done| {
        let held = field(done, "receipt").expect("the outcome holds its receipt");
        let mut receipt: CallReceipt =
            from_slice(&to_vec(held).expect("the receipt encodes")).expect("the receipt decodes");
        change(done, &mut receipt);
        let nonce = receipt
            .signed_by
            .as_ref()
            .expect("the serving node signed its receipt")
            .call_nonce
            .clone();
        let report = field(done, "report")
            .cloned()
            .expect("the outcome holds its report");
        receipt
            .sign(&*signer, &nonce, &report)
            .expect("the serving machine signs again");
        *entry_mut(done, "receipt").expect("the outcome holds its receipt") =
            from_slice(&to_vec(&receipt).expect("the receipt encodes"))
                .expect("the receipt reads as a value");
    })
}

/// A rewrite that answers each `Get` with a refusal: a node that ran the
/// call and then lost what it staged.
fn refuse_pieces() -> Rewrite {
    Arc::new(|bytes: Vec<u8>| match from_slice::<Value>(&bytes) {
        Ok(reply) if field(&reply, "piece").is_some() => to_vec(&Value::Map(vec![(
            "refused".into(),
            "the staged bytes are gone".into(),
        )]))
        .expect("the refusal encodes"),
        _ => bytes,
    })
}

/// The call ran on `serving` and what it returned did not come: the asking
/// node must end it as that node's failure, never wait to run it again on
/// another node.
fn not_fetched(routed: Result<Routed, HostError>, serving: &Device) {
    match routed {
        Err(HostError::Remote { machine, detail }) => {
            assert_eq!(machine, serving.machine.to_hex());
            assert!(
                detail.contains("ran there"),
                "the failure must say the call ran there: {detail}"
            );
        }
        Ok(Routed::Waiting(wait)) => panic!(
            "the call that ran waits to run again, as for an absent node: {}",
            wait.reason
        ),
        Ok(Routed::Done { ran_on, .. }) => {
            panic!("the call took what was refused, as run on {ran_on:?}")
        }
        Err(err) => panic!("the call fails otherwise: {err}"),
    }
}

#[tokio::test]
async fn a_receipt_naming_another_input_than_the_one_sent_is_refused() {
    let home = home();
    let serving = home.enrol(0x51);
    // The serving node signs a receipt that names the bytes this node lent,
    // under their own hash, as a vault version this node never sent: a
    // landing would take that version as the output's base.
    let rewrite = resigned(&serving, |_, receipt| {
        let line = receipt
            .inputs
            .first_mut()
            .expect("the receipt names the lent input");
        line.artifact = asking_id().to_hex();
        line.version = 2;
        line.lent = false;
    });
    let called = (
        ask_call(Value::String("a small ask".into())),
        lent(b"the lent bytes"),
    );
    let (routed, _) = run_on(&home, &serving, &serving, called, &ECHO, Some(rewrite)).await;
    let why = refused(routed);
    assert!(
        why.contains("another call"),
        "the refusal must say the receipt describes another call: {why}"
    );
}

#[tokio::test]
async fn a_report_the_json_writer_cannot_render_keeps_the_signed_receipt() {
    let home = home();
    let serving = home.enrol(0x51);
    // The serving node returns one output and a report with a nil map key,
    // and signs that report as its word.
    let rewrite = resigned(&serving, |done, _| {
        *entry_mut(done, "report").expect("the outcome holds its report") =
            Value::Map(vec![(Value::Nil, "a nil key".into())]);
    });
    let called = (outputs_call(1, 16), Vec::new());
    let (routed, _) = run_on(&home, &serving, &serving, called, &ECHO, Some(rewrite)).await;
    let outcome = match routed {
        Ok(Routed::Done { outcome, .. }) => outcome,
        Ok(Routed::Waiting(wait)) => panic!("the call waits: {}", wait.reason),
        Err(err) => panic!("the call fails: {err}"),
    };
    let native = outcome.native_outputs("run", None);
    assert_eq!(native.len(), 1, "the call made one output");
    let stored = &native[0].report;
    assert!(
        stored.starts_with(r#"{"report":null,"receipt":{"#),
        "the report the writer cannot render is null beside the receipt: {stored}"
    );
    let signed = format!(r#""signed_by":{{"machine":"{}""#, serving.machine.to_hex());
    assert!(
        stored.contains(&signed),
        "the proposal must keep the serving machine's signed receipt: {stored}"
    );
}

#[tokio::test]
async fn a_staged_result_that_does_not_come_is_not_run_again() {
    let home = home();
    let serving = home.enrol(0x51);
    // The big answer rides in the probe's report, so the serving node
    // stages the result; then it refuses the result's pieces.
    let called = (ask_call(Value::String("a small ask".into())), Vec::new());
    let (routed, _) = run_on(
        &home,
        &serving,
        &serving,
        called,
        &BIG_ANSWER,
        Some(refuse_pieces()),
    )
    .await;
    not_fetched(routed, &serving);
}

#[tokio::test]
async fn a_staged_output_that_does_not_come_is_not_run_again() {
    let home = home();
    let serving = home.enrol(0x51);
    let called = (outputs_call(1, STAGED_OUTPUT_BYTES), Vec::new());
    let (routed, _) = run_on(
        &home,
        &serving,
        &serving,
        called,
        &ECHO,
        Some(refuse_pieces()),
    )
    .await;
    not_fetched(routed, &serving);
}
