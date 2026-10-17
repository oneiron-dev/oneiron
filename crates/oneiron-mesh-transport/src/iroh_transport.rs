//! Private iroh data plane. `Minimal` has no public lookup; relay is disabled
//! unless the caller supplies an explicit private relay map. A transport bound
//! for pairing leaves a path receipt for every connection, direct or relayed,
//! and for every refused or failed attempt ([`PathRecorder`]).

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex, PoisonError},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_util::stream::{self, StreamExt};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey,
    address_lookup::{AddressLookup, EndpointInfo, Error as LookupError, Item},
    endpoint::{Accepting, Connection, PathEvent, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_future::boxed::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, mpsc};

use crate::{
    AcceptPolicy, MachineId, MachineRoster, MeshConnection, MeshDuplex, MeshError, MeshFuture,
    MeshPathDirection, MeshPathKind, MeshPathOutcome, MeshPathReceipt, MeshStream, MeshTransport,
    PathReceipts, transport_key::TransportKey,
};

const MAX_MESSAGE: usize = 1024 * 1024;

/// How long the refused or failed attempts from one machine, or from keys no
/// MACHINE names, fold into one path receipt.
const REFUSAL_RECEIPT_WINDOW: Duration = Duration::from_secs(60);

/// Refusals folded since each machine's last refusal receipt, by direction
/// (inbound or not) and the machine the roster named, if any: when that
/// receipt was written and how many came since.
type RefusalTally = BTreeMap<(bool, Option<MachineId>), (Instant, u64)>;

/// Leaves one transport's path receipts: a row per admitted connection,
/// written when it opens and again when it closes, and the refused or failed
/// attempts, folded per machine a window.
#[derive(Debug, Clone)]
struct PathRecorder {
    sink: Arc<dyn PathReceipts>,
    refusals: Arc<StdMutex<RefusalTally>>,
}

impl PathRecorder {
    fn new(sink: Arc<dyn PathReceipts>) -> Self {
        Self {
            sink,
            refusals: Arc::default(),
        }
    }

    /// Writes `receipt` for a refused or failed attempt from `machine`,
    /// unless that machine's refusals already left a receipt this window:
    /// then the attempt only counts toward its next one.
    fn refused(
        &self,
        mut receipt: MeshPathReceipt,
        machine: Option<MachineId>,
        connection: Option<&Connection>,
    ) {
        let key = (receipt.direction == MeshPathDirection::Inbound, machine);
        let now = Instant::now();
        {
            let mut tally = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
            match tally.get_mut(&key) {
                Some((since, folded)) if now.duration_since(*since) < REFUSAL_RECEIPT_WINDOW => {
                    *folded += 1;
                    return;
                }
                Some((since, folded)) => {
                    receipt.attempts = *folded + 1;
                    *since = now;
                    *folded = 0;
                }
                None => {
                    tally.insert(key, (now, 0));
                }
            }
        }
        receipt.machine = machine.map(|machine| machine.to_hex());
        if let Some(connection) = connection {
            note_open_paths(&mut receipt, connection);
        }
        let sink = Arc::clone(&self.sink);
        drop(tokio::task::spawn_blocking(move || sink.record(&receipt)));
    }

    /// Writes `receipt` for a connection admitted now, and again once it
    /// closes, with the paths that carried its data meanwhile.
    fn admitted(&self, mut receipt: MeshPathReceipt, connection: &Connection) {
        note_open_paths(&mut receipt, connection);
        let mut events = connection.path_events();
        // Taken while this handle lives, so the close always reaches it.
        let closing = connection.weak_handle().closed();
        let sink = Arc::clone(&self.sink);
        tokio::spawn(async move {
            receipt.id = write_receipt(&sink, &receipt).await.unwrap_or_default();
            tokio::pin!(closing);
            let closed = loop {
                tokio::select! {
                    closed = &mut closing => break closed,
                    event = events.next() => match event {
                        Some(PathEvent::Selected { remote_addr, .. }) => {
                            note_used_path(&mut receipt, &remote_addr);
                        }
                        Some(_) => {}
                        None => break (&mut closing).await,
                    },
                }
            };
            receipt.closed_at_ms = Some(unix_millis());
            receipt.detail = closed.map(|closed| closed.reason.to_string());
            write_receipt(&sink, &receipt).await;
        });
    }
}

/// Writes `receipt` on a blocking thread: its id, or `None` when it did not
/// land.
async fn write_receipt(sink: &Arc<dyn PathReceipts>, receipt: &MeshPathReceipt) -> Option<String> {
    let sink = Arc::clone(sink);
    let receipt = receipt.clone();
    tokio::task::spawn_blocking(move || sink.record(&receipt))
        .await
        .ok()
        .flatten()
}

/// Notes which paths `connection` has open, and the one carrying its data.
fn note_open_paths(receipt: &mut MeshPathReceipt, connection: &Connection) {
    let (mut direct, mut relay) = (false, false);
    for path in connection.paths().iter() {
        direct |= path.is_ip();
        relay |= path.is_relay();
        if path.is_selected() {
            note_used_path(receipt, path.remote_addr());
        }
    }
    receipt.paths = match (direct, relay) {
        (true, true) => MeshPathKind::Mixed,
        (true, false) => MeshPathKind::Direct,
        (false, true) => MeshPathKind::Relayed,
        (false, false) => MeshPathKind::None,
    };
}

/// Notes that the path at `addr` carried the connection's data.
fn note_used_path(receipt: &mut MeshPathReceipt, addr: &iroh::TransportAddr) {
    match addr {
        iroh::TransportAddr::Ip(addr) => {
            receipt.used_direct = true;
            receipt.direct_addr = Some(addr.to_string());
        }
        iroh::TransportAddr::Relay(url) => {
            receipt.used_relay = true;
            receipt.relay_url = Some(url.to_string());
        }
        _ => {}
    }
}

/// A receipt for an attempt with `key` that `error` refused or failed.
fn attempt(
    direction: MeshPathDirection,
    outcome: MeshPathOutcome,
    alpn: &[u8],
    key: Option<[u8; 32]>,
    error: &MeshError,
) -> MeshPathReceipt {
    let mut receipt = MeshPathReceipt::new(direction, outcome, alpn);
    receipt.endpoint_key = key.map(key_hex);
    receipt.detail = Some(error.to_string());
    receipt
}

/// A receipt for a connection to `machine` at `key`, admitted now.
fn admission(
    direction: MeshPathDirection,
    alpn: &[u8],
    machine: MachineId,
    key: [u8; 32],
) -> MeshPathReceipt {
    let mut receipt = MeshPathReceipt::new(direction, MeshPathOutcome::Admitted, alpn);
    receipt.machine = Some(machine.to_hex());
    receipt.endpoint_key = Some(key_hex(key));
    receipt
}

fn key_hex(key: [u8; 32]) -> String {
    use std::fmt::Write;
    key.iter().fold(String::with_capacity(64), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

#[derive(Debug, Clone)]
struct RosterLookup {
    roster: Arc<dyn MachineRoster>,
    allowed_relays: RelayMap,
}
impl AddressLookup for RosterLookup {
    // Intentionally no publish: never disclose membership to public DNS/pkarr.
    fn resolve(&self, id: EndpointId) -> Option<BoxStream<Result<Item, LookupError>>> {
        let result = self
            .roster
            .by_endpoint(*id.as_bytes())
            .and_then(|match_| {
                let (_, row) = match_.ok_or(MeshError::Refused)?;
                let mut addr = EndpointAddr::from_parts(
                    id,
                    row.direct_addrs.into_iter().map(iroh::TransportAddr::Ip),
                );
                if let Some(raw) = row.relay_url {
                    let relay: iroh::RelayUrl =
                        raw.parse().map_err(|_| MeshError::InvalidRoster)?;
                    if !self.allowed_relays.contains(&relay) {
                        return Err(MeshError::Refused);
                    }
                    addr = addr.with_relay_url(relay);
                }
                Ok(Item::new(EndpointInfo::from(addr), "machine_roster", None))
            })
            .map_err(|e| LookupError::from_err("machine_roster", e));
        Some(stream::once(async move { result }).boxed())
    }
}

#[derive(Debug, Clone)]
struct GateHandler {
    policy: AcceptPolicy,
    alpn: Vec<u8>,
    accepted: mpsc::Sender<(MachineId, Vec<u8>, Connection)>,
    receipts: Option<PathRecorder>,
}
impl GateHandler {
    /// Leaves the receipt of an inbound attempt `error` refused, folded with
    /// the refusals of the machine the roster names for `key`.
    fn refused(&self, connection: &Connection, key: [u8; 32], error: &MeshError) {
        let Some(receipts) = &self.receipts else {
            return;
        };
        let machine = self
            .policy
            .roster
            .by_endpoint(key)
            .ok()
            .flatten()
            .map(|(machine, _)| machine);
        let receipt = attempt(
            MeshPathDirection::Inbound,
            MeshPathOutcome::Refused,
            &self.alpn,
            Some(key),
            error,
        );
        receipts.refused(receipt, machine, Some(connection));
    }
}
impl ProtocolHandler for GateHandler {
    async fn on_accepting(&self, accepting: Accepting) -> Result<Connection, AcceptError> {
        // Await the authenticated TLS identity before permitting any application streams.
        // Never use 0-RTT/0.5-RTT: grants must be checked before data is served.
        let connection = accepting.await?;
        let key = *connection.remote_id().as_bytes();
        if let Err(error) = self.policy.inbound(key, &self.alpn) {
            self.refused(&connection, key, &error);
            return Err(n0_error::e!(AcceptError::NotAllowed));
        }
        Ok(connection)
    }
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // Recheck: revocation can race the completed handshake before dispatch.
        let key = *connection.remote_id().as_bytes();
        let machine = match self.policy.inbound(key, &self.alpn) {
            Ok(machine) => machine,
            Err(error) => {
                self.refused(&connection, key, &error);
                return Err(n0_error::e!(AcceptError::NotAllowed));
            }
        };
        if let Some(receipts) = &self.receipts {
            let receipt = admission(MeshPathDirection::Inbound, &self.alpn, machine, key);
            receipts.admitted(receipt, &connection);
        }
        self.accepted
            .send((machine, self.alpn.clone(), connection))
            .await
            .map_err(AcceptError::from_err)
    }
}

/// The private relays a configuration names, as the map [`IrohTransport::bind`]
/// takes; no URL is no relay. A URL that does not parse is refused, never
/// dropped.
pub fn private_relay_map(urls: &[String]) -> Result<Option<RelayMap>, MeshError> {
    if urls.is_empty() {
        return Ok(None);
    }
    let urls = urls
        .iter()
        .map(|url| url.parse::<iroh::RelayUrl>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| MeshError::InvalidRoster)?;
    Ok(Some(urls.into_iter().collect()))
}

/// Bound endpoint and ALPN router. The supplied secret is the pairing-derived
/// transport key; generating or persisting it is deliberately outside this slice.
#[derive(Debug)]
pub struct IrohTransport {
    router: Router,
    policy: AcceptPolicy,
    accepted: Mutex<mpsc::Receiver<(MachineId, Vec<u8>, Connection)>>,
    alpns: Vec<Vec<u8>>,
    receipts: Option<PathRecorder>,
}
impl IrohTransport {
    /// Bind only an explicitly supplied address and optional private relay map.
    /// A `None` relay map means direct-only (including all conformance tests).
    /// It leaves no path receipts.
    pub async fn bind(
        secret: SecretKey,
        policy: AcceptPolicy,
        alpns: Vec<Vec<u8>>,
        bind_addr: SocketAddr,
        private_relays: Option<RelayMap>,
    ) -> Result<Self, MeshError> {
        Self::bind_with(secret, policy, alpns, bind_addr, private_relays, None).await
    }
    async fn bind_with(
        secret: SecretKey,
        policy: AcceptPolicy,
        alpns: Vec<Vec<u8>>,
        bind_addr: SocketAddr,
        private_relays: Option<RelayMap>,
        receipts: Option<PathRecorder>,
    ) -> Result<Self, MeshError> {
        if alpns.is_empty() || alpns.iter().any(Vec::is_empty) {
            return Err(MeshError::Unavailable);
        }
        let allowed_relays = private_relays.unwrap_or_else(RelayMap::empty);
        let relay_mode = if allowed_relays.is_empty() {
            RelayMode::Disabled
        } else {
            RelayMode::Custom(allowed_relays.clone())
        };
        let mut builder = Endpoint::builder(presets::Minimal)
            .clear_ip_transports() // never leave the default wildcard IPv6 socket behind
            .clear_address_lookup()
            .address_lookup(RosterLookup {
                roster: Arc::clone(&policy.roster),
                allowed_relays,
            })
            .relay_mode(relay_mode)
            .secret_key(secret)
            .bind_addr(bind_addr)
            .map_err(|e| MeshError::Io(e.to_string()))?;
        if bind_addr.ip().is_loopback() {
            builder = builder
                .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
                .net_report_config(iroh::NetReportConfig::minimal());
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| MeshError::Io(e.to_string()))?;
        let (tx, rx) = mpsc::channel(64);
        let mut builder = Router::builder(endpoint);
        for alpn in &alpns {
            builder = builder.accept(
                alpn,
                GateHandler {
                    policy: policy.clone(),
                    alpn: alpn.clone(),
                    accepted: tx.clone(),
                    receipts: receipts.clone(),
                },
            );
        }
        Ok(Self {
            router: builder.spawn(),
            policy,
            accepted: Mutex::new(rx),
            alpns,
            receipts,
        })
    }
    /// Production pairing door: the device key derives the transport signer,
    /// and every connection and refused attempt leaves a path receipt in
    /// `receipts`.
    pub async fn bind_paired(
        key: TransportKey,
        policy: AcceptPolicy,
        alpns: Vec<Vec<u8>>,
        bind_addr: SocketAddr,
        private_relays: Option<RelayMap>,
        receipts: Arc<dyn PathReceipts>,
    ) -> Result<Self, MeshError> {
        Self::bind_with(
            key.into_iroh_secret(),
            policy,
            alpns,
            bind_addr,
            private_relays,
            Some(PathRecorder::new(receipts)),
        )
        .await
    }
    /// Leaves the receipt of a dial to `machine` that was refused or failed.
    fn dial_refused(
        &self,
        machine: MachineId,
        receipt: MeshPathReceipt,
        connection: Option<&Connection>,
    ) {
        if let Some(receipts) = &self.receipts {
            receipts.refused(receipt, Some(machine), connection);
        }
    }
    pub fn id(&self) -> [u8; 32] {
        *self.router.endpoint().id().as_bytes()
    }
    pub fn addr(&self) -> EndpointAddr {
        self.router.endpoint().addr()
    }
    pub async fn shutdown(&self) -> Result<(), MeshError> {
        self.router
            .shutdown()
            .await
            .map_err(|e| MeshError::Io(e.to_string()))
    }
}
impl MeshTransport for IrohTransport {
    fn dial(&self, machine: MachineId, alpn: &[u8]) -> MeshFuture<'_, Box<dyn MeshConnection>> {
        let alpn = alpn.to_vec();
        Box::pin(async move {
            if !self.alpns.contains(&alpn) {
                return Err(MeshError::Refused);
            }
            let row = match self.policy.outbound(machine, &alpn) {
                Ok(row) => row,
                Err(error) => {
                    let receipt = attempt(
                        MeshPathDirection::Outbound,
                        MeshPathOutcome::Refused,
                        &alpn,
                        None,
                        &error,
                    );
                    self.dial_refused(machine, receipt, None);
                    return Err(error);
                }
            };
            let key =
                EndpointId::from_bytes(&row.endpoint_key).map_err(|_| MeshError::InvalidRoster)?;
            // Key only: addresses must be resolved by our private roster lookup.
            let connection = match self
                .router
                .endpoint()
                .connect(EndpointAddr::new(key), &alpn)
                .await
            {
                Ok(connection) => connection,
                Err(error) => {
                    let error = MeshError::Io(error.to_string());
                    let receipt = attempt(
                        MeshPathDirection::Outbound,
                        MeshPathOutcome::Failed,
                        &alpn,
                        Some(row.endpoint_key),
                        &error,
                    );
                    self.dial_refused(machine, receipt, None);
                    return Err(error);
                }
            };
            if connection.remote_id() != key {
                let receipt = attempt(
                    MeshPathDirection::Outbound,
                    MeshPathOutcome::Refused,
                    &alpn,
                    Some(*connection.remote_id().as_bytes()),
                    &MeshError::Refused,
                );
                self.dial_refused(machine, receipt, Some(&connection));
                return Err(MeshError::Refused);
            }
            let admitted = IrohConnection {
                machine,
                alpn,
                inner: connection,
                policy: self.policy.clone(),
                incoming: false,
            };
            if let Err(error) = admitted.check() {
                let receipt = attempt(
                    MeshPathDirection::Outbound,
                    MeshPathOutcome::Refused,
                    &admitted.alpn,
                    Some(row.endpoint_key),
                    &error,
                );
                self.dial_refused(machine, receipt, Some(&admitted.inner));
                return Err(error);
            }
            if let Some(receipts) = &self.receipts {
                let receipt = admission(
                    MeshPathDirection::Outbound,
                    &admitted.alpn,
                    machine,
                    row.endpoint_key,
                );
                receipts.admitted(receipt, &admitted.inner);
            }
            Ok(Box::new(admitted) as Box<dyn MeshConnection>)
        })
    }
    fn accept(&self) -> MeshFuture<'_, Box<dyn MeshConnection>> {
        Box::pin(async move {
            let (machine, alpn, inner) = self
                .accepted
                .lock()
                .await
                .recv()
                .await
                .ok_or(MeshError::Unavailable)?;
            let admitted = IrohConnection {
                machine,
                alpn,
                inner,
                policy: self.policy.clone(),
                incoming: true,
            };
            // A queued connection does not outlive a grant revoke.
            admitted.check()?;
            Ok(Box::new(admitted) as Box<dyn MeshConnection>)
        })
    }
}

#[derive(Debug)]
struct IrohConnection {
    machine: MachineId,
    alpn: Vec<u8>,
    inner: Connection,
    policy: AcceptPolicy,
    incoming: bool,
}
impl IrohConnection {
    fn check(&self) -> Result<(), MeshError> {
        let key = *self.inner.remote_id().as_bytes();
        if self.incoming {
            if self.policy.inbound(key, &self.alpn)? != self.machine {
                return Err(MeshError::Refused);
            }
        } else if self.policy.outbound(self.machine, &self.alpn)?.endpoint_key != key {
            return Err(MeshError::Refused);
        }
        Ok(())
    }
}
impl MeshConnection for IrohConnection {
    fn machine(&self) -> MachineId {
        self.machine
    }
    fn alpn(&self) -> &[u8] {
        &self.alpn
    }
    fn open_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async move {
            self.check()?;
            let (send, recv) = self
                .inner
                .open_bi()
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.check()?;
            Ok(Box::new(IrohStream {
                send,
                recv,
                grant: StreamGrant {
                    policy: self.policy.clone(),
                    machine: self.machine,
                    alpn: self.alpn.clone(),
                    endpoint_key: *self.inner.remote_id().as_bytes(),
                    incoming: self.incoming,
                },
            }) as Box<dyn MeshStream>)
        })
    }
    fn accept_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async move {
            self.check()?;
            let (send, recv) = self
                .inner
                .accept_bi()
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.check()?;
            Ok(Box::new(IrohStream {
                send,
                recv,
                grant: StreamGrant {
                    policy: self.policy.clone(),
                    machine: self.machine,
                    alpn: self.alpn.clone(),
                    endpoint_key: *self.inner.remote_id().as_bytes(),
                    incoming: self.incoming,
                },
            }) as Box<dyn MeshStream>)
        })
    }
    fn endpoint_key(&self) -> [u8; 32] {
        *self.inner.remote_id().as_bytes()
    }
    fn open_duplex(&self) -> MeshFuture<'_, Box<dyn MeshDuplex>> {
        Box::pin(async move {
            self.check()?;
            let (send, recv) = self
                .inner
                .open_bi()
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.check()?;
            Ok(Box::new(IrohDuplex {
                send,
                recv,
                _connection: self.inner.clone(),
            }) as Box<dyn MeshDuplex>)
        })
    }
    fn accept_duplex(&self) -> MeshFuture<'_, Box<dyn MeshDuplex>> {
        Box::pin(async move {
            self.check()?;
            let (send, recv) = self
                .inner
                .accept_bi()
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.check()?;
            Ok(Box::new(IrohDuplex {
                send,
                recv,
                _connection: self.inner.clone(),
            }) as Box<dyn MeshDuplex>)
        })
    }
    fn close(&self) {
        self.inner.close(0u32.into(), b"closed");
    }
}

/// One bidirectional QUIC stream as a byte pipe. It keeps a handle to its
/// connection: the last handle dropped closes the connection.
struct IrohDuplex {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    _connection: Connection,
}
impl AsyncRead for IrohDuplex {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}
impl AsyncWrite for IrohDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}
#[derive(Debug)]
struct StreamGrant {
    policy: AcceptPolicy,
    machine: MachineId,
    alpn: Vec<u8>,
    endpoint_key: [u8; 32],
    incoming: bool,
}
impl StreamGrant {
    fn check(&self) -> Result<(), MeshError> {
        if self.incoming {
            if self.policy.inbound(self.endpoint_key, &self.alpn)? != self.machine {
                return Err(MeshError::Refused);
            }
        } else if self.policy.outbound(self.machine, &self.alpn)?.endpoint_key != self.endpoint_key
        {
            return Err(MeshError::Refused);
        }
        Ok(())
    }
}
struct IrohStream {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    grant: StreamGrant,
}
impl MeshStream for IrohStream {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> MeshFuture<'a, ()> {
        Box::pin(async move {
            self.grant.check()?;
            if bytes.len() > MAX_MESSAGE {
                return Err(MeshError::Unavailable);
            }
            self.send
                .write_all(bytes)
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.send
                .finish()
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.grant.check()
        })
    }
    fn recv(&mut self) -> MeshFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.grant.check()?;
            let bytes = self
                .recv
                .read_to_end(MAX_MESSAGE)
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.grant.check()?;
            Ok(bytes)
        })
    }
}
