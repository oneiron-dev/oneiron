//! Private iroh data plane. `Minimal` has no public lookup; relay is disabled
//! unless the caller supplies an explicit private relay map. A transport bound
//! for pairing leaves a path receipt for every connection, direct or relayed,
//! and for every refused or failed attempt ([`PathRecorder`]).

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex, PoisonError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_util::stream::{self, StreamExt};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey,
    address_lookup::{AddressLookup, EndpointInfo, Error as LookupError, Item},
    endpoint::{Accepting, Connection, Incoming, PathEvent, presets},
    protocol::AcceptError,
};
use n0_future::{boxed::BoxStream, task::AbortOnDropHandle};
use tokio::task::JoinSet;

use crate::{
    AcceptPolicy, MachineId, MachineRoster, MeshConnection, MeshError, MeshFuture,
    MeshPathDirection, MeshPathKind, MeshPathOutcome, MeshPathReceipt, MeshTransport, PathReceipts,
    transport_key::TransportKey,
};

// Fair dispatch of authenticated admissions, and their receipts (FIX 8620, 8621).
mod admission;
// An admitted connection and its policy-checked streams.
mod connection;
mod dial;
mod outbound;

use connection::IrohConnection;
pub use dial::{OwnerMachineLookup, owner_machine_lookup};

/// How long the refused or failed attempts from one machine, or from keys no
/// MACHINE names, fold into one path receipt.
const REFUSAL_RECEIPT_WINDOW: Duration = Duration::from_secs(60);

/// Whose refusals fold together: the direction (inbound or not) and the
/// machine the roster named, if any.
type RefusalKey = (bool, Option<MachineId>);

/// Refusals folded since each machine's last refusal receipt: when that
/// receipt was written, and the newest refusal since, counting them all, for
/// the window's end to write.
type RefusalTally = BTreeMap<RefusalKey, (Instant, Option<MeshPathReceipt>)>;

/// Leaves one transport's path receipts: a row per admitted connection,
/// written when it opens and again when it closes, and the refused or failed
/// attempts, folded per machine a window.
#[derive(Debug, Clone)]
struct PathRecorder {
    sink: Arc<dyn PathReceipts>,
    refusals: Arc<StdMutex<RefusalTally>>,
    unattributed: Arc<dial::Unattributed>,
}

impl PathRecorder {
    fn new(sink: Arc<dyn PathReceipts>) -> Self {
        Self {
            sink,
            refusals: Arc::default(),
            unattributed: Arc::default(),
        }
    }

    /// Writes `receipt` for a refused or failed attempt from `machine`,
    /// unless that machine's refusals already left a receipt this window:
    /// then the attempt counts toward the one the window's end writes.
    fn refused(
        &self,
        mut receipt: MeshPathReceipt,
        machine: Option<MachineId>,
        connection: Option<&Connection>,
    ) {
        let key = (receipt.direction == MeshPathDirection::Inbound, machine);
        receipt.machine = machine.map(|machine| machine.to_hex());
        if let Some(connection) = connection {
            note_open_paths(&mut receipt, connection);
        }
        let now = Instant::now();
        {
            let mut tally = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
            match tally.get_mut(&key) {
                Some((since, folded)) if now.duration_since(*since) < REFUSAL_RECEIPT_WINDOW => {
                    receipt.attempts += folded.as_ref().map_or(0, |prior| prior.attempts);
                    // The first refusal folded into a window arms its end.
                    if folded.replace(receipt).is_none() {
                        self.flush_at(key, *since);
                    }
                    return;
                }
                Some((since, folded)) => {
                    receipt.attempts += folded.take().map_or(0, |prior| prior.attempts);
                    *since = now;
                }
                None => {
                    tally.insert(key, (now, None));
                }
            }
        }
        let sink = Arc::clone(&self.sink);
        drop(tokio::task::spawn_blocking(move || sink.record(&receipt)));
    }

    /// Writes the refusals folded into `key`'s window from `since` when it
    /// ends, unless a later refusal's receipt counted them first. It holds
    /// the sink until then, so a transport dropped without
    /// [`IrohTransport::shutdown`] still leaves them, and its vault stays
    /// open until that window ([`REFUSAL_RECEIPT_WINDOW`]) ends; `shutdown`
    /// writes them itself.
    fn flush_at(&self, key: RefusalKey, since: Instant) {
        let refusals = Arc::clone(&self.refusals);
        let sink = Arc::clone(&self.sink);
        tokio::spawn(async move {
            tokio::time::sleep_until((since + REFUSAL_RECEIPT_WINDOW).into()).await;
            let folded = match refusals
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_mut(&key)
            {
                // The receipt it writes opens the machine's next window.
                Some((at, folded)) if *at == since => {
                    *at = Instant::now();
                    folded.take()
                }
                _ => None,
            };
            if let Some(receipt) = folded {
                write_receipt(&sink, &receipt).await;
            }
        });
    }

    /// Writes every machine's folded refusals now, as their windows' ends
    /// would.
    async fn flush(&self) {
        let folded: Vec<MeshPathReceipt> = self
            .refusals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values_mut()
            .filter_map(|(_, folded)| folded.take())
            .collect();
        for receipt in &folded {
            write_receipt(&self.sink, receipt).await;
        }
    }

    /// Leaves the receipt of an inbound attempt on `alpn` that ended before
    /// its handshake proved a key, folded with the others from keys no
    /// MACHINE names.
    fn unproven(&self, outcome: MeshPathOutcome, alpn: &[u8], error: &MeshError) {
        let receipt = attempt(MeshPathDirection::Inbound, outcome, alpn, None, error);
        self.refused(receipt, None, None);
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
    oneiron_hex::encode(&key)
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
    admissions: Arc<admission::Admissions>,
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
    async fn on_accepting(&self, accepting: Accepting) -> Result<Connection, AcceptError> {
        // Await the authenticated TLS identity before permitting any application streams.
        // Never use 0-RTT/0.5-RTT: grants must be checked before data is served.
        let connection = match accepting.await {
            Ok(connection) => connection,
            Err(error) => {
                if let Some(receipts) = &self.receipts {
                    let failure = MeshError::Io(error.to_string());
                    receipts.unproven(MeshPathOutcome::Failed, &self.alpn, &failure);
                }
                return Err(error.into());
            }
        };
        let key = *connection.remote_id().as_bytes();
        if let Err(error) = self.policy.inbound(key, &self.alpn) {
            self.refused(&connection, key, &error);
            return Err(n0_error::e!(AcceptError::NotAllowed));
        }
        Ok(connection)
    }
}

/// Takes each inbound attempt on `endpoint` to the gate for its ALPN, as
/// iroh's router does, until the endpoint closes. Unlike the router, it
/// leaves a receipt for an attempt that fails before a gate sees it. The
/// queue of admissions closes as it ends (`_closing`).
async fn accept_loop(
    endpoint: Endpoint,
    gates: Arc<BTreeMap<Vec<u8>, GateHandler>>,
    receipts: Option<PathRecorder>,
    _closing: admission::Closing,
) {
    let mut attempts = JoinSet::new();
    while let Some(incoming) = endpoint.accept().await {
        attempts.spawn(gate_attempt(incoming, Arc::clone(&gates), receipts.clone()));
        while attempts.try_join_next().is_some() {}
    }
}

/// One inbound attempt: its handshake as far as the ALPN, then the gate for
/// that ALPN. No key is proven before the gate, so a receipt left here names
/// none.
async fn gate_attempt(
    incoming: Incoming,
    gates: Arc<BTreeMap<Vec<u8>, GateHandler>>,
    receipts: Option<PathRecorder>,
) {
    let failed = |error: String| {
        if let Some(receipts) = &receipts {
            receipts.unproven(MeshPathOutcome::Failed, &[], &MeshError::Io(error));
        }
    };
    let mut accepting = match incoming.accept() {
        Ok(accepting) => accepting,
        Err(error) => return failed(error.to_string()),
    };
    // A TLS or ALPN failure ends the handshake here.
    let alpn = match accepting.alpn().await {
        Ok(alpn) => alpn,
        Err(error) => return failed(error.to_string()),
    };
    let Some(gate) = gates.get(&alpn) else {
        if let Some(receipts) = &receipts {
            receipts.unproven(MeshPathOutcome::Refused, &alpn, &MeshError::Refused);
        }
        return;
    };
    // A gate's own refusal or failure left its receipt, and its admission
    // leaves one on every exit after its proof (FIX 8621).
    if let Ok(connection) = gate.on_accepting(accepting).await {
        gate.admit(connection).await;
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

/// Bound endpoint and accept loop. The supplied secret is the pairing-derived
/// transport key; generating or persisting it is deliberately outside this slice.
#[derive(Debug)]
pub struct IrohTransport {
    endpoint: Endpoint,
    /// The accept loop; dropping the transport stops it.
    accepting: AbortOnDropHandle<()>,
    policy: AcceptPolicy,
    allowed_relays: RelayMap,
    admissions: Arc<admission::Admissions>,
    /// The protocols this endpoint serves, and so dials.
    alpns: Vec<Vec<u8>>,
    /// The protocols this endpoint dials but does not serve
    /// ([`Self::dialing`]).
    dial_only_alpns: Vec<Vec<u8>>,
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
        Self::bind_with(
            secret,
            policy,
            alpns,
            bind_addr,
            private_relays,
            None,
            false,
        )
        .await
    }
    async fn bind_with(
        secret: SecretKey,
        policy: AcceptPolicy,
        alpns: Vec<Vec<u8>>,
        bind_addr: SocketAddr,
        private_relays: Option<RelayMap>,
        receipts: Option<PathRecorder>,
        outbound_only: bool,
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
                allowed_relays: allowed_relays.clone(),
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
        let admissions = Arc::new(admission::Admissions::default());
        let gates = alpns
            .iter()
            .map(|alpn| {
                let gate = GateHandler {
                    policy: policy.clone(),
                    alpn: alpn.clone(),
                    admissions: Arc::clone(&admissions),
                    receipts: receipts.clone(),
                };
                (alpn.clone(), gate)
            })
            .collect();
        endpoint.set_alpns(if outbound_only {
            Vec::new()
        } else {
            alpns.clone()
        });
        let accepting = tokio::spawn(accept_loop(
            endpoint.clone(),
            Arc::new(gates),
            receipts.clone(),
            admission::Closing(Arc::clone(&admissions)),
        ));
        Ok(Self {
            endpoint,
            accepting: AbortOnDropHandle::new(accepting),
            policy,
            allowed_relays,
            admissions,
            alpns,
            dial_only_alpns: Vec::new(),
            receipts,
        })
    }
    /// This endpoint dials each of `alpns` as well, whether or not it serves
    /// it: a machine that offers no job protocol still dials the execution
    /// nodes that do. The handshake offers inbound only the protocols the
    /// endpoint serves, and every dial still passes the live grant check.
    #[must_use]
    pub fn dialing(mut self, alpns: impl IntoIterator<Item = Vec<u8>>) -> Self {
        for alpn in alpns {
            if !alpn.is_empty() && !self.dials(&alpn) {
                self.dial_only_alpns.push(alpn);
            }
        }
        self
    }
    /// Whether this endpoint dials `alpn`: one it serves, or one
    /// [`Self::dialing`] added.
    fn dials(&self, alpn: &[u8]) -> bool {
        self.alpns
            .iter()
            .chain(&self.dial_only_alpns)
            .any(|known| known.as_slice() == alpn)
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
            false,
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
        *self.endpoint.id().as_bytes()
    }
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }
    /// Stops accepting and closes the endpoint, then writes the refusals
    /// still folded into a window.
    pub async fn shutdown(&self) -> Result<(), MeshError> {
        self.admissions.close();
        self.accepting.abort();
        self.endpoint.close().await;
        if let Some(receipts) = &self.receipts {
            receipts.flush().await;
        }
        Ok(())
    }
}
