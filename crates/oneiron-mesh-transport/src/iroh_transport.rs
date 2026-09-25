//! Private iroh data plane. `Minimal` has no public lookup; relay is disabled
//! unless the caller supplies an explicit private relay map.

use std::{net::SocketAddr, sync::Arc};

use futures_util::stream::{self, StreamExt};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey,
    address_lookup::{AddressLookup, EndpointInfo, Error as LookupError, Item},
    endpoint::{Accepting, Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_future::boxed::BoxStream;
use tokio::sync::{Mutex, mpsc};

use crate::{
    AcceptPolicy, MachineId, MachineRoster, MeshConnection, MeshError, MeshFuture, MeshStream,
    MeshTransport,
};

const MAX_MESSAGE: usize = 1024 * 1024;

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
}
impl ProtocolHandler for GateHandler {
    async fn on_accepting(&self, accepting: Accepting) -> Result<Connection, AcceptError> {
        // Await the authenticated TLS identity before permitting any application streams.
        // Never use 0-RTT/0.5-RTT: grants must be checked before data is served.
        let connection = accepting.await?;
        self.policy
            .inbound(*connection.remote_id().as_bytes(), &self.alpn)
            .map_err(|_| n0_error::e!(AcceptError::NotAllowed))?;
        Ok(connection)
    }
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // Recheck: revocation can race the completed handshake before dispatch.
        let machine = self
            .policy
            .inbound(*connection.remote_id().as_bytes(), &self.alpn)
            .map_err(|_| n0_error::e!(AcceptError::NotAllowed))?;
        self.accepted
            .send((machine, self.alpn.clone(), connection))
            .await
            .map_err(AcceptError::from_err)
    }
}

/// Bound endpoint and ALPN router. The supplied secret is the pairing-derived
/// transport key; generating or persisting it is deliberately outside this slice.
#[derive(Debug)]
pub struct IrohTransport {
    router: Router,
    policy: AcceptPolicy,
    accepted: Mutex<mpsc::Receiver<(MachineId, Vec<u8>, Connection)>>,
    alpns: Vec<Vec<u8>>,
}
impl IrohTransport {
    /// Bind only an explicitly supplied address and optional private relay map.
    /// A `None` relay map means direct-only (including all conformance tests).
    pub async fn bind(
        secret: SecretKey,
        policy: AcceptPolicy,
        alpns: Vec<Vec<u8>>,
        bind_addr: SocketAddr,
        private_relays: Option<RelayMap>,
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
                },
            );
        }
        Ok(Self {
            router: builder.spawn(),
            policy,
            accepted: Mutex::new(rx),
            alpns,
        })
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
            let row = self.policy.outbound(machine, &alpn)?;
            let key =
                EndpointId::from_bytes(&row.endpoint_key).map_err(|_| MeshError::InvalidRoster)?;
            // Key only: addresses must be resolved by our private roster lookup.
            let connection = self
                .router
                .endpoint()
                .connect(EndpointAddr::new(key), &alpn)
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            if connection.remote_id() != key {
                return Err(MeshError::Refused);
            }
            let admitted = IrohConnection {
                machine,
                alpn,
                inner: connection,
                policy: self.policy.clone(),
                incoming: false,
            };
            admitted.check()?;
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
            Ok(Box::new(IrohStream { send, recv }) as Box<dyn MeshStream>)
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
            Ok(Box::new(IrohStream { send, recv }) as Box<dyn MeshStream>)
        })
    }
    fn close(&self) {
        self.inner.close(0u32.into(), b"closed");
    }
}
struct IrohStream {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}
impl MeshStream for IrohStream {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> MeshFuture<'a, ()> {
        Box::pin(async move {
            if bytes.len() > MAX_MESSAGE {
                return Err(MeshError::Unavailable);
            }
            self.send
                .write_all(bytes)
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.send.finish().map_err(|e| MeshError::Io(e.to_string()))
        })
    }
    fn recv(&mut self) -> MeshFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.recv
                .read_to_end(MAX_MESSAGE)
                .await
                .map_err(|e| MeshError::Io(e.to_string()))
        })
    }
}
