//! The same admission, stream and reconnect laws for the in-memory and iroh transports.
use oneiron::entity_id::EntityId;
use oneiron_mesh_transport::{
    AcceptPolicy, MachineAddress, MachineGrants, MachineId, MachineRoster, MeshConnection,
    MeshError, MeshFuture, MeshStream, MeshTransport,
};
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::mpsc,
};
const ALPN: &[u8] = b"oneiron/mesh-conformance/1";

type State = RwLock<BTreeMap<MachineId, (MachineAddress, bool)>>;
#[derive(Debug, Clone)]
struct MemoryRoster(Arc<State>);
impl MachineRoster for MemoryRoster {
    fn by_machine(&self, id: MachineId) -> Result<Option<MachineAddress>, MeshError> {
        Ok(self
            .0
            .read()
            .map_err(|_| MeshError::Unavailable)?
            .get(&id)
            .map(|(row, _)| row.clone()))
    }
    fn by_endpoint(&self, key: [u8; 32]) -> Result<Option<(MachineId, MachineAddress)>, MeshError> {
        let rows = self.0.read().map_err(|_| MeshError::Unavailable)?;
        let mut matches = rows.iter().filter(|(_, (row, _))| row.endpoint_key == key);
        let result = matches.next().map(|(&id, (row, _))| (id, row.clone()));
        if matches.next().is_some() {
            return Err(MeshError::InvalidRoster);
        }
        Ok(result)
    }
}
#[derive(Debug, Clone)]
struct MemoryGrants(Arc<State>);
impl MachineGrants for MemoryGrants {
    fn permits(&self, machine: MachineId, key: [u8; 32], alpn: &[u8]) -> Result<bool, MeshError> {
        Ok(self
            .0
            .read()
            .map_err(|_| MeshError::Unavailable)?
            .get(&machine)
            .is_some_and(|(row, admitted)| *admitted && row.endpoint_key == key && alpn == ALPN))
    }
}
fn policy(state: Arc<State>) -> AcceptPolicy {
    AcceptPolicy {
        roster: Arc::new(MemoryRoster(Arc::clone(&state))),
        grants: Arc::new(MemoryGrants(state)),
    }
}
fn state(rows: impl IntoIterator<Item = (MachineId, MachineAddress)>) -> Arc<State> {
    Arc::new(RwLock::new(
        rows.into_iter()
            .map(|(id, row)| (id, (row, true)))
            .collect(),
    ))
}
async fn bounded<T>(
    f: impl std::future::Future<Output = Result<T, MeshError>>,
) -> Result<T, MeshError> {
    tokio::time::timeout(Duration::from_secs(8), f)
        .await
        .map_err(|_| MeshError::Unavailable)?
}
async fn exchange(
    client: &dyn MeshTransport,
    server: &dyn MeshTransport,
    server_id: MachineId,
    client_id: MachineId,
) -> Result<(), MeshError> {
    let outgoing = bounded(client.dial(server_id, ALPN)).await?;
    let incoming = bounded(server.accept()).await?;
    assert_eq!(incoming.machine(), client_id);
    assert_eq!(outgoing.machine(), server_id);
    assert_eq!(incoming.alpn(), ALPN);
    assert_eq!(outgoing.alpn(), ALPN);
    let mut sent = bounded(outgoing.open_stream()).await?;
    bounded(sent.send(b"ping")).await?;
    let mut received = bounded(incoming.accept_stream()).await?;
    assert_eq!(bounded(received.recv()).await?, b"ping");
    bounded(received.send(b"pong")).await?;
    assert_eq!(bounded(sent.recv()).await?, b"pong");
    outgoing.close();
    incoming.close();
    Ok(())
}
async fn refused(peer: &dyn MeshTransport, server: &dyn MeshTransport, server_id: MachineId) {
    // Some QUIC clients observe the refusal only on their first stream, not in dial().
    match bounded(peer.dial(server_id, ALPN)).await {
        Err(_) => {}
        Ok(conn) => {
            if let Ok(mut stream) = bounded(conn.open_stream()).await
                && bounded(stream.send(b"probe")).await.is_ok()
            {
                assert!(
                    bounded(stream.recv()).await.is_err(),
                    "untrusted peer received stream data"
                );
            }
            conn.close();
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.accept())
            .await
            .is_err(),
        "server dispatched a refused connection"
    );
}

async fn laws(
    client: &dyn MeshTransport,
    server: &dyn MeshTransport,
    stranger: &dyn MeshTransport,
    server_id: MachineId,
    client_id: MachineId,
    server_state: Arc<State>,
) {
    exchange(client, server, server_id, client_id)
        .await
        .unwrap(); // dial, accept, stream
    refused(stranger, server, server_id).await; // unknown key at server
    server_state.write().unwrap().get_mut(&client_id).unwrap().1 = false;
    refused(client, server, server_id).await; // revoked grant on a NEW handshake
    server_state.write().unwrap().get_mut(&client_id).unwrap().1 = true;
    exchange(client, server, server_id, client_id)
        .await
        .unwrap(); // reconnect after drop
}

#[derive(Default)]
struct Hub(Mutex<BTreeMap<MachineId, Weak<TestEndpoint>>>);
struct TestEndpoint {
    id: MachineId,
    key: [u8; 32],
    hub: Arc<Hub>,
    policy: AcceptPolicy,
    sender: mpsc::Sender<Box<dyn MeshConnection>>,
    receiver: tokio::sync::Mutex<mpsc::Receiver<Box<dyn MeshConnection>>>,
}
impl TestEndpoint {
    fn new(id: MachineId, key: [u8; 32], hub: Arc<Hub>, policy: AcceptPolicy) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(16);
        let ep = Arc::new(Self {
            id,
            key,
            hub: Arc::clone(&hub),
            policy,
            sender,
            receiver: tokio::sync::Mutex::new(receiver),
        });
        hub.0.lock().unwrap().insert(id, Arc::downgrade(&ep));
        ep
    }
}
impl MeshTransport for TestEndpoint {
    fn dial(&self, machine: MachineId, alpn: &[u8]) -> MeshFuture<'_, Box<dyn MeshConnection>> {
        let alpn = alpn.to_vec();
        Box::pin(async move {
            let target = self.policy.outbound(machine, &alpn)?;
            let other = self
                .hub
                .0
                .lock()
                .map_err(|_| MeshError::Unavailable)?
                .get(&machine)
                .and_then(Weak::upgrade)
                .ok_or(MeshError::Unavailable)?;
            if target.endpoint_key != other.key {
                return Err(MeshError::Refused);
            }
            let caller = other.policy.inbound(self.key, &alpn)?;
            if caller != self.id {
                return Err(MeshError::Refused);
            }
            let (to_server, server_rx) = mpsc::channel(8);
            let (to_client, client_rx) = mpsc::channel(8);
            let client = TestConnection {
                machine,
                alpn: alpn.clone(),
                send: to_server,
                recv: tokio::sync::Mutex::new(client_rx),
            };
            let server = TestConnection {
                machine: self.id,
                alpn,
                send: to_client,
                recv: tokio::sync::Mutex::new(server_rx),
            };
            other
                .sender
                .send(Box::new(server))
                .await
                .map_err(|_| MeshError::Unavailable)?;
            Ok(Box::new(client) as Box<dyn MeshConnection>)
        })
    }
    fn accept(&self) -> MeshFuture<'_, Box<dyn MeshConnection>> {
        Box::pin(async move {
            self.receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or(MeshError::Unavailable)
        })
    }
}
struct TestConnection {
    machine: MachineId,
    alpn: Vec<u8>,
    send: mpsc::Sender<DuplexStream>,
    recv: tokio::sync::Mutex<mpsc::Receiver<DuplexStream>>,
}
impl MeshConnection for TestConnection {
    fn machine(&self) -> MachineId {
        self.machine
    }
    fn alpn(&self) -> &[u8] {
        &self.alpn
    }
    fn open_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(1024 * 1024 + 1);
            self.send
                .send(b)
                .await
                .map_err(|_| MeshError::Unavailable)?;
            Ok(Box::new(TestStream(a)) as Box<dyn MeshStream>)
        })
    }
    fn accept_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>> {
        Box::pin(async move {
            self.recv
                .lock()
                .await
                .recv()
                .await
                .map(|s| Box::new(TestStream(s)) as Box<dyn MeshStream>)
                .ok_or(MeshError::Unavailable)
        })
    }
    fn close(&self) {}
}
struct TestStream(DuplexStream);
impl MeshStream for TestStream {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> MeshFuture<'a, ()> {
        Box::pin(async move {
            if bytes.len() > 1024 * 1024 {
                return Err(MeshError::Unavailable);
            }
            self.0
                .write_all(bytes)
                .await
                .map_err(|e| MeshError::Io(e.to_string()))?;
            self.0
                .shutdown()
                .await
                .map_err(|e| MeshError::Io(e.to_string()))
        })
    }
    fn recv(&mut self) -> MeshFuture<'_, Vec<u8>> {
        Box::pin(async move {
            let mut buf = Vec::new();
            (&mut self.0)
                .take(1024 * 1024 + 1)
                .read_to_end(&mut buf)
                .await
                .map_err(|e: io::Error| MeshError::Io(e.to_string()))?;
            if buf.len() > 1024 * 1024 {
                return Err(MeshError::Unavailable);
            }
            Ok(buf)
        })
    }
}
#[tokio::test]
async fn in_memory_transport_conformance() {
    let (a, b, unknown) = (EntityId::now(), EntityId::now(), EntityId::now());
    let (ak, bk, uk) = ([1; 32], [2; 32], [3; 32]);
    let addr = |endpoint_key| MachineAddress {
        endpoint_key,
        direct_addrs: vec![],
        relay_url: None,
    };
    let server_state = state([(a, addr(ak))]);
    let client_state = state([(b, addr(bk))]);
    let stranger_state = state([(b, addr(bk))]);
    let hub = Arc::new(Hub::default());
    let server = TestEndpoint::new(b, bk, Arc::clone(&hub), policy(Arc::clone(&server_state)));
    let client = TestEndpoint::new(a, ak, Arc::clone(&hub), policy(client_state));
    let stranger = TestEndpoint::new(unknown, uk, hub, policy(stranger_state));
    laws(
        client.as_ref(),
        server.as_ref(),
        stranger.as_ref(),
        b,
        a,
        server_state,
    )
    .await;
}
#[cfg(feature = "iroh")]
#[tokio::test]
async fn iroh_loopback_conformance() {
    use oneiron_mesh_transport::iroh_transport::IrohTransport;
    let (a, b, _unknown) = (EntityId::now(), EntityId::now(), EntityId::now());
    let (as_, bs, us) = (
        iroh::SecretKey::generate(),
        iroh::SecretKey::generate(),
        iroh::SecretKey::generate(),
    );
    let addr = |key, direct_addrs| MachineAddress {
        endpoint_key: key,
        direct_addrs,
        relay_url: None,
    };
    let empty = state([]);
    let loopback = "127.0.0.1:0".parse().unwrap();
    let server = IrohTransport::bind(
        bs,
        policy(Arc::clone(&empty)),
        vec![ALPN.to_vec()],
        loopback,
        None,
    )
    .await
    .unwrap();
    let server_ip = server
        .addr()
        .addrs
        .into_iter()
        .find_map(|addr| match addr {
            iroh::TransportAddr::Ip(ip) => Some(ip),
            _ => None,
        })
        .unwrap();
    let server_row = addr(server.id(), vec![server_ip]);
    let client_state = state([(b, server_row.clone())]);
    let stranger_state = state([(b, server_row)]);
    let client = IrohTransport::bind(
        as_,
        policy(client_state),
        vec![ALPN.to_vec()],
        loopback,
        None,
    )
    .await
    .unwrap();
    let stranger = IrohTransport::bind(
        us,
        policy(stranger_state),
        vec![ALPN.to_vec()],
        loopback,
        None,
    )
    .await
    .unwrap();
    let server_state = state([(a, addr(client.id(), vec![]))]);
    // The gate reads live state; swap roster contents into the gate's shared state.
    *empty.write().unwrap() = server_state.read().unwrap().clone();
    laws(&client, &server, &stranger, b, a, Arc::clone(&empty)).await;
    client.shutdown().await.unwrap();
    stranger.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}
