//! The admission, stream and reconnect laws for the iroh transport.
#![cfg(feature = "iroh")]
use oneiron::entity_id::EntityId;
use oneiron_mesh_transport::{
    AcceptPolicy, MachineGrants, MachineId, MachineRoster, MeshError, MeshMachineAddress,
    MeshTransport,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
const ALPN: &[u8] = b"oneiron/mesh-conformance/1";
const MAX_FRAME: usize = 1024 * 1024;

#[derive(Default)]
struct State {
    rows: RwLock<BTreeMap<MachineId, (MeshMachineAddress, bool)>>,
    grant_checks: Mutex<BTreeMap<MachineId, usize>>,
    grant_checks_changed: tokio::sync::Notify,
}
#[derive(Clone)]
struct MemoryRoster(Arc<State>);
impl std::fmt::Debug for MemoryRoster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryRoster")
    }
}
impl MachineRoster for MemoryRoster {
    fn by_machine(&self, id: MachineId) -> Result<Option<MeshMachineAddress>, MeshError> {
        Ok(self
            .0
            .rows
            .read()
            .map_err(|_| MeshError::Unavailable)?
            .get(&id)
            .map(|(row, _)| row.clone()))
    }
    fn by_endpoint(
        &self,
        key: [u8; 32],
    ) -> Result<Option<(MachineId, MeshMachineAddress)>, MeshError> {
        let rows = self.0.rows.read().map_err(|_| MeshError::Unavailable)?;
        let mut matches = rows.iter().filter(|(_, (row, _))| row.endpoint_key == key);
        let result = matches.next().map(|(&id, (row, _))| (id, row.clone()));
        if matches.next().is_some() {
            return Err(MeshError::InvalidRoster);
        }
        Ok(result)
    }
}
#[derive(Clone)]
struct MemoryGrants(Arc<State>);
impl std::fmt::Debug for MemoryGrants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryGrants")
    }
}
impl MachineGrants for MemoryGrants {
    fn permits(&self, machine: MachineId, key: [u8; 32], alpn: &[u8]) -> Result<bool, MeshError> {
        let permitted = self
            .0
            .rows
            .read()
            .map_err(|_| MeshError::Unavailable)?
            .get(&machine)
            .is_some_and(|(row, admitted)| *admitted && row.endpoint_key == key && alpn == ALPN);
        *self
            .0
            .grant_checks
            .lock()
            .map_err(|_| MeshError::Unavailable)?
            .entry(machine)
            .or_default() += 1;
        self.0.grant_checks_changed.notify_waiters();
        Ok(permitted)
    }
}
fn policy(state: Arc<State>) -> AcceptPolicy {
    AcceptPolicy {
        roster: Arc::new(MemoryRoster(Arc::clone(&state))),
        grants: Arc::new(MemoryGrants(state)),
    }
}
fn state(rows: impl IntoIterator<Item = (MachineId, MeshMachineAddress)>) -> Arc<State> {
    Arc::new(State {
        rows: RwLock::new(
            rows.into_iter()
                .map(|(id, row)| (id, (row, true)))
                .collect(),
        ),
        ..State::default()
    })
}
fn grant_check_count(state: &State, machine: MachineId) -> usize {
    state
        .grant_checks
        .lock()
        .unwrap()
        .get(&machine)
        .copied()
        .unwrap_or_default()
}
async fn wait_for_grant_checks(state: &State, machine: MachineId, minimum: usize) {
    let wait = async {
        loop {
            let notified = state.grant_checks_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if grant_check_count(state, machine) >= minimum {
                return;
            }
            notified.await;
        }
    };
    tokio::time::timeout(Duration::from_secs(8), wait)
        .await
        .expect("transport did not complete the expected live grant checks");
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

    let exact = vec![b'x'; MAX_FRAME];
    let mut sent = bounded(outgoing.open_stream()).await?;
    let ((), body) = tokio::try_join!(bounded(sent.send(&exact)), async {
        let mut received = bounded(incoming.accept_stream()).await?;
        bounded(received.recv()).await
    })?;
    assert_eq!(body, exact);

    let mut sent = bounded(incoming.open_stream()).await?;
    let ((), body) = tokio::try_join!(bounded(sent.send(&exact)), async {
        let mut received = bounded(outgoing.accept_stream()).await?;
        bounded(received.recv()).await
    })?;
    assert_eq!(body, exact);

    let over_limit = vec![b'x'; MAX_FRAME + 1];
    let mut sent = bounded(outgoing.open_stream()).await?;
    assert!(matches!(
        bounded(sent.send(&over_limit)).await,
        Err(MeshError::Unavailable)
    ));
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

async fn queued_accept_revocation(
    client: &dyn MeshTransport,
    server: &dyn MeshTransport,
    server_id: MachineId,
    client_id: MachineId,
    server_state: &State,
) {
    let checks_after_queue = grant_check_count(server_state, client_id) + 2;
    let pending = bounded(client.dial(server_id, ALPN)).await.unwrap();
    wait_for_grant_checks(server_state, client_id, checks_after_queue).await;
    server_state
        .rows
        .write()
        .unwrap()
        .get_mut(&client_id)
        .unwrap()
        .1 = false;
    assert!(
        matches!(bounded(server.accept()).await, Err(MeshError::Refused)),
        "a queued connection survived grant revocation"
    );
    pending.close();
    server_state
        .rows
        .write()
        .unwrap()
        .get_mut(&client_id)
        .unwrap()
        .1 = true;
}
async fn established_stream_revocation(
    client: &dyn MeshTransport,
    server: &dyn MeshTransport,
    server_id: MachineId,
    client_id: MachineId,
    client_state: &State,
    server_state: &State,
) {
    let outgoing = bounded(client.dial(server_id, ALPN)).await.unwrap();
    let incoming = bounded(server.accept()).await.unwrap();
    let mut established = bounded(outgoing.open_stream()).await.unwrap();
    bounded(established.send(b"before revoke")).await.unwrap();
    let mut peer_stream = bounded(incoming.accept_stream()).await.unwrap();
    let mut queued_stream = bounded(outgoing.open_stream()).await.unwrap();

    server_state
        .rows
        .write()
        .unwrap()
        .get_mut(&client_id)
        .unwrap()
        .1 = false;
    client_state
        .rows
        .write()
        .unwrap()
        .get_mut(&server_id)
        .unwrap()
        .1 = false;
    assert!(
        matches!(
            bounded(queued_stream.send(b"after revoke")).await,
            Err(MeshError::Refused)
        ),
        "an established stream sent after grant revocation"
    );
    assert!(
        matches!(bounded(peer_stream.recv()).await, Err(MeshError::Refused)),
        "an established stream received after grant revocation"
    );
    assert!(
        matches!(
            bounded(incoming.accept_stream()).await,
            Err(MeshError::Refused)
        ),
        "an established connection accepted a stream after grant revocation"
    );
    assert!(
        matches!(
            bounded(incoming.open_stream()).await,
            Err(MeshError::Refused)
        ),
        "an established incoming connection opened a stream after grant revocation"
    );
    assert!(
        matches!(
            bounded(outgoing.open_stream()).await,
            Err(MeshError::Refused)
        ),
        "an established outgoing connection opened a stream after grant revocation"
    );
    outgoing.close();
    incoming.close();
    server_state
        .rows
        .write()
        .unwrap()
        .get_mut(&client_id)
        .unwrap()
        .1 = true;
    client_state
        .rows
        .write()
        .unwrap()
        .get_mut(&server_id)
        .unwrap()
        .1 = true;
}
async fn laws(
    client: &dyn MeshTransport,
    server: &dyn MeshTransport,
    stranger: &dyn MeshTransport,
    server_id: MachineId,
    client_id: MachineId,
    client_state: Arc<State>,
    server_state: Arc<State>,
) {
    exchange(client, server, server_id, client_id)
        .await
        .unwrap(); // dial, accept, frame bounds
    queued_accept_revocation(client, server, server_id, client_id, &server_state).await;
    established_stream_revocation(
        client,
        server,
        server_id,
        client_id,
        &client_state,
        &server_state,
    )
    .await;
    refused(stranger, server, server_id).await; // unknown key at server
    server_state
        .rows
        .write()
        .unwrap()
        .get_mut(&client_id)
        .unwrap()
        .1 = false;
    refused(client, server, server_id).await; // revoked grant on a NEW handshake
    server_state
        .rows
        .write()
        .unwrap()
        .get_mut(&client_id)
        .unwrap()
        .1 = true;
    exchange(client, server, server_id, client_id)
        .await
        .unwrap(); // reconnect after drop
}

#[tokio::test]
async fn iroh_loopback_conformance() {
    use oneiron_mesh_transport::iroh_transport::IrohTransport;
    let (a, b, _unknown) = (EntityId::now(), EntityId::now(), EntityId::now());
    let (as_, bs, us) = (
        iroh::SecretKey::generate(),
        iroh::SecretKey::generate(),
        iroh::SecretKey::generate(),
    );
    let addr = |key, direct_addrs| MeshMachineAddress {
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
        policy(Arc::clone(&client_state)),
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
    *empty.rows.write().unwrap() = server_state.rows.read().unwrap().clone();
    laws(
        &client,
        &server,
        &stranger,
        b,
        a,
        client_state,
        Arc::clone(&empty),
    )
    .await;
    client.shutdown().await.unwrap();
    stranger.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}
