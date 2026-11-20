#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! FIX 4748 on the mesh with several engine machines of one vault (FIX-LIST
//! [MESH-TWO-MACHINE-PEER-E2E], census L7-47, RULING L7-47-PR2-TESTS = A;
//! owner RULING B, 2026-10-19; ARCH-0023b `#peer-fetch`: "Only machines
//! marked mine serve. ... It serves state-only copies, never history, and
//! both ends write a receipt."). Three tests from PLAN-L7-47:
//! (1) a peer machine marked mine is served while the home is down, with a
//! receipt at both ends of one session; (2) a machine not marked mine is
//! refused, 403 and a refusal receipt; (3) a device asks a peer only once its
//! home has been down `HOME_DOWN_AFTER_SECS` (60 s, real time), the
//! full-copy holder first.
//!
//! The fixture is the owner's home H and its devices, each a replica of H's
//! vault in its own directory, each with its own install identity, enrolled
//! as `oneiron device enrol` enrols a device: H's owner makes a machine
//! pairing link, the device redeems it with its enrolment request, its
//! machine key's possession proof and its mesh identity, and H enrols it,
//! binds its endpoint and grants it sync in that one redemption. Each device
//! then takes H's signed authority history, so every replica folds every
//! machine and every slip. Each device's server runs as a device of H (no
//! models, so no Dreamer) with its real mesh listener on a loopback port the
//! system assigns, no relay; then each vault binds, at the address that
//! listener bound, and grants the machines it serves or dials. H itself
//! never runs: its URL is a loopback listener that closes every connection
//! before the upgrade and notes when each arrived. The asking device runs its
//! real `SyncConnection` on its server's windows, with the peer dialer on its
//! listener's endpoint, as device sync wires a served host's link; a
//! recorder around that dialer notes each peer dial as it starts.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test mesh_two_machine_peer_e2e`.
//! Each test runs about 70 s: the home-down window is not shortened.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, MachineOwnership, MachineRole, MeshBindingIdentity, MeshEnrolment,
    MeshMachineAddress, PairingPrincipal, pairing_binding_transcript_pinned,
};
use oneiron::federation::Scope;
use oneiron::sync::mesh_path::{
    MESH_PATH_RECEIPTS_READ_MAX, MeshPathDirection, MeshPathOutcome, MeshPathReceipt, SYNC_ALPN,
};
use oneiron::sync::peer_route::{HOME_DOWN_AFTER_SECS, choose_sync_peer};
use oneiron::sync::{
    ConnectionConfig, SyncClientConfig, SyncConnection, SyncDial, SyncEvent, SyncPeerDialer,
    SyncResidenceMode, SyncTransportCredential,
};
use oneiron::test_doors::steward;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_mesh_transport::sync_dialer::MeshPeerDialer;
use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::embedded_peer_path::{
    MeshListener, device_link_windows, start_mesh_listener,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// How long past the home-down window a test waits for its peer session.
const PEER_SESSION_GRACE: Duration = Duration::from_secs(45);

/// When an entity the serving peer holds was learned: a window the asker
/// holds nothing of.
const PEER_ENTITY_AT: u64 = 1_771_027_200;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// Runs `test` on a multi-thread runtime whose threads have the engine's
/// stack, driven from a thread that has it too, as the server's binary runs.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// The home that is down, at a loopback sync URL: a listener that closes
/// each connection before the upgrade and notes when it arrived. Every home
/// session fails unserved, the far end's fault as for a home nobody answers
/// (FIX 22217), and the first arrival comes before the first failure the
/// asker counts: the home-down window is measured from it.
struct DownHome {
    url: String,
    arrivals: Arc<Mutex<Vec<Instant>>>,
    accepting: tokio::task::JoinHandle<()>,
}

impl DownHome {
    async fn start() -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("ws://{}/ws", listener.local_addr()?);
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let noted = Arc::clone(&arrivals);
        let accepting = tokio::spawn(async move {
            while let Ok((connection, _)) = listener.accept().await {
                noted
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Instant::now());
                drop(connection);
            }
        });
        Ok(Self {
            url,
            arrivals,
            accepting,
        })
    }

    /// When the asker's first home session reached the home: before that
    /// session failed, and so before the asker began to count the home down.
    fn first_arrival(&self) -> Option<Instant> {
        self.arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .first()
            .copied()
    }
}

impl Drop for DownHome {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// The owner's home H: a rooted carrier install the owner answered as his
/// own machine, as `oneiron serve` leaves a self-hosted home. It never runs.
struct Home {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: oneiron::consent::AuthenticatedOwner,
    machine: EntityId,
}

fn home() -> TestResult<Home> {
    let dir = tempfile::tempdir()?;
    let vault =
        steward::open_owner_carrier_vault(dir.path()).map_err(at("open the home's vault"))?;
    let owner = steward::owner(&vault).map_err(at("the home's owner proof"))?;
    let machine = vault
        .local_machine()
        .map_err(at("read the home's install"))?
        .ok_or("fixture: the home's install has no machine")?
        .id;
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .map_err(at("the owner answers the home is his"))?;
    Ok(Home {
        _dir: dir,
        vault,
        owner,
        machine,
    })
}

/// One device of H: a replica of H's vault with its own install identity,
/// enrolled on H, and the credential its enrolment minted.
struct Device {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    machine: EntityId,
    identity: MeshBindingIdentity,
    /// The pairing slip H minted for the device's mesh binding.
    mesh_pairing: [u8; 32],
    credential: SyncTransportCredential,
}

impl Home {
    /// A device that copies H's vault and enrols on H as `ownership`, as
    /// `oneiron device enrol` does: H's owner makes the machine pairing
    /// link; the device redeems it with a holder key of its own, its
    /// enrolment request, its machine key's possession proof and its mesh
    /// identity; H enrols it, mints its credential, and binds and grants its
    /// endpoint on sync in the same redemption. `holder_seed` seeds the
    /// credential's holder key.
    fn enrol(&self, ownership: MachineOwnership, holder_seed: u8) -> TestResult<Device> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::device())
            .map_err(at("open the device's vault"))?;
        vault
            .import_signed_authority_history(
                &self
                    .vault
                    .export_signed_authority_history()
                    .map_err(at("the home's authority history"))?,
            )
            .map_err(at("the device takes the home's authority history"))?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let vault_id = vault
            .authority_vault_id()
            .map_err(at("the device's vault id"))?
            .ok_or("fixture: the device's copy has no vault id")?;
        let request = vault
            .machine_enrolment_request(
                vault_id,
                vault
                    .machine_encryption_key(vault_id)
                    .map_err(at("the device's encryption key"))?,
            )
            .map_err(at("the device's enrolment request"))?;
        let device_owner = steward::owner(&vault).map_err(at("the device's owner proof"))?;
        let identity = vault
            .mesh_binding_identity_as_owner(&device_owner)
            .map_err(at("the device's mesh identity"))?;
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
                ownership,
            )
            .map_err(at("the owner's machine pairing link"))?;
        let holder = SigningKey::from_bytes(&[holder_seed; 32]);
        let binding_key = holder.verifying_key().to_bytes();
        let holder_ref = request.machine.to_hex();
        let transcript = pairing_binding_transcript_pinned(
            &link.code,
            &binding_key,
            &holder_ref,
            link.pin.as_ref(),
        )
        .map_err(at("the pairing transcript"))?;
        let possession = vault
            .machine_possession_proof(&request, &transcript)
            .map_err(at("the machine key's possession proof"))?;
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
                (&identity, SYNC_ALPN),
            )
            .map_err(at("the home redeems the device's enrolment"))?;
        let pairing_slip_id = match redeemed.mesh {
            Some(MeshEnrolment::Bound {
                pairing_slip_id, ..
            }) => pairing_slip_id,
            other => {
                return Err(format!("fixture: the home did not bind the device: {other:?}").into());
            }
        };
        let token = redeemed
            .slip
            .to_token()
            .map_err(at("the credential's slip"))?;
        Ok(Device {
            _dir: dir,
            vault: Arc::new(vault),
            machine: request.machine,
            identity,
            mesh_pairing: pairing_slip_id,
            credential: SyncTransportCredential::new(token, holder),
        })
    }

    /// Every device takes H's authority history once all have enrolled, so
    /// each replica folds every machine and every slip H minted.
    fn share_history(&self, devices: &[&Device]) -> TestResult {
        let history = self
            .vault
            .export_signed_authority_history()
            .map_err(at("the home's authority history"))?;
        for device in devices {
            device
                .vault
                .import_signed_authority_history(&history)
                .map_err(at("a device takes the home's authority history"))?;
        }
        Ok(())
    }
}

impl Device {
    /// This vault binds `peer`'s endpoint at the loopback addresses its
    /// running listener bound (`listening`), on the pairing H minted for it,
    /// and grants it sync, as the owner does for a machine whose mesh calls
    /// this one takes or makes. The listeners and dialers read the roster and
    /// the grants live, so a bind after the listener started counts.
    fn bind(&self, peer: &Device, listening: &Served) -> TestResult {
        let issuer = test_host_issuer();
        self.vault
            .bind_mesh_machine(
                &issuer,
                peer.machine,
                MeshMachineAddress {
                    endpoint_key: peer.identity.endpoint_key,
                    direct_addrs: listening.addresses.clone(),
                    relay_url: None,
                },
                peer.identity.device_key,
                peer.mesh_pairing,
                [
                    peer.identity.device_proof.as_slice(),
                    peer.identity.transport_proof.as_slice(),
                ],
            )
            .map_err(at("bind the peer's endpoint"))?;
        self.vault
            .set_mesh_alpn_grant(
                &issuer,
                peer.machine,
                peer.identity.endpoint_key,
                SYNC_ALPN,
                true,
            )
            .map_err(at("grant the peer sync"))?;
        Ok(())
    }

    /// Starts this device's server as a device of H, with no models, and its
    /// mesh listener on a loopback port the system assigns as it binds: no
    /// other test of this binary (they run in parallel) can take that port
    /// between the choice and the bind. The vaults learn the address it bound
    /// afterwards ([`Device::bind`]).
    async fn serve(&self) -> TestResult<Served> {
        let server = SyncServer::new(Arc::clone(&self.vault), SyncServerConfig::default())
            .map_err(at("the device's server"))?;
        let (server, host) = AiHost::attach_device(server, None, true).await;
        let server = Arc::new(server);
        let app = oneiron_server::build_app(Arc::clone(&server));
        let listener = start_mesh_listener(
            Arc::clone(&server),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            &app,
        )
        .await
        .map_err(at("the device's mesh listener"))?;
        let addresses = listener.direct_addrs();
        if addresses.is_empty() {
            return Err("fixture: the device's mesh listener bound no direct address".into());
        }
        Ok(Served {
            server,
            _host: host,
            listener,
            addresses,
        })
    }
}

/// A device's running server and mesh listener.
struct Served {
    server: Arc<SyncServer>,
    _host: AiHost,
    listener: MeshListener,
    /// The loopback addresses the listener bound.
    addresses: Vec<SocketAddr>,
}

/// The asking device's real peer dialer, recording each dial as it starts:
/// the peer it names and when, before the dial reaches that peer. The timing
/// and order promises are about the dials: a peer receipt is written only
/// once the upgrade and the peer's proof succeed, so a dial that failed
/// before that leaves none, and one admitted late shows only its admission.
#[derive(Debug)]
struct RecordingPeerDialer {
    dialer: MeshPeerDialer,
    dials: Arc<Mutex<Vec<(EntityId, Instant)>>>,
}

impl SyncPeerDialer for RecordingPeerDialer {
    fn peers(&self) -> Vec<EntityId> {
        self.dialer.peers()
    }

    fn dial_peer(&self, peer: EntityId) -> SyncDial<'_> {
        self.dials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((peer, Instant::now()));
        self.dialer.dial_peer(peer)
    }
}

/// The asking device's link, running: its home is `home`, down at
/// `home_url`, and its peer dialer rides its listener's endpoint.
struct Asking {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    run: tokio::task::JoinHandle<oneiron::Result<()>>,
    events: Arc<Mutex<Vec<SyncEvent>>>,
    /// Every peer dial the link made, with when it started.
    dials: Arc<Mutex<Vec<(EntityId, Instant)>>>,
}

impl Asking {
    fn start(device: &Device, served: &Served, home: EntityId, home_url: &str) -> TestResult<Self> {
        let dials = Arc::new(Mutex::new(Vec::new()));
        let peer_dialer = Arc::new(RecordingPeerDialer {
            dialer: MeshPeerDialer::new(
                served.listener.transport(),
                Arc::clone(&device.vault),
                device.machine,
                Arc::new(move || home),
            ),
            dials: Arc::clone(&dials),
        }) as Arc<dyn SyncPeerDialer>;
        let config = ConnectionConfig {
            client_config: SyncClientConfig {
                server_url: home_url.to_owned(),
                transport_credential: Some(device.credential.clone()),
                residence_mode: SyncResidenceMode::All,
                reconnect_initial_ms: 100,
                reconnect_backoff_max_ms: 500,
                peer_dialer: Some(peer_dialer),
                ..Default::default()
            },
            auto_reconnect: true,
        };
        let connection = SyncConnection::new(device_link_windows(&served.server), config)
            .map_err(at("the asking device's link"))?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&events);
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            connection
                .run_observed(shutdown_rx, move |event| {
                    seen.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(event);
                })
                .await
        });
        Ok(Self {
            shutdown: Some(shutdown),
            run,
            events,
            dials,
        })
    }

    /// The peer dials the link has made, oldest first: the peer each named
    /// and how long after `since` it began (zero for one before it).
    fn dials_since(&self, since: Instant) -> Vec<(EntityId, Duration)> {
        self.dials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|&(peer, at)| (peer, at.saturating_duration_since(since)))
            .collect()
    }

    fn errors(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(|event| match event {
                SyncEvent::Error(error) => Some(error.clone()),
                _ => None,
            })
            .collect()
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(30), &mut self.run).await;
        self.run.abort();
    }
}

/// One end's receipt of a peer sync session: which part it played, the
/// other machine, the session, and whether it was admitted.
#[derive(Debug, Clone)]
struct PeerReceipt {
    asked: bool,
    peer: Option<String>,
    session: String,
    outcome: MeshPathOutcome,
    refused_because: Option<String>,
    opened_at_ms: u64,
}

/// The peer sync receipts `vault` holds, oldest first.
fn peer_receipts(vault: &Vault) -> Vec<PeerReceipt> {
    let mut receipts: Vec<PeerReceipt> = vault
        .mesh_path_receipts(MESH_PATH_RECEIPTS_READ_MAX)
        .unwrap_or_default()
        .iter()
        .filter_map(peer_receipt)
        .collect();
    receipts.sort_by_key(|receipt| receipt.opened_at_ms);
    receipts
}

fn peer_receipt(receipt: &MeshPathReceipt) -> Option<PeerReceipt> {
    let detail = receipt
        .detail
        .as_deref()?
        .strip_prefix("peer sync session ")?;
    let (session, part) = detail.split_once(": ")?;
    let (part, refused_because) = match part.split_once(", refused: ") {
        Some((part, why)) => (part, Some(why.to_owned())),
        None => (part, None),
    };
    let asked = match part {
        "asked" => true,
        "served" => false,
        _ => return None,
    };
    let direction = if asked {
        MeshPathDirection::Outbound
    } else {
        MeshPathDirection::Inbound
    };
    (receipt.direction == direction).then(|| PeerReceipt {
        asked,
        peer: receipt.machine.clone(),
        session: session.to_owned(),
        outcome: receipt.outcome,
        refused_because,
        opened_at_ms: receipt.opened_at_ms,
    })
}

/// Polls `probe` every 250 ms until it holds or `within` passes.
async fn eventually(within: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if probe() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// How long a test waits for its first peer session: the home-down window,
/// then the grace.
fn peer_session_within() -> Duration {
    Duration::from_secs(HOME_DOWN_AFTER_SECS) + PEER_SESSION_GRACE
}

/// An entity the serving peer holds and the asker does not.
fn put_peer_entity(device: &Device) -> TestResult<EntityId> {
    let entity = EntityId::now();
    device
        .vault
        .put_entity(
            &entity,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: PEER_ENTITY_AT,
                end: PEER_ENTITY_AT,
            },
            PEER_ENTITY_AT,
            b"held on the serving peer",
        )
        .map_err(at("the serving peer's entity"))?;
    Ok(entity)
}

fn holds(vault: &Vault, entity: EntityId) -> bool {
    vault.get(&entity).is_ok_and(|held| held.is_some())
}

#[test]
fn a_peer_marked_mine_serves_the_asker_while_its_home_is_down() -> TestResult {
    on_engine_stack(peer_marked_mine_serves)
}

async fn peer_marked_mine_serves() -> TestResult {
    let home = home()?;
    let asker = home.enrol(MachineOwnership::Yours, 0xA1)?;
    let peer = home.enrol(MachineOwnership::Yours, 0xB1)?;
    home.share_history(&[&asker, &peer])?;
    let entity = put_peer_entity(&peer)?;
    assert!(
        !holds(&asker.vault, entity),
        "FIXTURE: the asker does not hold the serving peer's entity"
    );
    let serving = peer.serve().await?;
    let asking_served = asker.serve().await?;
    asker.bind(&peer, &serving)?;
    peer.bind(&asker, &asking_served)?;
    let down_home = DownHome::start().await?;
    let asking = Asking::start(&asker, &asking_served, home.machine, &down_home.url)?;

    let asker_hex = asker.machine.to_hex();
    let peer_hex = peer.machine.to_hex();
    let one_session = eventually(peer_session_within(), || {
        let asked = peer_receipts(&asker.vault);
        let served = peer_receipts(&peer.vault);
        asked.iter().any(|ask| {
            ask.asked
                && ask.outcome == MeshPathOutcome::Admitted
                && ask.peer.as_deref() == Some(peer_hex.as_str())
                && served.iter().any(|serve| {
                    !serve.asked
                        && serve.outcome == MeshPathOutcome::Admitted
                        && serve.peer.as_deref() == Some(asker_hex.as_str())
                        && serve.session == ask.session
                })
        })
    })
    .await;
    let asked = peer_receipts(&asker.vault);
    let served = peer_receipts(&peer.vault);
    assert!(
        one_session,
        "with its home down, the asker syncs with the peer marked mine, and both ends leave an \
         admitted receipt of one session naming the other; asker receipts {asked:?}, peer \
         receipts {served:?}, asker errors {:?}",
        asking.errors()
    );
    // The earliest peer dial the asker made, whatever became of it, timed
    // from its first home session's arrival at the down home, which comes
    // before the failure the asker counts the home down from: a dial before
    // the window breaks the promise even when it failed before the peer
    // answered, or the peer admitted it only after the window.
    let unserved_from = down_home
        .first_arrival()
        .ok_or("the asker's home sessions never reached the home")?;
    let dials = asking.dials_since(unserved_from);
    let &(_, first_dial_after) = dials.first().ok_or("the asker made no peer dial")?;
    assert!(
        first_dial_after >= Duration::from_secs(HOME_DOWN_AFTER_SECS),
        "the asker dials a peer only once its home has served it nothing for \
         {HOME_DOWN_AFTER_SECS} s: first peer dial {first_dial_after:?} after its first home \
         session reached the home: {dials:?}"
    );
    assert!(
        eventually(PEER_SESSION_GRACE, || holds(&asker.vault, entity)).await,
        "the serving peer's state reaches the asker over the peer session"
    );

    asking.stop().await;
    serving.listener.stop().await;
    asking_served.listener.stop().await;
    Ok(())
}

#[test]
fn a_machine_not_marked_mine_is_refused_with_a_receipt() -> TestResult {
    on_engine_stack(machine_not_marked_mine_is_refused)
}

async fn machine_not_marked_mine_is_refused() -> TestResult {
    let home = home()?;
    // The owner's machine, answered work or school: enrolled, proved on its
    // key, never marked his own.
    let asker = home.enrol(MachineOwnership::WorkSchool, 0xC1)?;
    let peer = home.enrol(MachineOwnership::Yours, 0xD1)?;
    home.share_history(&[&asker, &peer])?;
    let entity = put_peer_entity(&peer)?;
    let serving = peer.serve().await?;
    let asking_served = asker.serve().await?;
    asker.bind(&peer, &serving)?;
    peer.bind(&asker, &asking_served)?;
    let down_home = DownHome::start().await?;
    let asking = Asking::start(&asker, &asking_served, home.machine, &down_home.url)?;

    let asker_hex = asker.machine.to_hex();
    let peer_hex = peer.machine.to_hex();
    let refused = eventually(peer_session_within(), || {
        peer_receipts(&peer.vault).iter().any(|serve| {
            !serve.asked
                && serve.outcome == MeshPathOutcome::Refused
                && serve.peer.as_deref() == Some(asker_hex.as_str())
                && serve.refused_because.as_deref() == Some("not proved as a machine marked mine")
        })
    })
    .await;
    let served = peer_receipts(&peer.vault);
    assert!(
        refused,
        "the peer refuses a machine not marked mine and leaves a refusal receipt naming it; \
         peer receipts {served:?}, asker errors {:?}",
        asking.errors()
    );
    // The peer commits its refusal receipt before it sends the 403, so the
    // asker's error may come a moment after the receipt shows.
    assert!(
        eventually(PEER_SESSION_GRACE, || {
            asking.errors().iter().any(|error| error.contains("403"))
        })
        .await,
        "the asker's upgrade is answered 403; asker errors {:?}",
        asking.errors()
    );
    assert!(
        !served
            .iter()
            .any(|serve| serve.outcome == MeshPathOutcome::Admitted),
        "the peer admits no session of a machine not marked mine: {served:?}"
    );
    assert!(
        !peer_receipts(&asker.vault).iter().any(|ask| {
            ask.outcome == MeshPathOutcome::Admitted
                && ask.peer.as_deref() == Some(peer_hex.as_str())
        }),
        "the refused asker holds no admitted session with the peer"
    );
    assert!(
        !holds(&asker.vault, entity),
        "nothing of the peer's state reaches a machine not marked mine"
    );

    asking.stop().await;
    serving.listener.stop().await;
    asking_served.listener.stop().await;
    Ok(())
}

#[test]
fn the_asker_turns_to_the_full_copy_holder_first_once_home_is_down() -> TestResult {
    on_engine_stack(full_copy_holder_first)
}

async fn full_copy_holder_first() -> TestResult {
    let home = home()?;
    let asker = home.enrol(MachineOwnership::Yours, 0xE1)?;
    let one = home.enrol(MachineOwnership::Yours, 0xE2)?;
    let two = home.enrol(MachineOwnership::Yours, 0xE3)?;
    home.share_history(&[&asker, &one, &two])?;
    let serving_one = one.serve().await?;
    let serving_two = two.serve().await?;
    let asking_served = asker.serve().await?;
    for (peer, serving) in [(&one, &serving_one), (&two, &serving_two)] {
        asker.bind(peer, serving)?;
        peer.bind(&asker, &asking_served)?;
    }
    // The peer that ranks second with no mark declares a full copy, signed by
    // its own install key, and the asker folds the mark.
    let unmarked = choose_sync_peer(&asker.vault, SYNC_ALPN, asker.machine, home.machine);
    assert_eq!(
        unmarked.len(),
        2,
        "FIXTURE: the asker lists both granted peers marked mine: {unmarked:?}"
    );
    let (second, first) = if unmarked[0] == one.machine {
        (&two, &one)
    } else {
        (&one, &two)
    };
    assert_eq!(
        unmarked,
        vec![first.machine, second.machine],
        "FIXTURE: the asker lists exactly its two peers"
    );
    second
        .vault
        .declare_full_copy(true)
        .map_err(at("the second peer declares a full copy"))?
        .ok_or("FIXTURE: the second peer wrote no full-copy mark")?;
    asker
        .vault
        .import_signed_authority_history(
            &second
                .vault
                .export_signed_authority_history()
                .map_err(at("the marked peer's authority history"))?,
        )
        .map_err(at("the asker folds the full-copy mark"))?;
    assert_eq!(
        choose_sync_peer(&asker.vault, SYNC_ALPN, asker.machine, home.machine),
        vec![second.machine, first.machine],
        "the full-copy holder ranks first once its mark lands"
    );
    let down_home = DownHome::start().await?;
    let asking = Asking::start(&asker, &asking_served, home.machine, &down_home.url)?;

    let asked_any = eventually(peer_session_within(), || {
        peer_receipts(&asker.vault)
            .iter()
            .any(|ask| ask.asked && ask.outcome == MeshPathOutcome::Admitted)
    })
    .await;
    let asked = peer_receipts(&asker.vault);
    assert!(
        asked_any,
        "with its home down, the asker syncs with one of its peers; asker receipts {asked:?}, \
         asker errors {:?}",
        asking.errors()
    );
    // The asker's first peer dial, whatever became of it, goes to the
    // full-copy holder once the window has passed, timed from its first home
    // session's arrival at the down home: a dial to the peer without the mark
    // that failed before reaching it would leave no receipt.
    let unserved_from = down_home
        .first_arrival()
        .ok_or("the asker's home sessions never reached the home")?;
    let dials = asking.dials_since(unserved_from);
    let &(first_dialled, first_dial_after) = dials.first().ok_or("the asker made no peer dial")?;
    assert_eq!(
        first_dialled, second.machine,
        "the asker's first peer dial goes to the full-copy holder, none to the peer without the \
         mark before it: {dials:?}"
    );
    assert!(
        first_dial_after >= Duration::from_secs(HOME_DOWN_AFTER_SECS),
        "no peer is dialled before the home has been down {HOME_DOWN_AFTER_SECS} s: first peer \
         dial {first_dial_after:?} after its first home session reached the home: {dials:?}"
    );
    // The full-copy holder admits that first session: the asker's first
    // peer receipt is an admitted one naming it.
    let first_ask = asked
        .iter()
        .find(|ask| ask.asked)
        .ok_or("the asker's first receipt went")?;
    assert_eq!(
        first_ask.peer.as_deref(),
        Some(second.machine.to_hex().as_str()),
        "the asker's first admitted peer session is the full-copy holder's: {asked:?}"
    );
    assert_eq!(
        first_ask.outcome,
        MeshPathOutcome::Admitted,
        "the full-copy holder serves the asker's first peer session: {asked:?}"
    );

    asking.stop().await;
    serving_one.listener.stop().await;
    serving_two.listener.stop().await;
    asking_served.listener.stop().await;
    Ok(())
}
