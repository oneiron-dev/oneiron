//! The device side of sync (ARCH-0023b): a machine that is not the home
//! dials its home and keeps its vault in sync there. The home is the one
//! `oneiron device enrol` recorded ([`enrolment`]), or one its `[device_sync]`
//! section names by hand. It dials over the paired mesh, on the mesh
//! listener's own endpoint, when the home has a paired mesh address and a
//! mesh transport runs here; an app-only device uses its explicitly configured
//! outbound endpoint instead of a serving listener. Otherwise it uses the
//! home's URL, over `wss` (or `ws` to a loopback host). Either way it presents
//! the paired owner-grade credential.
//!
//! One connection runs at a time, for the server's life. Its own loop
//! reconnects with backoff; the loop here only rebuilds it when the paired
//! credential is renewed (`renewal`, FIX 3377). It attaches its outbound
//! channel beside the server's relay to its own clients, never in place of
//! it. Logs carry machine ids only, never a slip or a key.
//!
//! Before it dials, the device declares its own MACRO home candidacy from
//! its section's `always_on` and `primary` flags and whether its Dreamer
//! runs (FIX 4898). A named or enrolled `home_node_id` stays this device's
//! own candidate for the home, always-on local, beside the vault's
//! authorized candidates, and is published, with `home_url` as its
//! endpoint, as the connection's home-node topology, so residence reads go
//! there while that node is the elected home. With no declaration the
//! device elects that home as before; once the home's own declaration names
//! its node, the declared facts rule, and a node only fallen machines
//! declare stands no more. Being elected moves no dial: an elected device
//! keeps its home as its route. The paired credential
//! also binds each socket's NOTE session, and the own-device grant it names
//! selects what residence reads (index, first touch, promotion) may return.
//! The checkpoint the enrolment's link pinned is adopted on the first
//! connection's authority catch-up.
//!
//! While its home is down, a device with a mesh listener syncs with the
//! vault's other machines over the mesh (FIX 4748): once the home has served
//! this machine no sync for a minute (dials unanswered, refused, or ended
//! before their first round completed), each connection goes to a machine
//! marked mine, the standby home first, and confirms nothing there; a probe
//! that gets the home's root ends it, and the home's own connection then
//! replays everything queued, or, failing first, hands back to a peer
//! (`oneiron::sync::peer_route`). Without a listener here nothing of it runs.
//!
//! While the home connection is synced, the device also learns the models
//! the owner's other nodes offer (OF-575): it asks them on each sync and then
//! on a cadence, since no mesh signal says a peer's offer changed, and writes
//! their own-server rows.
//!
//! On a managed vault (WILL-PLAN L14 row 14) the reap freeze governs the
//! connection ([`freeze`], FIX 5127): its opening writes hold one admission,
//! so a frozen vault starts none; then each batch the connection applies or
//! sends, each catalog refresh and each candidacy write holds its own (FIX
//! 12036), so an idle connection keeps no reap away. A freeze pauses the
//! connection with its socket open, and it runs on once the vault thaws; a
//! reap that stops the process ends it as any stop does. Its enrolment is looked for beside the supervisor's key
//! directory alone, never under HOME or XDG (FIX 5768).

use std::sync::Arc;

use oneiron::world_keys::DeviceSyncStart;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::ServeConfig;
use crate::handler::mesh::MeshHost;
use crate::server::SyncServer;

mod batch_admission;
#[cfg(feature = "mesh")]
mod catalog;
mod dial;
#[cfg(feature = "mesh")]
mod dial_gate;
mod enrolment;
mod freeze;
mod host;
mod removal_delivery;
#[cfg(feature = "mesh")]
mod renewal;
#[cfg(feature = "mesh")]
mod route;
#[cfg(feature = "mesh")]
mod selector;
#[cfg(feature = "mesh")]
mod url;
use dial::Dial;
#[cfg(feature = "mesh")]
pub(crate) use dial_gate::standing;
use enrolment::EnrolmentSource;
pub(crate) use enrolment::{Enrolled, EnrolmentFiles, enrol, enrolment_vault_id, home_bind, join};
pub(crate) use freeze::ReapFreeze;
use host::Host;
#[cfg(feature = "mesh")]
use selector::residence_selector;
#[cfg(feature = "mesh")]
use url::direct;

/// The running connection to the home.
#[cfg_attr(not(feature = "mesh"), allow(dead_code))]
pub(crate) struct DeviceSyncHost {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
    /// The archive receiver, kept after membership loss (FIX 3396).
    removal: Option<removal_delivery::Receiver>,
    /// Whether the link to the home opened; a host kept for its archive
    /// receiver alone has none (L7-47).
    linked: bool,
    /// Whether the link dials the vault's other machines while its home is
    /// down, read by the test door (L7-47).
    #[cfg(oneiron_test_support)]
    dials_peers: bool,
}

impl DeviceSyncHost {
    /// Dials this machine's home, when it has one and may: an enrolled
    /// machine, with the home a live machine. Otherwise one "disabled" line
    /// says why, and serve runs on without it.
    pub(crate) async fn start(
        server: &Arc<SyncServer>,
        config: &ServeConfig,
        mesh: Option<&MeshHost>,
    ) -> Option<Self> {
        let dial = Self::dial(server, config, EnrolmentSource::Plain)?;
        Self::open_logged(Host::Served(server), dial, mesh, ReapFreeze::never()).await
    }

    /// [`Self::start`] on a managed vault, under its reap `freeze`: the
    /// opening writes hold an admission taken before the home is held, and
    /// each batch, refresh and write after them holds its own (FIX 12036). A
    /// frozen vault starts none; it says so, and serve runs on without it.
    /// Its enrolment is the one beside the supervisor's key directory, if any.
    pub(crate) async fn start_admitted(
        server: &Arc<SyncServer>,
        config: &ServeConfig,
        mesh: Option<&MeshHost>,
        freeze: ReapFreeze,
    ) -> Option<Self> {
        let dial = Self::dial(server, config, EnrolmentSource::Managed)?;
        let Some(_opening) = freeze.admit() else {
            tracing::warn!(
                "device sync disabled: the vault is paused for reap preparation; it starts with \
                 the next serve"
            );
            server
                .vault
                .record_device_sync_start(DeviceSyncStart::FrozenForReap);
            return None;
        };
        Self::open_logged(Host::Served(server), dial, mesh, freeze).await
    }

    /// What this machine dials, its enrolment looked for where `source`
    /// says, or `None` with the one line that says why.
    fn dial(server: &SyncServer, config: &ServeConfig, source: EnrolmentSource) -> Option<Dial> {
        Self::dial_result(&server.vault, Dial::resolve(server, config, source))
    }

    #[cfg(feature = "mesh")]
    fn dial_for_vault(
        vault: &Arc<oneiron::Vault>,
        config: &ServeConfig,
        source: EnrolmentSource,
    ) -> Option<Dial> {
        Self::dial_result(vault, Dial::resolve_for_vault(vault, config, source))
    }

    fn dial_result(vault: &oneiron::Vault, result: anyhow::Result<Option<Dial>>) -> Option<Dial> {
        match result {
            Ok(Some(dial)) => {
                if let Err(error) = vault.record_configured_device_residence(
                    oneiron::sync::SyncClientConfig::default().residence_mode,
                ) {
                    tracing::warn!(%error, "device sync residence could not be recorded");
                }
                Some(dial)
            }
            Ok(None) => {
                vault.record_device_sync_start(DeviceSyncStart::NotConfigured);
                None
            }
            Err(reason) => {
                tracing::warn!("device sync disabled: {reason:#}");
                vault.record_device_sync_start(DeviceSyncStart::ConfigurationFailed);
                None
            }
        }
    }

    /// The connection to `dial`'s home and its archive receiver, or, with the
    /// line that says why, the receiver alone or `None`. `freeze` admits the
    /// connection's batches and writes (FIX 12036) and each archive import
    /// (FIX 11796).
    async fn open_logged(
        host: Host<'_>,
        dial: Dial,
        mesh: Option<&MeshHost>,
        freeze: ReapFreeze,
    ) -> Option<Self> {
        // The receiver runs whether or not the link opens (FIX 3396), its
        // imports admitted under the same freeze as the connection (FIX 12038),
        // and those the freeze refused taken in again at its thaw (FIX 12154).
        let vault = Arc::clone(host.vault());
        #[cfg(feature = "mesh")]
        let removal =
            removal_delivery::Receiver::start(&dial, host.transport(mesh), &vault, freeze.clone());
        #[cfg(not(feature = "mesh"))]
        let removal = removal_delivery::Receiver::start(&dial, mesh, &vault, freeze.clone());
        match open(host, dial, mesh, freeze).await {
            Ok(host) => {
                vault.record_device_sync_start(DeviceSyncStart::Started);
                Some(host.with_removal(removal))
            }
            Err(reason) => {
                tracing::warn!("device sync disabled: {reason:#}");
                vault.record_device_sync_start(DeviceSyncStart::OpenFailed {
                    archive_receiver_running: removal.is_some(),
                });
                removal.map(Self::receiving)
            }
        }
    }

    /// Whether the link to the home opened, rather than only the archive
    /// receiver running (L7-47).
    #[cfg(feature = "mesh")]
    pub(crate) fn linked(&self) -> bool {
        self.linked
    }

    /// Whether the link dials the vault's other machines while its home is
    /// down: exactly when it opened with a mesh listener here (L7-47).
    #[cfg(all(oneiron_test_support, feature = "mesh"))]
    pub(crate) fn dials_peers(&self) -> bool {
        self.dials_peers
    }

    /// Stops the connection and waits for its loop, and any credential
    /// renewal under way, to end, so its channel detaches and its renewal
    /// is gone before the mesh it rides closes (FIX 5772).
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(());
        if let Err(error) = self.task.await {
            tracing::warn!(%error, "device sync task");
        }
        if let Some(removal) = self.removal {
            removal.stop().await;
        }
    }
}

/// Whether this machine dials a home: its `[device_sync]` section names one,
/// or `oneiron device enrol` recorded one. Its host is then a device of that
/// home: its Dreamer claims nothing, and its MACRO home candidacy is the one
/// its section's flags declare (FIX 4898).
pub(crate) fn dials_home(config: &ServeConfig, vault: &oneiron::Vault) -> bool {
    dials(config, vault, EnrolmentSource::Plain)
}

/// [`dials_home`] on a managed vault: an enrolment counts only beside the
/// supervisor's key directory, never under HOME or XDG (FIX 5768).
pub(crate) fn dials_home_managed(config: &ServeConfig, vault: &oneiron::Vault) -> bool {
    dials(config, vault, EnrolmentSource::Managed)
}

/// Whether `config` names a home, or an enrolment where `source` says
/// records one.
fn dials(config: &ServeConfig, vault: &oneiron::Vault, source: EnrolmentSource) -> bool {
    config.device_sync.is_some()
        || EnrolmentFiles::for_serve(&config.keystore, vault, source)
            .ok()
            .flatten()
            .is_some_and(|files| files.read().is_ok_and(|record| record.is_some()))
}

#[cfg(not(feature = "mesh"))]
async fn open(
    _host: Host<'_>,
    _dial: Dial,
    _mesh: Option<&MeshHost>,
    _freeze: ReapFreeze,
) -> anyhow::Result<DeviceSyncHost> {
    anyhow::bail!("this server was built without the `mesh` feature")
}

/// Holds the home and opens the connection to it. Each batch the connection
/// applies or sends, each catalog refresh and each candidacy write a catch-up
/// starts holds an admission of `freeze` (FIX 12036).
#[cfg(feature = "mesh")]
async fn open(
    host: Host<'_>,
    dial: Dial,
    mesh: Option<&MeshHost>,
    freeze: ReapFreeze,
) -> anyhow::Result<DeviceSyncHost> {
    use oneiron::sync::{SyncDialer, SyncPeerDialer};
    use oneiron_mesh_transport::sync_dialer::{MeshPeerDialer, MeshSyncDialer};

    let Dial {
        home,
        url,
        credential_file,
        home_node,
        pin,
        enrolled,
        always_on,
        primary,
    } = dial;
    let vault = Arc::clone(host.vault());
    let candidacy = host.candidacy(always_on, primary);
    let (machine, paired) = tokio::task::spawn_blocking(move || {
        declare_candidacy(&vault, home_node, candidacy)?;
        standing(&vault, home, enrolled)
    })
    .await??;
    // While the home is down the link dials this vault's other machines,
    // on the listener's transport, whether the home itself rides the mesh or
    // its URL (FIX 4748); no listener here, no peer.
    let listener = mesh;
    // Over the mesh when the home has a paired or enrolled (FIX 3374) address
    // and this host has a transport; otherwise at the home's URL.
    let transport = host
        .transport(mesh)
        .filter(|_| paired || mesh.is_some_and(|mesh| mesh.pins_home(home)));
    if transport.is_none() {
        direct(&url)?;
    }
    let credential =
        crate::commands::credential_file::PairedCredentialFile::read(&credential_file)?;
    // Each mesh dial targets the home the last committed election routes to
    // (FIX 3131); a move of it rebuilds the link, as a renewal does.
    let topology = home_node.map(|node| route::home_topology(node, home, &url));
    let routes = || {
        topology
            .as_ref()
            .map(oneiron::sync::HomeNodeTopology::home_route)
    };
    let resolve = route::resolver(Arc::clone(host.vault()), home, machine, routes());
    let moves = route::RouteChanges::new(
        transport.as_ref().and_then(|_| routes()),
        Arc::clone(&resolve),
    );
    let peer_dialer = listener.map(|listener| {
        Arc::new(MeshPeerDialer::new(
            listener.transport(),
            Arc::clone(host.vault()),
            machine,
            Arc::clone(&resolve),
        )) as Arc<dyn SyncPeerDialer>
    });
    #[cfg(oneiron_test_support)]
    let dials_peers = peer_dialer.is_some();
    let mesh_dialer = match transport.as_ref() {
        Some(transport) => Some(
            Arc::new(MeshSyncDialer::resolving(Arc::clone(transport), resolve))
                as Arc<dyn SyncDialer>,
        ),
        None => url::dialer(&url)?,
    };
    let link = Link {
        freeze: freeze.clone(),
        windows: host.windows(),
        topology,
        url,
        mesh_dialer,
        peer_dialer,
        pin,
        machine,
        candidacy,
        authority_caught_up: Arc::new(tokio::sync::Notify::new()),
    };
    let connection = link.connection(link.client_config(&credential)?)?;
    let renewal = renewal::Renewal::new(
        &link.url,
        credential_file,
        Arc::clone(host.vault()),
        link.mesh_dialer.clone(),
        Arc::clone(&link.authority_caught_up),
        moves,
    );
    let (stop, stop_rx) = oneshot::channel();
    let home = home.to_hex();
    let over = if transport.is_some() { "mesh" } else { "url" };
    let catalog = host.catalog(mesh.filter(|_| paired), &freeze);
    tracing::info!(machine = %machine.to_hex(), %home, over, "device sync started");
    // From here the link's client persists each root it learns from its home
    // to `d:root`, so the server merges that root before it exports its own
    // (SERVE-DEVICE-PEER-STALE-ROOT): serve's link and the macOS app's alike.
    host.server().mark_device_link_opened();
    let task = tokio::spawn(async move {
        // The observer is synchronous, so each status goes to the catalog
        // loop; the channel closes when the last connection's run ends.
        let (statuses, status_rx) = tokio::sync::mpsc::unbounded_channel();
        let dialing = link.run(connection, renewal, stop_rx, statuses, &home);
        // Off the mesh there are no other nodes to ask, so no catalog.
        let catalog = async {
            match catalog {
                Some(catalog) => catalog.run(status_rx, &home).await,
                None => drop(status_rx),
            }
        };
        tokio::join!(catalog, dialing);
    });
    Ok(DeviceSyncHost {
        stop,
        task,
        removal: None,
        linked: true,
        #[cfg(oneiron_test_support)]
        dials_peers,
    })
}

/// What each connection to the home is built from, but its credential.
#[cfg(feature = "mesh")]
struct Link {
    /// The reap freeze each run is admitted under and paused by.
    freeze: ReapFreeze,
    windows: Arc<oneiron::sync::WindowManager>,
    url: String,
    topology: Option<oneiron::sync::HomeNodeTopology>,
    mesh_dialer: Option<Arc<dyn oneiron::sync::SyncDialer>>,
    /// The carriers to this vault's other machines while the home is down
    /// (FIX 4748); `None` with no mesh listener here.
    peer_dialer: Option<Arc<dyn oneiron::sync::SyncPeerDialer>>,
    /// The checkpoint the enrolment's link pinned: the first authority
    /// catch-up adopts it, and a later connection finds it adopted.
    pin: Option<oneiron::authority::AuthorityCheckpointPin>,
    /// This machine: each connection registers under it, so the owner's
    /// residence rows reach this machine through it (FIX 531).
    machine: oneiron::EntityId,
    /// Served hosts re-declare their candidacy after authority catch-up.
    /// An app-only device never declares itself as a home candidate.
    candidacy: Option<Candidacy>,
    /// Signalled on each authority catch-up that takes rows, so a renewal
    /// that found this install not a machine of the vault yet is made again
    /// (FIX DEVICE-RENEWAL-REFUSED-BEFORE-FIRST-SYNC).
    authority_caught_up: Arc<tokio::sync::Notify>,
}

#[cfg(feature = "mesh")]
#[derive(Clone, Copy)]
struct Candidacy {
    always_on: bool,
    primary: bool,
    macro_ready: bool,
}

#[cfg(feature = "mesh")]
impl Link {
    /// The client configuration on `credential`. Its holder is the residence
    /// actor, so it binds the NOTE session as well as the transport.
    fn client_config(
        &self,
        credential: &crate::commands::credential_file::PairedCredentialFile,
    ) -> anyhow::Result<oneiron::sync::SyncClientConfig> {
        use oneiron::sync::client::NoteSyncSession;
        use oneiron::sync::{SyncClientConfig, SyncTransportCredential};

        let key = credential.signing_key()?;
        let selector = residence_selector(&credential.token)?;
        if selector.is_none() {
            tracing::info!(
                "device sync residence reads off: the paired credential names no own-device grant"
            );
        }
        Ok(SyncClientConfig {
            server_url: self.url.clone(),
            transport_credential: Some(SyncTransportCredential::new(
                credential.token.clone(),
                key.clone(),
            )),
            note_session: Some(NoteSyncSession::new(credential.token.clone(), key)),
            residence_selector: selector,
            home_node_topology: self.topology.clone(),
            mesh_dialer: self.mesh_dialer.clone(),
            peer_dialer: self.peer_dialer.clone(),
            authority_checkpoint_pin: self.pin.clone(),
            ..SyncClientConfig::default()
        })
    }

    fn connection(
        &self,
        client_config: oneiron::sync::SyncClientConfig,
    ) -> anyhow::Result<Arc<oneiron::sync::SyncConnection>> {
        let connection = oneiron::sync::SyncConnection::new(
            Arc::clone(&self.windows),
            oneiron::sync::ConnectionConfig {
                client_config,
                auto_reconnect: true,
            },
        )?;
        let freeze = batch_admission::FreezeAdmission(self.freeze.clone());
        let connection = Arc::new(connection.with_batch_admission(Arc::new(freeze)));
        crate::residence_machines::register(self.machine, &connection);
        Ok(connection)
    }

    /// Runs the connections ([`Self::run_connections`]), then ends a renewal
    /// still under way and waits for its end, however the last connection
    /// ended: no renewal request outlives the link (FIX 5772).
    async fn run(
        self,
        connection: Arc<oneiron::sync::SyncConnection>,
        mut renewal: renewal::Renewal,
        stop: oneshot::Receiver<()>,
        statuses: tokio::sync::mpsc::UnboundedSender<oneiron::sync::SyncStatus>,
        home: &str,
    ) {
        self.run_connections(connection, &mut renewal, stop, statuses, home)
            .await;
        renewal.stop().await;
    }

    /// Runs `connection` until `stop`, and again on each renewed credential
    /// (FIX 3377): the old connection stops and ends before the new one is
    /// built. Each connection's own loop reconnects with backoff. Every
    /// status goes to `statuses`, which closes when the last run ends.
    ///
    /// A reap freeze pauses the connection inside its own loop, its socket
    /// open, until the vault thaws (FIX 12036).
    ///
    /// A renewed credential is written here, never by the request that
    /// fetched it (FIX 3563). A stop sent before the write wins, and the file
    /// stays as it was; a write once begun ends before the stop is seen, and
    /// stays. The old connection stops only once the write has landed.
    async fn run_connections(
        self,
        mut connection: Arc<oneiron::sync::SyncConnection>,
        renewal: &mut renewal::Renewal,
        mut stop: oneshot::Receiver<()>,
        statuses: tokio::sync::mpsc::UnboundedSender<oneiron::sync::SyncStatus>,
        home: &str,
    ) {
        loop {
            let (config, committed) = {
                let (end, ended) = oneshot::channel();
                let observed = connection.run_observed(
                    ended,
                    observer(
                        home.to_owned(),
                        statuses.clone(),
                        Arc::clone(self.windows.vault()),
                        self.candidacy,
                        self.freeze.admission(),
                        Arc::clone(&self.authority_caught_up),
                    ),
                );
                tokio::pin!(observed);
                let next = loop {
                    tokio::select! {
                        biased;
                        _ = &mut stop => break RunEnd::Stop,
                        ran = &mut observed => {
                            stopped(home, ran);
                            return;
                        }
                        candidate = renewal.next() => {
                            // Configured before the write, so a credential
                            // that configures none leaves the file as it was.
                            let config = match self.client_config(&candidate.credential) {
                                Ok(config) => config,
                                Err(error) => {
                                    renewal.failed(&format!(
                                        "the renewed credential configures no connection: \
                                         {error:#}"
                                    ));
                                    continue;
                                }
                            };
                            // Nothing is awaited from this look to the
                            // write's end.
                            if stop_sent(&mut stop) {
                                break RunEnd::Stop;
                            }
                            if let Some(committed) = renewal.commit(&candidate) {
                                break RunEnd::Renewed(config, committed);
                            }
                        }
                    }
                };
                let _ = end.send(());
                let ran = observed.await;
                let (config, committed) = match next {
                    RunEnd::Stop => {
                        stopped(home, ran);
                        return;
                    }
                    RunEnd::Renewed(config, committed) => (config, committed),
                };
                if let Err(error) = ran {
                    tracing::warn!(%home, %error, "device sync ended on its old credential");
                }
                // A stop sent while the old connection ended opens no new
                // one; the renewed credential, already written, stays.
                if stop_sent(&mut stop) {
                    tracing::info!(%home, "device sync stopped");
                    return;
                }
                (config, committed)
            };
            drop(connection);
            connection = match self.connection(config) {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(
                        %home,
                        error = %format!("{error:#}"),
                        "device sync ended: no connection on the renewed credential"
                    );
                    return;
                }
            };
            match committed {
                renewal::CommitOutcome::Retargeted => {
                    tracing::info!(%home, "device sync reconnects on its moved route");
                }
                renewal::CommitOutcome::Renewed => {
                    tracing::info!(%home, "device sync reconnects on its renewed credential");
                }
            }
        }
    }
}

/// How a run ended short of its own end.
#[cfg(feature = "mesh")]
enum RunEnd {
    Stop,
    Renewed(oneiron::sync::SyncClientConfig, renewal::CommitOutcome),
}

/// A connection's event observer: each status to `statuses`, each error to
/// the log. An authority catch-up that took rows declares this machine's
/// MACRO home candidacy again off the async thread, so a freshly enrolled
/// device counts at once, not at its next start: under an admission of its
/// own from `admit`, and not while frozen. Such a catch-up also signals
/// `authority_caught_up`, frozen or not, so a credential renewal that found
/// this install not a machine of the vault yet is made again.
#[cfg(feature = "mesh")]
fn observer(
    home: String,
    statuses: tokio::sync::mpsc::UnboundedSender<oneiron::sync::SyncStatus>,
    vault: Arc<oneiron::Vault>,
    candidacy: Option<Candidacy>,
    admit: crate::server::HousekeepingAdmission,
    authority_caught_up: Arc<tokio::sync::Notify>,
) -> impl FnMut(oneiron::sync::SyncEvent) + Send {
    use oneiron::sync::SyncEvent;

    move |event| match event {
        SyncEvent::StatusChanged(status) => {
            tracing::debug!(%home, ?status, "device sync");
            let _ = statuses.send(status);
        }
        SyncEvent::AuthorityCaughtUp => {
            authority_caught_up.notify_one();
            let Some(candidacy) = candidacy else {
                return;
            };
            let Some(admitted) = admit() else {
                tracing::debug!(%home, "home candidacy left as it was: the vault is frozen");
                return;
            };
            let vault = Arc::clone(&vault);
            tokio::task::spawn_blocking(move || {
                let _admitted = admitted;
                crate::home_candidacy::declare(
                    &vault,
                    candidacy.always_on,
                    candidacy.primary,
                    candidacy.macro_ready,
                );
            });
        }
        SyncEvent::Error(error) => tracing::warn!(%home, %error, "device sync"),
        _ => {}
    }
}

/// Whether `stop` was sent, or its sender dropped, without waiting for it.
/// Once it says so, `stop` is spent: the caller ends without polling it.
#[cfg(feature = "mesh")]
fn stop_sent(stop: &mut oneshot::Receiver<()>) -> bool {
    !matches!(stop.try_recv(), Err(oneshot::error::TryRecvError::Empty))
}

/// How a connection's run ended.
#[cfg(feature = "mesh")]
fn stopped(home: &str, ran: Result<(), impl std::fmt::Display>) {
    match ran {
        Ok(()) => tracing::info!(%home, "device sync stopped"),
        Err(error) => tracing::warn!(%home, %error, "device sync ended"),
    }
}

/// The candidate a named or enrolled home stands as on this device:
/// always-on local, the one class a configured home claims with no cloud
/// attachment to prove.
#[cfg(feature = "mesh")]
const fn home_candidate(node: u64) -> oneiron::DreamerHomeNodeCandidate {
    oneiron::DreamerHomeNodeCandidate::always_on_local(node)
}

/// Declares this machine's own MACRO home candidacy (FIX 4898) from its
/// `[device_sync]` flags and whether its Dreamer runs (`macro_ready`), then
/// elects with the home it dials (`home_node`) as this device's own
/// candidate beside the vault's authorized candidates, before `standing`
/// reads the election: a Dreamer that claimed this install yields to that
/// home, and the home's own declaration, once it names the node, rules over
/// it. A failed election is logged and the connection still starts, as
/// being elected moves no dial.
#[cfg(feature = "mesh")]
fn declare_candidacy(
    vault: &oneiron::Vault,
    home_node: Option<u64>,
    candidacy: Option<Candidacy>,
) -> anyhow::Result<()> {
    let store = oneiron::DreamerRunnerStore::new(vault);
    anyhow::ensure!(
        home_node != Some(store.local_home_node_candidate(true, true, false)?.node_id),
        "home_node_id is this machine's own sync node id"
    );
    if let Some(candidacy) = candidacy {
        crate::home_candidacy::declare(
            vault,
            candidacy.always_on,
            candidacy.primary,
            candidacy.macro_ready,
        );
    }
    let now = oneiron_base::unix_seconds_now();
    let own: Vec<_> = home_node.map(home_candidate).into_iter().collect();
    if let Err(error) = store.elect_home_node(&own, now) {
        tracing::warn!(
            kind = ?error.kind(),
            "device sync left the MACRO home as it stood: the election failed"
        );
    }
    Ok(())
}
