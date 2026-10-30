//! The device side of sync (ARCH-0023b): a machine that is not the home
//! dials its home and keeps its vault in sync there. The home is the one
//! `oneiron device enrol` recorded ([`enrolment`]), or one its `[device_sync]`
//! section names by hand. It dials over the paired mesh, on the mesh
//! listener's own endpoint, when the home has a paired mesh address and a
//! listener runs here; otherwise at the home's URL, over `wss` (or `ws` to a
//! loopback host). Either way it presents the paired owner-grade credential.
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
//! While the home connection is synced, the device also learns the models
//! the owner's other nodes offer (OF-575): it asks them on each sync and then
//! on a cadence, since no mesh signal says a peer's offer changed, and writes
//! their own-server rows.
//!
//! On a managed vault (WILL-PLAN L14 row 14) the reap freeze governs the
//! connection ([`freeze`], FIX 5127): each run between freezes, and each
//! catalog refresh, holds an admission of its own, so an idle connection
//! keeps no reap away. A freeze pauses the run, and the same connection runs
//! again once the vault thaws; a reap that stops the process ends it as any
//! stop does. Its enrolment is looked for beside the supervisor's key
//! directory alone, never under HOME or XDG (FIX 5768).

use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::ServeConfig;
use crate::handler::mesh::MeshHost;
use crate::server::SyncServer;

#[cfg(feature = "mesh")]
mod catalog;
mod dial;
mod enrolment;
mod freeze;
mod removal_delivery;
#[cfg(feature = "mesh")]
mod renewal;
#[cfg(feature = "mesh")]
mod route;
use dial::Dial;
use enrolment::EnrolmentSource;
pub(crate) use enrolment::{EnrolmentFiles, enrol};
use freeze::Admitted;
pub(crate) use freeze::ReapFreeze;

/// The running connection to the home.
#[cfg_attr(not(feature = "mesh"), allow(dead_code))]
pub(crate) struct DeviceSyncHost {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
    /// The archive receiver, kept after membership loss (FIX 3396).
    removal: Option<removal_delivery::Receiver>,
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
        let freeze = ReapFreeze::never();
        let first = freeze.admit()?;
        Self::open_logged(server, dial, mesh, freeze, first).await
    }

    /// [`Self::start`] on a managed vault, under its reap `freeze`: the
    /// opening writes and the first run hold an admission taken before the
    /// home is held. A frozen vault starts none; it says so, and serve runs
    /// on without it. Its enrolment is the one beside the supervisor's key
    /// directory, if any.
    pub(crate) async fn start_admitted(
        server: &Arc<SyncServer>,
        config: &ServeConfig,
        mesh: Option<&MeshHost>,
        freeze: ReapFreeze,
    ) -> Option<Self> {
        let dial = Self::dial(server, config, EnrolmentSource::Managed)?;
        let Some(first) = freeze.admit() else {
            tracing::warn!(
                "device sync disabled: the vault is paused for reap preparation; it starts with \
                 the next serve"
            );
            return None;
        };
        Self::open_logged(server, dial, mesh, freeze, first).await
    }

    /// What this machine dials, its enrolment looked for where `source`
    /// says, or `None` with the one line that says why.
    fn dial(server: &SyncServer, config: &ServeConfig, source: EnrolmentSource) -> Option<Dial> {
        match Dial::resolve(server, config, source) {
            Ok(dial) => dial,
            Err(reason) => {
                tracing::warn!("device sync disabled: {reason:#}");
                None
            }
        }
    }

    /// The connection to `dial`'s home and its archive receiver, or, with the
    /// line that says why, the receiver alone or `None`. `first` is the
    /// first run's admission; `freeze` also admits each archive import (FIX
    /// 11796).
    async fn open_logged(
        server: &Arc<SyncServer>,
        dial: Dial,
        mesh: Option<&MeshHost>,
        freeze: ReapFreeze,
        first: Admitted,
    ) -> Option<Self> {
        // The receiver runs whether or not the link opens (FIX 3396), its
        // imports admitted under the same freeze as the run (FIX 12038).
        let removal =
            removal_delivery::Receiver::start(&dial, mesh, &server.vault, freeze.clone());
        match open(server, dial, mesh, freeze, first).await {
            Ok(host) => Some(host.with_removal(removal)),
            Err(reason) => {
                tracing::warn!("device sync disabled: {reason:#}");
                removal.map(Self::receiving)
            }
        }
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
    _server: &Arc<SyncServer>,
    _dial: Dial,
    _mesh: Option<&MeshHost>,
    _freeze: ReapFreeze,
    _first: Admitted,
) -> anyhow::Result<DeviceSyncHost> {
    anyhow::bail!("this server was built without the `mesh` feature")
}

/// Holds the home and opens the connection to it. `first` was taken before
/// anything here writes; it moves into the first run and ends with it, and
/// a failed open drops it only once its own work has ended.
#[cfg(feature = "mesh")]
async fn open(
    server: &Arc<SyncServer>,
    dial: Dial,
    mesh: Option<&MeshHost>,
    freeze: ReapFreeze,
    first: Admitted,
) -> anyhow::Result<DeviceSyncHost> {
    use oneiron::sync::SyncDialer;
    use oneiron_mesh_transport::sync_dialer::MeshSyncDialer;

    let Dial {
        home,
        url,
        credential_file,
        worlds,
        home_node,
        pin,
        enrolled,
        always_on,
        primary,
    } = dial;
    let vault = Arc::clone(&server.vault);
    let macro_ready = server.ai.dreamer_runs();
    let (machine, paired) = tokio::task::spawn_blocking(move || {
        declare_candidacy(&vault, home_node, always_on, primary, macro_ready)?;
        standing(&vault, home, enrolled)
    })
    .await??;
    // Over the mesh when the home has a paired address and a listener runs
    // here; otherwise at the home's URL.
    let mesh = mesh.filter(|_| paired);
    if mesh.is_none() {
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
    let resolve = route::resolver(Arc::clone(&server.vault), home, machine, routes());
    let moves = route::RouteChanges::new(mesh.and_then(|_| routes()), Arc::clone(&resolve));
    let link = Link {
        freeze: freeze.clone(),
        windows: Arc::clone(&server.reassert_manager),
        topology,
        url,
        worlds,
        mesh_dialer: mesh.map(|mesh| {
            Arc::new(MeshSyncDialer::resolving(mesh.transport(), resolve)) as Arc<dyn SyncDialer>
        }),
        pin,
        machine,
        always_on,
        primary,
        macro_ready,
    };
    let connection = link.connection(link.client_config(&credential)?)?;
    let renewal = renewal::Renewal::new(
        &link.url,
        credential_file,
        Arc::clone(&server.vault),
        link.mesh_dialer.clone(),
        moves,
    );
    let (stop, stop_rx) = oneshot::channel();
    let home = home.to_hex();
    let over = if mesh.is_some() { "mesh" } else { "url" };
    let catalog = mesh.map(|mesh| {
        catalog::MeshCatalog::new(
            Arc::clone(&server.vault),
            mesh.transport(),
            server
                .ai
                .models()
                .mesh_routes(&server.vault, mesh.transport()),
            server.model_budgets.mesh_staging(),
            freeze.admission(),
        )
    });
    tracing::info!(machine = %machine.to_hex(), %home, over, "device sync started");
    let task = tokio::spawn(async move {
        // The observer is synchronous, so each status goes to the catalog
        // loop; the channel closes when the last connection's run ends.
        let (statuses, status_rx) = tokio::sync::mpsc::unbounded_channel();
        let dialing = link.run(connection, renewal, stop_rx, statuses, first, &home);
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
    })
}

/// What each connection to the home is built from, but its credential.
#[cfg(feature = "mesh")]
struct Link {
    /// The reap freeze each run is admitted under and paused by.
    freeze: ReapFreeze,
    windows: Arc<oneiron::sync::WindowManager>,
    url: String,
    worlds: Vec<oneiron::EntityId>,
    topology: Option<oneiron::sync::HomeNodeTopology>,
    mesh_dialer: Option<Arc<dyn oneiron::sync::SyncDialer>>,
    /// The checkpoint the enrolment's link pinned: the first authority
    /// catch-up adopts it, and a later connection finds it adopted.
    pin: Option<oneiron::authority::AuthorityCheckpointPin>,
    /// This machine: each connection registers under it, so the owner's
    /// residence rows reach this machine through it (FIX 531).
    machine: oneiron::EntityId,
    /// This machine's MACRO home candidacy as open declared it: an authority
    /// catch-up that took rows declares it again (FIX 5572).
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
            followed_worlds: Some(self.worlds.clone()),
            home_node_topology: self.topology.clone(),
            mesh_dialer: self.mesh_dialer.clone(),
            authority_checkpoint_pin: self.pin.clone(),
            ..SyncClientConfig::default()
        })
    }

    fn connection(
        &self,
        client_config: oneiron::sync::SyncClientConfig,
    ) -> anyhow::Result<Arc<oneiron::sync::SyncConnection>> {
        let connection = Arc::new(oneiron::sync::SyncConnection::new(
            Arc::clone(&self.windows),
            oneiron::sync::ConnectionConfig {
                client_config,
                auto_reconnect: true,
            },
        )?);
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
        first: Admitted,
        home: &str,
    ) {
        self.run_connections(connection, &mut renewal, stop, statuses, first, home)
            .await;
        renewal.stop().await;
    }

    /// Runs `connection` until `stop`, and again on each renewed credential
    /// (FIX 3377): the old connection stops and ends before the new one is
    /// built. Each connection's own loop reconnects with backoff. Every
    /// status goes to `statuses`, which closes when the last run ends.
    ///
    /// Each run holds an admission of the reap freeze, `first` for the
    /// first. A freeze pauses the run: it ends as a stop ends it, its
    /// admission drops, and once the vault thaws the same connection runs
    /// again on a fresh one. A stop while paused ends it there.
    ///
    /// A renewed credential is written here, never by the request that
    /// fetched it (FIX 3563). A stop sent before the write wins, and the file
    /// stays as it was; a write once begun ends before the stop is seen, and
    /// stays. The old connection stops only once the write has landed.
    async fn run_connections(
        mut self,
        mut connection: Arc<oneiron::sync::SyncConnection>,
        renewal: &mut renewal::Renewal,
        mut stop: oneshot::Receiver<()>,
        statuses: tokio::sync::mpsc::UnboundedSender<oneiron::sync::SyncStatus>,
        first: Admitted,
        home: &str,
    ) {
        // Dropped only once the run it admits has ended; none while paused.
        let mut _admitted = Some(first);
        loop {
            let (config, committed) = {
                let (end, ended) = oneshot::channel();
                let observed = connection.run_observed(
                    ended,
                    observer(
                        home.to_owned(),
                        statuses.clone(),
                        Arc::clone(self.windows.vault()),
                        self.always_on,
                        self.primary,
                        self.macro_ready,
                        self.freeze.admission(),
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
                        () = self.freeze.frozen() => break RunEnd::Pause,
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
                    RunEnd::Pause => {
                        if let Err(error) = ran {
                            tracing::warn!(%home, %error, "device sync ended at the reap pause");
                        }
                        _admitted = None;
                        tracing::info!(%home, "device sync paused: the vault is frozen for reap");
                        let Some(admitted) = self.freeze.resumed(&mut stop).await else {
                            tracing::info!(%home, "device sync stopped");
                            return;
                        };
                        _admitted = Some(admitted);
                        tracing::info!(%home, "device sync resumes: the vault thawed");
                        continue;
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
            // The renewed run takes an admission of its own, as every run
            // between freezes does: the old one goes first, and a vault
            // frozen meanwhile is waited out (FIX 5127).
            _admitted = None;
            _admitted = match self.freeze.admit() {
                Some(admitted) => Some(admitted),
                None => {
                    tracing::info!(%home, "device sync paused: the vault is frozen for reap");
                    let Some(admitted) = self.freeze.resumed(&mut stop).await else {
                        tracing::info!(%home, "device sync stopped");
                        return;
                    };
                    tracing::info!(%home, "device sync resumes: the vault thawed");
                    Some(admitted)
                }
            };
        }
    }
}

/// How a run ended short of its own end.
#[cfg(feature = "mesh")]
enum RunEnd {
    Stop,
    /// The vault froze for reap.
    Pause,
    Renewed(oneiron::sync::SyncClientConfig, renewal::CommitOutcome),
}

/// A connection's event observer: each status to `statuses`, each error to
/// the log. An authority catch-up that took rows declares this machine's
/// MACRO home candidacy again off the async thread, so a freshly enrolled
/// device counts at once, not at its next start: under an admission of its
/// own from `admit`, as it may outlast the run, and not while frozen.
#[cfg(feature = "mesh")]
fn observer(
    home: String,
    statuses: tokio::sync::mpsc::UnboundedSender<oneiron::sync::SyncStatus>,
    vault: Arc<oneiron::Vault>,
    always_on: bool,
    primary: bool,
    macro_ready: bool,
    admit: crate::server::HousekeepingAdmission,
) -> impl FnMut(oneiron::sync::SyncEvent) + Send {
    use oneiron::sync::SyncEvent;

    move |event| match event {
        SyncEvent::StatusChanged(status) => {
            tracing::debug!(%home, ?status, "device sync");
            let _ = statuses.send(status);
        }
        SyncEvent::AuthorityCaughtUp => {
            let Some(admitted) = admit() else {
                tracing::debug!(%home, "home candidacy left as it was: the vault is frozen");
                return;
            };
            let vault = Arc::clone(&vault);
            tokio::task::spawn_blocking(move || {
                let _admitted = admitted;
                crate::home_candidacy::declare(&vault, always_on, primary, macro_ready);
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
    always_on: bool,
    primary: bool,
    macro_ready: bool,
) -> anyhow::Result<()> {
    let store = oneiron::DreamerRunnerStore::new(vault);
    anyhow::ensure!(
        home_node != Some(store.local_home_node_candidate(true, true, false)?.node_id),
        "home_node_id is this machine's own sync node id"
    );
    crate::home_candidacy::declare(vault, always_on, primary, macro_ready);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let own: Vec<_> = home_node.map(home_candidate).into_iter().collect();
    if let Err(error) = store.elect_home_node(&own, now) {
        tracing::warn!(
            kind = ?error.kind(),
            "device sync left the MACRO home as it stood: the election failed"
        );
    }
    Ok(())
}

/// What residence reads select: the own-device member grant the paired
/// credential names (`grant_ref`, provisioned at the home), for the
/// credential's holder, over every world that grant admits. `None` when the
/// credential names no grant.
#[cfg(feature = "mesh")]
fn residence_selector(token: &str) -> anyhow::Result<Option<oneiron::sync::SyncSelector>> {
    let slip = oneiron::authority::CapabilitySlip::from_token(token)?;
    let claims = &slip.claims;
    let Some(grant) = claims.grant_ref.as_deref() else {
        return Ok(None);
    };
    let grant = oneiron::EntityId::from_hex(grant)
        .map_err(|_| anyhow::anyhow!("the paired credential's grant_ref is not an entity id"))?;
    let holder = oneiron::EntityId::from_hex(&claims.holder_ref)
        .map_err(|_| anyhow::anyhow!("the paired credential's holder is not an actor"))?;
    Ok(Some(oneiron::sync::SyncSelector::new(
        grant,
        holder,
        oneiron::sync::SyncSelectorWorld::All,
        Vec::new(),
        Vec::new(),
    )))
}

/// A home dialed at its URL, off the mesh: `wss`, or `ws` to a loopback
/// host, as the NOTE session binds only over TLS or on this machine.
#[cfg(feature = "mesh")]
fn direct(url: &str) -> anyhow::Result<()> {
    let uri: axum::http::Uri = url
        .parse()
        .map_err(|_| anyhow::anyhow!("home_url is not a URL"))?;
    let loopback = uri.host().is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    anyhow::ensure!(
        uri.scheme_str() == Some("wss") || loopback,
        "the home has no paired mesh address here, and off the mesh its home_url must be \
         wss:// (or ws:// to a loopback host)"
    );
    Ok(())
}

/// This install's MACHINE, when it may dial `home`, and whether `home` has a
/// paired mesh address. It may when it is enrolled and live, and `home` is a
/// live machine; an elected MACRO home dials its home as any device does. A
/// machine `oneiron device enrol` added (`enrolled`) is enrolled at the home:
/// its own profile, and the home's, reach this vault on the first authority
/// catch-up. A profile the owner has not answered yet (an unanswered serving
/// install's own) counts here as no profile, so it dials and is dialled as
/// before it had one (selfprofile).
#[cfg(feature = "mesh")]
fn standing(
    vault: &oneiron::Vault,
    home: oneiron::EntityId,
    enrolled: bool,
) -> anyhow::Result<(oneiron::EntityId, bool)> {
    let live = |machine: &oneiron::authority::FoldedMachine| {
        machine.chains().any(|(_, chain)| chain.is_live())
    };
    let answered = |machine: &&oneiron::authority::FoldedMachine| {
        machine
            .chains()
            .any(|(_, chain)| chain.profile.role.answered())
    };
    let local = vault
        .local_machine()?
        .ok_or_else(|| anyhow::anyhow!("this install is not a machine yet"))?;
    match local.profile.as_ref().filter(answered) {
        Some(profile) => anyhow::ensure!(
            live(profile),
            "this machine is not enrolled live in the vault"
        ),
        None => anyhow::ensure!(
            enrolled,
            "this machine is not enrolled in the vault; `oneiron device enrol` enrols it"
        ),
    }
    anyhow::ensure!(local.id != home, "home_machine names this machine");
    match vault.authority_fold()?.machine(home).filter(answered) {
        Some(machine) => anyhow::ensure!(
            live(machine),
            "home_machine {} is not a live machine",
            home.to_hex()
        ),
        None => anyhow::ensure!(
            enrolled,
            "home_machine {} is not a machine of this vault",
            home.to_hex()
        ),
    }
    Ok((local.id, vault.mesh_machine(home)?.is_some()))
}
