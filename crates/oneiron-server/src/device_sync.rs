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
//! On a managed vault (WILL-PLAN L14 row 14) the connection runs under one
//! admission of the reap freeze, taken before the home is held and kept
//! until its task ends: a frozen vault starts none, and while it runs, its
//! imports, renewals and catalog writes keep a reap from finding the vault
//! quiescent.

use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::ServeConfig;
use crate::handler::mesh::MeshHost;
use crate::server::{HousekeepingAdmission, SyncServer};

/// The admission a managed vault's connection holds for its whole run.
type Admission = Box<dyn Send>;

mod dial;
mod enrolment;
#[cfg(feature = "mesh")]
mod renewal;
use dial::Dial;
pub(crate) use enrolment::{EnrolmentFiles, enrol};

/// The running connection to the home.
#[cfg_attr(not(feature = "mesh"), allow(dead_code))]
pub(crate) struct DeviceSyncHost {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
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
        let dial = Self::dial(server, config)?;
        Self::open_logged(server, dial, mesh, None).await
    }

    /// [`Self::start`] on a managed vault: the connection, and every write
    /// it makes, run under one admission `admit` grants, taken before the
    /// home is held and kept until the connection's task ends. A frozen
    /// vault starts none; it says so, and serve runs on without it.
    pub(crate) async fn start_admitted(
        server: &Arc<SyncServer>,
        config: &ServeConfig,
        mesh: Option<&MeshHost>,
        admit: &HousekeepingAdmission,
    ) -> Option<Self> {
        let dial = Self::dial(server, config)?;
        let Some(admission) = admit() else {
            tracing::warn!(
                "device sync disabled: the vault is paused for reap preparation; it starts with \
                 the next serve"
            );
            return None;
        };
        Self::open_logged(server, dial, mesh, Some(admission)).await
    }

    /// What this machine dials, or `None` with the one line that says why.
    fn dial(server: &SyncServer, config: &ServeConfig) -> Option<Dial> {
        match Dial::resolve(server, config) {
            Ok(dial) => dial,
            Err(reason) => {
                tracing::warn!("device sync disabled: {reason:#}");
                None
            }
        }
    }

    /// The connection to `dial`'s home, or `None` with the line that says
    /// why. `admission`, when given, ends with the connection's task.
    async fn open_logged(
        server: &Arc<SyncServer>,
        dial: Dial,
        mesh: Option<&MeshHost>,
        admission: Option<Admission>,
    ) -> Option<Self> {
        match open(server, dial, mesh, admission).await {
            Ok(host) => Some(host),
            Err(reason) => {
                tracing::warn!("device sync disabled: {reason:#}");
                None
            }
        }
    }

    /// Stops the connection and waits for its loop to end, so its channel
    /// detaches before the mesh it rides closes.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(());
        if let Err(error) = self.task.await {
            tracing::warn!(%error, "device sync task");
        }
    }
}

/// Whether this machine dials a home: its `[device_sync]` section names one,
/// or `oneiron device enrol` recorded one. Its host is then a device of that
/// home: its Dreamer claims nothing, and its MACRO home candidacy is the one
/// its section's flags declare (FIX 4898).
pub(crate) fn dials_home(config: &ServeConfig, vault: &oneiron::Vault) -> bool {
    config.device_sync.is_some()
        || EnrolmentFiles::for_vault(&config.keystore, vault)
            .is_ok_and(|files| files.read().is_ok_and(|record| record.is_some()))
}

#[cfg(not(feature = "mesh"))]
async fn open(
    _server: &Arc<SyncServer>,
    _dial: Dial,
    _mesh: Option<&MeshHost>,
    _admission: Option<Admission>,
) -> anyhow::Result<DeviceSyncHost> {
    anyhow::bail!("this server was built without the `mesh` feature")
}

/// Holds the home and opens the connection to it. `admission`, a managed
/// vault's, was taken before anything here writes; it moves into the
/// connection's task and ends with it, and a failed open drops it only
/// once its own work has ended.
#[cfg(feature = "mesh")]
async fn open(
    server: &Arc<SyncServer>,
    dial: Dial,
    mesh: Option<&MeshHost>,
    admission: Option<Admission>,
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
    let link = Link {
        windows: Arc::clone(&server.reassert_manager),
        topology: home_node.map(|node| home_topology(node, &url)),
        url,
        worlds,
        mesh_dialer: mesh.map(|mesh| {
            Arc::new(MeshSyncDialer::new(mesh.transport(), home)) as Arc<dyn SyncDialer>
        }),
        pin,
        machine,
    };
    let connection = link.connection(link.client_config(&credential)?)?;
    let renewal = renewal::Renewal::new(
        &link.url,
        credential_file,
        Arc::clone(&server.vault),
        link.mesh_dialer.clone(),
    );
    let (stop, stop_rx) = oneshot::channel();
    let home = home.to_hex();
    let over = if mesh.is_some() { "mesh" } else { "url" };
    let catalog = mesh.map(|mesh| MeshCatalog {
        vault: Arc::clone(&server.vault),
        transport: mesh.transport(),
        backend: None,
        routes: server
            .ai
            .models()
            .mesh_routes(&server.vault, mesh.transport()),
    });
    tracing::info!(machine = %machine.to_hex(), %home, over, "device sync started");
    let task = tokio::spawn(async move {
        // Held through every run, reconnect, renewal and catalog refresh,
        // and dropped only once all of them end.
        let _admission = admission;
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
    Ok(DeviceSyncHost { stop, task })
}

/// What each connection to the home is built from, but its credential.
#[cfg(feature = "mesh")]
struct Link {
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

    /// Runs `connection` until `stop`, and again on each renewed credential
    /// (FIX 3377): the old connection stops and ends before the new one is
    /// built. Each connection's own loop reconnects with backoff. Every
    /// status goes to `statuses`, which closes when the last run ends.
    ///
    /// A renewed credential is written here, never by the request that
    /// fetched it (FIX 3563). A stop sent before the write wins, and the file
    /// stays as it was; a write once begun ends before the stop is seen, and
    /// stays. The old connection stops only once the write has landed.
    async fn run(
        self,
        mut connection: Arc<oneiron::sync::SyncConnection>,
        mut renewal: renewal::Renewal,
        mut stop: oneshot::Receiver<()>,
        statuses: tokio::sync::mpsc::UnboundedSender<oneiron::sync::SyncStatus>,
        home: &str,
    ) {
        loop {
            let config = {
                let (end, ended) = oneshot::channel();
                let observed =
                    connection.run_observed(ended, observer(home.to_owned(), statuses.clone()));
                tokio::pin!(observed);
                let renewed = loop {
                    tokio::select! {
                        biased;
                        _ = &mut stop => break None,
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
                                break None;
                            }
                            if renewal.commit(&candidate) {
                                break Some(config);
                            }
                        }
                    }
                };
                let _ = end.send(());
                let ran = observed.await;
                let Some(config) = renewed else {
                    stopped(home, ran);
                    return;
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
                config
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
            tracing::info!(%home, "device sync reconnects on its renewed credential");
        }
    }
}

/// A connection's event observer: each status to `statuses`, each error to
/// the log.
#[cfg(feature = "mesh")]
fn observer(
    home: String,
    statuses: tokio::sync::mpsc::UnboundedSender<oneiron::sync::SyncStatus>,
) -> impl FnMut(oneiron::sync::SyncEvent) + Send {
    use oneiron::sync::SyncEvent;

    move |event| match event {
        SyncEvent::StatusChanged(status) => {
            tracing::debug!(%home, ?status, "device sync");
            let _ = statuses.send(status);
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

/// How often a synced device asks the owner's other nodes for their models
/// again. A catalog is pulled, never pushed: no mesh signal says a peer's
/// roster entry or offer changed.
#[cfg(feature = "mesh")]
const MESH_CATALOG_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// The device's view of the models the owner's other nodes offer
/// ([`oneiron_llm_own_server::OwnServerBackend::refresh_from_mesh`]), over the
/// mesh listener's own transport.
#[cfg(feature = "mesh")]
struct MeshCatalog {
    vault: Arc<oneiron::Vault>,
    transport: Arc<dyn oneiron_mesh_transport::MeshTransport>,
    /// Built at the first refresh; a failed build is tried again at the next.
    backend:
        Option<oneiron_llm_own_server::OwnServerBackend<oneiron_llm_own_server::MeshLlmTransport>>,
    /// The router's routes to those models (FIX 3229), published after each
    /// refresh.
    routes: crate::models::MeshRoutes,
}

#[cfg(feature = "mesh")]
impl MeshCatalog {
    /// Refreshes on each `Synced`, then every [`MESH_CATALOG_EVERY`] while
    /// the connection stays synced. Ends when `statuses` closes, after any
    /// refresh in flight: its catalog call runs on a task of its own, so a
    /// dropped refresh would leave that call running past the mesh.
    async fn run(
        mut self,
        mut statuses: tokio::sync::mpsc::UnboundedReceiver<oneiron::sync::SyncStatus>,
        home: &str,
    ) {
        let mut synced = false;
        let mut every = tokio::time::interval(MESH_CATALOG_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                status = statuses.recv() => match status {
                    None => return,
                    Some(oneiron::sync::SyncStatus::Synced) => {
                        synced = true;
                        self.refresh(home).await;
                        every.reset();
                    }
                    Some(_) => synced = false,
                },
                _ = every.tick(), if synced => self.refresh(home).await,
            }
        }
    }

    async fn refresh(&mut self, home: &str) {
        use oneiron_llm_own_server::{MeshLlmTransport, OwnServerBackend, VaultLlmNodes};

        if self.backend.is_none() {
            let transport = MeshLlmTransport::new(
                Arc::clone(&self.transport),
                Arc::new(VaultLlmNodes(Arc::clone(&self.vault))),
                tokio::runtime::Handle::current(),
            );
            match OwnServerBackend::from_registry(&self.vault, transport) {
                Ok(backend) => self.backend = Some(backend),
                Err(error) => {
                    tracing::warn!(%home, %error, "mesh model catalog unavailable");
                    return;
                }
            }
        }
        let Some(backend) = &self.backend else {
            return;
        };
        match backend.refresh_from_mesh(&self.vault).await {
            Ok(refresh) => {
                self.routes.publish(&self.vault);
                if !refresh.conflicts.is_empty() {
                    tracing::warn!(
                        %home,
                        conflicts = ?refresh.conflicts,
                        "mesh model catalog kept the vault's own routes"
                    );
                }
                tracing::debug!(
                    %home,
                    written = ?refresh.written,
                    unreached = ?refresh.unreached,
                    "mesh model catalog refreshed"
                );
            }
            Err(error) => tracing::warn!(%home, %error, "mesh model catalog refresh failed"),
        }
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

/// The connection's home-node topology: the one named home, as this
/// device's own candidate beside the vault's authorized candidates, reached
/// at `url`, so residence reads go there while it is the elected home. It
/// is the sync URL itself, so residence reads ride the same mesh dialer.
#[cfg(feature = "mesh")]
fn home_topology(node: u64, url: &str) -> oneiron::sync::HomeNodeTopology {
    let home = home_candidate(node);
    let topology = oneiron::sync::HomeNodeTopology::new(vec![home]);
    topology.publish_with_endpoints(
        vec![home],
        std::collections::BTreeMap::from([(node, url.to_owned())]),
    );
    topology
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
