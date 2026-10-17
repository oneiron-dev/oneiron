//! The device side of sync (ARCH-0023b): a machine that is not the elected
//! home dials its home and keeps its vault in sync there. It dials over the
//! paired mesh, on the mesh listener's own endpoint, and presents the paired
//! owner-grade credential its `[device_sync]` section names.
//!
//! One connection runs for the server's life. Its own loop reconnects with
//! backoff, so there is no second loop here. It attaches its outbound channel
//! beside the server's relay to its own clients, never in place of it. Logs
//! carry machine ids only, never a slip or a key.
//!
//! A named `home_node_id` makes the home this machine's elected home before
//! anything reads the election, and publishes it, with `home_url` as its
//! endpoint, as the connection's home-node topology. The paired credential
//! also binds each socket's NOTE session, and the own-device grant it names
//! selects what residence reads (index, first touch, promotion) may return.
//!
//! While the home connection is synced, the device also learns the models
//! the owner's other nodes offer (OF-575): it asks them on each sync and then
//! on a cadence, since no mesh signal says a peer's offer changed, and writes
//! their own-server rows.

use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::DeviceSyncConfig;
use crate::handler::mesh::MeshHost;
use crate::server::SyncServer;

/// The running connection to the home.
#[cfg_attr(not(feature = "mesh"), allow(dead_code))]
pub(crate) struct DeviceSyncHost {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl DeviceSyncHost {
    /// Dials the home `config` names, when it names one and this machine may:
    /// an enrolled machine that is not the elected home, with the home a live
    /// paired machine and a mesh listener to ride. Otherwise one "disabled"
    /// line says why, and serve runs on without it.
    pub(crate) async fn start(
        server: &Arc<SyncServer>,
        config: Option<&DeviceSyncConfig>,
        mesh: Option<&MeshHost>,
    ) -> Option<Self> {
        let config = config?;
        match open(server, config, mesh).await {
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

#[cfg(not(feature = "mesh"))]
async fn open(
    _server: &Arc<SyncServer>,
    _config: &DeviceSyncConfig,
    _mesh: Option<&MeshHost>,
) -> anyhow::Result<DeviceSyncHost> {
    anyhow::bail!("this server was built without the `mesh` feature")
}

#[cfg(feature = "mesh")]
async fn open(
    server: &Arc<SyncServer>,
    config: &DeviceSyncConfig,
    mesh: Option<&MeshHost>,
) -> anyhow::Result<DeviceSyncHost> {
    use oneiron::sync::client::NoteSyncSession;
    use oneiron::sync::{
        ConnectionConfig, SyncClientConfig, SyncConnection, SyncEvent, SyncTransportCredential,
    };
    use oneiron_mesh_transport::sync_dialer::MeshSyncDialer;

    let mesh = mesh
        .ok_or_else(|| anyhow::anyhow!("no mesh listener to dial from; set ONEIRON_MESH_BIND"))?;
    let home = config.home()?;
    let home_node = config.home_node_id;
    let vault = Arc::clone(&server.vault);
    let machine = tokio::task::spawn_blocking(move || {
        if let Some(node) = home_node {
            hold_home(&vault, node)?;
        }
        standing(&vault, home)
    })
    .await??;
    let credential =
        crate::commands::credential_file::PairedCredentialFile::read(&config.credential_file)?;
    let key = credential.signing_key()?;
    let selector = residence_selector(&credential.token)?;
    if selector.is_none() {
        tracing::info!(
            "device sync residence reads off: the paired credential names no own-device grant"
        );
    }
    let client_config = SyncClientConfig {
        server_url: config.home_url.clone(),
        transport_credential: Some(SyncTransportCredential::new(
            credential.token.clone(),
            key.clone(),
        )),
        // The paired credential's holder is the residence actor, so it binds
        // the NOTE session too.
        note_session: Some(NoteSyncSession::new(credential.token, key)),
        residence_selector: selector,
        followed_worlds: Some(config.followed_worlds()?),
        home_node_topology: home_node.map(|node| home_topology(node, &config.home_url)),
        mesh_dialer: Some(Arc::new(MeshSyncDialer::new(mesh.transport(), home))),
        ..SyncClientConfig::default()
    };
    let connection = SyncConnection::new(
        Arc::clone(&server.reassert_manager),
        ConnectionConfig {
            client_config,
            auto_reconnect: true,
        },
    )?;
    let (stop, stop_rx) = oneshot::channel();
    let home = home.to_hex();
    let catalog = MeshCatalog {
        vault: Arc::clone(&server.vault),
        transport: mesh.transport(),
        backend: None,
    };
    tracing::info!(machine = %machine.to_hex(), %home, "device sync started");
    let task = tokio::spawn(async move {
        // The observer is synchronous, so each status goes to the catalog
        // loop; the channel closes when the connection's run ends.
        let (statuses, status_rx) = tokio::sync::mpsc::unbounded_channel();
        let observed = connection.run_observed(stop_rx, {
            let home = home.clone();
            move |event| match event {
                SyncEvent::StatusChanged(status) => {
                    tracing::debug!(%home, ?status, "device sync");
                    let _ = statuses.send(status);
                }
                SyncEvent::Error(error) => tracing::warn!(%home, %error, "device sync"),
                _ => {}
            }
        });
        let ((), ran) = tokio::join!(catalog.run(status_rx, &home), observed);
        match ran {
            Ok(()) => tracing::info!(%home, "device sync stopped"),
            Err(error) => tracing::warn!(%home, %error, "device sync ended"),
        }
    });
    Ok(DeviceSyncHost { stop, task })
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

/// The candidate a named home stands as: always-on local, the one class a
/// configured home claims with no cloud attachment to prove.
#[cfg(feature = "mesh")]
const fn home_candidate(node: u64) -> oneiron::DreamerHomeNodeCandidate {
    oneiron::DreamerHomeNodeCandidate::always_on_local(node)
}

/// Holds `node` as this install's elected home, before `standing` reads the
/// election: a Dreamer that claimed this install at start yields to the
/// home the config names.
#[cfg(feature = "mesh")]
fn hold_home(vault: &oneiron::Vault, node: u64) -> anyhow::Result<()> {
    let store = oneiron::DreamerRunnerStore::new(vault);
    anyhow::ensure!(
        store.local_home_node_candidate(true, true, false)?.node_id != node,
        "home_node_id is this machine's own sync node id"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    store.elect_home_node(&[home_candidate(node)], now)?;
    Ok(())
}

/// The connection's home-node topology: the one named home, reached at
/// `url`. It is the sync URL itself, so residence reads ride the same mesh
/// dialer.
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
    let claims = slip.claims();
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

/// This install's MACHINE, when it may dial `home`: enrolled and live, not
/// the elected home, and `home` a live machine with a paired mesh address.
#[cfg(feature = "mesh")]
fn standing(vault: &oneiron::Vault, home: oneiron::EntityId) -> anyhow::Result<oneiron::EntityId> {
    let live = |machine: &oneiron::authority::FoldedMachine| {
        machine.chains().any(|(_, chain)| chain.is_live())
    };
    let local = vault
        .local_machine()?
        .ok_or_else(|| anyhow::anyhow!("this install is not a machine yet"))?;
    anyhow::ensure!(
        local.profile.as_ref().is_some_and(live),
        "this machine is not enrolled live in the vault"
    );
    anyhow::ensure!(local.id != home, "home_machine names this machine");
    anyhow::ensure!(
        !oneiron::sync::residence::local_is_elected_home(vault)?,
        "this machine is the elected home, which dials no one (name the home's \
         sync_node_id as home_node_id to hold it as home instead)"
    );
    anyhow::ensure!(
        vault.mesh_machine(home)?.is_some(),
        "home_machine {} has no paired mesh address",
        home.to_hex()
    );
    anyhow::ensure!(
        vault.authority_fold()?.machine(home).is_some_and(live),
        "home_machine {} is not a live machine",
        home.to_hex()
    );
    Ok(local.id)
}
