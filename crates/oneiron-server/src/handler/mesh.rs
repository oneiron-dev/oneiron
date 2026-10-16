//! The paired-machine mesh listener (OF-535). Off unless the host names a bind
//! address (`ONEIRON_MESH_BIND`), and refused in a build without the `mesh`
//! feature. It binds this install's transport key, admits a connection only
//! from the paired machine its endpoint key names (`PairedMachineGrants`), and
//! routes each connection by its ALPN ([`mesh_routes`]).
//!
//! Sync (`oneiron/sync/1`) serves the very router the TCP listener serves, one
//! HTTP/1.1 connection per stream, so every slip, machine proof and grant check
//! runs unchanged. A mesh caller is always off this device: its requests carry
//! a peer address made from its endpoint key, never a loopback one.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;

/// Where the mesh listener binds; unset leaves it off.
const BIND_ENV: &str = "ONEIRON_MESH_BIND";
/// Comma-separated private relay URLs; unset is direct paths only.
const RELAYS_ENV: &str = "ONEIRON_MESH_RELAYS";

/// The mesh listener's settings, from the host's environment.
#[derive(Debug, Clone, Default)]
pub(crate) struct MeshConfig {
    bind: Option<SocketAddr>,
    relays: Vec<String>,
}

impl MeshConfig {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let bind = match std::env::var(BIND_ENV) {
            Ok(raw) if !raw.trim().is_empty() => Some(
                raw.trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{BIND_ENV} is not a socket address: {raw}"))?,
            ),
            _ => None,
        };
        let relays = std::env::var(RELAYS_ENV)
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|url| !url.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self { bind, relays })
    }
}

/// Starts the mesh listener when `config` names a bind address, serving
/// `app` for sync. `None` when it is off.
pub(crate) async fn start(
    server: Arc<crate::server::SyncServer>,
    config: &MeshConfig,
    app: &Router,
    header_read_timeout: Duration,
) -> anyhow::Result<Option<MeshHost>> {
    let Some(bind) = config.bind else {
        return Ok(None);
    };
    host::start(server, bind, &config.relays, app, header_read_timeout).await
}

#[cfg(not(feature = "mesh"))]
mod host {
    use super::{Arc, Duration, Router, SocketAddr};

    /// The listener a build without the `mesh` feature never runs.
    pub(crate) struct MeshHost;

    impl MeshHost {
        pub(crate) async fn stop(self) {}
    }

    pub(super) async fn start(
        _server: Arc<crate::server::SyncServer>,
        _bind: SocketAddr,
        _relays: &[String],
        _app: &Router,
        _header_read_timeout: Duration,
    ) -> anyhow::Result<Option<MeshHost>> {
        anyhow::bail!(
            "{} is set, but this server was built without the `mesh` feature",
            super::BIND_ENV
        )
    }
}

#[cfg(feature = "mesh")]
mod host {
    use std::future::Future;
    use std::net::{Ipv6Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use hyper::body::Incoming;
    use hyper_util::rt::{TokioIo, TokioTimer};
    use hyper_util::service::TowerToHyperService;
    use oneiron_llm_own_server::{LLM_ALPN, LlmMeshService};
    use oneiron_mesh_transport::iroh_transport::{IrohTransport, private_relay_map};
    use oneiron_mesh_transport::transport_key::TransportKey;
    use oneiron_mesh_transport::{
        AcceptPolicy, MeshConnection, MeshError, MeshFuture, MeshService, MeshTransport,
        PairedMachineGrants, SYNC_ALPN, VaultMachineRoster,
    };
    use oneiron_organ_host::{
        AskHandlers, HostConfig, ORGAN_ALPN, OrganHost, OrganRouter, OrganService,
    };
    use tokio::task::JoinHandle;

    /// How often the routes' ticks run.
    const TICK_EVERY: Duration = Duration::from_secs(30);

    /// Work a route needs done while the listener runs, such as re-driving
    /// jobs that wait for a node.
    pub(crate) type MeshTick =
        Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

    /// The route table: one service per ALPN, and the ticks the routes need.
    #[derive(Default)]
    pub(crate) struct MeshRoutes {
        routes: Vec<(Vec<u8>, Arc<dyn MeshService>)>,
        ticks: Vec<MeshTick>,
    }

    impl MeshRoutes {
        pub(crate) fn route(mut self, alpn: &[u8], service: Arc<dyn MeshService>) -> Self {
            self.routes.push((alpn.to_vec(), service));
            self
        }

        pub(crate) fn tick(mut self, tick: MeshTick) -> Self {
            self.ticks.push(tick);
            self
        }

        fn service(&self, alpn: &[u8]) -> Option<Arc<dyn MeshService>> {
            self.routes
                .iter()
                .find(|(name, _)| name == alpn)
                .map(|(_, service)| Arc::clone(service))
        }
    }

    /// Every protocol the mesh listener serves. Add a protocol's row here.
    pub(crate) fn mesh_routes(
        app: &Router,
        header_read_timeout: Duration,
        server: &Arc<crate::server::SyncServer>,
    ) -> MeshRoutes {
        let vault = &server.vault;
        // This machine's organ host serves the owner's other nodes, and its
        // calls that wait for a node are re-driven on the tick (OF-575).
        let organs = Arc::new(OrganHost::new(HostConfig::default()));
        let router = Arc::new(OrganRouter::new().with_local(Arc::clone(&organs)));
        MeshRoutes::default()
            .route(
                SYNC_ALPN,
                Arc::new(SyncRoute {
                    app: app.clone(),
                    header_read_timeout,
                }),
            )
            .route(
                ORGAN_ALPN,
                Arc::new(OrganService::new(organs, Arc::clone(vault))),
            )
            // This machine's models serve the owner's other nodes (OF-575).
            .route(
                LLM_ALPN,
                Arc::new(LlmMeshService::new(Arc::new(crate::api::MeshLlm(
                    Arc::clone(server),
                )))),
            )
            .tick(organ_redrive(router, Arc::clone(vault)))
    }

    /// Runs every held organ call a node can take now, on a blocking thread.
    fn organ_redrive(router: Arc<OrganRouter>, vault: Arc<oneiron::Vault>) -> MeshTick {
        Arc::new(move || -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let router = Arc::clone(&router);
            let vault = Arc::clone(&vault);
            Box::pin(async move {
                let ran = tokio::task::spawn_blocking(move || {
                    router.redrive_waiting(&vault, &AskHandlers::none())
                })
                .await;
                if let Ok(Err(error)) = ran {
                    tracing::warn!(%error, "organ redrive");
                }
            })
        })
    }

    /// The running mesh listener.
    pub(crate) struct MeshHost {
        transport: Arc<IrohTransport>,
        tasks: Vec<JoinHandle<()>>,
    }

    impl MeshHost {
        /// Stops accepting and closes the endpoint; connections end with it.
        pub(crate) async fn stop(self) {
            for task in &self.tasks {
                task.abort();
            }
            if let Err(error) = self.transport.shutdown().await {
                tracing::warn!(%error, "mesh listener shutdown");
            }
        }
    }

    pub(super) async fn start(
        server: Arc<crate::server::SyncServer>,
        bind: SocketAddr,
        relays: &[String],
        app: &Router,
        header_read_timeout: Duration,
    ) -> anyhow::Result<Option<MeshHost>> {
        let vault = Arc::clone(&server.vault);
        let (machine, key) = TransportKey::for_install(&vault)
            .map_err(|error| anyhow::anyhow!("mesh transport key: {error}"))?
            .ok_or_else(|| {
                anyhow::anyhow!("the mesh listener needs this install enrolled as a machine")
            })?;
        let routes = Arc::new(mesh_routes(app, header_read_timeout, &server));
        let policy = AcceptPolicy {
            roster: Arc::new(VaultMachineRoster(Arc::clone(&vault))),
            grants: Arc::new(PairedMachineGrants(vault)),
        };
        let relays =
            private_relay_map(relays).map_err(|_| anyhow::anyhow!("mesh relay URL refused"))?;
        let alpns = routes.routes.iter().map(|(alpn, _)| alpn.clone()).collect();
        let transport = Arc::new(
            IrohTransport::bind_paired(key, policy, alpns, bind, relays)
                .await
                .map_err(|error| anyhow::anyhow!("mesh listener bind {bind}: {error}"))?,
        );
        tracing::info!(%bind, machine = %machine.to_hex(), "mesh listening");
        let mut tasks = vec![tokio::spawn(accept_loop(
            Arc::clone(&transport),
            Arc::clone(&routes),
        ))];
        if !routes.ticks.is_empty() {
            let ticks = routes.ticks.clone();
            tasks.push(tokio::spawn(async move {
                let mut every = tokio::time::interval(TICK_EVERY);
                every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    every.tick().await;
                    for tick in &ticks {
                        tick().await;
                    }
                }
            }));
        }
        Ok(Some(MeshHost { transport, tasks }))
    }

    /// Hands each admitted connection to its ALPN's route. A connection whose
    /// grant went between the handshake and here is refused by the accept
    /// itself; one on an ALPN no route serves is closed.
    async fn accept_loop(transport: Arc<IrohTransport>, routes: Arc<MeshRoutes>) {
        loop {
            let connection = match transport.accept().await {
                Ok(connection) => connection,
                Err(MeshError::Unavailable) => return,
                Err(error) => {
                    tracing::debug!(%error, "mesh connection refused");
                    continue;
                }
            };
            let Some(service) = routes.service(connection.alpn()) else {
                connection.close();
                continue;
            };
            tokio::spawn(async move {
                let _ = service.serve(connection).await;
            });
        }
    }

    /// The peer address a mesh caller's requests carry: a unique local IPv6
    /// address made from its endpoint key, so per-address limits count each
    /// machine apart and the caller is never read as on this device.
    fn mesh_peer_address(endpoint_key: [u8; 32]) -> SocketAddr {
        let mut octets = [0u8; 16];
        octets[0] = 0xfd;
        octets[1..].copy_from_slice(&endpoint_key[..15]);
        SocketAddr::from((Ipv6Addr::from(octets), 0))
    }

    /// Sync over the mesh: each stream the peer opens is one HTTP/1.1
    /// connection to the server's router, upgrades included.
    struct SyncRoute {
        app: Router,
        header_read_timeout: Duration,
    }

    impl MeshService for SyncRoute {
        fn serve(&self, connection: Box<dyn MeshConnection>) -> MeshFuture<'_, ()> {
            Box::pin(async move {
                let peer = mesh_peer_address(connection.endpoint_key());
                loop {
                    let stream = connection.accept_duplex().await?;
                    let routes = TowerToHyperService::new(self.app.clone());
                    let service =
                        hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                            let mut request = request.map(Body::new);
                            request.extensions_mut().insert(ConnectInfo(peer));
                            hyper::service::Service::call(&routes, request)
                        });
                    let header_read_timeout = self.header_read_timeout;
                    tokio::spawn(async move {
                        let mut builder = hyper::server::conn::http1::Builder::new();
                        builder
                            .timer(TokioTimer::new())
                            .header_read_timeout(header_read_timeout);
                        // A closed or reset stream is the peer's business.
                        let _ = builder
                            .serve_connection(TokioIo::new(stream), service)
                            .with_upgrades()
                            .await;
                    });
                }
            })
        }
    }
}

pub(crate) use host::MeshHost;
