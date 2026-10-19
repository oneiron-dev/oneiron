//! The paired-machine mesh listener (OF-535). Off unless the host names a bind
//! address (`ONEIRON_MESH_BIND`), and refused in a build without the `mesh`
//! feature. It binds this install's transport key, admits a connection only
//! from the paired machine its endpoint key names (`PairedMachineGrants`), and
//! routes each connection by its ALPN ([`mesh_routes`]).
//!
//! Sync (`oneiron/sync/1`) serves the very router the TCP listener serves, one
//! HTTP/1.1 connection per stream, so every slip, machine proof and grant check
//! runs unchanged. A mesh caller is always off this device: its requests carry
//! a peer address made from its endpoint key, never a loopback one, and the
//! MACHINE its handshake proved ([`MeshProvedMachine`]). The listener's own
//! connection floor, header timeout and body-idle limit are the TCP
//! listener's numbers; every mesh peer is a paired machine the handshake
//! admitted, so there is no stranger to give a share. Every connection and
//! refused attempt leaves a path receipt in the vault (`VaultPathReceipts`).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;

use crate::http_listener::ConnectionLimits;

/// Where the mesh listener binds; unset leaves it off.
const BIND_ENV: &str = "ONEIRON_MESH_BIND";
/// Comma-separated private relay URLs; unset is direct paths only.
const RELAYS_ENV: &str = "ONEIRON_MESH_RELAYS";

/// The MACHINE a mesh connection's handshake proved, on every request its
/// streams carry. A request off the TCP listener has none.
#[cfg_attr(not(feature = "mesh"), allow(dead_code))] // Only the mesh listener makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MeshProvedMachine(pub(crate) oneiron::EntityId);

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
    limits: ConnectionLimits,
) -> anyhow::Result<Option<MeshHost>> {
    let Some(bind) = config.bind else {
        return Ok(None);
    };
    host::start(server, bind, &config.relays, app, limits).await
}

#[cfg(not(feature = "mesh"))]
mod host {
    use super::{Arc, ConnectionLimits, Router, SocketAddr};

    /// The listener a build without the `mesh` feature never runs.
    pub(crate) struct MeshHost;

    impl MeshHost {
        pub(crate) async fn close_streams(&self) {}

        pub(crate) async fn end_streams(&self) {}

        pub(crate) async fn stop(self) {}
    }

    pub(super) async fn start(
        _server: Arc<crate::server::SyncServer>,
        _bind: SocketAddr,
        _relays: &[String],
        _app: &Router,
        _limits: ConnectionLimits,
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
    use std::pin::{Pin, pin};
    use std::sync::Arc;
    use std::time::Duration;

    use axum::Router;
    use axum::extract::ConnectInfo;
    use hyper::body::Incoming;
    use hyper_util::rt::{TokioIo, TokioTimer};
    use hyper_util::service::TowerToHyperService;
    use oneiron_llm_own_server::{LLM_ALPN, LlmMeshService};
    use oneiron_mesh_transport::iroh_transport::{IrohTransport, private_relay_map};
    use oneiron_mesh_transport::transport_key::TransportKey;
    use oneiron_mesh_transport::{
        AcceptPolicy, MeshConnection, MeshError, MeshFuture, MeshService, MeshTransport,
        PairedMachineGrants, SYNC_ALPN, VaultMachineRoster, VaultPathReceipts,
    };
    use oneiron_organ_host::{AskHandlers, ORGAN_ALPN, OrganRouter, OrganService};
    use tokio::sync::{Semaphore, watch};
    use tokio::task::{JoinHandle, JoinSet};

    use super::MeshProvedMachine;
    use crate::http_listener::ConnectionLimits;

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

    /// How far the mesh listener's stop has come (OF-237). It only moves
    /// forward.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Winding {
        /// Taking connections and streams.
        Serving,
        /// Taking none; each sync stream's HTTP connection ends once the
        /// request it carries has.
        Closing,
        /// Each sync stream still open ends where it is.
        Ended,
    }

    /// The mesh listener's stop, which its accept loop and its sync
    /// connections answer.
    pub(crate) struct MeshStop {
        winding: watch::Sender<Winding>,
        /// Each receiver subscribed to it is one sync connection's place: it
        /// is released once that connection's streams have all ended.
        sync_open: watch::Sender<()>,
    }

    impl MeshStop {
        fn new() -> Self {
            Self {
                winding: watch::Sender::new(Winding::Serving),
                sync_open: watch::Sender::new(()),
            }
        }

        /// Moves the stop on to `step`, never back, and returns once every
        /// sync connection has ended.
        async fn wind(&self, step: Winding) {
            self.winding.send_modify(|now| *now = (*now).max(step));
            self.sync_open.closed().await;
        }
    }

    /// Returns once the listener's stop has come to `step`, or once the
    /// listener is gone.
    async fn wound_to(winding: &mut watch::Receiver<Winding>, step: Winding) {
        let _ = winding.wait_for(|now| *now >= step).await;
    }

    /// Every protocol the mesh listener serves. Add a protocol's row here.
    pub(crate) fn mesh_routes(
        app: &Router,
        limits: ConnectionLimits,
        server: &Arc<crate::server::SyncServer>,
        stop: &Arc<MeshStop>,
    ) -> MeshRoutes {
        let vault = &server.vault;
        // This machine's organ host (the server's one, which the seal worker
        // shares) serves the owner's other nodes, and its calls that wait for
        // a node are re-driven on the tick (OF-575).
        let organs = Arc::clone(&server.organs);
        let router = Arc::new(OrganRouter::new().with_local(Arc::clone(&organs)));
        MeshRoutes::default()
            .route(
                SYNC_ALPN,
                Arc::new(SyncRoute {
                    app: app.clone(),
                    limits,
                    floor: Arc::new(Semaphore::new(limits.max_connections)),
                    stop: Arc::clone(stop),
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
            .tick(server.pack_organ_tick())
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
        stopping: Arc<MeshStop>,
        /// The accept loop, which owns each connection it admitted.
        accepts: JoinHandle<()>,
        /// The routes' ticks, when they have any.
        ticks: Option<JoinHandle<()>>,
    }

    impl MeshHost {
        /// The listener's transport, so a dialer rides this install's one
        /// endpoint rather than binding a second ([`crate::device_sync`]).
        pub(crate) fn transport(&self) -> Arc<dyn MeshTransport> {
            Arc::clone(&self.transport) as Arc<dyn MeshTransport>
        }

        /// Takes no more connections or sync streams, and returns once each
        /// sync stream's HTTP connection has ended after the request it
        /// carries (OF-237). A socket upgraded on one keeps its own place in
        /// the embedded drain. Connections on the other routes run on until
        /// [`Self::stop`]. Dropped before it returns, at the drain grace, it
        /// leaves the streams still open to [`Self::end_streams`].
        pub(crate) async fn close_streams(&self) {
            self.stopping.wind(Winding::Closing).await;
        }

        /// Takes no more, ends each sync stream still open where it is, and
        /// returns once all have ended.
        pub(crate) async fn end_streams(&self) {
            self.stopping.wind(Winding::Ended).await;
        }

        /// Stops the listener: its sync streams end, the ticks stop, the
        /// endpoint closes, and this returns once every connection the
        /// listener admitted has ended with it.
        pub(crate) async fn stop(self) {
            self.end_streams().await;
            if let Some(ticks) = self.ticks {
                ticks.abort();
                let _ = ticks.await;
            }
            if let Err(error) = self.transport.shutdown().await {
                tracing::warn!(%error, "mesh listener shutdown");
            }
            let _ = self.accepts.await;
        }
    }

    pub(super) async fn start(
        server: Arc<crate::server::SyncServer>,
        bind: SocketAddr,
        relays: &[String],
        app: &Router,
        limits: ConnectionLimits,
    ) -> anyhow::Result<Option<MeshHost>> {
        let vault = Arc::clone(&server.vault);
        let (machine, key) = TransportKey::for_install(&vault)
            .map_err(|error| anyhow::anyhow!("mesh transport key: {error}"))?
            .ok_or_else(|| {
                anyhow::anyhow!("the mesh listener needs this install enrolled as a machine")
            })?;
        // The installed packs' organs go on the host before it is offered.
        let installing = Arc::clone(&server);
        tokio::task::spawn_blocking(move || installing.install_pack_organs())
            .await
            .map_err(|error| anyhow::anyhow!("pack organ install: {error}"))?;
        let stopping = Arc::new(MeshStop::new());
        let routes = Arc::new(mesh_routes(app, limits, &server, &stopping));
        let policy = AcceptPolicy {
            roster: Arc::new(VaultMachineRoster(Arc::clone(&vault))),
            grants: Arc::new(PairedMachineGrants(Arc::clone(&vault))),
        };
        let relays =
            private_relay_map(relays).map_err(|_| anyhow::anyhow!("mesh relay URL refused"))?;
        let alpns = routes.routes.iter().map(|(alpn, _)| alpn.clone()).collect();
        let transport = Arc::new(
            IrohTransport::bind_paired(
                key,
                policy,
                alpns,
                bind,
                relays,
                Arc::new(VaultPathReceipts(vault)),
            )
            .await
            .map_err(|error| anyhow::anyhow!("mesh listener bind {bind}: {error}"))?,
        );
        server.mesh_transport.set(Arc::clone(&transport))
            .map_err(|_| anyhow::anyhow!("mesh endpoint is already attached to this server"))?;
        tracing::info!(%bind, machine = %machine.to_hex(), "mesh listening");
        let accepts = tokio::spawn(accept_loop(
            Arc::clone(&transport),
            Arc::clone(&routes),
            stopping.winding.subscribe(),
        ));
        let ticks = (!routes.ticks.is_empty()).then(|| {
            let ticks = routes.ticks.clone();
            tokio::spawn(async move {
                let mut every = tokio::time::interval(TICK_EVERY);
                every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    every.tick().await;
                    for tick in &ticks {
                        tick().await;
                    }
                }
            })
        });
        Ok(Some(MeshHost {
            transport,
            stopping,
            accepts,
            ticks,
        }))
    }

    /// Hands each admitted connection to its ALPN's route, as a task of its
    /// own set, reaped as it ends. A connection whose grant went between the
    /// handshake and here is refused by the accept itself; one on an ALPN no
    /// route serves is closed. Once the listener closes it takes no more, and
    /// it returns once each connection it admitted has ended: a sync one with
    /// its streams, the rest with the endpoint.
    async fn accept_loop(
        transport: Arc<IrohTransport>,
        routes: Arc<MeshRoutes>,
        mut winding: watch::Receiver<Winding>,
    ) {
        let mut connections = JoinSet::new();
        loop {
            let connection = tokio::select! {
                biased;
                () = wound_to(&mut winding, Winding::Closing) => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => continue,
                accepted = transport.accept() => match accepted {
                    Ok(connection) => connection,
                    Err(MeshError::Unavailable) => break,
                    Err(error) => {
                        tracing::debug!(%error, "mesh connection refused");
                        continue;
                    }
                },
            };
            let Some(service) = routes.service(connection.alpn()) else {
                connection.close();
                continue;
            };
            connections.spawn(async move {
                let _ = service.serve(connection).await;
            });
        }
        while connections.join_next().await.is_some() {}
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
    /// connection to the server's router, upgrades included, a task of the
    /// connection's own set. The streams held open at once stay under the TCP
    /// listener's connection floor, as a count of their own; past it, a new
    /// stream waits for a place. On the listener's stop it takes no more
    /// streams and ends with its open ones (OF-237).
    struct SyncRoute {
        app: Router,
        limits: ConnectionLimits,
        floor: Arc<Semaphore>,
        stop: Arc<MeshStop>,
    }

    impl MeshService for SyncRoute {
        fn serve(&self, connection: Box<dyn MeshConnection>) -> MeshFuture<'_, ()> {
            // The connection's place in the listener's stop, held until its
            // streams have ended. One whose task starts after the listener
            // closed takes no stream.
            let open = self.stop.sync_open.subscribe();
            let mut winding = self.stop.winding.subscribe();
            Box::pin(async move {
                let _open = open;
                let peer = mesh_peer_address(connection.endpoint_key());
                let machine = MeshProvedMachine(connection.machine());
                let mut streams = JoinSet::new();
                let ended = loop {
                    // A stream is reaped once it ends.
                    while streams.try_join_next().is_some() {}
                    let stream = tokio::select! {
                        biased;
                        () = wound_to(&mut winding, Winding::Closing) => break Ok(()),
                        stream = connection.accept_duplex() => match stream {
                            Ok(stream) => stream,
                            Err(error) => break Err(error),
                        },
                    };
                    let place = tokio::select! {
                        biased;
                        () = wound_to(&mut winding, Winding::Closing) => break Ok(()),
                        place = Arc::clone(&self.floor).acquire_owned() => match place {
                            Ok(place) => place,
                            Err(_) => break Err(MeshError::Unavailable),
                        },
                    };
                    let routes = TowerToHyperService::new(self.app.clone());
                    let body_idle = self.limits.body_idle_timeout;
                    let service =
                        hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                            let mut request = request
                                .map(|body| crate::http_listener::idle_body(body, body_idle));
                            request.extensions_mut().insert(ConnectInfo(peer));
                            request.extensions_mut().insert(machine);
                            hyper::service::Service::call(&routes, request)
                        });
                    let header_read_timeout = self.limits.header_read_timeout;
                    let mut stop = winding.clone();
                    streams.spawn(async move {
                        // The place is the stream's until it closes, upgrades
                        // included.
                        let _place = place;
                        let mut builder = hyper::server::conn::http1::Builder::new();
                        builder
                            .timer(TokioTimer::new())
                            .header_read_timeout(header_read_timeout);
                        let mut served = pin!(
                            builder
                                .serve_connection(TokioIo::new(stream), service)
                                .with_upgrades()
                        );
                        // A closed or reset stream is the peer's business.
                        // Once the listener closes, the connection ends after
                        // the request it carries.
                        let closing = tokio::select! {
                            _ = served.as_mut() => false,
                            () = wound_to(&mut stop, Winding::Closing) => true,
                        };
                        if closing {
                            served.as_mut().graceful_shutdown();
                            let _ = served.as_mut().await;
                        }
                    });
                };
                // The open streams end on their own, after their requests
                // once the listener closes, or where they are once it ends.
                tokio::select! {
                    () = async { while streams.join_next().await.is_some() {} } => {}
                    () = wound_to(&mut winding, Winding::Ended) => streams.shutdown().await,
                }
                ended
            })
        }
    }
}

pub(crate) use host::MeshHost;
