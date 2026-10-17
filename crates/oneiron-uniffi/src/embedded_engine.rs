//! The embedded engine (OF-237): the full server `oneiron serve` runs,
//! inside the app's own process, over the vault at one path.
//!
//! [`EmbeddedEngine::start`] opens the vault the way `oneiron serve` does,
//! with the app's [`AppHostCallbacks`] as its host, and returns once the
//! app's `ready` has run. [`EmbeddedEngine::client`] binds an [`Oneiron`]
//! handle served by that server under the caller's own credential: each verb
//! POSTs the facade route through the server's Router over the in-process
//! transport (`oneiron_remote::InProcessTransport`), host doors included.
//! [`EmbeddedEngine::local_client`] attaches a handle to the same open vault
//! instead, bound to the embedded owner actor; neither opens the path again.
//! [`EmbeddedEngine::request`] sends the server one buffered HTTP/1.1
//! request, and [`EmbeddedEngine::open_connection`] opens an
//! [`EngineConnection`] the app holds, for `/ws` and streamed replies.
//!
//! The engine owns a multi-thread Tokio runtime and blocks on it from the
//! calling thread. Call its methods from app threads, never from inside an
//! [`AppHostCallbacks`] method: those calls are refused. Every handle from
//! `client` or `local_client` (and their `as_actor` / `in_room_turn`
//! children), and every connection, keeps the engine alive. Call `close`
//! from an app thread to stop it in order; an engine released unclosed
//! closes the same way on the releasing thread.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use oneiron_remote::{InProcessReply, InProcessRequest, InProcessTransport};
use oneiron_server::embedded::{
    BlockingConnection, BlockingEngine, EmbeddedRequest, embedded_serve_config, host_limits,
    unix_millis,
};
use oneiron_vault_contract::host_adapters::AppHost;
use zeroize::Zeroizing;

use crate::Oneiron;
use crate::codec::Lower;
use crate::dto::OpenOptions;
use crate::error::OneironError;

/// What the app brings its embedded engine. The engine calls these from its
/// own threads; an implementation must be safe to call from any thread and
/// must not call back into the engine.
#[uniffi::export(with_foreign)]
pub trait AppHostCallbacks: Send + Sync {
    /// One secret from the app keychain, by exact name; `None` when it
    /// holds none.
    fn keychain(&self, name: String) -> Option<Vec<u8>>;
    /// Arms the app's timer for `at_unix_ms`, or clears it on `None`. When
    /// the timer fires the app calls `EmbeddedEngine.wake`.
    fn schedule_wake(&self, at_unix_ms: Option<u64>);
    /// The engine opened its vault and takes requests.
    fn ready(&self);
}

/// The limits the app grants its engine; an absent one is unbounded.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct EngineLimits {
    /// Memory the engine may size its bounds from, in bytes.
    pub memory_bytes: Option<u64>,
    /// CPU time per second, in milliseconds.
    pub cpu_millis_per_second: Option<u32>,
}

/// One HTTP header, its value as bytes.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct EngineHeader {
    pub name: String,
    pub value: Vec<u8>,
}

/// One buffered HTTP/1.1 request to the embedded server.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct EngineRequest {
    pub method: String,
    /// Origin form: the path and query, such as `/.well-known/oneiron`.
    pub path: String,
    /// Sent as given; the caller brings its own auth. A request without a
    /// `Host` header is sent with `Host: localhost`.
    pub headers: Vec<EngineHeader>,
    pub body: Vec<u8>,
}

/// The embedded server's reply. A 4xx or 5xx status is a reply, not an
/// error.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct EngineReply {
    pub status: u16,
    pub headers: Vec<EngineHeader>,
    pub body: Vec<u8>,
}

/// The app's callbacks as the engine's host.
#[derive(Clone)]
struct ForeignHost(Arc<dyn AppHostCallbacks>);

impl AppHost for ForeignHost {
    fn keychain(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.0
            .keychain(name.to_owned())
            .map(Zeroizing::new)
            .ok_or_else(|| anyhow::anyhow!("no such secret in the app keychain: {name}"))
    }

    fn schedule_wake(&mut self, at: Option<SystemTime>) -> anyhow::Result<()> {
        self.0.schedule_wake(at.map(unix_millis));
        Ok(())
    }

    fn ready(&mut self) -> anyhow::Result<()> {
        self.0.ready();
        Ok(())
    }
}

/// The engine inside the app's process: the server, its workers, and the
/// one vault they and every attached handle share.
#[derive(uniffi::Object)]
pub struct EmbeddedEngine {
    engine: BlockingEngine<ForeignHost>,
    /// The options every attached handle names, so each attach agrees.
    options: oneiron_remote::OpenOptions,
}

#[uniffi::export]
impl EmbeddedEngine {
    /// Opens the vault at `path` and serves it in this process.
    ///
    /// The config is the one `oneiron serve --config <config_file>` would
    /// resolve, for this path, with `options.dimensions` when given. A relay
    /// host's config is refused before anything opens. `limits` absent, or
    /// either field absent, is unbounded. Returns once `host.ready` has run.
    /// Installs the engine panic hook first.
    #[uniffi::constructor]
    pub fn start(
        path: String,
        options: Option<OpenOptions>,
        config_file: Option<String>,
        host: Arc<dyn AppHostCallbacks>,
        limits: Option<EngineLimits>,
    ) -> Result<Arc<Self>, OneironError> {
        // Crash output never carries world text: the engine's hook goes in
        // before any vault opens (owner ruling 2026-10-14, fix 6).
        oneiron::panic_report::install_panic_hook();
        let dimensions: Option<usize> = options.and_then(|options| options.dimensions).lower()?;
        let path = PathBuf::from(path);
        let config =
            embedded_serve_config(&path, dimensions, config_file.as_deref().map(Path::new))
                .map_err(engine_failure)?;
        let limits = limits.unwrap_or_default();
        let limits = host_limits(limits.memory_bytes, limits.cpu_millis_per_second);
        let engine =
            BlockingEngine::start(ForeignHost(host), config, limits).map_err(engine_failure)?;
        Ok(Arc::new(Self {
            engine,
            options: oneiron_remote::OpenOptions { dimensions },
        }))
    }

    /// A NEW handle served by this engine's own server under `key`, the
    /// caller's credential, passed verbatim: the credential `pair` returned,
    /// or the host secret (the keychain's `auth_secret`) as a bare bearer.
    /// Every verb, `retry` and lens-frame call is the request a connected
    /// handle sends, credential and holder proof, room turn and invocation
    /// included, carried through the server's Router in process, so the
    /// host-door rows answer as on any server and the server decides each
    /// call from `key`. `as_actor` refuses on it, as on a connected handle.
    /// It keeps the engine alive and makes no request; a stopped engine
    /// refuses its verbs until `wake`.
    pub fn client(self: Arc<Self>, key: String) -> Result<Arc<Oneiron>, OneironError> {
        let transport = Arc::new(EngineTransport(Arc::clone(&self)));
        let inner = oneiron_remote::OneironClient::connect_in_process(transport, &key)?;
        Ok(Arc::new(Oneiron {
            inner,
            engine: Some(self),
        }))
    }

    /// A NEW handle on the engine's own vault, bound to the embedded owner
    /// actor, as `Oneiron.open` binds one: its verbs answer through the vault
    /// itself, not the server, so the host-door rows only a server's state
    /// answers refuse on it (use `client` for those). It keeps the engine
    /// alive. Ask again for each handle the app needs: each attaches anew,
    /// none reopens the path.
    pub fn local_client(self: Arc<Self>) -> Result<Arc<Oneiron>, OneironError> {
        let vault = self.engine.vault().map_err(engine_failure)?;
        let inner =
            oneiron_remote::OneironClient::attach(self.engine.path(), vault, &self.options)?;
        Ok(Arc::new(Oneiron {
            inner,
            engine: Some(self),
        }))
    }

    /// Opens a connection the app holds to the engine's server: one
    /// in-process stream it serves as a socket's connection, HTTP/1.1 with
    /// upgrades, so a `GET /ws` with its upgrade headers holds `/ws` on it
    /// and a streamed reply arrives as it is written. Refused while stopped;
    /// a stop drains it as it drains a socket's, so after `wake` open
    /// another. The connection keeps the engine alive.
    pub fn open_connection(self: Arc<Self>) -> Result<Arc<EngineConnection>, OneironError> {
        let connection = self.engine.connect().map_err(engine_failure)?;
        Ok(Arc::new(EngineConnection {
            connection,
            _engine: self,
        }))
    }

    /// Sends one request and returns the whole reply. Streaming and `/ws`
    /// are not served through it; open a connection for those.
    pub fn request(&self, request: EngineRequest) -> Result<EngineReply, OneironError> {
        let reply = self
            .engine
            .request(EmbeddedRequest {
                method: request.method,
                path: request.path,
                headers: request
                    .headers
                    .into_iter()
                    .map(|header| (header.name, header.value))
                    .collect(),
                body: request.body,
            })
            .map_err(engine_failure)?;
        Ok(EngineReply {
            status: reply.status,
            headers: reply
                .headers
                .into_iter()
                .map(|(name, value)| EngineHeader { name, value })
                .collect(),
            body: reply.body,
        })
    }

    /// The app's timer fired, or a push arrived: run what is due. A stopped
    /// engine serves again first, over the same vault.
    pub fn wake(&self) -> Result<(), OneironError> {
        self.engine.wake().map_err(engine_failure)
    }

    /// The app is backgrounding: drain, stop every worker, keep the vault
    /// open for the next `wake`.
    pub fn stop(&self) -> Result<(), OneironError> {
        self.engine.stop().map_err(engine_failure)
    }

    /// Stops the engine in order and releases its runtime. Handles from
    /// `client` keep the vault until they go; this engine refuses every
    /// later call.
    pub fn close(&self) -> Result<(), OneironError> {
        self.engine.close().map_err(engine_failure)
    }
}

/// One connection the app holds to its engine's server
/// ([`EmbeddedEngine::open_connection`]): bytes both ways. The app writes the
/// HTTP/1.1 request (bringing its own auth) and, after a `101`, the upgraded
/// protocol's frames; it reads what the server writes. A `send` and a
/// `receive` may block two app threads at once, and `close` from a third
/// returns the blocked `receive`. It keeps the engine alive; once the engine
/// stops or closes, `receive` returns empty and `send` refuses.
#[derive(uniffi::Object)]
pub struct EngineConnection {
    connection: BlockingConnection,
    _engine: Arc<EmbeddedEngine>,
}

#[uniffi::export]
impl EngineConnection {
    /// Writes all of `bytes` to the server, blocking until the connection
    /// has taken them. Refused once closed, or once the server has ended the
    /// connection.
    pub fn send(&self, bytes: Vec<u8>) -> Result<(), OneironError> {
        self.connection.send(&bytes).map_err(engine_failure)
    }

    /// The next bytes the server wrote, at most 64 KiB, blocking until some
    /// arrive. Empty once the server has ended the connection or `close`
    /// has run.
    pub fn receive(&self) -> Result<Vec<u8>, OneironError> {
        self.connection.receive().map_err(engine_failure)
    }

    /// Ends the app's side: a blocked `receive` returns empty, a later
    /// `send` refuses, and the server reads the end of the stream. Closing
    /// again does nothing.
    pub fn close(&self) -> Result<(), OneironError> {
        self.connection.close().map_err(engine_failure)
    }
}

/// The engine's own server as a served handle's transport: each exchange is
/// one buffered request through the engine, as `request` sends it.
struct EngineTransport(Arc<EmbeddedEngine>);

impl InProcessTransport for EngineTransport {
    fn exchange(&self, request: InProcessRequest) -> Result<InProcessReply, String> {
        let reply = self
            .0
            .engine
            .request(EmbeddedRequest {
                method: request.method,
                path: request.path,
                headers: request.headers,
                body: request.body,
            })
            .map_err(|error| format!("{error:#}"))?;
        Ok(InProcessReply {
            status: reply.status,
            headers: reply.headers,
            body: reply.body,
        })
    }
}

/// An engine failure, as the one error this surface raises.
fn engine_failure(error: anyhow::Error) -> OneironError {
    oneiron::MemoryError::new(
        oneiron::memory::MEMORY_CODE_INTERNAL,
        format!("{error:#}"),
        &[],
    )
    .into()
}
