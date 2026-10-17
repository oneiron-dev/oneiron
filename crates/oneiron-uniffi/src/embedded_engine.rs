//! The embedded engine (OF-237): the full server `oneiron serve` runs,
//! inside the app's own process, over the vault at one path.
//!
//! [`EmbeddedEngine::start`] opens the vault the way `oneiron serve` does,
//! with the app's [`AppHostCallbacks`] as its host, and returns once the
//! app's `ready` has run. [`EmbeddedEngine::client`] attaches an [`Oneiron`]
//! handle to that same open vault, as often as the app asks; it never opens
//! the path again. [`EmbeddedEngine::request`] sends the server one
//! buffered HTTP/1.1 request.
//!
//! The engine owns a multi-thread Tokio runtime and blocks on it from the
//! calling thread. Call its methods from app threads, never from inside an
//! [`AppHostCallbacks`] method: those calls are refused. Every handle from
//! `client` (and their `as_actor` / `in_room_turn` children) keeps the
//! engine alive. Call `close` from an app thread to stop it in order; an
//! engine released unclosed closes the same way on the releasing thread.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use oneiron_server::embedded::{
    BlockingEngine, EmbeddedRequest, embedded_serve_config, host_limits, unix_millis,
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

    /// A NEW handle on the engine's own vault, bound to the embedded owner
    /// actor; it keeps the engine alive. Ask again for each handle the app
    /// needs: each attaches anew, none reopens the path.
    pub fn client(self: Arc<Self>) -> Result<Arc<Oneiron>, OneironError> {
        let vault = self.engine.vault().map_err(engine_failure)?;
        let inner =
            oneiron_remote::OneironClient::attach(self.engine.path(), vault, &self.options)?;
        Ok(Arc::new(Oneiron {
            inner,
            engine: Some(self),
        }))
    }

    /// Sends one request and returns the whole reply. Streaming and `/ws`
    /// are not served through it.
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

/// An engine failure, as the one error this surface raises.
fn engine_failure(error: anyhow::Error) -> OneironError {
    oneiron::MemoryError::new(
        oneiron::memory::MEMORY_CODE_INTERNAL,
        format!("{error:#}"),
        &[],
    )
    .into()
}
