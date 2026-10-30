//! The engine-backed served client (OF-237), behind the default-off `engine`
//! feature: the full server `oneiron serve` runs, inside this Python
//! process, over the vault at one path, and handles served by that server
//! under the caller's own credential.
//!
//! [`NativeEngine::start`] opens the vault the way `oneiron serve` does,
//! once. [`NativeEngine::client`] binds a `NativeClient` whose every verb is
//! the request a connected handle sends, carried through the server's Router
//! over the in-process transport UniFFI's `EmbeddedEngine.client` uses, host
//! doors included: the server decides each call from the caller's key, and
//! nothing opens the vault a second time. A long call (`vault.export`)
//! streams its reply.
//!
//! The process is the app: its keychain is the secrets it starts the engine
//! with ([`ProcessHost`]), and a serving engine wakes its own Dreamer.
//!
//! The app also reaches the engine as UniFFI's and the C ABI's hosts do
//! (FIX 4895): a buffered request on the API's origin or the artifact app's,
//! a connection it holds (`/ws` and streamed replies), and a local handle
//! attached to the engine's own vault. Each keeps the engine alive, and none
//! opens the vault again.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::MemoryError;
use oneiron_remote::{InProcessReply, InProcessRequest, InProcessStream, InProcessTransport};
use oneiron_server::embedded::{
    BlockingConnection, BlockingEngine, EmbeddedRequest, EngineErrorKind, ProcessHost,
    embedded_serve_config, engine_error_kind, engine_memory_error, host_limits,
};
use pyo3::prelude::*;

use crate::{NativeClient, raise};

/// The engine inside this process, shared by every handle it serves.
#[pyclass(frozen)]
pub(crate) struct NativeEngine {
    engine: Arc<BlockingEngine<ProcessHost>>,
    /// The options a local handle attaches to the engine's vault under: the
    /// ones it was started with.
    options: oneiron_remote::OpenOptions,
    /// Set once `close` begins: every local handle refuses its next call
    /// (FIX 4895).
    closed: Arc<AtomicBool>,
}

#[pymethods]
impl NativeEngine {
    /// Opens the vault at `path` and serves it in this process. The config
    /// is the one `oneiron serve --config <config_file>` resolves for this
    /// path, with `dimensions` when given. `secrets` is the host keychain
    /// (`auth_secret`, `vault_password`), by exact name. An absent limit is
    /// unbounded. Returns once the server is ready.
    #[staticmethod]
    #[pyo3(signature = (path, dimensions=None, config_file=None, secrets=None, memory_bytes=None, cpu_millis_per_second=None))]
    fn start(
        py: Python<'_>,
        path: PathBuf,
        dimensions: Option<usize>,
        config_file: Option<PathBuf>,
        secrets: Option<HashMap<String, Vec<u8>>>,
        memory_bytes: Option<u64>,
        cpu_millis_per_second: Option<u32>,
    ) -> PyResult<Self> {
        // Crash output never carries world text: the engine's hook goes in
        // before any vault opens (owner ruling 2026-10-14, fix 6).
        oneiron::panic_report::install_panic_hook();
        let host = ProcessHost::new(secrets.unwrap_or_default());
        let limits = host_limits(memory_bytes, cpu_millis_per_second);
        let engine = py
            .detach(|| {
                let config = embedded_serve_config(&path, dimensions, config_file.as_deref())?;
                BlockingEngine::start(host, config, limits)
            })
            .map_err(|error| raise(engine_memory_error(&error)))?;
        Ok(Self {
            engine: Arc::new(engine),
            options: oneiron_remote::OpenOptions {
                dimensions,
                device_class: None,
                hold_checkpoint_root_signer: false,
            },
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// A NEW handle served by this engine's server under `key`, the
    /// caller's own credential, passed verbatim: the credential `pair`
    /// returned, or the host secret as a bare bearer. It makes no request,
    /// refuses `as_actor` as any connected handle does, and keeps the engine
    /// alive.
    fn client(&self, key: String) -> PyResult<NativeClient> {
        let transport = Arc::new(EngineTransport(Arc::clone(&self.engine)));
        let inner =
            oneiron_remote::OneironClient::connect_in_process(transport, &key).map_err(raise)?;
        Ok(NativeClient { inner, keep: None })
    }

    /// A NEW handle on the engine's own vault, bound to the embedded owner
    /// as `open` binds one (FIX 4895): its verbs answer through the vault
    /// itself, not the server, so the host-door rows only a server answers
    /// refuse on it (use `client` for those). It and every handle rebound
    /// from it keep the engine alive; each call attaches anew, and none
    /// reopens the path. Once the engine closes, each refuses
    /// `ENGINE_CLOSED`; a call already running finishes.
    fn local_client(&self) -> PyResult<NativeClient> {
        let vault = self
            .engine
            .vault()
            .map_err(|error| raise(engine_memory_error(&error)))?;
        let closed = Arc::clone(&self.closed);
        let host_open: oneiron_remote::HostOpenCheck = Arc::new(move || {
            if closed.load(Ordering::Acquire) {
                return Err(engine_closed());
            }
            Ok(())
        });
        let inner = oneiron_remote::OneironClient::attach_while_open(
            self.engine.path(),
            vault,
            &self.options,
            host_open,
        )
        .map_err(raise)?;
        Ok(NativeClient {
            inner,
            keep: Some(Arc::clone(&self.engine) as Arc<dyn std::any::Any + Send + Sync>),
        })
    }

    /// Sends one request on the API's origin and returns the whole reply as
    /// `(status, headers, body)`. `/ws` is not served through it, and a reply
    /// body past the buffered ceiling refuses; open a connection for those.
    /// Refused while stopped.
    #[pyo3(signature = (method, path, headers=None, body=None))]
    fn request(
        &self,
        py: Python<'_>,
        method: String,
        path: String,
        headers: Option<Vec<(String, Vec<u8>)>>,
        body: Option<Vec<u8>>,
    ) -> PyResult<(u16, Vec<(String, Vec<u8>)>, Vec<u8>)> {
        let request = EmbeddedRequest {
            method,
            path,
            headers: headers.unwrap_or_default(),
            body: body.unwrap_or_default(),
        };
        let reply = py
            .detach(|| self.engine.request(request))
            .map_err(|error| raise(engine_memory_error(&error)))?;
        Ok((reply.status, reply.headers, reply.body))
    }

    /// [`Self::request`] on the artifact app's own origin (`/a/`).
    #[pyo3(signature = (method, path, headers=None, body=None))]
    fn request_artifact(
        &self,
        py: Python<'_>,
        method: String,
        path: String,
        headers: Option<Vec<(String, Vec<u8>)>>,
        body: Option<Vec<u8>>,
    ) -> PyResult<(u16, Vec<(String, Vec<u8>)>, Vec<u8>)> {
        let request = EmbeddedRequest {
            method,
            path,
            headers: headers.unwrap_or_default(),
            body: body.unwrap_or_default(),
        };
        let reply = py
            .detach(|| self.engine.request_artifact(request))
            .map_err(|error| raise(engine_memory_error(&error)))?;
        Ok((reply.status, reply.headers, reply.body))
    }

    /// Opens a connection the app holds to the engine's server, served as a
    /// socket's connection, HTTP/1.1 with upgrades: a `GET /ws` with its
    /// upgrade headers holds `/ws` on it, and a streamed reply arrives as it
    /// is written. Refused while stopped; a stop drains it, so after `wake`
    /// open another. It keeps the engine alive.
    fn connect(&self, py: Python<'_>) -> PyResult<NativeEngineConnection> {
        let connection = py
            .detach(|| self.engine.connect())
            .map_err(|error| raise(engine_memory_error(&error)))?;
        Ok(NativeEngineConnection {
            connection,
            _engine: Arc::clone(&self.engine),
        })
    }

    /// [`Self::connect`] on the artifact app's own origin (`/a/`), apart
    /// from the API's. Refused while stopped.
    fn connect_artifact(&self, py: Python<'_>) -> PyResult<NativeEngineConnection> {
        let connection = py
            .detach(|| self.engine.connect_artifact())
            .map_err(|error| raise(engine_memory_error(&error)))?;
        Ok(NativeEngineConnection {
            connection,
            _engine: Arc::clone(&self.engine),
        })
    }

    /// Runs what is due; a stopped engine serves again first.
    fn wake(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.engine.wake())
            .map_err(|error| raise(engine_memory_error(&error)))
    }

    /// Drains, stops every worker and keeps the vault open for `wake`.
    fn stop(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.engine.stop())
            .map_err(|error| raise(engine_memory_error(&error)))
    }

    /// Stops the engine in order and releases its runtime; every handle it
    /// served refuses `ENGINE_CLOSED` from then on.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        self.closed.store(true, Ordering::Release);
        let closed = py.detach(|| self.engine.close());
        // A close refused before it began (off an app thread) closes nothing.
        if let Err(error) = &closed
            && matches!(engine_error_kind(error), EngineErrorKind::WrongThread)
        {
            self.closed.store(false, Ordering::Release);
        }
        closed.map_err(|error| raise(engine_memory_error(&error)))
    }
}

/// One connection the app holds to its engine's server: bytes both ways.
/// The app writes the HTTP/1.1 request and, after a `101`, the upgraded
/// protocol's frames; it reads what the server writes. Each call blocks the
/// calling thread until it completes. It keeps the engine alive; once the
/// engine stops or closes, `receive` returns empty and `send` refuses.
#[pyclass(frozen)]
pub(crate) struct NativeEngineConnection {
    connection: BlockingConnection,
    _engine: Arc<BlockingEngine<ProcessHost>>,
}

#[pymethods]
impl NativeEngineConnection {
    /// Writes `bytes` to the server.
    fn send(&self, py: Python<'_>, bytes: Vec<u8>) -> PyResult<()> {
        py.detach(|| self.connection.send(&bytes))
            .map_err(|error| raise(engine_memory_error(&error)))
    }

    /// The next bytes the server wrote; empty once the connection ended.
    fn receive(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        py.detach(|| self.connection.receive())
            .map_err(|error| raise(engine_memory_error(&error)))
    }

    /// Ends the connection; a blocked `receive` returns empty.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.connection.close())
            .map_err(|error| raise(engine_memory_error(&error)))
    }
}

/// The refusal a closed engine's handles raise, as `engine_memory_error`
/// words the engine's own.
fn engine_closed() -> MemoryError {
    let kind = EngineErrorKind::Closed;
    MemoryError::new(
        kind.code(),
        "the embedded engine is closed",
        &[kind.suggestion()],
    )
}

/// The engine's own server as a served handle's transport: buffered as a
/// verb's reply is, streamed for a long call.
struct EngineTransport(Arc<BlockingEngine<ProcessHost>>);

impl InProcessTransport for EngineTransport {
    fn exchange(&self, request: InProcessRequest) -> Result<InProcessReply, MemoryError> {
        let reply = self
            .0
            .request(embedded_request(request))
            .map_err(|error| engine_memory_error(&error))?;
        Ok(InProcessReply {
            status: reply.status,
            headers: reply.headers,
            body: reply.body,
        })
    }

    fn exchange_streamed(&self, request: InProcessRequest) -> Result<InProcessStream, MemoryError> {
        let reply = self
            .0
            .request_streamed(embedded_request(request))
            .map_err(|error| engine_memory_error(&error))?;
        Ok(InProcessStream {
            status: reply.status,
            headers: reply.headers,
            body: Box::new(reply.body),
        })
    }
}

/// A served handle's request as the engine sends it.
fn embedded_request(request: InProcessRequest) -> EmbeddedRequest {
    EmbeddedRequest {
        method: request.method,
        path: request.path,
        headers: request.headers,
        body: request.body,
    }
}
