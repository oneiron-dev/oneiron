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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use oneiron::MemoryError;
use oneiron_remote::{InProcessReply, InProcessRequest, InProcessStream, InProcessTransport};
use oneiron_server::embedded::{
    BlockingEngine, EmbeddedRequest, ProcessHost, embedded_serve_config, engine_memory_error,
    host_limits,
};
use pyo3::prelude::*;

use crate::{NativeClient, raise};

/// The engine inside this process, shared by every handle it serves.
#[pyclass(frozen)]
pub(crate) struct NativeEngine {
    engine: Arc<BlockingEngine<ProcessHost>>,
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
        Ok(NativeClient { inner })
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
        py.detach(|| self.engine.close())
            .map_err(|error| raise(engine_memory_error(&error)))
    }
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
