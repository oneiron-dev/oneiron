//! The engine-backed served client (OF-237), behind the default-off `engine`
//! feature: the full server `oneiron serve` runs, inside this Node process,
//! over the vault at one path, and handles served by that server under the
//! caller's own credential.
//!
//! [`NativeEngine::start`] opens the vault the way `oneiron serve` does,
//! once. [`NativeEngine::client`] binds a [`NativeClient`] whose every verb is
//! the request a connected handle sends, carried through the server's Router
//! over the in-process transport UniFFI's `EmbeddedEngine.client` uses, host
//! doors included: the server decides each call from the caller's key, and
//! nothing opens the vault a second time. A long call (`vault.export`)
//! streams its reply.
//!
//! The process is the app: its keychain is the secrets it starts the engine
//! with ([`ProcessHost`]), and a serving engine wakes its own Dreamer.

use std::collections::HashMap;
use std::sync::Arc;

use napi_derive::napi;
use oneiron::MemoryError;
use oneiron_remote::{InProcessReply, InProcessRequest, InProcessStream, InProcessTransport};
use oneiron_server::embedded::{
    BlockingEngine, EmbeddedRequest, ProcessHost, embedded_serve_config, engine_memory_error,
    host_limits,
};

use super::super::numeric::dimensions_to_engine;
use super::NativeClient;
use crate::facade::{boundary_error, facade_error};

/// What `NativeEngine.start` takes besides the path.
#[napi(object)]
pub struct NapiEngineOptions {
    /// Embedding vector dimensions; omitted takes the config's.
    pub dimensions: Option<f64>,
    /// The `oneiron serve --config` file to resolve; omitted resolves none.
    pub config_file: Option<String>,
    /// The host keychain by exact name (`auth_secret`, `vault_password`),
    /// each value UTF-8.
    pub secrets: Option<HashMap<String, String>>,
    /// Memory the engine may size its bounds from, in bytes; omitted is
    /// unbounded.
    pub memory_bytes: Option<i64>,
    /// CPU time per second, in milliseconds; omitted is unbounded.
    pub cpu_millis_per_second: Option<u32>,
}

/// The engine inside this process, shared by every handle it serves.
#[napi]
pub struct NativeEngine {
    engine: Arc<BlockingEngine<ProcessHost>>,
}

#[napi]
impl NativeEngine {
    /// Opens the vault at `path` and serves it in this process; returns once
    /// the server is ready.
    #[napi(factory)]
    pub fn start(path: String, options: Option<NapiEngineOptions>) -> napi::Result<Self> {
        crate::facade::before_vault_open();
        let options = options.unwrap_or(NapiEngineOptions {
            dimensions: None,
            config_file: None,
            secrets: None,
            memory_bytes: None,
            cpu_millis_per_second: None,
        });
        let dimensions = options
            .dimensions
            .map(dimensions_to_engine)
            .transpose()
            .map_err(facade_error)?;
        let memory_bytes = options
            .memory_bytes
            .map(u64::try_from)
            .transpose()
            .map_err(|_| boundary_error("memoryBytes must not be negative".to_owned()))?;
        let host = ProcessHost::new(
            options
                .secrets
                .unwrap_or_default()
                .into_iter()
                .map(|(name, secret)| (name, secret.into_bytes())),
        );
        let config = embedded_serve_config(
            std::path::Path::new(&path),
            dimensions,
            options.config_file.as_deref().map(std::path::Path::new),
        )
        .map_err(|error| facade_error(engine_memory_error(&error)))?;
        let limits = host_limits(memory_bytes, options.cpu_millis_per_second);
        let engine = BlockingEngine::start(host, config, limits)
            .map_err(|error| facade_error(engine_memory_error(&error)))?;
        Ok(Self {
            engine: Arc::new(engine),
        })
    }

    /// A NEW handle served by this engine's server under `key`, the
    /// caller's own credential, passed verbatim: the credential `pair`
    /// returned, or the host secret as a bare bearer. It makes no request,
    /// refuses `asActor` as any connected handle does, and keeps the engine
    /// alive.
    #[napi]
    pub fn client(&self, key: String) -> napi::Result<NativeClient> {
        let transport = Arc::new(EngineTransport(Arc::clone(&self.engine)));
        let inner = oneiron_remote::OneironClient::connect_in_process(transport, &key)
            .map_err(facade_error)?;
        Ok(NativeClient { inner })
    }

    /// Runs what is due; a stopped engine serves again first.
    #[napi]
    pub fn wake(&self) -> napi::Result<()> {
        self.engine
            .wake()
            .map_err(|error| facade_error(engine_memory_error(&error)))
    }

    /// Drains, stops every worker and keeps the vault open for `wake`.
    #[napi]
    pub fn stop(&self) -> napi::Result<()> {
        self.engine
            .stop()
            .map_err(|error| facade_error(engine_memory_error(&error)))
    }

    /// Stops the engine in order and releases its runtime; every handle it
    /// served refuses `ENGINE_CLOSED` from then on.
    #[napi]
    pub fn close(&self) -> napi::Result<()> {
        self.engine
            .close()
            .map_err(|error| facade_error(engine_memory_error(&error)))
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
