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
//!
//! The app also reaches the engine as UniFFI's and the C ABI's hosts do
//! (FIX 4895): a buffered request on the API's origin or the artifact app's,
//! a connection it holds (`/ws` and streamed replies), and a local handle
//! attached to the engine's own vault. Each keeps the engine alive, and none
//! opens the vault again.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use oneiron::MemoryError;
use oneiron_remote::{InProcessReply, InProcessRequest, InProcessStream, InProcessTransport};
use oneiron_server::embedded::{
    BlockingConnection, BlockingEngine, EmbeddedReply, EmbeddedRequest, EngineErrorKind,
    ProcessHost, embedded_serve_config, engine_error_kind, engine_memory_error, host_limits,
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
    /// The options a local handle attaches to the engine's vault under: the
    /// ones it was started with.
    options: oneiron_remote::OpenOptions,
    /// Set once `close` begins: every local handle refuses its next call
    /// (FIX 4895).
    closed: Arc<AtomicBool>,
}

/// One header of a request to the engine or of its reply.
#[napi(object)]
pub struct NapiEngineHeader {
    pub name: String,
    pub value: Buffer,
}

/// One request the app sends its engine: the request a socket's client
/// would send, bringing its own auth.
#[napi(object)]
pub struct NapiEngineRequest {
    pub method: String,
    /// The path and query, e.g. `/v1/core/health`.
    pub path: String,
    pub headers: Option<Vec<NapiEngineHeader>>,
    pub body: Option<Buffer>,
}

/// The engine's whole reply to one request. A 4xx or 5xx status is a
/// reply, not an error.
#[napi(object)]
pub struct NapiEngineReply {
    pub status: u32,
    /// Every header the reply carried, repeats included.
    pub headers: Vec<NapiEngineHeader>,
    pub body: Buffer,
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
        let started = BlockingEngine::start(host, config, limits);
        let engine = engine_result(started, engine_memory_error)?;
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
    /// refuses `asActor` as any connected handle does, and keeps the engine
    /// alive.
    #[napi]
    pub fn client(&self, key: String) -> napi::Result<NativeClient> {
        let transport = Arc::new(EngineTransport(Arc::clone(&self.engine)));
        let inner = oneiron_remote::OneironClient::connect_in_process(transport, &key)
            .map_err(facade_error)?;
        Ok(NativeClient { inner, keep: None })
    }

    /// A NEW handle on the engine's own vault, bound to the embedded owner
    /// as `open` binds one (FIX 4895): its verbs answer through the vault
    /// itself, not the server, so the host-door rows only a server answers
    /// refuse on it (use `client` for those). It and every handle rebound
    /// from it keep the engine alive; each call attaches anew, and none
    /// reopens the path. Once the engine closes, each refuses
    /// `ENGINE_CLOSED`; a call already running finishes.
    #[napi]
    pub fn local_client(&self) -> napi::Result<NativeClient> {
        let vault = engine_result(self.engine.vault(), engine_memory_error)?;
        let closed = Arc::clone(&self.closed);
        let host_open: oneiron_remote::HostOpenCheck = Arc::new(move || {
            if closed.load(Ordering::Acquire) {
                return Err(engine_closed());
            }
            Ok(())
        });
        let attached = oneiron_remote::OneironClient::attach_while_open(
            self.engine.path(),
            vault,
            &self.options,
            host_open,
        );
        let inner = attached.map_err(facade_error)?;
        Ok(NativeClient {
            inner,
            keep: Some(Arc::clone(&self.engine) as Arc<dyn std::any::Any + Send + Sync>),
        })
    }

    /// Sends one request on the API's origin and returns the whole reply.
    /// `/ws` is not served through it, and a reply body past the buffered
    /// ceiling refuses; open a connection for those. Refused while stopped.
    #[napi]
    pub fn request(&self, request: NapiEngineRequest) -> napi::Result<NapiEngineReply> {
        let reply = self.engine.request(engine_request(request));
        Ok(engine_reply(engine_result(reply, engine_memory_error)?))
    }

    /// [`Self::request`] on the artifact app's own origin (`/a/`).
    #[napi]
    pub fn request_artifact(&self, request: NapiEngineRequest) -> napi::Result<NapiEngineReply> {
        let reply = self.engine.request_artifact(engine_request(request));
        Ok(engine_reply(engine_result(reply, engine_memory_error)?))
    }

    /// Opens a connection the app holds to the engine's server, served as a
    /// socket's connection, HTTP/1.1 with upgrades: a `GET /ws` with its
    /// upgrade headers holds `/ws` on it, and a streamed reply arrives as it
    /// is written. Refused while stopped; a stop drains it, so after `wake`
    /// open another. It keeps the engine alive.
    #[napi]
    pub fn connect(&self) -> napi::Result<NativeEngineConnection> {
        let connection = engine_result(self.engine.connect(), engine_memory_error)?;
        Ok(NativeEngineConnection {
            connection,
            _engine: Arc::clone(&self.engine),
        })
    }

    /// [`Self::connect`] on the artifact app's own origin (`/a/`), apart
    /// from the API's. Refused while stopped.
    #[napi]
    pub fn connect_artifact(&self) -> napi::Result<NativeEngineConnection> {
        let connection = self.engine.connect_artifact();
        let connection = engine_result(connection, engine_memory_error)?;
        Ok(NativeEngineConnection {
            connection,
            _engine: Arc::clone(&self.engine),
        })
    }

    /// Runs what is due; a stopped engine serves again first.
    #[napi]
    pub fn wake(&self) -> napi::Result<()> {
        engine_result(self.engine.wake(), engine_memory_error)
    }

    /// Drains, stops every worker and keeps the vault open for `wake`.
    #[napi]
    pub fn stop(&self) -> napi::Result<()> {
        engine_result(self.engine.stop(), engine_memory_error)
    }

    /// Stops the engine in order and releases its runtime; every handle it
    /// served refuses `ENGINE_CLOSED` from then on.
    #[napi]
    pub fn close(&self) -> napi::Result<()> {
        self.closed.store(true, Ordering::Release);
        let closed = self.engine.close();
        // A close refused before it began (off an app thread) closes nothing.
        if let Err(error) = &closed
            && matches!(engine_error_kind(error), EngineErrorKind::WrongThread)
        {
            self.closed.store(false, Ordering::Release);
        }
        engine_result(closed, engine_memory_error)
    }
}

/// One connection the app holds to its engine's server: bytes both ways.
/// The app writes the HTTP/1.1 request and, after a `101`, the upgraded
/// protocol's frames; it reads what the server writes. Each call blocks the
/// calling thread until it completes. It keeps the engine alive; once the
/// engine stops or closes, `receive` returns empty and `send` refuses.
#[napi]
pub struct NativeEngineConnection {
    connection: BlockingConnection,
    _engine: Arc<BlockingEngine<ProcessHost>>,
}

#[napi]
impl NativeEngineConnection {
    /// Writes `bytes` to the server.
    #[napi]
    pub fn send(&self, bytes: Buffer) -> napi::Result<()> {
        engine_result(self.connection.send(&bytes), engine_memory_error)
    }

    /// The next bytes the server wrote; empty once the connection ended.
    #[napi]
    pub fn receive(&self) -> napi::Result<Buffer> {
        Ok(engine_result(self.connection.receive(), engine_memory_error)?.into())
    }

    /// Ends the connection; a blocked `receive` returns empty.
    #[napi]
    pub fn close(&self) -> napi::Result<()> {
        engine_result(self.connection.close(), engine_memory_error)
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

/// An engine call's result, its failure as the facade's typed error
/// (`engine_memory_error`).
fn engine_result<T, E>(result: Result<T, E>, error: fn(&E) -> MemoryError) -> napi::Result<T> {
    result.map_err(|failure| facade_error(error(&failure)))
}

/// The app's request as the engine sends it.
fn engine_request(request: NapiEngineRequest) -> EmbeddedRequest {
    EmbeddedRequest {
        method: request.method,
        path: request.path,
        headers: request
            .headers
            .unwrap_or_default()
            .into_iter()
            .map(|header| (header.name, header.value.to_vec()))
            .collect(),
        body: request.body.map(|body| body.to_vec()).unwrap_or_default(),
    }
}

/// The engine's reply as the app reads it.
fn engine_reply(reply: EmbeddedReply) -> NapiEngineReply {
    NapiEngineReply {
        status: u32::from(reply.status),
        headers: reply
            .headers
            .into_iter()
            .map(|(name, value)| NapiEngineHeader {
                name,
                value: value.into(),
            })
            .collect(),
        body: reply.body.into(),
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
