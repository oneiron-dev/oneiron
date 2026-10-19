//! The embedded engine for a binding whose callers are app threads
//! (OF-237): [`BlockingEngine`] runs an [`EmbeddedEngine`] on a runtime of
//! its own, and each of its calls, connections and streamed bodies blocks
//! the calling app thread on that runtime.

use std::io::Read;
use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use anyhow::Context as _;
use axum::body::Bytes;
use oneiron_vault_contract::host::HostLimits;
use oneiron_vault_contract::host_adapters::AppHost;
use tokio::runtime::{Handle, Runtime};

use super::engine::{
    EmbeddedBody, EmbeddedConnection, EmbeddedEngine, EmbeddedReply, EmbeddedRequest,
    ensure_app_thread,
};
use super::failure::{EngineErrorKind, cause, failure};
use crate::config::ServeConfig;

/// An [`EmbeddedConnection`] from a [`BlockingEngine`], whose calls block an
/// app thread on that engine's runtime.
///
/// Every method is refused from inside an async runtime
/// ([`ensure_app_thread`]). A send and a receive may block two app threads at
/// once, and a close from a third returns the waiting receive. No call holds
/// a lock on the engine while it waits, so the engine's stop or close goes
/// ahead and ends the connection: a receive then returns empty and a send is
/// refused.
pub struct BlockingConnection {
    connection: EmbeddedConnection,
    runtime: Handle,
}

impl BlockingConnection {
    /// [`EmbeddedConnection::send`].
    pub fn send(&self, bytes: &[u8]) -> anyhow::Result<()> {
        ensure_app_thread()?;
        self.runtime.block_on(self.connection.send(bytes))
    }

    /// [`EmbeddedConnection::receive`].
    pub fn receive(&self) -> anyhow::Result<Vec<u8>> {
        ensure_app_thread()?;
        self.runtime.block_on(self.connection.receive())
    }

    /// [`EmbeddedConnection::close`].
    pub fn close(&self) -> anyhow::Result<()> {
        ensure_app_thread()?;
        self.runtime.block_on(self.connection.close());
        Ok(())
    }
}

/// An engine and the runtime it runs on, while it runs.
struct Running<A> {
    engine: EmbeddedEngine<A>,
    runtime: Runtime,
}

impl<A: AppHost + Clone + 'static> Running<A> {
    /// The ordered stop, then the runtime, last.
    fn close(self) -> anyhow::Result<()> {
        let Self { engine, runtime } = self;
        let closed = runtime.block_on(engine.close());
        drop(runtime);
        closed
    }
}

/// An [`EmbeddedEngine`] on a multi-thread Tokio runtime it owns, for a
/// binding whose callers are app threads.
///
/// Every method blocks its caller and is refused from inside an async
/// runtime, an app host callback included ([`ensure_app_thread`]). Calls
/// may come from several app threads at once.
///
/// [`Self::close`] stops serving in order, then drops the runtime; call it
/// from an app thread. Dropped unclosed, it closes the same way on the
/// dropping thread, or, when that thread is inside a runtime, on a thread
/// of its own, so nothing blocks inside a runtime.
pub struct BlockingEngine<A: AppHost + Clone + 'static> {
    running: RwLock<Option<Running<A>>>,
    path: std::path::PathBuf,
    dimensions: usize,
}

impl<A: AppHost + Clone + 'static> BlockingEngine<A> {
    /// Starts an engine as [`EmbeddedEngine::start`] does, on a runtime of
    /// its own, whose worker threads the app's CPU share in `limits` caps
    /// (FIX 2661). The engine serves on that same runtime, so no second
    /// worker pool runs beside it.
    pub fn start(app: A, config: ServeConfig, limits: HostLimits) -> anyhow::Result<Self> {
        ensure_app_thread()?;
        let runtime =
            super::runtime::engine_runtime(super::runtime::worker_cap(limits)).context(cause(
                EngineErrorKind::StartFailed,
                "the embedded engine's runtime did not start",
            ))?;
        let engine =
            runtime.block_on(EmbeddedEngine::start_serving_on(app, config, limits, None))?;
        Ok(Self {
            path: engine.path().to_path_buf(),
            dimensions: engine.config().dimensions,
            running: RwLock::new(Some(Running { engine, runtime })),
        })
    }

    /// The vault's directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The embedding width the vault was opened with.
    pub fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// The open vault, to share; refused once closed.
    pub fn vault(&self) -> anyhow::Result<Arc<oneiron::Vault>> {
        self.with_running(|running| Ok(Arc::clone(running.engine.vault())))
    }

    /// [`EmbeddedEngine::request`].
    pub fn request(&self, request: EmbeddedRequest) -> anyhow::Result<EmbeddedReply> {
        self.with_running(|running| running.runtime.block_on(running.engine.request(request)))
    }

    /// [`EmbeddedEngine::request_streamed`]: returns once the reply's head
    /// arrives, its body a [`BlockingBody`] each read of which blocks on this
    /// engine's runtime. Refused once closed; a body read after the engine
    /// closed fails as a reply cut off.
    pub fn request_streamed(&self, request: EmbeddedRequest) -> anyhow::Result<BlockingReply> {
        self.with_running(|running| {
            let reply = running
                .runtime
                .block_on(running.engine.request_streamed(request))?;
            Ok(BlockingReply {
                status: reply.status,
                headers: reply.headers,
                body: BlockingBody {
                    body: reply.body,
                    pending: Bytes::new(),
                    ended: false,
                    runtime: running.runtime.handle().clone(),
                },
            })
        })
    }

    /// [`EmbeddedEngine::request_artifact`]: the artifact app's own origin.
    pub fn request_artifact(&self, request: EmbeddedRequest) -> anyhow::Result<EmbeddedReply> {
        self.with_running(|running| {
            running
                .runtime
                .block_on(running.engine.request_artifact(request))
        })
    }

    /// [`EmbeddedEngine::connect`], as a [`BlockingConnection`] on this
    /// engine's runtime. Refused once closed.
    pub fn connect(&self) -> anyhow::Result<BlockingConnection> {
        self.with_running(|running| {
            Ok(BlockingConnection {
                connection: running.runtime.block_on(running.engine.connect())?,
                runtime: running.runtime.handle().clone(),
            })
        })
    }

    /// [`EmbeddedEngine::connect_artifact`], as a [`BlockingConnection`] on
    /// this engine's runtime: the artifact app's own origin. Refused once
    /// closed.
    pub fn connect_artifact(&self) -> anyhow::Result<BlockingConnection> {
        self.with_running(|running| {
            Ok(BlockingConnection {
                connection: running
                    .runtime
                    .block_on(running.engine.connect_artifact())?,
                runtime: running.runtime.handle().clone(),
            })
        })
    }

    /// [`EmbeddedEngine::wake`].
    pub fn wake(&self) -> anyhow::Result<()> {
        self.with_running(|running| running.runtime.block_on(running.engine.wake()))
    }

    /// [`EmbeddedEngine::stop`].
    pub fn stop(&self) -> anyhow::Result<()> {
        self.with_running(|running| running.runtime.block_on(running.engine.stop()))
    }

    /// Stops serving in order and releases the runtime and the engine's
    /// share of the vault. Later calls are refused; closing again does
    /// nothing.
    pub fn close(&self) -> anyhow::Result<()> {
        ensure_app_thread()?;
        let running = self
            .running
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        running.map_or(Ok(()), Running::close)
    }

    fn with_running<T>(
        &self,
        call: impl FnOnce(&Running<A>) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        ensure_app_thread()?;
        let running = self.running.read().unwrap_or_else(PoisonError::into_inner);
        let running = running
            .as_ref()
            .ok_or_else(|| failure(EngineErrorKind::Closed, "the embedded engine is closed"))?;
        call(running)
    }
}

impl<A: AppHost + Clone + 'static> Drop for BlockingEngine<A> {
    fn drop(&mut self) {
        let Some(running) = self
            .running
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        if Handle::try_current().is_err() {
            close_logged(running);
            return;
        }
        // Dropped inside a runtime, where nothing may block: the ordered
        // stop finishes on a thread of its own.
        let (hand_over, handed) = std::sync::mpsc::channel::<Running<A>>();
        let closer = std::thread::Builder::new()
            .name("oneiron-engine-close".to_owned())
            .spawn(move || {
                if let Ok(running) = handed.recv() {
                    close_logged(running);
                }
            });
        match closer {
            Ok(_) => {
                let _ = hand_over.send(running);
            }
            Err(error) => {
                tracing::warn!(%error, "the embedded engine could not stop in order; stopping it at once");
                let Running { engine, runtime } = running;
                drop(engine);
                runtime.shutdown_background();
            }
        }
    }
}

fn close_logged<A: AppHost + Clone + 'static>(running: Running<A>) {
    if let Err(error) = running.close() {
        tracing::warn!(%error, "the embedded engine did not stop cleanly");
    }
}

/// [`BlockingEngine::request_streamed`]'s reply. A 4xx or 5xx status is a
/// reply, not an error.
pub struct BlockingReply {
    pub status: u16,
    /// Every header the reply carried, repeats included.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body as the server writes it.
    pub body: BlockingBody,
}

/// A streamed reply's body as an app thread reads it: each read blocks on
/// the engine's runtime until the server has written more, and returns 0
/// once the body has ended. A read from inside an async runtime, or of a
/// body the server cut off, fails.
pub struct BlockingBody {
    body: EmbeddedBody,
    /// What the last chunk held past the last read.
    pending: Bytes,
    ended: bool,
    runtime: Handle,
}

impl Read for BlockingBody {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() {
            if self.ended {
                return Ok(0);
            }
            ensure_app_thread().map_err(std::io::Error::other)?;
            match self.runtime.block_on(self.body.next_chunk()) {
                Ok(Some(chunk)) => self.pending = chunk,
                Ok(None) => self.ended = true,
                Err(error) => return Err(std::io::Error::other(error)),
            }
        }
        let read = buf.len().min(self.pending.len());
        buf[..read].copy_from_slice(&self.pending.split_to(read));
        Ok(read)
    }
}
