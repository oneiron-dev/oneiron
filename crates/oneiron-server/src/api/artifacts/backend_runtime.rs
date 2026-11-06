//! Request-owned HTTP/1 exchanges with the native untrusted guest.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::Request;
use axum::response::Response;
use hyper::body::{Frame, Incoming};
use hyper_util::rt::TokioIo;
use oneiron_container::{
    EgressRelay, HostNetFloor, HttpRequest, HttpResponse, SessionLease, SessionManifest,
    SessionTransport, UnmeteredFloor,
};
use std::thread::JoinHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::AbortHandle;

use crate::config::ArtifactBackendConfig;
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

#[path = "backend_actions.rs"]
mod actions;
#[cfg(target_os = "linux")]
#[path = "backend_loopback.rs"]
mod native;

pub(super) struct StagedBackend {
    pub transport: super::BackendTransport,
    pub identity: oneiron::artifact_hosting::ArtifactBackendSource,
    pub directory: tempfile::TempDir,
    pub source: std::path::PathBuf,
    pub command: Vec<std::ffi::OsString>,
    pub permit: tokio::sync::OwnedSemaphorePermit,
}

struct AppActionEgress {
    server: Arc<SyncServer>,
    identity: oneiron::artifact_hosting::ArtifactBackendSource,
    runtime: tokio::runtime::Handle,
}

fn no_engine_egress() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "artifact backend egress is limited to its own engine actions",
    )
}

impl EgressRelay for AppActionEgress {
    fn connect(&self, _: SocketAddr) -> io::Result<TcpStream> {
        Err(no_engine_egress())
    }
    fn authorize_datagram(&self, _: SocketAddr) -> io::Result<()> {
        Err(no_engine_egress())
    }
    fn record_session(&self, _: &SessionManifest) -> io::Result<()> {
        Ok(())
    }
    fn record_abandoned(&self, _: &SessionManifest) -> io::Result<()> {
        Ok(())
    }
    fn datagram(&self, _: SocketAddr, _: &[u8]) -> io::Result<Vec<u8>> {
        Err(no_engine_egress())
    }
    fn fetch(&self, request: HttpRequest) -> io::Result<HttpResponse> {
        self.runtime.block_on(actions::fetch(
            Arc::clone(&self.server),
            self.identity.clone(),
            request,
        ))
    }
    fn transferred(&self, _: SocketAddr, _: [u8; 32], _: u64) {}
    fn host_net_floor(&self) -> &dyn HostNetFloor {
        &UnmeteredFloor
    }
}

fn transport_error(_: impl std::fmt::Display) -> EnvelopedApiError {
    ApiError::internal_server_error("artifact backend transport failed").into()
}

/// Only the request/response owns the lease. IO workers cannot keep the guest alive.
struct SessionGuard {
    lease: Option<Box<dyn SessionLease>>,
    directory: Option<tempfile::TempDir>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    connection: Option<AbortHandle>,
    stdin: Option<Box<dyn Write + Send>>,
    input: Option<JoinHandle<io::Result<u64>>>,
    output: Option<JoinHandle<io::Result<u64>>>,
    runtime: tokio::runtime::Handle,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.abort();
        }
        let lease = self.lease.take();
        let directory = self.directory.take();
        let permit = self.permit.take();
        let stdin = self.stdin.take();
        let input = self.input.take();
        let output = self.output.take();
        // Native lease drop stops/reaps the process and wakes pipe IO. Aborting
        // Hyper closes the duplex peer, including a worker waiting on its body.
        self.runtime.spawn_blocking(move || {
            drop(lease);
            drop(stdin);
            if let Some(input) = input {
                let _ = input.join();
            }
            if let Some(output) = output {
                let _ = output.join();
            }
            drop(directory);
            drop(permit);
        });
    }
}

struct BackendBody {
    inner: Incoming,
    session: Option<SessionGuard>,
}

impl HttpBody for BackendBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let frame = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(frame, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.session.take();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

struct StartedBackend {
    transport: SessionTransport,
    directory: tempfile::TempDir,
    permit: tokio::sync::OwnedSemaphorePermit,
    relay: Arc<dyn EgressRelay>,
}

fn start(
    profile: ArtifactBackendConfig,
    staged: StagedBackend,
    server: Arc<SyncServer>,
    runtime: tokio::runtime::Handle,
) -> io::Result<StartedBackend> {
    profile.validate().map_err(io::Error::other)?;
    let spec = profile.spec(staged.source).map_err(io::Error::other)?;
    let backend = oneiron::code_sandbox::microvm::select_backend_for_session(
        oneiron::code_sandbox::SandboxGuestTier::Untrusted,
        profile.runtime,
        &profile.image,
    )
    .map_err(io::Error::other)?;
    let relay: Arc<dyn EgressRelay> = Arc::new(AppActionEgress {
        server,
        identity: staged.identity,
        runtime,
    });
    let transport = backend
        .start_session(&spec, &staged.command, relay.clone())
        .map_err(io::Error::other)?;
    relay.record_session(&transport.manifest)?;
    Ok(StartedBackend {
        transport,
        directory: staged.directory,
        permit: staged.permit,
        relay,
    })
}

pub(super) async fn forward(
    profile: ArtifactBackendConfig,
    staged: StagedBackend,
    request: Request,
    server: Arc<SyncServer>,
) -> Result<Response, EnvelopedApiError> {
    match staged.transport {
        super::BackendTransport::Http1Stdio => {
            forward_stdio(profile, staged, request, server).await
        }
        super::BackendTransport::Http1Loopback { address } => {
            #[cfg(target_os = "linux")]
            {
                native::forward(profile, staged, request, server, address).await
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = address;
                Err(transport_error(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "native loopback backends require Linux",
                )))
            }
        }
    }
}

async fn forward_stdio(
    profile: ArtifactBackendConfig,
    staged: StagedBackend,
    request: Request,
    server: Arc<SyncServer>,
) -> Result<Response, EnvelopedApiError> {
    let capacity = profile.bridge_buffer_bytes;
    let runtime = tokio::runtime::Handle::current();
    let relay_runtime = runtime.clone();
    let StartedBackend {
        transport,
        directory,
        permit,
        relay,
    } = tokio::task::spawn_blocking(move || start(profile, staged, server, relay_runtime))
        .await
        .map_err(transport_error)?
        .map_err(transport_error)?;
    drop(relay);
    let SessionTransport {
        mut reader,
        mut writer,
        manifest: _,
        lease,
    } = transport;
    let mut session = SessionGuard {
        lease: Some(lease),
        directory: Some(directory),
        permit: Some(permit),
        connection: None,
        stdin: None,
        input: None,
        output: None,
        runtime: runtime.clone(),
    };
    let (client, peer) = tokio::io::duplex(capacity);
    let (mut input, mut output) = tokio::io::split(peer);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
        .await
        .map_err(transport_error)?;
    let connection = tokio::spawn(connection);
    let abort = connection.abort_handle();
    session.connection = Some(abort.clone());
    let input_runtime = runtime.clone();
    let input_abort = abort.clone();
    session.input = Some(
        std::thread::Builder::new()
            .spawn(move || {
                let mut copy = || -> io::Result<u64> {
                    let mut buffer = vec![0; capacity];
                    let mut bytes = 0;
                    loop {
                        let n = input_runtime.block_on(input.read(&mut buffer))?;
                        if n == 0 {
                            writer.flush()?;
                            return Ok(bytes);
                        }
                        writer.write_all(&buffer[..n])?;
                        writer.flush()?;
                        bytes += n as u64;
                    }
                };
                let result = copy();
                if result.is_err() {
                    input_abort.abort();
                }
                result
            })
            .map_err(transport_error)?,
    );
    session.output = Some(
        std::thread::Builder::new()
            .spawn(move || {
                let mut copy = || -> io::Result<u64> {
                    let mut buffer = vec![0; capacity];
                    let mut bytes = 0;
                    loop {
                        let n = reader.read(&mut buffer)?;
                        if n == 0 {
                            runtime.block_on(output.shutdown())?;
                            return Ok(bytes);
                        }
                        runtime.block_on(output.write_all(&buffer[..n]))?;
                        bytes += n as u64;
                    }
                };
                let result = copy();
                if result.is_err() {
                    abort.abort();
                }
                result
            })
            .map_err(transport_error)?,
    );
    let response = sender
        .send_request(request)
        .await
        .map_err(transport_error)?;
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(
        parts,
        Body::new(BackendBody {
            inner: body,
            session: Some(session),
        }),
    ))
}
