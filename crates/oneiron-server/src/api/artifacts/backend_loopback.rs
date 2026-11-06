//! HTTP/1 on a request-owned native loopback connection.

use std::io::{self, Read};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use oneiron_container::{HostNetPermit, SessionTransport};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{BackendBody, SessionGuard, StagedBackend, StartedBackend, start, transport_error};
use crate::config::ArtifactBackendConfig;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;

const PORT_WAIT_CADENCE: Duration = Duration::from_millis(250);

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct NativeIo {
    stream: tokio::net::UnixStream,
    // The descriptor closes before its original room is released.
    _charge: HostNetPermit,
}

impl AsyncRead for NativeIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for NativeIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn blocking_setup(
    profile: ArtifactBackendConfig,
    staged: StagedBackend,
    server: Arc<SyncServer>,
    runtime: tokio::runtime::Handle,
    address: SocketAddr,
    alive: Arc<AtomicBool>,
) -> io::Result<(SessionGuard, std::os::unix::net::UnixStream, HostNetPermit)> {
    let capacity = profile.bridge_buffer_bytes;
    let StartedBackend {
        transport,
        directory,
        permit,
        relay,
    } = start(profile, staged, server, runtime.clone())?;
    let SessionTransport {
        mut reader,
        writer,
        manifest: _,
        lease,
    } = transport;
    let drain_worker = relay.host_net_floor().acquire(0, 1)?;
    let drain_bytes = relay.host_net_floor().acquire_bytes(capacity as u64)?;
    let mut session = SessionGuard {
        lease: Some(lease),
        directory: Some(directory),
        permit: Some(permit),
        stdin: Some(writer),
        connection: None,
        input: None,
        output: None,
        runtime,
    };
    // Drain logs before opening the port: a full stdout pipe can block startup.
    session.output = Some(
        std::thread::Builder::new().spawn(move || -> io::Result<u64> {
            let _room = (drain_worker, drain_bytes);
            let mut buffer = vec![0; capacity];
            let mut total = 0;
            let result = loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break Ok(total),
                    Ok(n) => total += n as u64,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => break Err(error),
                }
            };
            drop(reader);
            result
        })?,
    );
    loop {
        let lease = session
            .lease
            .as_mut()
            .expect("native backend owns its lease");
        if !alive.load(Ordering::Acquire) || !lease.is_running() {
            return Err(io::Error::from_raw_os_error(libc::EINTR));
        }
        let waiting = || alive.load(Ordering::Acquire);
        match lease.connect_loopback(address, &waiting) {
            Ok(connection) => {
                let (stream, charge) = connection.into_parts();
                if let Err(error) = stream.set_nonblocking(true) {
                    drop(stream);
                    return Err(error);
                }
                return Ok((session, stream, charge));
            }
            Err(error) if error.raw_os_error() == Some(libc::ECONNREFUSED) => {
                // Same cadence as native blocked IO; no opening deadline.
                std::thread::park_timeout(PORT_WAIT_CADENCE);
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) async fn forward(
    profile: ArtifactBackendConfig,
    staged: StagedBackend,
    request: axum::extract::Request,
    server: Arc<SyncServer>,
    address: SocketAddr,
) -> Result<axum::response::Response, EnvelopedApiError> {
    let runtime = tokio::runtime::Handle::current();
    let alive = Arc::new(AtomicBool::new(true));
    let _cancel = CancelOnDrop(Arc::clone(&alive));
    let (mut session, std_stream, charge) = tokio::task::spawn_blocking(move || {
        blocking_setup(profile, staged, server, runtime, address, alive)
    })
    .await
    .map_err(transport_error)?
    .map_err(transport_error)?;
    let stream = tokio::net::UnixStream::from_std(std_stream).map_err(transport_error)?;
    let io = NativeIo {
        stream,
        _charge: charge,
    };
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .map_err(transport_error)?;
    let connection = tokio::spawn(connection);
    session.connection = Some(connection.abort_handle());
    let response = sender
        .send_request(request)
        .await
        .map_err(transport_error)?;
    let (parts, body) = response.into_parts();
    Ok(axum::response::Response::from_parts(
        parts,
        axum::body::Body::new(BackendBody {
            inner: body,
            session: Some(session),
        }),
    ))
}
