//! Managed sockets: listener resolution and binding, the ctl plane, and readiness.

use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use oneiron_vault_contract::{CtlRequest, CtlResponse, MAX_CTL_LINE, READY_BYTE};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing_subscriber::EnvFilter;

use super::args::{ManagedArgs, ManagedError};
use super::state_serve::ManagedState;

/// The one environment value managed mode uses. When set, it names an
/// already-bound listening unix socket the supervisor passed across spawn.
pub const HYPNOS_LISTEN_FD: &str = "HYPNOS_LISTEN_FD";

/// Socket directories are owner-only; the socket file itself is owner-rw.
const SOCKET_DIR_MODE: u32 = 0o700;

const SOCKET_FILE_MODE: u32 = 0o600;

/// Where the HTTP surface listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeListener {
    /// Unmanaged `host:port` bind — today's serve path, unchanged.
    Tcp(SocketAddr),
    /// Managed self-bind fallback, used when no listen fd was inherited.
    UnixPath(PathBuf),
    /// A socket the supervisor bound and passed across spawn. This process
    /// never binds, unlinks or chmods the path behind it.
    InheritedFd(RawFd),
}

impl ServeListener {
    /// Resolves the managed HTTP listener.
    ///
    /// [`HYPNOS_LISTEN_FD`] is the only environment value managed mode
    /// uses, and its absence is not an error — it selects the self-bind
    /// fallback on `--http-socket`.
    pub fn for_managed(args: &ManagedArgs) -> Result<Self, ManagedError> {
        match std::env::var(HYPNOS_LISTEN_FD) {
            Ok(raw) => {
                let fd: RawFd = raw
                    .trim()
                    .parse()
                    .map_err(|_| ManagedError::InvalidListenFd {
                        env: HYPNOS_LISTEN_FD,
                        value: raw.clone(),
                    })?;
                if fd < 0 {
                    return Err(ManagedError::InvalidListenFd {
                        env: HYPNOS_LISTEN_FD,
                        value: raw,
                    });
                }
                // Resolution, not adoption: this is the last point before the
                // descriptor becomes a `ServeListener` that `bind` will take
                // ownership of, so an alias of either argv fd is refused while
                // refusing still costs nothing.
                args.refuse_listen_fd_alias(fd)?;
                Ok(Self::InheritedFd(fd))
            }
            Err(std::env::VarError::NotPresent) => Ok(Self::UnixPath(args.http_socket.clone())),
            Err(std::env::VarError::NotUnicode(raw)) => Err(ManagedError::InvalidListenFd {
                env: HYPNOS_LISTEN_FD,
                value: raw.to_string_lossy().into_owned(),
            }),
        }
    }

    /// Binds — or, for an inherited fd, adopts — the listener this variant
    /// names. Consuming `self` is what makes double-adoption of the inherited
    /// descriptor unrepresentable.
    pub async fn bind(self) -> Result<BoundServeListener, ManagedError> {
        match self {
            Self::Tcp(addr) => Ok(BoundServeListener::Tcp(
                tokio::net::TcpListener::bind(addr).await?,
            )),
            Self::UnixPath(path) => {
                let listener = bind_unix_socket(&path)?;
                Ok(BoundServeListener::Unix {
                    listener,
                    owned_path: Some(path),
                })
            }
            Self::InheritedFd(fd) => Ok(BoundServeListener::Unix {
                listener: adopt_listen_fd(fd)?,
                owned_path: None,
            }),
        }
    }
}

/// A listener that is bound and ready to serve.
#[derive(Debug)]
pub enum BoundServeListener {
    Tcp(tokio::net::TcpListener),
    Unix {
        listener: UnixListener,
        /// `Some` only when this process created the socket file. An inherited
        /// socket's path belongs to the supervisor and must outlive us.
        owned_path: Option<PathBuf>,
    },
}

impl BoundServeListener {
    /// The socket path this process is responsible for removing, if any.
    pub fn owned_path(&self) -> Option<&Path> {
        match self {
            Self::Tcp(_) => None,
            Self::Unix { owned_path, .. } => owned_path.as_deref(),
        }
    }

    /// Serves until the process ends — the unmanaged shape.
    pub async fn serve(self, app: Router) -> std::io::Result<()> {
        match self {
            Self::Tcp(listener) => axum::serve(listener, app).await,
            Self::Unix { listener, .. } => axum::serve(listener, app).await,
        }
    }

    /// Serves until `shutdown` resolves, then stops accepting and drains
    /// in-flight requests.
    pub async fn serve_until(
        self,
        app: Router,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        match self {
            Self::Tcp(listener) => {
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown)
                    .await
            }
            Self::Unix { listener, .. } => {
                axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown)
                    .await
            }
        }
    }
}

/// Binds a unix socket this process owns: owner-only directory, owner-rw
/// socket file.
///
/// Binding replaces whatever is already at the path, and the path comes from
/// argv. A socket left behind by a previous run is exactly what that
/// replacement is for; anything else at that path is somebody's data, and
/// `--ctl-socket` one character off from a config or vault file would delete it
/// with no way back. So the gate below is the whole difference between reusing
/// a stale socket and destroying a file, and it runs before this function
/// creates or tightens a directory, so a mistyped path changes nothing at all.
fn bind_unix_socket(path: &Path) -> Result<UnixListener, ManagedError> {
    // `symlink_metadata`, not `metadata`: a symlink is refused as itself rather
    // than judged by what it points at, so a link aimed at a live socket cannot
    // talk this into unlinking a path it never inspected.
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(metadata) => {
            return Err(ManagedError::SocketPathOccupied {
                path: path.to_path_buf(),
                kind: node_kind(&metadata.file_type()),
            });
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(SOCKET_DIR_MODE))?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_FILE_MODE))?;
    Ok(listener)
}

/// Names what is at a path, so the refusal tells an operator what they hit
/// rather than only that they hit something.
fn node_kind(file_type: &std::fs::FileType) -> &'static str {
    if file_type.is_file() {
        "a regular file"
    } else if file_type.is_dir() {
        "a directory"
    } else if file_type.is_symlink() {
        "a symlink"
    } else if file_type.is_fifo() {
        "a fifo"
    } else if file_type.is_block_device() {
        "a block device"
    } else if file_type.is_char_device() {
        "a character device"
    } else {
        "another kind of node"
    }
}

/// Adopts a listening unix socket the supervisor already bound.
///
/// The child must not bind, unlink or chmod the path: the inode is the
/// supervisor's, and a child that recreated it would strand every connection
/// already queued on the original.
pub fn adopt_listen_fd(fd: RawFd) -> Result<UnixListener, ManagedError> {
    // SAFETY: `fd` arrives through the supervisor's spawn contract (the
    // HYPNOS_LISTEN_FD environment variable) and names a bound, listening unix
    // socket handed to this process for its whole lifetime. Ownership moves
    // here exactly once: `ServeListener::InheritedFd` is consumed by
    // `ServeListener::bind`, so no second adoption can double-own the
    // descriptor, and the std listener below closes it on drop.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    Ok(UnixListener::from_std(std_listener)?)
}

/// Writes the ready byte.
///
/// Ordering is the whole point of this function existing separately: the
/// supervisor treats the byte as "this child is serving", so it may only be
/// written after both sockets are bound, the credentials are consumed, and the
/// vault open gates have passed.
pub fn signal_ready(fd: RawFd) -> Result<(), ManagedError> {
    // SAFETY: `fd` arrives on argv (`--ready-fd`) through the supervisor's
    // spawn contract and is this process's to own. The `File` takes it over
    // exactly once; closing it on drop is what the supervisor's read side
    // observes as EOF if this process dies before signalling.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    std::io::Write::write_all(&mut file, &[READY_BYTE])?;
    std::io::Write::flush(&mut file)?;
    Ok(())
}

/// The control socket: one JSON request line per connection, one response line
/// back, both under [`MAX_CTL_LINE`].
#[derive(Debug)]
pub struct ManagedCtl {
    listener: UnixListener,
    path: PathBuf,
}

impl ManagedCtl {
    /// Binds `ctl.sock`. This process owns the path, so it also owns removing
    /// it — unlike the inherited HTTP socket.
    pub fn bind(path: &Path) -> Result<Self, ManagedError> {
        Ok(Self {
            listener: bind_unix_socket(path)?,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serves control verbs until `shutdown` resolves, then closes the socket
    /// and removes the path it created.
    pub async fn serve(self, state: Arc<ManagedState>, shutdown: impl Future<Output = ()> + Send) {
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(error) = handle_ctl_connection(stream, &state).await {
                                tracing::warn!(%error, "ctl connection failed");
                            }
                        });
                    }
                    Err(error) => tracing::warn!(%error, "ctl accept failed"),
                },
            }
        }
        drop(self.listener);
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != ErrorKind::NotFound
        {
            tracing::warn!(%error, path = %self.path.display(), "ctl socket unlink failed");
        }
    }
}

async fn handle_ctl_connection(
    stream: UnixStream,
    state: &ManagedState,
) -> Result<(), ManagedError> {
    let (mut request_half, mut writer) = stream.into_split();
    // Cap + 2 leaves room for the terminating newline on a maximal valid line
    // while still stopping short of reading an over-cap one whole. Borrowed
    // rather than moved because the read half has to outlive this reader: the
    // request tail is drained through it once the reply is out.
    let mut reader = BufReader::new((&mut request_half).take(MAX_CTL_LINE as u64 + 2));
    let mut line = String::new();
    let response = match reader.read_line(&mut line).await {
        Ok(_) => dispatch_ctl_line(&line, state).await,
        Err(error) => {
            tracing::warn!(%error, "ctl line unreadable; rejected whole");
            CtlResponse::Ok { ok: false }
        }
    };

    let mut out =
        serde_json::to_string(&response).map_err(|error| ManagedError::CtlRequestRefused {
            reason: error.to_string(),
        })?;
    out.push('\n');
    writer.write_all(out.as_bytes()).await?;
    writer.flush().await?;
    // Written is not delivered. Dropping a socket that still has unread bytes
    // queued on it resets the peer, and the reset discards the reply the peer
    // had not read yet — which is precisely the refusal case, because an
    // over-cap line is rejected after `MAX_CTL_LINE + 2` bytes while the rest
    // of it is still arriving. The supervisor would see a connection error
    // where the engine sent it a considered answer.
    //
    // So the close is done in two halves. Ending the reply half first is what
    // gives the peer its EOF, so this drain can never leave it waiting; then
    // the tail of that one request line is consumed so nothing is queued when
    // the socket finally drops.
    writer.shutdown().await?;
    let mut sink = [0u8; 1024];
    let mut drained = 0usize;
    while drained < MAX_CTL_LINE {
        let Ok(read) = request_half.read(&mut sink).await else {
            break;
        };
        // EOF, or the end of the one line this connection was ever allowed.
        if read == 0 || sink[..read].contains(&b'\n') {
            break;
        }
        drained += read;
    }
    Ok(())
}

/// Parses and dispatches one ctl line.
///
/// Over-cap lines are rejected whole and never truncated: a truncated line can
/// parse into a different, smaller request than the supervisor sent, which is
/// worse than no request at all.
async fn dispatch_ctl_line(line: &str, state: &ManagedState) -> CtlResponse {
    let payload = line.trim_end_matches(['\r', '\n']);
    if payload.len() > MAX_CTL_LINE {
        let error = ManagedError::CtlLineTooLong {
            len: payload.len(),
            cap: MAX_CTL_LINE,
        };
        tracing::warn!(%error, "ctl line rejected");
        return CtlResponse::Ok { ok: false };
    }
    let request: CtlRequest = match serde_json::from_str(payload) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(%error, "ctl line did not parse; rejected");
            return CtlResponse::Ok { ok: false };
        }
    };
    match state.handle_request(request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "ctl request refused");
            CtlResponse::Ok { ok: false }
        }
    }
}

/// Managed mode's log filter comes from argv, never from the environment.
/// `EnvFilter::try_from_default_env` would read `RUST_LOG`, and the managed
/// environment surface is exactly `PATH` and [`HYPNOS_LISTEN_FD`].
pub(super) fn init_managed_tracing(log_level: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_level))
        .try_init();
}
