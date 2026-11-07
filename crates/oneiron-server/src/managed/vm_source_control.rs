//! The root bootstrap's original engine, proved by its kernel pidfd.
//!
//! A source-only control connection carries one hello and one ctl exchange.
//! It cannot outlive that child or the bootstrap's owner guard. The ordinary
//! VM control bridge is unchanged; unavailable source proof leaves a restore
//! with its existing Unknown path.

use anyhow::{Context, ensure};
use oneiron_vault_contract::host_adapters::{VsockListener, VsockStream};
use oneiron_vault_contract::vm::{VM_HOST_CID, VM_SOURCE_CTL_PORT, VmSourceEngine};
use oneiron_vault_contract::{CtlRequest, CtlResponse, MAX_CTL_LINE};
use serde::{Deserialize, Serialize};
use std::fs::{DirBuilder, Permissions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

const OWNER_DIR: &str = "/run/oneiron-source-control";
const OWNER_LEAF: &str = "owner.sock";

fn owner_socket() -> PathBuf {
    PathBuf::from(OWNER_DIR).join(OWNER_LEAF)
}

struct Directory;

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(owner_socket());
        let _ = std::fs::remove_dir(OWNER_DIR);
    }
}

/// Bound before the child starts, so its one registration need not retry.
/// An existing directory is never removed or adopted.
pub(super) struct Prepared {
    vault: String,
    listener: std::os::unix::net::UnixListener,
    directory: Directory,
}

impl Prepared {
    pub(super) fn new(vault: &str) -> anyhow::Result<Self> {
        DirBuilder::new().mode(0o711).create(OWNER_DIR)?;
        let directory = Directory;
        std::fs::set_permissions(OWNER_DIR, Permissions::from_mode(0o711))?;
        let listener = std::os::unix::net::UnixListener::bind(owner_socket())?;
        std::fs::set_permissions(owner_socket(), Permissions::from_mode(0o666))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            vault: vault.to_owned(),
            listener,
            directory,
        })
    }

    /// Called while the parent's actual Child is still unreaped. The pidfd
    /// continues naming that process after try_wait/wait has reaped it.
    pub(super) fn start(self, child: &std::process::Child) -> anyhow::Result<Guard> {
        let pid = child.id();
        // SAFETY: pid is the caller's live or unreaped child; pidfd_open
        // returns a new owned descriptor and takes no pointers.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: the successful syscall returned this new descriptor once.
        let death = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let (closing, receiver) = watch::channel(false);
        std::thread::Builder::new()
            .name("vm-source-owner".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        eprintln!("oneiron-vm-init: source owner runtime unavailable: {error}");
                        return;
                    }
                };
                if let Err(error) = runtime.block_on(self.serve(pid, death, receiver)) {
                    eprintln!("oneiron-vm-init: source owner unavailable: {error:#}");
                }
            })?;
        Ok(Guard { closing })
    }

    async fn serve(
        self,
        pid: u32,
        death: OwnedFd,
        mut closing: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let Self {
            vault,
            listener,
            directory: _directory,
        } = self;
        let state = Arc::new(Engine {
            vault,
            pid,
            death: AsyncFd::new(death)?,
            closing: closing.clone(),
            ctl_socket: OnceLock::new(),
        });
        ensure!(
            state.is_live(),
            "original engine owner ended before source startup"
        );
        let registration = UnixListener::from_std(listener)?;
        let source = VsockListener::bind(VM_SOURCE_CTL_PORT)?;
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = closing.changed() => break,
                _ = state.death.readable() => break,
                accepted = registration.accept() => {
                    let (stream, _) = accepted?;
                    let state = state.clone();
                    tasks.spawn(async move { let _ = state.register(stream).await; });
                }
                accepted = source.accept() => {
                    let (stream, cid) = accepted?;
                    if cid == VM_HOST_CID {
                        let state = state.clone();
                        tasks.spawn(async move { let _ = state.exchange(stream).await; });
                    }
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

pub(super) struct Guard {
    closing: watch::Sender<bool>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.closing.send_replace(true);
    }
}

struct Engine {
    vault: String,
    pid: u32,
    death: AsyncFd<OwnedFd>,
    closing: watch::Receiver<bool>,
    ctl_socket: OnceLock<PathBuf>,
}

impl Engine {
    fn is_live(&self) -> bool {
        if *self.closing.borrow() {
            return false;
        }
        let mut poll = libc::pollfd {
            fd: self.death.get_ref().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd is borrowed for this nonblocking
        // readiness query. An error, or any ready event, proves nothing live.
        unsafe { libc::poll(&mut poll, 1, 0) == 0 }
    }

    fn same_peer(&self, stream: &UnixStream) -> anyhow::Result<()> {
        ensure!(self.is_live(), "original engine is no longer live");
        ensure!(
            stream.peer_cred()?.pid().map(|pid| pid as u32) == Some(self.pid),
            "not the original engine peer"
        );
        Ok(())
    }

    async fn register(&self, stream: UnixStream) -> anyhow::Result<()> {
        self.same_peer(&stream)?;
        let mut reader = BufReader::new(stream);
        let line = read_line(&mut reader).await?;
        self.same_peer(reader.get_ref())?;
        let registration: Registration = serde_json::from_slice(&line)?;
        // The peer, not a claimed PID or path, authorizes this one immutable
        // binding. Every subsequent ctl connect proves that peer again.
        let _ = self.ctl_socket.set(registration.ctl_socket);
        Ok(())
    }

    async fn exchange(&self, stream: VsockStream) -> anyhow::Result<()> {
        ensure!(self.is_live(), "original engine is no longer live");
        let socket = self
            .ctl_socket
            .get()
            .context("original engine has not registered")?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        let hello = VmSourceEngine {
            vault: self.vault.clone(),
            engine_pid: self.pid,
        };
        let mut hello = serde_json::to_vec(&hello)?;
        hello.push(b'\n');
        writer.write_all(&hello).await?;
        let request = read_line(&mut reader).await?;
        let parsed: CtlRequest = serde_json::from_slice(&request)?;
        ensure!(
            matches!(
                parsed,
                CtlRequest::PrepareReap | CtlRequest::ReapAbort | CtlRequest::HostOrderHolds { .. }
            ),
            "not a source ctl request"
        );
        let response = tokio::select! {
            response = self.relay(socket, &request) => response?,
            // Existing ctl callers keep both halves until the answer. EOF
            // cancels their pending relay; this one-call transport does not
            // accept another request pipelined before its answer.
            _ = reader.read_u8() => anyhow::bail!("source ctl caller disconnected or pipelined"),
        };
        ensure!(
            self.is_live(),
            "original engine owner ended during source ctl"
        );
        writer.write_all(&response).await?;
        writer.shutdown().await?;
        Ok(())
    }

    async fn relay(&self, socket: &PathBuf, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut ctl = UnixStream::connect(socket).await?;
        self.same_peer(&ctl)?;
        ctl.write_all(request).await?;
        let mut reader = BufReader::new(ctl);
        let response = read_line(&mut reader).await?;
        self.same_peer(reader.get_ref())?;
        let parsed: CtlResponse = serde_json::from_slice(&response)?;
        parsed
            .validate()
            .context("invalid original-engine ctl response")?;
        Ok(response)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    ctl_socket: PathBuf,
}

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut line = Vec::new();
    let n = (&mut *reader)
        .take((MAX_CTL_LINE + 2) as u64)
        .read_until(b'\n', &mut line)
        .await?;
    ensure!(
        n > 0 && line.last() == Some(&b'\n'),
        "source ctl line ended before its newline"
    );
    let payload = line.strip_suffix(b"\n").unwrap_or(&line);
    let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
    ensure!(
        payload.len() <= MAX_CTL_LINE,
        "source ctl line exceeds the ctl bound"
    );
    Ok(line)
}

/// The real engine publishes its selected ctl path. Source setup is not a
/// readiness gate: ordinary VM bridges and cold restores keep working.
pub(super) fn register(ctl_socket: PathBuf) {
    tokio::spawn(async move {
        let result: anyhow::Result<()> = async {
            let mut stream = UnixStream::connect(owner_socket()).await?;
            ensure!(
                stream.peer_cred()?.uid() == 0,
                "source owner is not the root bootstrap"
            );
            let mut line = serde_json::to_vec(&Registration { ctl_socket })?;
            ensure!(
                line.len() <= MAX_CTL_LINE,
                "source registration exceeds the ctl bound"
            );
            line.push(b'\n');
            stream.write_all(&line).await?;
            stream.shutdown().await?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(error = %format!("{error:#}"), "VM source owner registration unavailable; ordinary VM control is unchanged");
        }
    });
}
