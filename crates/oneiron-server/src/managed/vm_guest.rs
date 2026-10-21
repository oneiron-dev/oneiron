//! Managed mode as a Firecracker vault VM's engine (VAULT-VM = B: built now,
//! adopted after the owner's answer on the wake budget).
//!
//! The guest keeps the node's managed contract whole. Its HTTP and ctl unix
//! sockets, its ledger push and its boot order are the process child's; only
//! the transport differs. The host reaches the two sockets through vsock
//! ports and the guest bridges each connection onto them, and the ledger push
//! leaves through a guest-local socket bridged to the host's ledger port.
//! The credential frame and the ready byte ride the vsock boot channel.
//! The outbox carrier is the root companion's, beside the engine
//! (`vm_outbox`); the engine only asks it its revision at boot and parks it
//! around an idle report. A cold restore's start (FIX 6584) dials only its
//! boot channel at first: its vsock ports and bridges are bound once the
//! restore is kept, as a node's child binds its sockets only then.

use super::args::{ManagedArgs, ManagedStartMode};
use super::listener::{ServeListener, bind_unix_socket};
use super::state_serve::{ManagedShutdown, ManagedState};
use crate::server::SyncServer;
use oneiron_vault_contract::host::{Host, HostFuture, HostLimits};
use oneiron_vault_contract::host_adapters::{
    EdgeBackend, FirecrackerGuest, GuestLink, MicroVmHost, VsockListener, VsockStream,
};
use oneiron_vault_contract::vm::{
    VM_ARTIFACT_PORT, VM_CTL_PORT, VM_HOST_CID, VM_LEDGER_PORT, VM_VOICE_PORT,
};
use oneiron_vault_contract::{Schedule, WakeEntry};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

/// A failed accept is retried after this pause rather than in a hot loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

pub(super) struct VmGuestHost {
    inner: MicroVmHost<FirecrackerGuest>,
    http_socket: PathBuf,
    ctl_socket: PathBuf,
    hypnos_socket: PathBuf,
    artifact_socket: Option<PathBuf>,
    shutdown: ManagedShutdown,
    /// The outbox carrier's revision its companion reported at boot.
    vm_outbox_revision: Option<u32>,
    /// A cold restore's start whose bridges wait for the keep.
    restoring: bool,
}
impl VmGuestHost {
    pub(super) fn new(args: &ManagedArgs, shutdown: ManagedShutdown) -> Self {
        Self {
            inner: MicroVmHost(FirecrackerGuest::new(args.vault_name.clone())),
            http_socket: args.http_socket.clone(),
            ctl_socket: args.ctl_socket.clone(),
            hypnos_socket: args.hypnos_socket.clone(),
            artifact_socket: args.artifact_socket.clone(),
            shutdown,
            vm_outbox_revision: super::vm_outbox::companion_revision(),
            restoring: matches!(args.start_mode, ManagedStartMode::Restore { .. }),
        }
    }
    /// The outbox carrier's revision, when the image's companion answered at
    /// boot with its storage laid out and its carrier attached (FIX 5235).
    pub(super) fn vm_outbox_revision(&self) -> Option<u32> {
        self.vm_outbox_revision
    }
    pub(super) fn clear_secrets(&mut self) {
        self.inner.0.clear_secrets();
    }
    pub(super) fn link(&self) -> Option<GuestLink> {
        self.inner.0.link()
    }
    /// Bridges the voice port to the voice loop's socket (FIX 2391).
    pub(super) fn bridge_voice(&self, socket: PathBuf) -> anyhow::Result<()> {
        spawn_inbound(VsockListener::bind(VM_VOICE_PORT)?, socket);
        Ok(())
    }
    /// A cold restore's bridges, once its vault is kept; nothing for a
    /// start that opened, whose bridges are bound already.
    pub(super) fn activate_service_bridges_after_keep(&mut self) -> anyhow::Result<()> {
        if std::mem::take(&mut self.restoring) {
            self.bind_bridges()?;
        }
        Ok(())
    }
    /// Binds the vsock ports and starts the bridges. The unix sockets they
    /// reach are bound later in the managed order; the host routes nothing
    /// before the ready byte, so no bridge dials early.
    fn bind_bridges(&mut self) -> anyhow::Result<()> {
        let http = self.inner.listener()?;
        spawn_inbound(http, self.http_socket.clone());
        spawn_inbound(VsockListener::bind(VM_CTL_PORT)?, self.ctl_socket.clone());
        if let Some(artifacts) = &self.artifact_socket {
            spawn_inbound(VsockListener::bind(VM_ARTIFACT_PORT)?, artifacts.clone());
        }
        let ledger = bind_unix_socket(&self.hypnos_socket)?;
        spawn_outbound(ledger, VM_LEDGER_PORT);
        Ok(())
    }
}

impl Host for VmGuestHost {
    type Listener = ServeListener;
    /// Boots the boot channel, then binds the vsock ports and starts the
    /// bridges, or for a cold restore's start leaves them for the keep.
    fn listener(&mut self) -> anyhow::Result<ServeListener> {
        if self.restoring {
            self.inner.0.boot()?;
        } else {
            self.bind_bridges()?;
        }
        Ok(ServeListener::UnixPath(self.http_socket.clone()))
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        self.inner.ready()
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.inner.secret(name)
    }
    fn on_stop(&mut self) -> anyhow::Result<()> {
        self.shutdown.trigger();
        self.inner.on_stop()
    }
    fn limits(&self) -> HostLimits {
        self.inner.limits()
    }
    fn idle(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        self.inner.idle(next_wake)
    }
}

/// Host-initiated connections on a vsock port, each spliced onto `target`.
fn spawn_inbound(listener: VsockListener, target: PathBuf) {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut vsock, _host)) => {
                    let target = target.clone();
                    tokio::spawn(async move {
                        match UnixStream::connect(&target).await {
                            Ok(mut unix) => {
                                let _ = tokio::io::copy_bidirectional(&mut vsock, &mut unix).await;
                            }
                            Err(error) => tracing::warn!(%error, "vault VM bridge dial failed"),
                        }
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "vault VM vsock accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            }
        }
    });
}

/// Guest-local connections, each carried out to the host's `port`.
fn spawn_outbound(listener: UnixListener, port: u32) {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut unix, _)) => {
                    tokio::spawn(async move {
                        match VsockStream::connect(VM_HOST_CID, port).await {
                            Ok(mut vsock) => {
                                let _ = tokio::io::copy_bidirectional(&mut unix, &mut vsock).await;
                            }
                            Err(error) => tracing::warn!(%error, "vault VM host dial failed"),
                        }
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "vault VM ledger accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            }
        }
    });
}

/// The earliest wake the ledger holds. A window counts from its start.
fn next_wake(entries: &[WakeEntry]) -> Option<SystemTime> {
    entries
        .iter()
        .map(|entry| match entry.at {
            Schedule::Exact { at } => at,
            Schedule::Window { start, .. } => start,
        })
        .min()
        .map(|at| UNIX_EPOCH + Duration::from_secs(at))
}

/// Answers the host's boot-channel requests for the life of the vault. Sleep
/// reports the next wake and parks until resumed; RAM may reach disk only
/// while no off-record stretch is open (OFFREC-SNAPSHOT = A). The outbox
/// companion, when there is one, is parked before the report and resumed
/// after, so no carrier commit is in flight at a snapshot. Stop drains the
/// vault exactly as SIGTERM does on a node.
pub(super) fn spawn_lifecycle(
    link: GuestLink,
    state: Arc<ManagedState>,
    server: Arc<SyncServer>,
    shutdown: ManagedShutdown,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = link.stop_requested() => {
                    shutdown.trigger();
                    return;
                }
                () = link.sleep_requested() => {
                    let wake = match state.ledger().export(&server) {
                        Ok(entries) => next_wake(&entries),
                        Err(error) => {
                            tracing::warn!(%error, "vault VM idle without a ledger");
                            None
                        }
                    };
                    let snapshot_ok = !server.vault().has_open_off_record_session();
                    let companion = state.vm_outbox_revision().is_some();
                    if companion {
                        super::vm_outbox::park_companion().await;
                    }
                    if let Err(error) = link.idle(wake, snapshot_ok).await {
                        tracing::warn!(%error, "vault VM idle report failed");
                    }
                    if companion {
                        super::vm_outbox::resume_companion().await;
                    }
                }
            }
        }
    });
}
