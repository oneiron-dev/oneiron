//! Managed process entry behind the shared six-verb Host contract.
use super::{
    args::{ManagedArgs, ManagedError},
    listener::{ServeListener, signal_ready},
    state_serve::ManagedShutdown,
    vault_gates::read_managed_credentials,
};
use crate::owner::backup::CustodyAnchorCredentials;
use oneiron_vault_contract::{
    Credentials,
    host::{Host, HostFuture, HostLimits},
    tenancy::VaultHost,
};
use std::sync::Arc;
use std::time::SystemTime;
use zeroize::Zeroizing;

/// Managed mode on a node or in a vault VM. Each preserves the managed boot
/// order: resolve the listener, consume credentials, pass vault gates, bind,
/// ready.
pub(super) enum ManagedHost {
    Process(VaultHost<ProcessHost>),
    #[cfg(target_os = "linux")]
    Vm(VaultHost<super::vm_guest::VmGuestHost>),
}
impl ManagedHost {
    pub(super) fn new(
        args: &ManagedArgs,
        limits: HostLimits,
        shutdown: ManagedShutdown,
    ) -> anyhow::Result<Self> {
        let binding = args.vault_binding()?;
        if args.vsock_guest {
            #[cfg(target_os = "linux")]
            return Ok(Self::Vm(VaultHost::new(
                binding,
                super::vm_guest::VmGuestHost::new(args, shutdown),
            )?));
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("--vsock-guest runs only inside a Linux vault VM");
        }
        Ok(Self::Process(VaultHost::new(
            binding,
            ProcessHost::new(args, limits, shutdown)?,
        )?))
    }
    /// Lets the supervisor reach the voice loop's `socket` (FIX 2391): a
    /// vault VM bridges its voice port to it, and a node's process vault is
    /// dialled on the socket itself.
    pub(super) fn bridge_voice(&mut self, socket: std::path::PathBuf) -> anyhow::Result<()> {
        match self {
            Self::Process(_) => {
                drop(socket);
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::Vm(host) => host.adapter_mut().bridge_voice(socket),
        }
    }
    pub(super) fn clear_secrets(&mut self) {
        match self {
            Self::Process(host) => host.adapter_mut().clear_secrets(),
            #[cfg(target_os = "linux")]
            Self::Vm(host) => host.adapter_mut().clear_secrets(),
        }
    }
    /// The custody anchor door's owner credential the supervisor handed on
    /// its own pipe, read once, before storage; `None` when it handed none.
    /// A vault VM is handed none: its argv refuses the flag.
    pub(super) fn custody_anchor_credentials(
        &mut self,
    ) -> Result<Option<Arc<CustodyAnchorCredentials>>, ManagedError> {
        match self {
            Self::Process(host) => host.adapter_mut().custody_anchor_credentials(),
            #[cfg(target_os = "linux")]
            Self::Vm(_) => Ok(None),
        }
    }
    /// The outbox carrier's revision a vault VM's companion reported at
    /// boot (FIX 5235); a node's process vault has none.
    pub(super) fn vm_outbox_revision(&self) -> Option<u32> {
        match self {
            Self::Process(_) => None,
            #[cfg(target_os = "linux")]
            Self::Vm(host) => host.adapter().vm_outbox_revision(),
        }
    }
    /// The boot channel a vault VM answers sleep and stop requests on.
    #[cfg(target_os = "linux")]
    pub(super) fn vm_link(&self) -> Option<oneiron_vault_contract::host_adapters::GuestLink> {
        match self {
            Self::Process(_) => None,
            Self::Vm(host) => host.adapter().link(),
        }
    }
}
impl Host for ManagedHost {
    type Listener = ServeListener;
    fn listener(&mut self) -> anyhow::Result<ServeListener> {
        match self {
            Self::Process(host) => host.listener(),
            #[cfg(target_os = "linux")]
            Self::Vm(host) => host.listener(),
        }
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Process(host) => host.ready(),
            #[cfg(target_os = "linux")]
            Self::Vm(host) => host.ready(),
        }
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Process(host) => host.secret(name),
            #[cfg(target_os = "linux")]
            Self::Vm(host) => host.secret(name),
        }
    }
    fn on_stop(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Process(host) => host.on_stop(),
            #[cfg(target_os = "linux")]
            Self::Vm(host) => host.on_stop(),
        }
    }
    fn limits(&self) -> HostLimits {
        match self {
            Self::Process(host) => host.limits(),
            #[cfg(target_os = "linux")]
            Self::Vm(host) => host.limits(),
        }
    }
    fn idle(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        match self {
            Self::Process(host) => host.idle(next_wake),
            #[cfg(target_os = "linux")]
            Self::Vm(host) => host.idle(next_wake),
        }
    }
}

/// The node's process child. It owns descriptor consumption.
pub(super) struct ProcessHost {
    listener: Option<ServeListener>,
    credentials_fd: Option<std::os::fd::RawFd>,
    credentials: Option<Credentials>,
    ready_fd: Option<std::os::fd::RawFd>,
    anchor_credentials_fd: Option<std::os::fd::RawFd>,
    limits: HostLimits,
    shutdown: ManagedShutdown,
}
impl ProcessHost {
    fn new(
        args: &ManagedArgs,
        limits: HostLimits,
        shutdown: ManagedShutdown,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            listener: Some(ServeListener::for_managed(args)?),
            credentials_fd: Some(args.credentials_fd),
            credentials: None,
            ready_fd: Some(args.ready_fd),
            anchor_credentials_fd: args.custody_anchor_credentials_fd,
            limits,
            shutdown,
        })
    }
    fn clear_secrets(&mut self) {
        self.credentials = None;
    }
    /// Fail-closed as the credential frame is: a descriptor that is not a
    /// pipe, or bytes that are not the one credentials object, is a typed
    /// refusal that names no byte read.
    fn custody_anchor_credentials(
        &mut self,
    ) -> Result<Option<Arc<CustodyAnchorCredentials>>, ManagedError> {
        let Some(fd) = self.anchor_credentials_fd.take() else {
            return Ok(None);
        };
        CustodyAnchorCredentials::read_fd(fd)
            .map(|credentials| Some(Arc::new(credentials)))
            .map_err(|reason| ManagedError::CustodyAnchorCredentialsRejected { reason })
    }
}
impl Host for ProcessHost {
    type Listener = ServeListener;
    fn listener(&mut self) -> anyhow::Result<ServeListener> {
        self.listener
            .take()
            .ok_or_else(|| anyhow::anyhow!("managed listener already consumed"))
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        let fd = self
            .ready_fd
            .take()
            .ok_or_else(|| anyhow::anyhow!("managed readiness already signalled"))?;
        signal_ready(fd)?;
        Ok(())
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if !matches!(name, "dek" | "spawn_token") {
            anyhow::bail!("unknown managed secret");
        }
        if self.credentials.is_none() {
            let fd = self
                .credentials_fd
                .take()
                .ok_or_else(|| anyhow::anyhow!("managed secrets already consumed"))?;
            self.credentials = Some(read_managed_credentials(fd)?);
        }
        let credentials = self.credentials.as_ref().expect("loaded");
        Ok(Zeroizing::new(if name == "dek" {
            credentials.dek.to_vec()
        } else {
            credentials.token.to_vec()
        }))
    }
    fn on_stop(&mut self) -> anyhow::Result<()> {
        self.clear_secrets();
        self.shutdown.trigger();
        Ok(())
    }
    fn limits(&self) -> HostLimits {
        self.limits
    }
    fn idle(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        let stopped = self.shutdown.triggered();
        Box::pin(async move {
            if let Some(at) = next_wake {
                tokio::select! {()=stopped=>{},()=tokio::time::sleep(at.duration_since(SystemTime::now()).unwrap_or_default())=>{}}
            } else {
                stopped.await;
            }
            Ok(())
        })
    }
}
