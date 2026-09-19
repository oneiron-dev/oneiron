//! Managed process entry behind the shared six-verb Host contract.
use super::{
    args::ManagedArgs,
    listener::{ServeListener, signal_ready},
    state_serve::ManagedShutdown,
    vault_gates::read_managed_credentials,
};
use oneiron_vault_contract::{
    Credentials,
    host::{Host, HostFuture, HostLimits},
};
use std::time::SystemTime;
use zeroize::Zeroizing;

/// This adapter owns descriptor consumption. It preserves managed boot order:
/// resolve the listener, consume credentials, pass vault gates, bind, ready.
pub(super) struct ManagedHost {
    listener: Option<ServeListener>,
    credentials_fd: Option<std::os::fd::RawFd>,
    credentials: Option<Credentials>,
    ready_fd: Option<std::os::fd::RawFd>,
    limits: HostLimits,
    shutdown: ManagedShutdown,
}
impl ManagedHost {
    pub(super) fn new(
        args: &ManagedArgs,
        limits: HostLimits,
        shutdown: ManagedShutdown,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            listener: Some(ServeListener::for_managed(args)?),
            credentials_fd: Some(args.credentials_fd),
            credentials: None,
            ready_fd: Some(args.ready_fd),
            limits,
            shutdown,
        })
    }
    pub(super) fn clear_secrets(&mut self) {
        self.credentials = None;
    }
}
impl Host for ManagedHost {
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
