//! Native socket ownership, secret lookup, and cooperative idle wakeup.

use crate::host::{Host, HostFuture, HostLimits};
use std::{collections::BTreeMap, net::TcpListener, sync::Arc, time::SystemTime};
use tokio::sync::Notify;
use zeroize::Zeroizing;

type Hook = Box<dyn FnMut() -> anyhow::Result<()> + Send>;

/// The owner injects readiness and drain hooks. Secrets stay zeroizing and are
/// looked up by exact name; neither environment fallback nor logging occurs.
pub struct InProcessHost {
    listener: TcpListener,
    secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
    limits: HostLimits,
    ready: Hook,
    stop: Hook,
    wake: Arc<Notify>,
}
impl InProcessHost {
    pub fn new(
        listener: TcpListener,
        limits: HostLimits,
        ready: impl FnMut() -> anyhow::Result<()> + Send + 'static,
        stop: impl FnMut() -> anyhow::Result<()> + Send + 'static,
    ) -> Self {
        Self {
            listener,
            limits,
            ready: Box::new(ready),
            stop: Box::new(stop),
            secrets: BTreeMap::new(),
            wake: Arc::new(Notify::new()),
        }
    }
    pub fn insert_secret(&mut self, name: String, value: Zeroizing<Vec<u8>>) {
        self.secrets.insert(name, value);
    }
    /// An inbound event wakes idle without stopping the vault.
    pub fn wake_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }
}

pub(super) fn wait(wake: &Notify, next: Option<SystemTime>) -> HostFuture<'_> {
    Box::pin(async move {
        match next {
            Some(at) => {
                let duration = at.duration_since(SystemTime::now()).unwrap_or_default();
                tokio::select! { () = wake.notified() => {}, () = tokio::time::sleep(duration) => {} }
            }
            None => wake.notified().await,
        }
        Ok(())
    })
}
impl Host for InProcessHost {
    type Listener = TcpListener;
    fn listener(&mut self) -> anyhow::Result<Self::Listener> {
        Ok(self.listener.try_clone()?)
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        (self.ready)()
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.secrets
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown host secret"))
    }
    fn on_stop(&mut self) -> anyhow::Result<()> {
        (self.stop)()
    }
    fn limits(&self) -> HostLimits {
        self.limits
    }
    fn idle(&mut self, next: Option<SystemTime>) -> HostFuture<'_> {
        wait(&self.wake, next)
    }
}
