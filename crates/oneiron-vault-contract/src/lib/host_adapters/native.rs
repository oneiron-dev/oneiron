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

fn wait(wake: &Notify, next: Option<SystemTime>) -> HostFuture<'_> {
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

#[cfg(unix)]
mod activated {
    use super::*;
    use std::{io::Write, os::unix::net::UnixListener};

    /// Owned activation socket, credential map, and readiness channel. OS fd
    /// discovery stays at process entry; adapters never own a raw fd twice.
    pub struct SystemdHost {
        listener: UnixListener,
        secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
        limits: HostLimits,
        ready: Hook,
        stop: Hook,
        wake: Arc<Notify>,
    }
    impl SystemdHost {
        pub fn new(
            listener: UnixListener,
            secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
            limits: HostLimits,
            ready: impl FnMut() -> anyhow::Result<()> + Send + 'static,
            stop: impl FnMut() -> anyhow::Result<()> + Send + 'static,
        ) -> Self {
            Self {
                listener,
                secrets,
                limits,
                ready: Box::new(ready),
                stop: Box::new(stop),
                wake: Arc::new(Notify::new()),
            }
        }
        pub fn wake_handle(&self) -> Arc<Notify> {
            Arc::clone(&self.wake)
        }
        /// sd_notify through an already-connected notification socket. The
        /// launcher resolves NOTIFY_SOCKET, including abstract namespaces.
        pub fn with_notify_socket(
            listener: UnixListener,
            secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
            limits: HostLimits,
            notify: std::os::unix::net::UnixDatagram,
            stop: impl FnMut() -> anyhow::Result<()> + Send + 'static,
        ) -> Self {
            Self::new(
                listener,
                secrets,
                limits,
                move || {
                    notify.send(b"READY=1")?;
                    Ok(())
                },
                stop,
            )
        }
    }
    impl Host for SystemdHost {
        type Listener = UnixListener;
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

    /// launchd supplies an owned activation socket and a readiness pipe.
    pub struct LaunchdHost(SystemdHost);
    impl LaunchdHost {
        pub fn new(
            listener: UnixListener,
            secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
            limits: HostLimits,
            mut ready: impl Write + Send + 'static,
            stop: impl FnMut() -> anyhow::Result<()> + Send + 'static,
        ) -> Self {
            Self(SystemdHost::new(
                listener,
                secrets,
                limits,
                move || {
                    ready.write_all(&[crate::READY_BYTE])?;
                    ready.flush()?;
                    Ok(())
                },
                stop,
            ))
        }
        pub fn wake_handle(&self) -> Arc<Notify> {
            self.0.wake_handle()
        }
    }
    impl Host for LaunchdHost {
        type Listener = UnixListener;
        fn listener(&mut self) -> anyhow::Result<Self::Listener> {
            self.0.listener()
        }
        fn ready(&mut self) -> anyhow::Result<()> {
            self.0.ready()
        }
        fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
            self.0.secret(name)
        }
        fn on_stop(&mut self) -> anyhow::Result<()> {
            self.0.on_stop()
        }
        fn limits(&self) -> HostLimits {
            self.0.limits()
        }
        fn idle(&mut self, next: Option<SystemTime>) -> HostFuture<'_> {
            self.0.idle(next)
        }
    }
}
#[cfg(unix)]
pub use activated::{LaunchdHost, SystemdHost};
