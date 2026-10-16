//! The in-process adapter for an engine embedded in a mobile app (NAPI or
//! FFI). There is no socket: the app hands connections over a channel. The
//! app's keychain holds the secrets, the app calls on-stop before it
//! backgrounds, and the next wake becomes the app's own local timer
//! (BGTaskScheduler, WorkManager). Grants here are ergonomics and audit, not
//! a boundary: the app could open the vault files itself.

use super::native::wait;
use crate::host::{Host, HostFuture, HostLimits};
use std::{sync::Arc, time::SystemTime};
use tokio::sync::{Notify, mpsc};
use zeroize::Zeroizing;

/// What the embedding app brings.
pub trait AppHost: Send {
    /// One secret from the app keychain, by exact name.
    fn keychain(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>>;
    /// Arms the app's local timer for the next wake; `None` clears it. The
    /// app wakes the engine through [`EmbeddedHost::wake_handle`].
    fn schedule_wake(&mut self, at: Option<SystemTime>) -> anyhow::Result<()>;
    /// The engine opened its vault and takes connections.
    fn ready(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// `C` is one in-process connection: whatever the binding passes, such as a
/// duplex stream or a request with its reply channel.
pub struct EmbeddedHost<A, C> {
    app: A,
    connections: Option<mpsc::Receiver<C>>,
    connector: mpsc::Sender<C>,
    limits: HostLimits,
    wake: Arc<Notify>,
    stopping: Arc<Notify>,
}
impl<A: AppHost, C> EmbeddedHost<A, C> {
    /// `backlog` bounds connections the app queued before the engine took them.
    pub fn new(app: A, limits: HostLimits, backlog: usize) -> Self {
        let (connector, connections) = mpsc::channel(backlog.max(1));
        Self {
            app,
            connections: Some(connections),
            connector,
            limits,
            wake: Arc::new(Notify::new()),
            stopping: Arc::new(Notify::new()),
        }
    }
    /// The app's end of the channel where a listener would be.
    pub fn connector(&self) -> mpsc::Sender<C> {
        self.connector.clone()
    }
    /// The app's timer fired, or a push arrived: run what is due.
    pub fn wake_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }
    /// The engine's serve loop stops taking connections when this fires.
    pub fn stop_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.stopping)
    }
}

impl<A: AppHost, C: Send> Host for EmbeddedHost<A, C> {
    type Listener = mpsc::Receiver<C>;
    fn listener(&mut self) -> anyhow::Result<Self::Listener> {
        self.connections
            .take()
            .ok_or_else(|| anyhow::anyhow!("embedded listener already taken"))
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        self.app.ready()
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.app.keychain(name)
    }
    /// The app is about to background. The serve loop drains and stops;
    /// the app's timer stays armed for the next wake.
    fn on_stop(&mut self) -> anyhow::Result<()> {
        self.stopping.notify_one();
        Ok(())
    }
    fn limits(&self) -> HostLimits {
        self.limits
    }
    fn idle(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        if let Err(error) = self.app.schedule_wake(next_wake) {
            return Box::pin(async move { Err(error) });
        }
        wait(&self.wake, next_wake)
    }
}
