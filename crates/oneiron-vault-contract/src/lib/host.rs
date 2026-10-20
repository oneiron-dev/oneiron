//! One vault-hosting contract. Idle waits; it never means process exit.

use std::{future::Future, pin::Pin, time::SystemTime};
use zeroize::Zeroizing;

#[cfg(not(target_arch = "wasm32"))]
pub type HostFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;

/// Browser timer futures may be thread-local; native hosts retain Send.
#[cfg(target_arch = "wasm32")]
pub type HostFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>>;

/// Limits are supplied by the host policy, not chosen by the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostLimits {
    pub memory_bytes: u64,
    /// The CPU share the host grants, in CPU milliseconds each second;
    /// `u32::MAX` is unbounded. Advisory, not an OS-enforced quota: an
    /// embedded engine sizes the worker pool of the runtime it owns from it,
    /// one worker per whole CPU second, rounded up, at least one and at most
    /// the CPUs available.
    pub cpu_millis_per_second: u32,
}

impl HostLimits {
    /// No engine-imposed cap. An OS supervisor can still enforce its own caps.
    pub const fn unbounded() -> Self {
        Self {
            memory_bytes: u64::MAX,
            cpu_millis_per_second: u32::MAX,
        }
    }
}

/// Six verbs shared by embedded, OS-supervised and sandboxed deployments.
/// Listener ownership crosses this boundary exactly once per start.
pub trait Host {
    type Listener;
    fn listener(&mut self) -> anyhow::Result<Self::Listener>;
    fn ready(&mut self) -> anyhow::Result<()>;
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>>;
    fn on_stop(&mut self) -> anyhow::Result<()>;
    fn limits(&self) -> HostLimits;
    fn idle(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_>;

    /// Boot must finish opening the vault and binding its control socket
    /// before readiness can be published. Failure never publishes ready.
    fn start(
        &mut self,
        boot: impl FnOnce(Self::Listener) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let listener = self.listener()?;
        boot(listener)?;
        self.ready()
    }
    fn stop(&mut self) -> anyhow::Result<()> {
        self.on_stop()
    }
    fn restart(
        &mut self,
        boot: impl FnOnce(Self::Listener) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.stop()?;
        self.start(boot)
    }
}

/// Result of opening an optional session preview on a native host.
#[cfg(not(target_arch = "wasm32"))]
pub type PreviewHostFuture<'a, L> = Pin<Box<dyn Future<Output = anyhow::Result<L>> + Send + 'a>>;

/// Embedded WebAssembly adapters may use thread-local forwarding futures.
#[cfg(target_arch = "wasm32")]
pub type PreviewHostFuture<'a, L> = Pin<Box<dyn Future<Output = anyhow::Result<L>> + 'a>>;

/// Optional live-port half of the host contract. Opening consumes a manifest
/// authenticated by the session runtime, never arbitrary HTTP port numbers.
/// The returned lease owns forwarding: drop, expiry, process exit and host
/// stop must close both the listener and connections already using it.
pub trait PreviewPortHost {
    type Lease;

    fn open_preview(
        &self,
        manifest: crate::preview::PreviewSessionManifest,
    ) -> PreviewHostFuture<'_, Self::Lease>;
}

/// Pressure cutoffs and reap eligibility remain host policy. Even a refused
/// shed must complete before the existing reap decision is evaluated. A ctl
/// failure is returned separately and never skips or overrides that decision.
pub fn shed_before_reap<S, R>(
    waited_secs: u64,
    mut ctl: impl FnMut(crate::CtlRequest) -> anyhow::Result<S>,
    reap: impl FnOnce() -> R,
) -> (anyhow::Result<S>, R) {
    let request = crate::CtlRequest::Shed {
        cause: crate::ShedCause::MemoryPressure,
        waited_secs,
        wait_id: None,
    };
    let shed = request
        .validate()
        .map_err(anyhow::Error::msg)
        .and_then(|()| ctl(request));
    let decision = reap();
    (shed, decision)
}
