//! Host adapters. Native adapters own sockets; sandbox adapters own capabilities.

use crate::host::{Host, HostFuture, HostLimits};
use std::time::SystemTime;
use zeroize::Zeroizing;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::InProcessHost;
#[cfg(unix)]
pub use native::{LaunchdHost, SystemdHost};

/// The embedding WASM runtime supplies only its sandbox capabilities. It may
/// implement sleep with a browser timer or WASI poll; it must not exit on idle.
pub trait SandboxBackend {
    type Listener;
    fn listener(&mut self) -> anyhow::Result<Self::Listener>;
    fn ready(&mut self) -> anyhow::Result<()>;
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>>;
    fn stop(&mut self) -> anyhow::Result<()>;
    fn limits(&self) -> HostLimits;
    fn sleep(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_>;
}

pub struct WasmHost<B>(pub B);
impl<B: SandboxBackend> Host for WasmHost<B> {
    type Listener = B::Listener;
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
        self.0.stop()
    }
    fn limits(&self) -> HostLimits {
        self.0.limits()
    }
    fn idle(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        self.0.sleep(next_wake)
    }
}

/// Hypervisor boundary, deliberately free of fleet placement policy. Suspend
/// must arm the wake before parking and resolve only after the guest resumes.
pub trait EdgeBackend: SandboxBackend {
    fn boot(&mut self) -> anyhow::Result<()>;
    fn suspend_until(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_>;
}

pub struct MicroVmHost<B>(pub B);
impl<B: EdgeBackend> Host for MicroVmHost<B> {
    type Listener = B::Listener;
    fn listener(&mut self) -> anyhow::Result<Self::Listener> {
        self.0.boot()?;
        self.0.listener()
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        self.0.ready()
    }
    fn secret(&mut self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.0.secret(name)
    }
    fn on_stop(&mut self) -> anyhow::Result<()> {
        self.0.stop()
    }
    fn limits(&self) -> HostLimits {
        self.0.limits()
    }
    fn idle(&mut self, next_wake: Option<SystemTime>) -> HostFuture<'_> {
        self.0.suspend_until(next_wake)
    }
}

#[cfg(test)]
mod tests;
