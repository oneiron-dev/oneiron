//! The daemon position's adapters: systemd on Linux, launchd on macOS, and a
//! plain bind when neither started the process.
//!
//! The service manager owns the socket and the secrets; the engine adopts the
//! one and reads the other. Readiness goes back as sd_notify `READY=1` under
//! systemd; launchd has no readiness protocol. While a wake pass runs on a
//! plugged-in laptop, an idle-sleep assertion keeps it awake; display sleep
//! is never blocked and a manual sleep or closed lid always wins.

mod hosts;
mod keep_awake;

pub use hosts::{ActivatedListener, DesktopHost, LaunchdHost, SecretSource, SystemdHost};
pub use keep_awake::{AwakeGuard, AwakePolicy, KeepAwake};
