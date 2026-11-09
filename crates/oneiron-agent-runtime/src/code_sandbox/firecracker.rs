//! Host-configured jailer execution with a bounded vsock guest-agent protocol.
//!
//! No binary or guest image is downloaded. Absence of configuration, jailer,
//! KVM, pinned images, cgroups or a compatible guest agent refuses execution.
//! There is no process-backend fallback. See `guest-protocol.md` for the
//! externally built guest contract and the real-boot acceptance requirements.
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::firecracker::*;

mod config;
#[cfg(target_os = "linux")]
mod egress;
#[cfg(target_os = "linux")]
mod oci_mounts;
#[cfg(target_os = "linux")]
mod oci_session;
#[cfg(target_os = "linux")]
mod snapshot;

use super::microvm::prepare_overlay_handle;
pub use config::FirecrackerHostConfig;
pub use config::GuestArtifactPins;
