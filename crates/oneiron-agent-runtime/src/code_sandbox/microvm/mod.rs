//! The microVM lane: core's contract and selection law
//! (`oneiron::code_sandbox::microvm`, re-exported whole), and the OCI fenced
//! container backend, with the guest protocol and source snapshot it shares
//! with the Firecracker backend.

pub use oneiron::code_sandbox::microvm::*;

#[cfg(target_os = "linux")]
mod container;
#[cfg(target_os = "linux")]
pub use container::{CONTAINER_BACKEND_NAME, ContainerBackend};
#[cfg(target_os = "linux")]
#[path = "../firecracker/protocol.rs"]
mod protocol;
#[cfg(target_os = "linux")]
#[path = "../firecracker/snapshot.rs"]
mod snapshot;
#[cfg(target_os = "linux")]
fn refused(detail: impl Into<String>) -> crate::Error {
    backend_error("isolated-guest", detail)
}
