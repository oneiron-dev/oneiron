//! The microVM lane: core's contract and selection law
//! (`oneiron::code_sandbox::microvm`, re-exported whole), the OCI fenced
//! container backend and the vendor sandbox batch backend (L8-43), with the
//! guest protocol and source snapshot they share with the Firecracker backend.

pub use oneiron::code_sandbox::microvm::*;

#[cfg(target_os = "linux")]
mod container;
#[cfg(target_os = "linux")]
pub use container::{CONTAINER_BACKEND_NAME, ContainerBackend};
#[cfg(target_os = "linux")]
#[path = "../firecracker/protocol.rs"]
mod protocol;
#[cfg(target_os = "linux")]
mod vendor_batch;
#[cfg(target_os = "linux")]
pub use vendor_batch::{
    MAX_VENDOR_TRANSCRIPT_BYTES, VENDOR_BATCH_DIR, VENDOR_GUEST_BIN, VendorBatchBackend,
    VendorCallBound, VendorSandboxClient, VendorSandboxId, VendorSandboxSpec,
};
#[cfg(target_os = "linux")]
#[path = "../firecracker/snapshot.rs"]
mod snapshot;
#[cfg(target_os = "linux")]
fn refused(detail: impl Into<String>) -> crate::Error {
    backend_error("isolated-guest", detail)
}
