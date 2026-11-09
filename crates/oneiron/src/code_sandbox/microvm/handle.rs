//! The VM value objects: guest image, running handle, exit and execution budget.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use crate::Result;
use crate::code_sandbox::SandboxGuestTier;

use super::backend::backend_error;

/// Prebuilt guest image: kernel, root filesystem and the guest component.
///
/// The paths are host-owned build artifacts; nothing here is guest-visible.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestImage {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub component: PathBuf,
    /// Untrusted source passed to the canonical typed run-step export.
    pub source: String,
    pub oci: Option<OciGuestImage>,
}

/// OCI variant of a guest. A microVM host maps this digest to its pinned
/// bootable rootfs; the container backend runs the exact OCI image directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciGuestImage {
    pub image: String,
}
impl GuestImage {
    pub fn with_oci(mut self, image: &str) -> Result<Self> {
        oneiron_container::ImageRef::pinned(image)
            .map_err(|e| backend_error("oci", e.to_string()))?;
        self.oci = Some(OciGuestImage {
            image: image.to_owned(),
        });
        Ok(self)
    }

}

impl fmt::Debug for GuestImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestImage")
            .field("artifacts", &["kernel", "rootfs", "component"])
            .field("host_paths", &"<host-only>")
            .finish()
    }
}

/// Live handle for one prepared microVM.
///
/// Host paths (overlay dirs, egress socket) stay host-side: the [`fmt::Debug`]
/// rendering redacts them so they cannot leak into guest-visible diagnostics.
#[derive(Clone)]
pub struct MicroVmHandle {
    pub id: String,
    pub tier: SandboxGuestTier,
    pub base_root: PathBuf,
    pub overlay_upper: PathBuf,
    pub egress_socket: PathBuf,
    pub scratch: Option<super::scratch::ScratchHandle>,
}

impl fmt::Debug for MicroVmHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MicroVmHandle")
            .field("id", &self.id)
            .field("tier", &self.tier)
            .field("host_paths", &"<host-only>")
            .finish()
    }
}

/// Result of one guest run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroVmExit {
    pub status: i32,
    pub overlay_dirty: bool,
    pub result_json: Option<String>,
    /// A failed run's program error, as its guest sent it, header included
    /// (FIX 9209). It is not masked; the caller masks it before it leaves
    /// the host. `None` for a run that succeeded or sent no error.
    pub guest_error: Option<String>,
}

/// Resource ceiling applied to one guest run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
    pub wall_clock_secs: u64,
    pub mem_mib: u32,
    pub pids: u32,
}

impl Default for ExecutionBudget {
    fn default() -> Self {
        Self::new(30, 512, 64)
    }
}

impl ExecutionBudget {

    /// True when every axis of the budget is actually bounded. A zero on any
    /// axis is treated as "unbounded" and refused by backends.
    #[must_use]
    pub const fn is_bounded(self) -> bool {
        self.wall_clock_secs > 0 && self.mem_mib > 0 && self.pids > 0
    }
}

impl PartialEq for MicroVmHandle {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.tier == other.tier
            && self.base_root == other.base_root
            && self.overlay_upper == other.overlay_upper
            && self.egress_socket == other.egress_socket
            && self.scratch.is_some() == other.scratch.is_some()
    }
}
impl Eq for MicroVmHandle {}
