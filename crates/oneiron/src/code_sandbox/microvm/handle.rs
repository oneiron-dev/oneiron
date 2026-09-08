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
}

impl GuestImage {
    #[must_use]
    pub fn new(
        kernel: impl Into<PathBuf>,
        rootfs: impl Into<PathBuf>,
        component: impl Into<PathBuf>,
    ) -> Self {
        Self {
            kernel: kernel.into(),
            rootfs: rootfs.into(),
            component: component.into(),
        }
    }

    /// Checks that every image artifact is present before a guest is booted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when an artifact is missing. The
    /// message names the artifact class, never the host path.
    pub fn ensure_present(&self, backend: &'static str) -> Result<()> {
        for (class, path) in [
            ("kernel", &self.kernel),
            ("rootfs", &self.rootfs),
            ("component", &self.component),
        ] {
            if !path.exists() {
                return Err(backend_error(
                    backend,
                    format!("guest image artifact `{class}` is missing"),
                ));
            }
        }
        Ok(())
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
#[derive(Clone, PartialEq, Eq)]
pub struct MicroVmHandle {
    id: String,
    tier: SandboxGuestTier,
    base_root: PathBuf,
    overlay_upper: PathBuf,
    egress_socket: PathBuf,
}

impl MicroVmHandle {
    /// Creates a handle for a VM a backend has prepared.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when the VM id is blank or
    /// contains control characters.
    pub fn new(
        id: impl Into<String>,
        tier: SandboxGuestTier,
        base_root: impl Into<PathBuf>,
        overlay_upper: impl Into<PathBuf>,
        egress_socket: impl Into<PathBuf>,
    ) -> Result<Self> {
        let id = id.into();
        let trimmed = id.trim();
        if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
            return Err(backend_error("microvm", "vm id must be a non-blank label"));
        }
        Ok(Self {
            id: trimmed.to_owned(),
            tier,
            base_root: base_root.into(),
            overlay_upper: overlay_upper.into(),
            egress_socket: egress_socket.into(),
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn tier(&self) -> SandboxGuestTier {
        self.tier
    }

    /// Host root of the read-only base mount. Never written through this handle.
    #[must_use]
    pub fn base_root(&self) -> &Path {
        &self.base_root
    }

    /// Host root of the overlay upper directory the guest writes into.
    #[must_use]
    pub fn overlay_upper(&self) -> &Path {
        &self.overlay_upper
    }

    /// Host endpoint of the VM-internal egress channel owned by the adapter.
    #[must_use]
    pub fn egress_socket(&self) -> &Path {
        &self.egress_socket
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MicroVmExit {
    pub status: i32,
    pub overlay_dirty: bool,
}

/// Resource ceiling applied to one guest run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
    pub wall_clock_secs: u64,
    pub mem_mib: u32,
    pub pids: u32,
}

impl ExecutionBudget {
    #[must_use]
    pub const fn new(wall_clock_secs: u64, mem_mib: u32, pids: u32) -> Self {
        Self {
            wall_clock_secs,
            mem_mib,
            pids,
        }
    }

    /// True when every axis of the budget is actually bounded. A zero on any
    /// axis is treated as "unbounded" and refused by backends.
    #[must_use]
    pub const fn is_bounded(self) -> bool {
        self.wall_clock_secs > 0 && self.mem_mib > 0 && self.pids > 0
    }
}
