//! Lifted half of `oneiron::code_sandbox::microvm::handle` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::microvm::handle::*;
#[allow(unused_imports)]
use crate::ext::*;
use std::path::Path;
use std::path::PathBuf;
use crate::Result;
use crate::code_sandbox::SandboxGuestTier;
use super::backend::backend_error;

/// Methods of [`GuestImage`] that moved out of `oneiron` with `code_sandbox::microvm::handle` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxMicrovmHandleGuestImageExt {
    #[must_use]
    fn new(
        kernel: impl Into<PathBuf>,
        rootfs: impl Into<PathBuf>,
        component: impl Into<PathBuf>,
    ) -> Self;
    /// Select source for a reusable interpreter component. Empty source is
    /// valid for a component with its own embedded entry program.
    #[must_use]
    fn with_source(self, source: impl Into<String>) -> Self;
    /// Checks that every image artifact is present before a guest is booted.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when an artifact is missing. The
    /// message names the artifact class, never the host path.
    fn ensure_present(&self, backend: &'static str) -> Result<()>;
}

impl CodeSandboxMicrovmHandleGuestImageExt for GuestImage {
    #[must_use]
    fn new(
            kernel: impl Into<PathBuf>,
            rootfs: impl Into<PathBuf>,
            component: impl Into<PathBuf>,
        ) -> Self {
            Self {
                kernel: kernel.into(),
                rootfs: rootfs.into(),
                component: component.into(),
                source: String::new(),
                oci: None,
            }
        }

    /// Select source for a reusable interpreter component. Empty source is
    /// valid for a component with its own embedded entry program.
    #[must_use]
    fn with_source(mut self, source: impl Into<String>) -> Self {
            self.source = source.into();
            self
        }

    /// Checks that every image artifact is present before a guest is booted.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when an artifact is missing. The
    /// message names the artifact class, never the host path.
    fn ensure_present(&self, backend: &'static str) -> Result<()> {
            if self.source.len() > 1024 * 1024 {
                return Err(backend_error(
                    backend,
                    "guest source exceeds message budget",
                ));
            }
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

/// Methods of [`MicroVmHandle`] that moved out of `oneiron` with `code_sandbox::microvm::handle` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxMicrovmHandleMicroVmHandleExt {
    /// Creates a handle for a VM a backend has prepared.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when the VM id is blank or
    /// contains control characters.
    fn new(
        id: impl Into<String>,
        tier: SandboxGuestTier,
        base_root: impl Into<PathBuf>,
        overlay_upper: impl Into<PathBuf>,
        egress_socket: impl Into<PathBuf>,
    ) -> Result<Self>;
    fn with_scratch(self, scratch: super::scratch::ScratchHandle) -> Self;
    #[must_use]
    fn id(&self) -> &str;
    #[must_use]
    fn tier(&self) -> SandboxGuestTier;
    /// Host root of the read-only base mount. Never written through this handle.
    #[must_use]
    fn base_root(&self) -> &Path;
    /// Host root of the overlay upper directory the guest writes into.
    #[must_use]
    fn overlay_upper(&self) -> &Path;
    /// Host endpoint of the VM-internal egress channel owned by the adapter.
    #[must_use]
    fn egress_socket(&self) -> &Path;
}

impl CodeSandboxMicrovmHandleMicroVmHandleExt for MicroVmHandle {
    /// Creates a handle for a VM a backend has prepared.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when the VM id is blank or
    /// contains control characters.
    fn new(
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
                scratch: None,
            })
        }

    fn with_scratch(mut self, scratch: super::scratch::ScratchHandle) -> Self {
            self.scratch = Some(scratch);
            self
        }

    #[must_use]
    fn id(&self) -> &str {
            &self.id
        }

    #[must_use]
    fn tier(&self) -> SandboxGuestTier {
            self.tier
        }

    /// Host root of the read-only base mount. Never written through this handle.
    #[must_use]
    fn base_root(&self) -> &Path {
            &self.base_root
        }

    /// Host root of the overlay upper directory the guest writes into.
    #[must_use]
    fn overlay_upper(&self) -> &Path {
            &self.overlay_upper
        }

    /// Host endpoint of the VM-internal egress channel owned by the adapter.
    #[must_use]
    fn egress_socket(&self) -> &Path {
            &self.egress_socket
        }
}

/// Methods of [`ExecutionBudget`] that moved out of `oneiron` with `code_sandbox::microvm::handle` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxMicrovmHandleExecutionBudgetExt {
    #[must_use]
    fn new(wall_clock_secs: u64, mem_mib: u32, pids: u32) -> Self;
}

impl CodeSandboxMicrovmHandleExecutionBudgetExt for ExecutionBudget {
    #[must_use]
    fn new(wall_clock_secs: u64, mem_mib: u32, pids: u32) -> Self {
            Self {
                wall_clock_secs,
                mem_mib,
                pids,
            }
        }
}
