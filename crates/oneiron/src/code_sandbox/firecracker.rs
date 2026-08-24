//! Firecracker microVM backend (Linux only, feature `microvm-firecracker`).
//!
//! This is the isolating backend the foreign/untrusted lane is meant to run on.
//! It is compiled only behind its feature, and `FirecrackerBackend::detect`
//! returns `None` unless the host actually has the VMM binary — so a build with
//! the feature on but no VMM present still fails closed through
//! `super::microvm::select_backend_for_tier` rather than running unisolated.
//!
//! The boundary halves that are host-side (overlay diff, credential proxy) are
//! shared verbatim with the other backends; what is Firecracker-specific is
//! booting the guest, which requires a configured jailer root and image set.

use std::{fmt, path::PathBuf};

use super::{
    SandboxBoundaryContract, SandboxMount, SandboxMountTable, SandboxProposalWrite,
    microvm::{
        CredentialResolver, ExecutionBudget, GuestImage, MicroVmBackend, MicroVmExit,
        MicroVmHandle, collect_overlay_writes, prepare_overlay_handle,
    },
};
use crate::{Error, Result};

/// Stable backend label.
pub const FIRECRACKER_BACKEND_NAME: &str = "firecracker";

/// Host environment key naming the VMM binary.
pub const FIRECRACKER_BIN_ENV: &str = "ONEIRON_MICROVM_FIRECRACKER_BIN";
/// Host environment key naming the jailer/scratch root for VM state.
pub const FIRECRACKER_ROOT_ENV: &str = "ONEIRON_MICROVM_ROOT";

const DEFAULT_BINARY: &str = "/usr/bin/firecracker";

/// Firecracker-backed microVM lane.
pub struct FirecrackerBackend {
    binary: PathBuf,
    root: PathBuf,
}

impl FirecrackerBackend {
    /// Creates a backend against an explicit VMM binary and state root.
    #[must_use]
    pub fn new(binary: impl Into<PathBuf>, root: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            root: root.into(),
        }
    }

    /// Detects a usable Firecracker install, or `None`.
    ///
    /// `None` is the fail-closed answer: the caller then has no isolating
    /// backend and refuses the run instead of downgrading it.
    #[must_use]
    pub fn detect() -> Option<Self> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let binary = std::env::var_os(FIRECRACKER_BIN_ENV)
            .map_or_else(|| PathBuf::from(DEFAULT_BINARY), PathBuf::from);
        if !binary.is_file() {
            return None;
        }
        let root = std::env::var_os(FIRECRACKER_ROOT_ENV).map_or_else(
            || std::env::temp_dir().join("oneiron-microvm"),
            PathBuf::from,
        );
        Some(Self::new(binary, root))
    }

    fn not_configured(detail: &'static str) -> Error {
        Error::MicroVmBackendError {
            backend: FIRECRACKER_BACKEND_NAME,
            detail: detail.to_owned(),
        }
    }
}

impl MicroVmBackend for FirecrackerBackend {
    fn name(&self) -> &'static str {
        FIRECRACKER_BACKEND_NAME
    }

    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle> {
        prepare_overlay_handle(&self.root, FIRECRACKER_BACKEND_NAME, contract, mounts)
    }

    fn run(
        &self,
        _vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
    ) -> Result<MicroVmExit> {
        if !budget.is_bounded() {
            return Err(Self::not_configured(
                "execution budget must bound wall clock, memory and pids",
            ));
        }
        if !self.binary.is_file() {
            return Err(Error::MicroVmBackendUnavailable {
                tier: "foreign_or_untrusted",
            });
        }
        image.ensure_present(FIRECRACKER_BACKEND_NAME)?;

        // Booting the guest needs a jailer profile and a machine-config the
        // host supplies; until that arrives the lane refuses the run rather
        // than executing foreign code outside a VM.
        Err(Self::not_configured(
            "guest boot is not configured for this host",
        ))
    }

    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        collect_overlay_writes(vm.overlay_upper(), SandboxMount::Workspace)
    }

    fn proxy_credentials(
        &self,
        vm: &MicroVmHandle,
        _resolver: &dyn CredentialResolver,
    ) -> Result<()> {
        // The vsock endpoint lives beside the VM's overlay state; the resolver
        // itself is consulted host-side by `CredentialEgressProxy`, which is
        // backend-independent on purpose.
        let Some(parent) = vm.egress_socket().parent() else {
            return Err(Self::not_configured(
                "egress endpoint has no host directory",
            ));
        };
        if !parent.is_dir() {
            return Err(Self::not_configured("egress endpoint directory is missing"));
        }
        Ok(())
    }
}

impl fmt::Debug for FirecrackerBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirecrackerBackend")
            .field("name", &FIRECRACKER_BACKEND_NAME)
            .field("host_paths", &"<host-only>")
            .finish()
    }
}
