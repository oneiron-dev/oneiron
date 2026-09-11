//! The backend trait, tier-based selection, and the cfg-gated dev and Firecracker implementations.

use std::{fmt, fs, path::PathBuf};

use crate::code_sandbox::{
    SandboxBoundaryContract, SandboxGuestTier, SandboxMount, SandboxMountTable,
    SandboxProposalWrite,
};
use crate::{Error, Result};

use super::credential::CredentialResolver;
use super::handle::{ExecutionBudget, GuestImage, MicroVmExit, MicroVmHandle};
use super::overlay::{
    collect_overlay_writes, overlay_error, overlay_io_detail, prepare_overlay_handle,
};
use crate::error::CodeError;

/// Virtualization backend able to run one propose-only guest.
pub trait MicroVmBackend: Send + Sync {
    /// Stable backend label for diagnostics.
    fn name(&self) -> &'static str;

    /// Provisions overlay dirs and the egress channel for one guest.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when provisioning fails or the
    /// contract is not a propose-only one.
    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle>;

    /// Runs the guest image under `budget`.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when the VM is unknown, the
    /// budget is unbounded, the image is incomplete, or the guest cannot boot.
    fn run(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
    ) -> Result<MicroVmExit>;

    /// Diffs the overlay upper against the base into write proposals.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmOverlayError`](crate::error::CodeError::MicroVmOverlayError) when the overlay cannot be read
    /// or contains an entry that is not a plain file.
    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>>;

    /// Binds `resolver` into the VM's egress transport.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when the VM has no egress
    /// channel this backend can bind.
    fn proxy_credentials(
        &self,
        vm: &MicroVmHandle,
        resolver: &dyn CredentialResolver,
    ) -> Result<()>;
}

impl MicroVmBackend for Box<dyn MicroVmBackend> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle> {
        (**self).prepare(contract, mounts)
    }

    fn run(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
    ) -> Result<MicroVmExit> {
        (**self).run(vm, image, budget)
    }

    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        (**self).collect_overlay_delta(vm)
    }

    fn proxy_credentials(
        &self,
        vm: &MicroVmHandle,
        resolver: &dyn CredentialResolver,
    ) -> Result<()> {
        (**self).proxy_credentials(vm, resolver)
    }
}

/// Routes one guest tier to its execution backend.
///
/// `Ok(None)` means "no microVM": first-party code runs in-process. Foreign and
/// untrusted code either gets an isolating backend or fails closed — there is
/// no silent no-sandbox path, and the dev reference backend is only ever
/// reachable under `cfg(test)` / `debug_assertions` / feature `microvm-dev`.
///
/// # Errors
///
/// Returns [`CodeError::MicroVmBackendUnavailable`](crate::error::CodeError::MicroVmBackendUnavailable) when the tier needs isolation
/// and no backend is compiled in or detected.
pub fn select_backend_for_tier(tier: SandboxGuestTier) -> Result<Option<Box<dyn MicroVmBackend>>> {
    match tier {
        SandboxGuestTier::FirstPartyDreamer => Ok(None),
        SandboxGuestTier::Foreign | SandboxGuestTier::Untrusted => {
            #[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
            {
                Ok(Some(select_isolating_backend()))
            }
            #[cfg(not(any(test, debug_assertions, feature = "microvm-dev")))]
            {
                select_isolating_backend(tier).map(Some)
            }
        }
    }
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
fn select_isolating_backend() -> Box<dyn MicroVmBackend> {
    if let Some(backend) = firecracker_backend() {
        return backend;
    }
    dev_backend()
}

#[cfg(not(any(test, debug_assertions, feature = "microvm-dev")))]
fn select_isolating_backend(tier: SandboxGuestTier) -> Result<Box<dyn MicroVmBackend>> {
    if let Some(backend) = firecracker_backend() {
        return Ok(backend);
    }
    Err(backend_unavailable(tier))
}

#[cfg(any(test, all(not(debug_assertions), not(feature = "microvm-dev"))))]
pub(super) fn backend_unavailable(tier: SandboxGuestTier) -> Error {
    Error::Code(CodeError::MicroVmBackendUnavailable {
        tier: tier.as_str(),
    })
}

#[cfg(feature = "microvm-firecracker")]
fn firecracker_backend() -> Option<Box<dyn MicroVmBackend>> {
    super::firecracker::FirecrackerBackend::detect()
        .map(|backend| Box::new(backend) as Box<dyn MicroVmBackend>)
}

#[cfg(not(feature = "microvm-firecracker"))]
const fn firecracker_backend() -> Option<Box<dyn MicroVmBackend>> {
    None
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
fn dev_backend() -> Box<dyn MicroVmBackend> {
    Box::new(DevProcessBackend::in_temp_root())
}

/// True when the dev reference backend is compiled into this build.
#[must_use]
pub const fn dev_backend_compiled() -> bool {
    cfg!(any(test, debug_assertions, feature = "microvm-dev"))
}

/// True when the Firecracker backend is compiled into this build.
#[must_use]
pub const fn firecracker_backend_compiled() -> bool {
    cfg!(feature = "microvm-firecracker")
}

/// Name of the dev reference backend.
pub const DEV_BACKEND_NAME: &str = "dev-process-isolation";

/// Development-only reference backend.
///
/// It reproduces the boundary *discipline* — writes land in an overlay upper
/// and only reach the host as proposals, credentials resolve behind the
/// allowlist — but it is **not** a security boundary: no VMM, no kernel
/// isolation. It is compiled only under `cfg(test)`, `debug_assertions` or the
/// explicit `microvm-dev` feature, and [`select_backend_for_tier`] never hands
/// it to a release build without that feature.
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
pub struct DevProcessBackend {
    root: PathBuf,
    prepared: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
impl DevProcessBackend {
    /// Creates a backend rooted at a host-owned scratch directory.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            prepared: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        }
    }

    /// Creates a backend under the platform temp dir.
    #[must_use]
    pub fn in_temp_root() -> Self {
        Self::new(std::env::temp_dir().join("oneiron-microvm-dev"))
    }

    fn ensure_prepared(&self, vm: &MicroVmHandle) -> Result<()> {
        let prepared = self
            .prepared
            .lock()
            .map_err(|_| backend_error(DEV_BACKEND_NAME, "backend state is poisoned"))?;
        if prepared.contains(vm.id()) {
            return Ok(());
        }
        Err(backend_error(
            DEV_BACKEND_NAME,
            "vm was not prepared by this backend",
        ))
    }
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
impl MicroVmBackend for DevProcessBackend {
    fn name(&self) -> &'static str {
        DEV_BACKEND_NAME
    }

    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle> {
        let handle = prepare_overlay_handle(&self.root, DEV_BACKEND_NAME, contract, mounts)?;
        self.prepared
            .lock()
            .map_err(|_| backend_error(DEV_BACKEND_NAME, "backend state is poisoned"))?
            .insert(handle.id().to_owned());
        Ok(handle)
    }

    fn run(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
    ) -> Result<MicroVmExit> {
        self.ensure_prepared(vm)?;
        if !budget.is_bounded() {
            return Err(backend_error(
                DEV_BACKEND_NAME,
                "execution budget must bound wall clock, memory and pids",
            ));
        }
        image.ensure_present(DEV_BACKEND_NAME)?;

        // The dev backend boots no guest: with no VMM and no interpreter linked
        // it exercises the host half of the boundary only. Anything a guest
        // "wrote" is whatever the caller staged in the overlay upper, which is
        // exactly what an isolating backend would hand back.
        let overlay_dirty = fs::read_dir(vm.overlay_upper())
            .map_err(|error| overlay_error(overlay_io_detail("upper", &error)))?
            .next()
            .is_some();
        Ok(MicroVmExit {
            status: 0,
            overlay_dirty,
        })
    }

    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        self.ensure_prepared(vm)?;
        collect_overlay_writes(vm.overlay_upper(), SandboxMount::Workspace)
    }

    fn proxy_credentials(
        &self,
        vm: &MicroVmHandle,
        _resolver: &dyn CredentialResolver,
    ) -> Result<()> {
        // The dev backend has no in-guest transport to bind the resolver into;
        // arming is the parent-directory check that the egress endpoint could
        // exist. Resolution and allowlist enforcement stay host-side in
        // `CredentialEgressProxy`, which is backend-independent by design.
        self.ensure_prepared(vm)?;
        let Some(parent) = vm.egress_socket().parent() else {
            return Err(backend_error(
                DEV_BACKEND_NAME,
                "egress endpoint has no host directory",
            ));
        };
        if !parent.is_dir() {
            return Err(backend_error(
                DEV_BACKEND_NAME,
                "egress endpoint directory is missing",
            ));
        }
        Ok(())
    }
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
impl fmt::Debug for DevProcessBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevProcessBackend")
            .field("name", &DEV_BACKEND_NAME)
            .field("root", &"<host-only>")
            .finish()
    }
}

pub(super) fn backend_error(backend: &'static str, detail: impl Into<String>) -> Error {
    Error::Code(CodeError::MicroVmBackendError {
        backend,
        detail: detail.into(),
    })
}
