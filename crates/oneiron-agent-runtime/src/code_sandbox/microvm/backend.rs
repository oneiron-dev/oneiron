//! Lifted half of `oneiron::code_sandbox::microvm::backend` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::microvm::backend::*;
#[allow(unused_imports)]
use crate::ext::*;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use std::fmt;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use std::fs;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use std::path::PathBuf;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use crate::code_sandbox::SandboxMount;
use crate::code_sandbox::SandboxBoundaryContract;
use crate::code_sandbox::SandboxGuestTier;
use crate::code_sandbox::SandboxMountTable;
use crate::code_sandbox::SandboxProposalWrite;
use crate::Result;
use super::credential::CredentialResolver;
use super::handle::ExecutionBudget;
use super::handle::GuestImage;
use super::handle::MicroVmExit;
use super::handle::MicroVmHandle;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use super::overlay::collect_overlay_writes;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use super::overlay::overlay_error;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use super::overlay::overlay_io_detail;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use super::overlay::prepare_overlay_handle;

/// Browser/native sessions use the host's OCI runtime and image configuration,
/// and the same KVM-first selection law as finite code runs: a KVM host
/// with no Firecracker installed runs them in the OCI fenced container
/// (`installed_firecracker`).
pub fn select_backend_for_session(
    tier: SandboxGuestTier,
    runtime: std::path::PathBuf,
    image: &str,
) -> Result<Box<dyn MicroVmBackend>> {
    if tier == SandboxGuestTier::FirstPartyDreamer {
        return Err(backend_unavailable(tier));
    }
    if let Some(backend) = installed_firecracker() {
        return Ok(backend);
    }
    #[cfg(target_os = "linux")]
    {
        super::ContainerBackend::for_session(runtime, image)
            .map(|b| Box::new(b) as Box<dyn MicroVmBackend>)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (runtime, image);
        Err(backend_unavailable(tier))
    }
}

#[cfg(target_os = "linux")]
fn container_backend() -> Option<Box<dyn MicroVmBackend>> {
    super::ContainerBackend::detect().map(|b| Box::new(b) as Box<dyn MicroVmBackend>)
}

#[cfg(feature = "microvm-firecracker")]
fn firecracker_backend() -> Option<Box<dyn MicroVmBackend>> {
    super::firecracker::FirecrackerBackend::detect()
        .map(|backend| Box::new(backend) as Box<dyn MicroVmBackend>)
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
/// explicit `microvm-dev` feature. [`select_backend_for_tier`] never selects it.
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
pub struct DevProcessBackend {
    root: PathBuf,
    prepared: std::sync::Mutex<std::collections::BTreeMap<String, MicroVmHandle>>,
}

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
impl DevProcessBackend {
    /// Creates a backend rooted at a host-owned scratch directory.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            prepared: std::sync::Mutex::new(std::collections::BTreeMap::new()),
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
        if prepared.get(vm.id()) == Some(vm) {
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
            .insert(handle.id().to_owned(), handle.clone());
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
            result_json: None,
            guest_error: None,
        })
    }

    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        self.ensure_prepared(vm)?;
        collect_overlay_writes(vm.overlay_upper(), SandboxMount::Workspace)
    }

    fn cleanup(&self, vm: &MicroVmHandle) {
        if let Ok(mut prepared) = self.prepared.lock()
            && prepared.get(vm.id()) == Some(vm)
        {
            prepared.remove(vm.id());
        }
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
