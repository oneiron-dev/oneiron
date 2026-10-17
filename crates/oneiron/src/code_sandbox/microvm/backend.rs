//! The backend trait, tier-based selection, and the cfg-gated dev and Firecracker implementations.

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use std::{fmt, fs, path::PathBuf};

#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use crate::code_sandbox::SandboxMount;
use crate::code_sandbox::{
    SandboxBoundaryContract, SandboxGuestTier, SandboxMountTable, SandboxProposalWrite,
};
use crate::engine_executor::StepCancellation;
use crate::{Error, Result};

use super::credential::CredentialResolver;
use super::handle::{ExecutionBudget, GuestImage, MicroVmExit, MicroVmHandle};
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use super::overlay::{
    collect_overlay_writes, overlay_error, overlay_io_detail, prepare_overlay_handle,
};
use crate::error::CodeError;

/// Virtualization backend able to run one propose-only guest.
pub trait MicroVmBackend: Send + Sync {
    fn set_read_transport(
        &mut self,
        _transport: std::sync::Arc<dyn super::CredentialReadTransport>,
    ) {
    }
    fn set_egress(&mut self, _relay: std::sync::Arc<dyn oneiron_container::EgressRelay>) {}
    fn session_manifest(&self, _vm: &MicroVmHandle) -> Option<oneiron_container::SessionManifest> {
        None
    }
    fn start_session(
        &self,
        _spec: &oneiron_container::GuestSpec,
        _command: &[std::ffi::OsString],
        _relay: std::sync::Arc<dyn oneiron_container::EgressRelay>,
    ) -> Result<oneiron_container::SessionTransport> {
        Err(backend_error(
            self.name(),
            "native session image unavailable",
        ))
    }

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

    /// Runs with the adapter's host-bound credential policy. Backends without
    /// an egress transport keep their ordinary run implementation.
    fn run_with_proxy(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        _proxy: &super::credential::CredentialEgressProxy,
    ) -> Result<MicroVmExit> {
        self.run(vm, image, budget)
    }

    /// [`Self::run_with_proxy`] for a step `cancel` may stop (FIX 600). A
    /// backend that runs a guest overrides it and ends that guest alone (its
    /// own process group or container) once `cancel` fires. This default
    /// only checks the token before the run and after it, and drops a run
    /// cancelled meanwhile; every backend the selector picks overrides it.
    fn run_with_proxy_cancellable(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &super::credential::CredentialEgressProxy,
        cancel: &StepCancellation,
    ) -> Result<MicroVmExit> {
        cancel.check()?;
        let exit = self.run_with_proxy(vm, image, budget, proxy);
        cancel.check()?;
        exit
    }

    /// Collects the guest delta as typed review proposals (writes, deletes,
    /// renames or opaque directories). The backend never commits them.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmOverlayError`](crate::error::CodeError::MicroVmOverlayError) when the overlay cannot be read
    /// or contains an unsupported filesystem entry.
    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>>;

    /// Releases backend custody after collection or on any run/arming failure.
    /// Clones of the handle keep the scratch directory alive until their last drop.
    fn cleanup(&self, vm: &MicroVmHandle);

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
    fn set_read_transport(
        &mut self,
        transport: std::sync::Arc<dyn super::CredentialReadTransport>,
    ) {
        (**self).set_read_transport(transport);
    }
    fn set_egress(&mut self, relay: std::sync::Arc<dyn oneiron_container::EgressRelay>) {
        (**self).set_egress(relay);
    }
    fn session_manifest(&self, vm: &MicroVmHandle) -> Option<oneiron_container::SessionManifest> {
        (**self).session_manifest(vm)
    }
    fn start_session(
        &self,
        spec: &oneiron_container::GuestSpec,
        command: &[std::ffi::OsString],
        relay: std::sync::Arc<dyn oneiron_container::EgressRelay>,
    ) -> Result<oneiron_container::SessionTransport> {
        (**self).start_session(spec, command, relay)
    }

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

    fn run_with_proxy(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &super::credential::CredentialEgressProxy,
    ) -> Result<MicroVmExit> {
        (**self).run_with_proxy(vm, image, budget, proxy)
    }

    fn run_with_proxy_cancellable(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &super::credential::CredentialEgressProxy,
        cancel: &StepCancellation,
    ) -> Result<MicroVmExit> {
        (**self).run_with_proxy_cancellable(vm, image, budget, proxy, cancel)
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

    fn cleanup(&self, vm: &MicroVmHandle) {
        (**self).cleanup(vm);
    }
}

/// Routes one guest tier to its execution backend.
///
/// `Ok(None)` means "no microVM": first-party code runs in-process. Foreign and
/// untrusted code either gets an isolating backend or fails closed — there is
/// no silent no-sandbox path, including in debug and test builds. The dev
/// reference backend is available only by explicit construction.
///
/// # Errors
///
/// Returns [`CodeError::MicroVmBackendUnavailable`](crate::error::CodeError::MicroVmBackendUnavailable) when the tier needs isolation
/// and no backend is compiled in or detected.
pub fn select_backend_for_tier(tier: SandboxGuestTier) -> Result<Option<Box<dyn MicroVmBackend>>> {
    match tier {
        SandboxGuestTier::FirstPartyDreamer => Ok(None),
        SandboxGuestTier::Foreign | SandboxGuestTier::Untrusted => {
            if kvm_available() {
                firecracker_backend()
                    .map(Some)
                    .ok_or_else(|| backend_unavailable(tier))
            } else {
                container_backend()
                    .map(Some)
                    .ok_or_else(|| backend_unavailable(tier))
            }
        }
    }
}

/// Browser/native sessions use the host's OCI runtime and image configuration,
/// but the same KVM-first selection law as finite code runs.
pub fn select_backend_for_session(
    tier: SandboxGuestTier,
    runtime: std::path::PathBuf,
    image: &str,
) -> Result<Box<dyn MicroVmBackend>> {
    if tier == SandboxGuestTier::FirstPartyDreamer {
        return Err(backend_unavailable(tier));
    }
    if kvm_available() {
        return firecracker_backend().ok_or_else(|| backend_unavailable(tier));
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

fn kvm_available() -> bool {
    cfg!(target_os = "linux")
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
}

#[cfg(target_os = "linux")]
fn container_backend() -> Option<Box<dyn MicroVmBackend>> {
    super::ContainerBackend::detect().map(|b| Box::new(b) as Box<dyn MicroVmBackend>)
}
#[cfg(not(target_os = "linux"))]
fn container_backend() -> Option<Box<dyn MicroVmBackend>> {
    None
}

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

pub(super) fn backend_error(backend: &'static str, detail: impl Into<String>) -> Error {
    Error::Code(CodeError::MicroVmBackendError {
        backend,
        detail: detail.into(),
    })
}
