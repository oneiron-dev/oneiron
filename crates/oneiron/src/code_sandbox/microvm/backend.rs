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
use super::output::MicroVmOutputSink;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
use super::overlay::overlay_error;
use crate::error::CodeError;

/// Virtualization backend able to run one propose-only guest.
pub trait MicroVmBackend: Send + Sync {
    fn set_read_transport(
        &mut self,
        _transport: std::sync::Arc<dyn super::CredentialReadTransport>,
    ) {
    }
    fn set_egress(&mut self, _relay: std::sync::Arc<dyn oneiron_container::EgressRelay>) {}
    /// Lends the host's measured disk floor its guests' proposed files spool
    /// on (FIX 7650). A backend lent none spools as before; a backend that
    /// receives no streamed proposals takes none.
    fn set_proposal_spool(
        &mut self,
        _spool: std::sync::Arc<dyn crate::code_sandbox::ProposalSpoolFloor>,
    ) {
    }
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
        _output: &mut dyn MicroVmOutputSink,
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
        output: &mut dyn MicroVmOutputSink,
    ) -> Result<MicroVmExit> {
        cancel.check()?;
        let exit = self.run_with_proxy(vm, image, budget, proxy, output);
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
    fn set_proposal_spool(
        &mut self,
        spool: std::sync::Arc<dyn crate::code_sandbox::ProposalSpoolFloor>,
    ) {
        (**self).set_proposal_spool(spool);
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
        output: &mut dyn MicroVmOutputSink,
    ) -> Result<MicroVmExit> {
        (**self).run_with_proxy(vm, image, budget, proxy, output)
    }

    fn run_with_proxy_cancellable(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &super::credential::CredentialEgressProxy,
        cancel: &StepCancellation,
        output: &mut dyn MicroVmOutputSink,
    ) -> Result<MicroVmExit> {
        (**self).run_with_proxy_cancellable(vm, image, budget, proxy, cancel, output)
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
        SandboxGuestTier::Foreign | SandboxGuestTier::Untrusted => installed_firecracker()
            .or_else(container_backend)
            .map(Some)
            .ok_or_else(|| backend_unavailable(tier)),
    }
}

/// The Firecracker backend a session or a Foreign/Untrusted run takes: on a
/// KVM host where Firecracker is installed. A KVM host without it gives
/// none, so the guest falls back to the OCI fenced container, the posture it
/// already has on a host with no /dev/kvm; Firecracker still wins wherever
/// it is installed (Engine 10-21 02:4x and 03:0x, CALLS rows).
pub fn installed_firecracker() -> Option<Box<dyn MicroVmBackend>> {
    kvm_available().then(firecracker_backend).flatten()
}

fn kvm_available() -> bool {
    cfg!(target_os = "linux")
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
}

#[cfg(not(target_os = "linux"))]
fn container_backend() -> Option<Box<dyn MicroVmBackend>> {
    None
}

pub fn backend_unavailable(tier: SandboxGuestTier) -> Error {
    Error::Code(CodeError::MicroVmBackendUnavailable {
        tier: tier.as_str(),
    })
}

#[cfg(not(feature = "microvm-firecracker"))]
const fn firecracker_backend() -> Option<Box<dyn MicroVmBackend>> {
    None
}

pub fn backend_error(backend: &'static str, detail: impl Into<String>) -> Error {
    Error::Code(CodeError::MicroVmBackendError {
        backend,
        detail: detail.into(),
    })
}
