//! Lifted half of `oneiron::code_sandbox::microvm::adapter` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::microvm::adapter::*;
#[allow(unused_imports)]
use crate::ext::*;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use crate::code_sandbox::SandboxBoundaryContract;
use crate::code_sandbox::SandboxGuestTier;
use crate::code_sandbox::SandboxMountTable;
use crate::code_sandbox::SandboxProposalDelta;
use crate::engine_executor::StepCancellation;
use crate::Error;
use crate::Result;
use super::backend::MicroVmBackend;
use super::backend::backend_error;
use super::credential::CredentialAllowlist;
use super::credential::CredentialEgressProxy;
use super::credential::CredentialInjection;
use super::credential::CredentialResolver;
use super::handle::ExecutionBudget;
use super::handle::GuestImage;
use super::handle::MicroVmExit;
use super::handle::MicroVmHandle;
use super::output::MicroVmOutputSink;
use super::overlay::overlay_error;
use crate::error::CodeError;

/// Methods of [`MicroVmSandboxAdapter`] that moved out of `oneiron` with `code_sandbox::microvm::adapter` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxMicrovmAdapterMicroVmSandboxAdapterExt {
    /// Prepares a VM for `tier` and arms its credential proxy.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when `tier` is not a propose-only
    /// tier, or when the backend fails to prepare the VM or bind the egress
    /// transport.
    fn new(
        tier: SandboxGuestTier,
        mounts: SandboxMountTable,
        backend: Box<dyn MicroVmBackend>,
        resolver: Arc<dyn CredentialResolver>,
        allowlist: CredentialAllowlist,
    ) -> Result<Self>;
    #[must_use]
    fn session_manifest(&self) -> Option<oneiron_container::SessionManifest>;
    #[must_use]
    fn backend_name(&self) -> &'static str;
    #[must_use]
    fn contract(&self) -> SandboxBoundaryContract;
    #[must_use]
    fn vm(&self) -> &MicroVmHandle;
    #[must_use]
    fn proposal_deltas(&self) -> &[SandboxProposalDelta];
    #[must_use]
    fn credential_injections(&self) -> &[CredentialInjection];
    /// Runs the guest image under `budget`.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmOverlayError`](crate::error::CodeError::MicroVmOverlayError) after overlay export is sealed;
    /// otherwise propagates the backend's run failure.
    fn run(
        &mut self,
        image: &GuestImage,
        budget: ExecutionBudget,
        output: &mut dyn MicroVmOutputSink,
    ) -> Result<MicroVmExit>;
}

impl CodeSandboxMicrovmAdapterMicroVmSandboxAdapterExt for MicroVmSandboxAdapter {
    /// Prepares a VM for `tier` and arms its credential proxy.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when `tier` is not a propose-only
    /// tier, or when the backend fails to prepare the VM or bind the egress
    /// transport.
    fn new(
            tier: SandboxGuestTier,
            mounts: SandboxMountTable,
            backend: Box<dyn MicroVmBackend>,
            resolver: Arc<dyn CredentialResolver>,
            allowlist: CredentialAllowlist,
        ) -> Result<Self> {
            let contract = SandboxBoundaryContract::for_tier(tier);
            if !contract.has_proposal_delta_channel() || contract.links_write_imports() {
                return Err(backend_error(
                    backend.name(),
                    "microVM lane accepts propose-only guest tiers only",
                ));
            }

            let vm = backend.prepare(&contract, &mounts)?;
            let mut proxy = CredentialEgressProxy::new(allowlist, resolver);
            if let Err(error) = backend.proxy_credentials(&vm, proxy.resolver()) {
                backend.cleanup(&vm);
                return Err(error);
            }
            proxy.arm();

            Ok(Self {
                contract,
                mounts,
                backend,
                vm,
                proxy,
                proposal_deltas: Vec::new(),
                credential_injections: Vec::new(),
                overlay_collected: false,
            })
        }

    #[must_use]
    fn session_manifest(&self) -> Option<oneiron_container::SessionManifest> {
            self.backend.session_manifest(&self.vm)
        }

    #[must_use]
    fn backend_name(&self) -> &'static str {
            self.backend.name()
        }

    #[must_use]
    fn contract(&self) -> SandboxBoundaryContract {
            self.contract
        }

    #[must_use]
    fn vm(&self) -> &MicroVmHandle {
            &self.vm
        }

    #[must_use]
    fn proposal_deltas(&self) -> &[SandboxProposalDelta] {
            &self.proposal_deltas
        }

    #[must_use]
    fn credential_injections(&self) -> &[CredentialInjection] {
            &self.credential_injections
        }

    /// Runs the guest image under `budget`.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmOverlayError`](crate::error::CodeError::MicroVmOverlayError) after overlay export is sealed;
    /// otherwise propagates the backend's run failure.
    fn run(
            &mut self,
            image: &GuestImage,
            budget: ExecutionBudget,
            output: &mut dyn MicroVmOutputSink,
        ) -> Result<MicroVmExit> {
            self.run_cancellable(image, budget, &StepCancellation::never(), output)
        }
}

/// Opens `relative` under the mount `root` for reading, each directory
/// relative to the one before through its descriptor, and no component a
/// symlink (FIX 17063): what the caller then checks and reads is the entry
/// this walk named, whatever moves on the path meanwhile. An entry that is
/// no plain file is refused before it is opened, as before; the caller's
/// check of the open handle is the one that binds. `shown` names the entry
/// in a refusal.
#[cfg(unix)]
fn open_base_entry(root: &Path, relative: &Path, shown: &str) -> Result<fs::File> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, open, openat, statat};
    use rustix::io::Errno;
    let failed = |error: Errno, symlink: &str| match error {
        Errno::NOENT | Errno::NOTDIR => Error::EntityNotFound,
        Errno::LOOP => Error::Code(CodeError::MicroVmOverlayError {
            detail: format!("base mount entry {shown} {symlink}"),
        }),
        _ => Error::Code(CodeError::MicroVmOverlayError {
            detail: format!("base mount read failed for {shown}"),
        }),
    };
    let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let mut dir =
        open(root, directory, Mode::empty()).map_err(|error| failed(error, "is unreachable"))?;
    let components: Vec<_> = relative.components().collect();
    let Some((last, parents)) = components.split_last() else {
        return Err(overlay_error(format!(
            "base mount entry {shown} is not a plain file"
        )));
    };
    for component in parents {
        dir = openat(
            &dir,
            component.as_os_str(),
            directory | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| failed(error, "crosses a symlinked directory"))?;
    }
    let kind = statat(&dir, last.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map(|stat| FileType::from_raw_mode(stat.st_mode))
        .map_err(|error| failed(error, "is a symlink"))?;
    match kind {
        FileType::RegularFile => {}
        FileType::Symlink => {
            return Err(Error::Code(CodeError::MicroVmOverlayError {
                detail: format!("base mount entry {shown} is a symlink"),
            }));
        }
        _ => {
            return Err(overlay_error(format!(
                "base mount entry {shown} is not a plain file"
            )));
        }
    }
    let file = openat(
        &dir,
        last.as_os_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| failed(error, "is a symlink"))?;
    Ok(fs::File::from(file))
}
