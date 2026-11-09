//! The SandboxBoundaryAdapter implementation that binds a backend to the boundary contract.

use std::{fmt, fs, io::Read, path::Path, sync::Arc};

use crate::code_sandbox::{
    SandboxBoundaryAdapter, SandboxBoundaryContract, SandboxCredentialCall,
    SandboxCredentialOutcome, SandboxFileRead, SandboxGuestTier, SandboxMountTable,
    SandboxProposalDelta, SandboxProposalWrite, SandboxReadFile,
};
use crate::engine_executor::StepCancellation;
use crate::{Error, Result};

use super::backend::{MicroVmBackend, backend_error};
use super::credential::{
    CredentialAllowlist, CredentialEgressProxy, CredentialInjection, CredentialResolver,
    egress_destination_from_args,
};
use super::handle::{ExecutionBudget, GuestImage, MicroVmExit, MicroVmHandle};
use super::output::MicroVmOutputSink;
use super::overlay::overlay_error;
use crate::error::CodeError;

/// [`SandboxBoundaryAdapter`] whose guarantees are backed by a microVM.
///
/// There is deliberately no commit verb here: overlay writes become
/// [`SandboxProposalDelta`] values and stop.
pub struct MicroVmSandboxAdapter {
    pub contract: SandboxBoundaryContract,
    mounts: SandboxMountTable,
    pub backend: Box<dyn MicroVmBackend>,
    pub vm: MicroVmHandle,
    proxy: CredentialEgressProxy,
    pub proposal_deltas: Vec<SandboxProposalDelta>,
    pub credential_injections: Vec<CredentialInjection>,
    overlay_collected: bool,
}

impl MicroVmSandboxAdapter {

    /// Attaches the SAME existing egress relay to the credential proxy for
    /// per-decision receipts. Additive builder; the proxy stays silent
    /// without it.
    #[must_use]
    pub fn with_credential_relay(mut self, relay: Arc<dyn oneiron_container::EgressRelay>) -> Self {
        self.proxy.set_credential_relay(relay);
        self
    }

    /// [`Self::run`] for a step `cancel` may stop (FIX 600): the backend ends
    /// this adapter's guest alone once `cancel` fires, and the run fails
    /// with [`CodeError::CodeStepCancelled`].
    ///
    /// # Errors
    ///
    /// [`CodeError::CodeStepCancelled`] once `cancel` fires; otherwise as
    /// [`Self::run`].
    pub fn run_cancellable(
        &mut self,
        image: &GuestImage,
        budget: ExecutionBudget,
        cancel: &StepCancellation,
        output: &mut dyn MicroVmOutputSink,
    ) -> Result<MicroVmExit> {
        if self.overlay_collected {
            return Err(overlay_error(
                "guest execution is forbidden after overlay export is sealed",
            ));
        }
        self.backend.run_with_proxy_cancellable(
            &self.vm,
            image,
            budget,
            &self.proxy,
            cancel,
            output,
        )
    }

    /// Drains the overlay into proposal deltas.
    ///
    /// This is the only path from a guest write to the host: every collected
    /// overlay entry goes through [`SandboxBoundaryAdapter::propose_write`].
    ///
    /// # Errors
    ///
    /// Propagates [`CodeError::MicroVmOverlayError`](crate::error::CodeError::MicroVmOverlayError) from the overlay diff, or the
    /// proposal-channel refusal for a tier without one.
    pub fn collect_overlay_proposals(&mut self) -> Result<Vec<SandboxProposalDelta>> {
        if self.overlay_collected {
            return Err(overlay_error("overlay proposals were already collected"));
        }

        let writes = self.backend.collect_overlay_delta(&self.vm)?;
        let mut deltas = Vec::with_capacity(writes.len());
        for write in writes {
            deltas.push(self.propose_write(write)?);
        }
        self.overlay_collected = true;
        Ok(deltas)
    }
}

/// [`open_base_entry`] where no descriptor walk is built: each component
/// is checked by path, refused when a symlink, then the entry is opened by
/// path.
#[cfg(not(unix))]
fn open_base_entry(root: &Path, relative: &Path, shown: &str) -> Result<fs::File> {
    let mut walked = root.to_path_buf();
    for component in relative.components() {
        walked.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&walked).map_err(|_| Error::EntityNotFound)?;
        if metadata.is_symlink() {
            return Err(Error::Code(CodeError::MicroVmOverlayError {
                detail: format!("base mount entry {shown} is a symlink"),
            }));
        }
    }
    fs::File::open(&walked).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => Error::EntityNotFound,
        _ => Error::Code(CodeError::MicroVmOverlayError {
            detail: format!("base mount read failed for {shown}"),
        }),
    })
}

impl SandboxBoundaryAdapter for MicroVmSandboxAdapter {
    fn read_file(&self, call: SandboxReadFile) -> Result<SandboxFileRead> {
        let host_path = self.mounts.resolve_host_path(&call.path)?;
        // The mount root is the trusted anchor; no component under it may be
        // a symlink, which would smuggle host bytes from outside it, as the
        // overlay walker refuses them per entry. The entry checked is the
        // entry read (FIX 17063): the checks and the read go through one
        // handle, so a rename or symlink swap after the check opens nothing
        // else.
        let relative = Path::new(call.path.relative_path());
        let mut root = host_path.clone();
        for _ in relative.components() {
            root.pop();
        }
        let mut file = open_base_entry(&root, relative, call.path.as_str())?;
        let metadata = file.metadata().map_err(|_| {
            Error::Code(CodeError::MicroVmOverlayError {
                detail: format!("base mount read failed for {}", call.path.as_str()),
            })
        })?;
        if !metadata.is_file() {
            return Err(overlay_error(format!(
                "base mount entry {} is not a plain file",
                call.path.as_str()
            )));
        }

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|error| {
            Error::Code(CodeError::MicroVmOverlayError {
                detail: format!(
                    "base mount read failed for {}: {}",
                    call.path.as_str(),
                    error.kind()
                ),
            })
        })?;
        Ok(SandboxFileRead {
            path: call.path,
            bytes,
        })
    }

    fn call_credential(&mut self, call: SandboxCredentialCall) -> Result<SandboxCredentialOutcome> {
        let destination = egress_destination_from_args(call.args())?;
        let injection = self
            .proxy
            .inject(&self.vm, call.credential(), &destination)?;
        self.credential_injections.push(injection);
        Ok(SandboxCredentialOutcome {
            operation: call.operation,
            credential: call.credential,
        })
    }

    fn propose_write(&mut self, write: SandboxProposalWrite) -> Result<SandboxProposalDelta> {
        if !self.contract.has_proposal_delta_channel() {
            return Err(Error::InvalidClaimBody(
                "sandbox tier does not expose proposal deltas",
            ));
        }
        let delta = SandboxProposalDelta::new(self.contract.tier(), write)?;
        self.proposal_deltas.push(delta.clone());
        Ok(delta)
    }
}

impl Drop for MicroVmSandboxAdapter {
    fn drop(&mut self) {
        // A backend must not retain its cloned handle after an adapter ends.
        // Scratch custody is Arc-owned, so external handle clones remain safe.
        self.backend.cleanup(&self.vm);
    }
}

impl fmt::Debug for MicroVmSandboxAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MicroVmSandboxAdapter")
            .field("backend", &self.backend.name())
            .field("tier", &self.contract.tier())
            .field("mounts", &self.mounts)
            .field("vm", &self.vm)
            .field("proxy", &self.proxy)
            .field("proposal_deltas", &self.proposal_deltas.len())
            .field("credential_injections", &self.credential_injections)
            .field("overlay_collected", &self.overlay_collected)
            .finish()
    }
}
