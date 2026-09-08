//! The SandboxBoundaryAdapter implementation that binds a backend to the boundary contract.

use std::{fmt, fs, io::Read, path::Path, sync::Arc};

use crate::code_sandbox::{
    SandboxBoundaryAdapter, SandboxBoundaryContract, SandboxCredentialCall,
    SandboxCredentialOutcome, SandboxFileRead, SandboxGuestTier, SandboxMountTable,
    SandboxProposalDelta, SandboxProposalWrite, SandboxReadFile,
};
use crate::{Error, Result};

use super::backend::{MicroVmBackend, backend_error};
use super::credential::{
    CredentialAllowlist, CredentialEgressProxy, CredentialInjection, CredentialResolver,
    egress_destination_from_args,
};
use super::handle::{ExecutionBudget, GuestImage, MicroVmExit, MicroVmHandle};
use super::overlay::{MAX_OVERLAY_FILE_BYTES, overlay_error};

/// [`SandboxBoundaryAdapter`] whose guarantees are backed by a microVM.
///
/// There is deliberately no commit verb here: overlay writes become
/// [`SandboxProposalDelta`] values and stop.
pub struct MicroVmSandboxAdapter {
    contract: SandboxBoundaryContract,
    mounts: SandboxMountTable,
    backend: Box<dyn MicroVmBackend>,
    vm: MicroVmHandle,
    proxy: CredentialEgressProxy,
    proposal_deltas: Vec<SandboxProposalDelta>,
    credential_injections: Vec<CredentialInjection>,
    overlay_collected: bool,
}

impl MicroVmSandboxAdapter {
    /// Prepares a VM for `tier` and arms its credential proxy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmBackendError`] when `tier` is not a propose-only
    /// tier, or when the backend fails to prepare the VM or bind the egress
    /// transport.
    pub fn new(
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
        backend.proxy_credentials(&vm, proxy.resolver())?;
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
    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    #[must_use]
    pub const fn contract(&self) -> SandboxBoundaryContract {
        self.contract
    }

    #[must_use]
    pub const fn vm(&self) -> &MicroVmHandle {
        &self.vm
    }

    #[must_use]
    pub fn proposal_deltas(&self) -> &[SandboxProposalDelta] {
        &self.proposal_deltas
    }

    #[must_use]
    pub fn credential_injections(&self) -> &[CredentialInjection] {
        &self.credential_injections
    }

    /// Runs the guest image under `budget`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MicroVmOverlayError`] after overlay export is sealed;
    /// otherwise propagates the backend's run failure.
    pub fn run(&mut self, image: &GuestImage, budget: ExecutionBudget) -> Result<MicroVmExit> {
        if self.overlay_collected {
            return Err(overlay_error(
                "guest execution is forbidden after overlay export is sealed",
            ));
        }
        self.backend.run(&self.vm, image, budget)
    }

    /// Drains the overlay into proposal deltas.
    ///
    /// This is the only path from a guest write to the host: every collected
    /// overlay entry goes through [`SandboxBoundaryAdapter::propose_write`].
    ///
    /// # Errors
    ///
    /// Propagates [`Error::MicroVmOverlayError`] from the overlay diff, or the
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

impl SandboxBoundaryAdapter for MicroVmSandboxAdapter {
    fn read_file(&self, call: SandboxReadFile) -> Result<SandboxFileRead> {
        let host_path = self.mounts.resolve_host_path(&call.path);
        // Confinement walk: the OS path resolver follows intermediate symlinks,
        // so a symlinked directory under the mount root would smuggle host
        // bytes from outside it — the overlay walker refuses symlinks per
        // entry for exactly this reason. Descend each intermediate component
        // of the relative path with `symlink_metadata` and refuse before any
        // byte is read; the mount root itself is the trusted anchor.
        let relative = Path::new(call.path.relative_path());
        let mut walked = host_path.clone();
        for _ in relative.components() {
            walked.pop();
        }
        let component_total = relative.components().count();
        for (index, component) in relative.components().enumerate() {
            walked.push(component.as_os_str());
            if index + 1 == component_total {
                break; // the final component keeps the refusal below
            }
            let metadata = fs::symlink_metadata(&walked).map_err(|_| Error::EntityNotFound)?;
            if metadata.is_symlink() {
                return Err(Error::MicroVmOverlayError {
                    detail: format!(
                        "base mount entry {} crosses a symlinked directory",
                        call.path.as_str()
                    ),
                });
            }
        }
        let metadata = fs::symlink_metadata(&host_path).map_err(|_| Error::EntityNotFound)?;
        if metadata.is_symlink() {
            return Err(Error::MicroVmOverlayError {
                detail: format!("base mount entry {} is a symlink", call.path.as_str()),
            });
        }
        let file_bytes = metadata.len();
        if file_bytes > MAX_OVERLAY_FILE_BYTES {
            return Err(overlay_error(format!(
                "base mount file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at {} ({file_bytes} bytes)",
                call.path.as_str()
            )));
        }
        if !metadata.is_file() {
            return Err(overlay_error(format!(
                "base mount entry {} is not a plain file",
                call.path.as_str()
            )));
        }

        let file = fs::File::open(&host_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => Error::EntityNotFound,
            _ => Error::MicroVmOverlayError {
                detail: format!("base mount read failed for {}", call.path.as_str()),
            },
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_OVERLAY_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| Error::MicroVmOverlayError {
                detail: format!(
                    "base mount read failed for {}: {}",
                    call.path.as_str(),
                    error.kind()
                ),
            })?;
        let actual_bytes = u64::try_from(bytes.len()).map_err(|_| {
            overlay_error(format!(
                "base mount file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at {}",
                call.path.as_str()
            ))
        })?;
        if actual_bytes > MAX_OVERLAY_FILE_BYTES {
            return Err(overlay_error(format!(
                "base mount file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at {} ({actual_bytes} bytes)",
                call.path.as_str()
            )));
        }
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
