//! Host-configured jailer execution with a bounded vsock guest-agent protocol.
//!
//! No binary or guest image is downloaded. Absence of configuration, jailer,
//! KVM, pinned images, cgroups or a compatible guest agent refuses execution.
//! There is no process-backend fallback. See `guest-protocol.md` for the
//! externally built guest contract and the real-boot acceptance requirements.

mod config;
#[cfg(target_os = "linux")]
mod launch;
#[cfg(target_os = "linux")]
mod protocol;
#[cfg(target_os = "linux")]
mod snapshot;
#[cfg(test)]
mod tests;

use super::microvm::{
    CredentialEgressProxy, CredentialReadTransport, CredentialResolver, ExecutionBudget,
    GuestImage, MicroVmBackend, MicroVmExit, MicroVmHandle, prepare_overlay_handle,
};
use super::{SandboxBoundaryContract, SandboxMountTable, SandboxProposalWrite};
use crate::error::CodeError;
use crate::{Error, Result};
use std::{
    collections::BTreeMap,
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub use config::{FirecrackerHostConfig, GuestArtifactPins};

pub const FIRECRACKER_BACKEND_NAME: &str = "firecracker";
pub const FIRECRACKER_BIN_ENV: &str = "ONEIRON_MICROVM_FIRECRACKER_BIN";
pub const FIRECRACKER_ROOT_ENV: &str = "ONEIRON_MICROVM_ROOT";
/// JSON host profile. Paths, uid/gid, cgroups and image pins are HOST authority.
pub const FIRECRACKER_CONFIG_ENV: &str = "ONEIRON_MICROVM_CONFIG";

/// Prepared handles are capabilities belonging to this backend, not path inputs.
pub struct FirecrackerBackend {
    root: PathBuf,
    config: Option<FirecrackerHostConfig>,
    transport: Option<Arc<dyn CredentialReadTransport>>,
    state: Mutex<BTreeMap<String, VmState>>,
}

struct VmState {
    handle: MicroVmHandle,
    phase: Phase,
}
enum Phase {
    Prepared,
    Armed,
    Running,
    Failed,
    Complete(Vec<SandboxProposalWrite>),
    Collected,
}

impl FirecrackerBackend {
    /// An unconfigured backend always refuses to run. Use `configured` for boot.
    /// The binary-only constructor cannot authorize jailer identity or images.
    #[must_use]
    pub fn new(_binary: impl Into<PathBuf>, root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            config: None,
            transport: None,
            state: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn configured(config: FirecrackerHostConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            root: config.scratch_root.clone(),
            config: Some(config),
            transport: None,
            state: Mutex::new(BTreeMap::new()),
        })
    }

    /// Egress is denied unless the host explicitly installs a read transport.
    #[must_use]
    pub fn with_read_transport(mut self, transport: Arc<dyn CredentialReadTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Detects a fully configured profile, never just the presence of a binary.
    #[must_use]
    pub fn detect() -> Option<Self> {
        let path = std::env::var_os(FIRECRACKER_CONFIG_ENV)?;
        let bytes = config::read_regular_bounded(std::path::Path::new(&path), 64 * 1024).ok()?;
        let config: FirecrackerHostConfig = serde_json::from_slice(&bytes).ok()?;
        Self::configured(config).ok()
    }

    fn boot(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &CredentialEgressProxy,
    ) -> Result<MicroVmExit> {
        if !budget.is_bounded()
            || budget.wall_clock_secs > 86_400
            || budget.mem_mib > 65_536
            || budget.pids > 65_536
        {
            return Err(refused("execution budget outside supported bounds"));
        }
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| refused("jailer host profile unavailable"))?;
        config.validate()?;
        config.pins.verify(image)?;
        {
            let mut states = self
                .state
                .lock()
                .map_err(|_| refused("backend state poisoned"))?;
            let state = states
                .get_mut(vm.id())
                .ok_or_else(|| refused("unknown VM handle"))?;
            if state.handle != *vm || !matches!(state.phase, Phase::Armed) || !proxy.is_armed() {
                return Err(refused("VM not armed or already consumed"));
            }
            state.phase = Phase::Running;
        }
        #[cfg(target_os = "linux")]
        let result = launch::run(config, vm, image, budget, proxy, self.transport.as_deref());
        #[cfg(not(target_os = "linux"))]
        let result: Result<(MicroVmExit, Vec<SandboxProposalWrite>)> =
            Err(refused("Firecracker requires Linux"));
        let mut states = self
            .state
            .lock()
            .map_err(|_| refused("backend state poisoned"))?;
        let state = states
            .get_mut(vm.id())
            .ok_or_else(|| refused("VM state disappeared"))?;
        match result {
            Ok((exit, proposals)) => {
                state.phase = Phase::Complete(proposals);
                Ok(exit)
            }
            Err(error) => {
                state.phase = Phase::Failed;
                Err(error)
            }
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
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| refused("jailer host profile unavailable"))?;
        config.validate()?;
        let handle = prepare_overlay_handle(&self.root, self.name(), contract, mounts)?;
        self.state
            .lock()
            .map_err(|_| refused("backend state poisoned"))?
            .insert(
                handle.id().to_owned(),
                VmState {
                    handle: handle.clone(),
                    phase: Phase::Prepared,
                },
            );
        Ok(handle)
    }

    fn run(
        &self,
        _vm: &MicroVmHandle,
        _image: &GuestImage,
        _budget: ExecutionBudget,
    ) -> Result<MicroVmExit> {
        Err(refused("VM run requires its host-bound credential policy"))
    }

    fn run_with_proxy(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &CredentialEgressProxy,
    ) -> Result<MicroVmExit> {
        self.boot(vm, image, budget, proxy)
    }

    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        let mut states = self
            .state
            .lock()
            .map_err(|_| refused("backend state poisoned"))?;
        let state = states
            .get_mut(vm.id())
            .ok_or_else(|| refused("unknown VM handle"))?;
        if state.handle != *vm {
            return Err(refused("VM handle mismatch"));
        }
        if !matches!(state.phase, Phase::Complete(_)) {
            return Err(refused("no completed VM delta"));
        }
        let Phase::Complete(writes) = std::mem::replace(&mut state.phase, Phase::Collected) else {
            unreachable!()
        };
        Ok(writes)
    }

    fn proxy_credentials(
        &self,
        vm: &MicroVmHandle,
        _resolver: &dyn CredentialResolver,
    ) -> Result<()> {
        let mut states = self
            .state
            .lock()
            .map_err(|_| refused("backend state poisoned"))?;
        let state = states
            .get_mut(vm.id())
            .ok_or_else(|| refused("unknown VM handle"))?;
        if state.handle != *vm || !matches!(state.phase, Phase::Prepared) {
            return Err(refused("VM handle mismatch or already armed"));
        }
        // No resolver is retained from this borrowed call. The actual armed
        // policy is passed by the owning adapter to run_with_proxy.
        state.phase = Phase::Armed;
        Ok(())
    }
}

impl fmt::Debug for FirecrackerBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirecrackerBackend")
            .field("configured", &self.config.is_some())
            .field("host_paths", &"<host-only>")
            .finish_non_exhaustive()
    }
}

fn refused(detail: &'static str) -> Error {
    Error::Code(CodeError::MicroVmBackendError {
        backend: FIRECRACKER_BACKEND_NAME,
        detail: detail.to_owned(),
    })
}
