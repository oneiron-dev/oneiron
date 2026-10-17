//! Host-configured jailer execution with a bounded vsock guest-agent protocol.
//!
//! No binary or guest image is downloaded. Absence of configuration, jailer,
//! KVM, pinned images, cgroups or a compatible guest agent refuses execution.
//! There is no process-backend fallback. See `guest-protocol.md` for the
//! externally built guest contract and the real-boot acceptance requirements.

mod config;
#[cfg(target_os = "linux")]
mod egress;
#[cfg(target_os = "linux")]
mod launch;
#[cfg(target_os = "linux")]
mod oci_session;
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
use crate::engine_executor::StepCancellation;
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
    manifest: Option<oneiron_container::SessionManifest>,
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
        #[cfg(unix)]
        super::microvm::reap_overlay_scratch(&config.scratch_root, FIRECRACKER_BACKEND_NAME)?;
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

    /// Boots one armed VM under its step's token (FIX 600): a step cancelled
    /// before its boot stages nothing, and one cancelled while it runs ends
    /// with its own guest killed and the run failed.
    fn boot(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &CredentialEgressProxy,
        cancel: &StepCancellation,
    ) -> Result<MicroVmExit> {
        cancel.check()?;
        #[cfg(target_os = "linux")]
        let resolved;
        #[cfg(target_os = "linux")]
        let image = if let Some(oci) = &image.oci {
            resolved = oci_session::resolve(&oci.image, &image.source)?;
            &resolved
        } else {
            image
        };
        validate_guest_budget(&budget)?;
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
        let result = launch::run(
            config,
            vm,
            image,
            budget,
            proxy,
            self.transport.as_deref(),
            cancel,
        );
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
                #[cfg(target_os = "linux")]
                {
                    let bytes = serde_json::to_vec(&launch::machine_config(config, budget))
                        .map_err(|_| refused("VM evidence encoding"))?;
                    let hash = blake3::hash(&bytes).to_hex().to_string();
                    state.manifest =
                        Some(oneiron_container::SessionManifest {
                            backend: "firecracker".into(),
                            runtime: config.firecracker.display().to_string(),
                            image: image.oci.as_ref().map(|i| i.image.clone()).unwrap_or_else(
                                || {
                                    config
                                        .pins
                                        .rootfs
                                        .iter()
                                        .map(|b| format!("{b:02x}"))
                                        .collect()
                                },
                            ),
                            argv_digest: hash.clone(),
                            network: "no-nic; host-vsock".into(),
                            seccomp: oneiron_container::GuestSeccomp::RuntimeDefault,
                            generation: vm.id().to_owned(),
                            fence_unproven: false,
                            fence_proof: Some(oneiron_container::FenceProof {
                                ruleset_hash: hash.clone(),
                                seccomp_hash: blake3::hash(&config::read_regular_bounded(
                                    &config.firecracker,
                                    256 * 1024 * 1024,
                                )?)
                                .to_hex()
                                .to_string(),
                                network_routes: vec!["no NIC; host-owned vsock only".into()],
                                network_evidence_digest: hash,
                                sandbox_generation: vm.id().to_owned(),
                                launcher_digest: config
                                    .pins
                                    .rootfs
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect(),
                            }),
                        });
                }
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
    fn session_manifest(&self, vm: &MicroVmHandle) -> Option<oneiron_container::SessionManifest> {
        self.state.lock().ok()?.get(vm.id())?.manifest.clone()
    }

    fn start_session(
        &self,
        spec: &oneiron_container::GuestSpec,
        command: &[std::ffi::OsString],
        relay: Arc<dyn oneiron_container::EgressRelay>,
    ) -> Result<oneiron_container::SessionTransport> {
        #[cfg(target_os = "linux")]
        {
            oci_session::start(
                self.config
                    .as_ref()
                    .ok_or_else(|| refused("jailer profile unavailable"))?,
                spec,
                command,
                relay,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (spec, command, relay);
            Err(refused("native VM requires Linux"))
        }
    }

    fn set_read_transport(&mut self, transport: Arc<dyn CredentialReadTransport>) {
        self.transport = Some(transport);
    }

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
                    manifest: None,
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
        self.boot(vm, image, budget, proxy, &StepCancellation::never())
    }

    fn run_with_proxy_cancellable(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &CredentialEgressProxy,
        cancel: &StepCancellation,
    ) -> Result<MicroVmExit> {
        self.boot(vm, image, budget, proxy, cancel)
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

    fn cleanup(&self, vm: &MicroVmHandle) {
        if let Ok(mut states) = self.state.lock()
            && states.get(vm.id()).is_some_and(|state| state.handle == *vm)
            && !matches!(
                states.get(vm.id()).map(|state| &state.phase),
                Some(Phase::Running)
            )
        {
            states.remove(vm.id());
        }
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

fn validate_guest_budget(budget: &ExecutionBudget) -> Result<()> {
    // Protocol v1 and the provisioned guest cgroup door both cap pids at 4096.
    // Refuse an unsupported request before boot, not at the first guest frame.
    if !budget.is_bounded()
        || budget.wall_clock_secs > 86_400
        || budget.mem_mib > 65_536
        || budget.pids > 4096
    {
        return Err(refused("execution budget outside supported bounds"));
    }
    Ok(())
}
