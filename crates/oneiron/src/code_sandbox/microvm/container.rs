//! OCI code and browser sessions on Linux hosts without a usable microVM.

use super::{backend::backend_error, *};
use crate::Result;
use crate::code_sandbox::{SandboxBoundaryContract, SandboxMountTable, SandboxProposalWrite};
use oneiron_container::{
    ContainerRuntime, EgressRelay, GuestLimits, GuestSeccomp, GuestSpec, ImageRef, SessionManifest,
    SessionTransport,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const CONTAINER_BACKEND_NAME: &str = "landlock-container";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    runtime: PathBuf,
    image: String,
    scratch_root: PathBuf,
}
pub struct ContainerBackend {
    runtime: ContainerRuntime,
    image: ImageRef,
    root: PathBuf,
    states: Mutex<BTreeMap<String, State>>,
    transport: Option<Arc<dyn CredentialReadTransport>>,
    egress: Option<Arc<dyn EgressRelay>>,
}
struct State {
    handle: MicroVmHandle,
    armed: bool,
    proposals: Option<Vec<SandboxProposalWrite>>,
    manifest: Option<SessionManifest>,
}
impl ContainerBackend {
    pub fn for_session(runtime: PathBuf, image: &str) -> Result<Self> {
        oneiron_container::FenceConfig::from_env().map_err(|e| failed(e.to_string()))?;
        Ok(Self {
            runtime: ContainerRuntime::new(runtime).map_err(|e| failed(e.to_string()))?,
            image: ImageRef::pinned(image).map_err(|e| failed(e.to_string()))?,
            root: std::env::temp_dir().join("oneiron-container"),
            states: Mutex::new(BTreeMap::new()),
            transport: None,
            egress: None,
        })
    }

    pub fn detect() -> Option<Self> {
        oneiron_container::FenceConfig::from_env().ok()?;
        let path = std::env::var_os("ONEIRON_CONTAINER_CONFIG")?;
        let bytes = std::fs::read(path).ok()?;
        let config: Config = serde_json::from_slice(&bytes).ok()?;
        if !config.scratch_root.is_absolute() {
            return None;
        }
        Some(Self {
            runtime: ContainerRuntime::new(config.runtime).ok()?,
            image: ImageRef::pinned(&config.image).ok()?,
            root: config.scratch_root,
            states: Mutex::new(BTreeMap::new()),
            transport: None,
            egress: None,
        })
    }
    fn state<'a>(
        &'a self,
        vm: &MicroVmHandle,
    ) -> Result<std::sync::MutexGuard<'a, BTreeMap<String, State>>> {
        let state = self
            .states
            .lock()
            .map_err(|_| failed("container state poisoned"))?;
        if state.get(vm.id()).is_none_or(|s| s.handle != *vm) {
            return Err(failed("unknown container handle"));
        }
        Ok(state)
    }
}
impl MicroVmBackend for ContainerBackend {
    fn name(&self) -> &'static str {
        CONTAINER_BACKEND_NAME
    }
    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle> {
        let handle = prepare_overlay_handle(&self.root, self.name(), contract, mounts)?;
        self.states
            .lock()
            .map_err(|_| failed("container state poisoned"))?
            .insert(
                handle.id().into(),
                State {
                    handle: handle.clone(),
                    armed: false,
                    proposals: None,
                    manifest: None,
                },
            );
        Ok(handle)
    }
    fn proxy_credentials(&self, vm: &MicroVmHandle, _: &dyn CredentialResolver) -> Result<()> {
        let mut states = self.state(vm)?;
        let state = states
            .get_mut(vm.id())
            .ok_or_else(|| failed("unknown container handle"))?;
        if state.armed {
            return Err(failed("container already armed"));
        }
        state.armed = true;
        Ok(())
    }
    fn set_read_transport(&mut self, transport: Arc<dyn CredentialReadTransport>) {
        self.transport = Some(transport);
    }
    fn set_egress(&mut self, relay: Arc<dyn EgressRelay>) {
        self.egress = Some(relay);
    }
    fn session_manifest(&self, vm: &MicroVmHandle) -> Option<SessionManifest> {
        self.states.lock().ok()?.get(vm.id())?.manifest.clone()
    }
    fn start_session(
        &self,
        spec: &GuestSpec,
        command: &[OsString],
        relay: Arc<dyn EgressRelay>,
    ) -> Result<SessionTransport> {
        self.runtime
            .start_fenced(spec, command, relay)
            .and_then(|s| s.into_transport())
            .map_err(|e| failed(e.to_string()))
    }
    fn run(&self, _: &MicroVmHandle, _: &GuestImage, _: ExecutionBudget) -> Result<MicroVmExit> {
        Err(failed("container requires its host-bound proxy"))
    }
    fn run_with_proxy(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &CredentialEgressProxy,
    ) -> Result<MicroVmExit> {
        if !budget.is_bounded() || !proxy.is_armed() {
            return Err(failed("unbounded or unarmed container"));
        }
        {
            let states = self.state(vm)?;
            if states
                .get(vm.id())
                .is_none_or(|s| !s.armed || s.manifest.is_some())
            {
                return Err(failed("container run already consumed or unarmed"));
            }
        }
        let mut component = Vec::new();
        std::fs::File::open(&image.component)
            .map_err(|_| failed("guest component unavailable"))?
            .take(oneiron_sandbox_contract::MAX_COMPONENT_BYTES as u64 + 1)
            .read_to_end(&mut component)?;
        if component.is_empty() || component.len() > oneiron_sandbox_contract::MAX_COMPONENT_BYTES {
            return Err(failed("component size"));
        }
        let spec = GuestSpec {
            image: image
                .oci
                .as_ref()
                .map(|o| ImageRef::pinned(&o.image))
                .transpose()
                .map_err(|e| failed(e.to_string()))?
                .unwrap_or_else(|| self.image.clone()),
            user: (10001, 10001),
            limits: GuestLimits {
                memory_mib: budget.mem_mib,
                cpu_millis: 1000,
                pids: budget.pids,
                tmpfs_mib: budget.mem_mib,
            },
            seccomp: GuestSeccomp::EngineFence,
            read_only_mounts: Vec::new(),
        };
        let relay = self
            .egress
            .as_ref()
            .cloned()
            .ok_or_else(|| failed("engine egress proxy unbound"))?;
        let mut guest = self
            .runtime
            .start_fenced(
                &spec,
                &["/usr/local/bin/oneiron-guest".into(), "--container".into()],
                Arc::clone(&relay),
            )
            .map_err(|e| failed(e.to_string()))?;
        let manifest = guest.manifest().clone();
        self.state(vm)?
            .get_mut(vm.id())
            .ok_or_else(|| failed("unknown handle"))?
            .manifest = Some(manifest.clone());
        let (mut input, mut output) = guest
            .take_stdio()
            .ok_or_else(|| failed("container stdio missing"))?;
        let (stream, mut bridge) =
            std::os::unix::net::UnixStream::pair().map_err(|e| failed(e.to_string()))?;
        let mut reader = bridge.try_clone().map_err(|e| failed(e.to_string()))?;
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut output, &mut bridge);
            let _ = bridge.shutdown(std::net::Shutdown::Write);
        });
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut reader, &mut input);
        });
        let deadline = Instant::now() + Duration::from_secs(budget.wall_clock_secs);
        let result = super::protocol::exchange(
            stream,
            vm,
            super::protocol::GuestProgram {
                component: &component,
                source: &image.source,
            },
            budget,
            deadline,
            proxy,
            self.transport.as_deref(),
        );
        let abandoned = guest.abandoned();
        drop(guest);
        if abandoned {
            relay
                .record_abandoned(&manifest)
                .map_err(|e| failed(e.to_string()))?;
            return Err(crate::Error::Code(
                crate::error::CodeError::SandboxAbandoned {
                    backend: CONTAINER_BACKEND_NAME,
                },
            ));
        }
        let (exit, proposals) = result?;
        self.state(vm)?
            .get_mut(vm.id())
            .ok_or_else(|| failed("unknown handle"))?
            .proposals = Some(proposals);
        Ok(exit)
    }
    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        self.state(vm)?
            .get_mut(vm.id())
            .and_then(|s| s.proposals.take())
            .ok_or_else(|| failed("no completed container proposals"))
    }
    fn cleanup(&self, vm: &MicroVmHandle) {
        if let Ok(mut states) = self.states.lock() {
            states.remove(vm.id());
        }
    }
}
fn failed(detail: impl Into<String>) -> crate::Error {
    backend_error(CONTAINER_BACKEND_NAME, detail)
}
