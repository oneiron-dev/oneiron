//! The isolating backends this build carries, behind [`SandboxBackends`]:
//! the Firecracker microVM (feature `microvm-firecracker`) and the OCI fenced
//! container (Linux). The selection law in `microvm::select_backend_for_tier`
//! and `microvm::select_backend_for_session` reaches them only through the
//! trait, so this file is the one place that names a backend type.

use super::microvm::{MicroVmBackend, SandboxBackends};
use crate::Result;

/// The [`SandboxBackends`] of this build: each backend its features and
/// target compile in, detected on the host when asked.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompiledSandboxBackends;

/// This build's one [`SandboxBackends`], for every caller that selects a
/// backend.
pub static SANDBOX_BACKENDS: CompiledSandboxBackends = CompiledSandboxBackends;

impl SandboxBackends for CompiledSandboxBackends {
    fn firecracker(&self) -> Option<Box<dyn MicroVmBackend>> {
        firecracker_backend()
    }

    fn container(&self) -> Option<Box<dyn MicroVmBackend>> {
        container_backend()
    }

    fn session_container(
        &self,
        runtime: std::path::PathBuf,
        image: &str,
    ) -> Option<Result<Box<dyn MicroVmBackend>>> {
        #[cfg(target_os = "linux")]
        {
            Some(
                super::microvm::ContainerBackend::for_session(runtime, image)
                    .map(|b| Box::new(b) as Box<dyn MicroVmBackend>),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (runtime, image);
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn container_backend() -> Option<Box<dyn MicroVmBackend>> {
    super::microvm::ContainerBackend::detect().map(|b| Box::new(b) as Box<dyn MicroVmBackend>)
}
#[cfg(not(target_os = "linux"))]
fn container_backend() -> Option<Box<dyn MicroVmBackend>> {
    None
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
