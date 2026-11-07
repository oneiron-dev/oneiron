//! Host-owned execution profile for published artifact HTTP backends.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const ARTIFACT_BACKEND_MOUNT: &str = "/app";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBackendConfig {
    pub runtime: PathBuf,
    pub image: String,
    pub uid: u32,
    pub gid: u32,
    pub memory_mib: u32,
    pub cpu_millis: u32,
    pub pids: u32,
    pub tmpfs_mib: u32,
    /// Backpressure buffer for each direction, not an HTTP body-size limit.
    pub bridge_buffer_bytes: usize,
    /// Host-selected requests in staging, execution or native cleanup together.
    pub max_concurrent_sessions: usize,
}

impl ArtifactBackendConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        oneiron_container::ContainerRuntime::new(self.runtime.clone())?;
        oneiron_container::ImageRef::pinned(&self.image)?;
        if self.uid == 0 || self.gid == 0 {
            anyhow::bail!("artifact_backend uid and gid must be non-root");
        }
        if self.memory_mib == 0
            || self.cpu_millis == 0
            || self.pids == 0
            || self.tmpfs_mib == 0
            || self.bridge_buffer_bytes == 0
            || self.max_concurrent_sessions == 0
        {
            anyhow::bail!("artifact_backend resource values must be positive");
        }
        if self.max_concurrent_sessions > tokio::sync::Semaphore::MAX_PERMITS {
            anyhow::bail!("artifact_backend max_concurrent_sessions exceeds semaphore capacity");
        }
        Ok(())
    }

    pub(crate) fn spec(
        &self,
        source: PathBuf,
    ) -> oneiron_container::Result<oneiron_container::GuestSpec> {
        Ok(oneiron_container::GuestSpec {
            image: oneiron_container::ImageRef::pinned(&self.image)?,
            user: (self.uid, self.gid),
            limits: oneiron_container::GuestLimits {
                memory_mib: self.memory_mib,
                cpu_millis: self.cpu_millis,
                pids: self.pids,
                tmpfs_mib: self.tmpfs_mib,
            },
            seccomp: oneiron_container::GuestSeccomp::EngineFence,
            read_only_mounts: vec![(source, PathBuf::from(ARTIFACT_BACKEND_MOUNT))],
        })
    }
}
