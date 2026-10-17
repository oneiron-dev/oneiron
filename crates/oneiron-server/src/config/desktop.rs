//! `[desktop]`: the guest a code run's `self.desktop.*` verbs drive.
//!
//! File-only, like `[browser]`. Absent means no run has a desktop, and every
//! desktop verb answers `browser_unbound`. Each bound below is a manifest
//! row for one guest; none of them counts or refuses a program's calls.

use oneiron_browser::{DesktopGuest, GuestLimits, ImageRef};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DesktopConfig {
    /// A Docker-compatible container CLI, as an absolute path.
    pub runtime: PathBuf,
    /// The guest image, pinned: `name@sha256:<digest>` or a local
    /// `sha256:<id>`, built from `crates/oneiron-container/guest/desktop`.
    pub image: String,
    #[serde(default = "default_memory_mib")]
    pub memory_mib: u32,
    #[serde(default = "default_cpu_millis")]
    pub cpu_millis: u32,
    #[serde(default = "default_pids")]
    pub pids: u32,
    #[serde(default = "default_tmpfs_mib")]
    pub tmpfs_mib: u32,
    /// The longest one `wait_for` call holds its run.
    #[serde(default = "default_wait_cap_ms")]
    pub wait_cap_ms: u32,
}

const fn default_memory_mib() -> u32 {
    3072
}

const fn default_cpu_millis() -> u32 {
    2000
}

const fn default_pids() -> u32 {
    1024
}

const fn default_tmpfs_mib() -> u32 {
    1024
}

const fn default_wait_cap_ms() -> u32 {
    30_000
}

impl DesktopConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        // The desktop guest is an isolated box on a fleet host. It never
        // runs on the owner's Mac, and never drives the owner's own desktop.
        #[cfg(target_os = "macos")]
        {
            anyhow::bail!(
                "the desktop guest never runs on this host; serve from a fleet Linux host"
            );
        }
        if !self.runtime.is_absolute() {
            anyhow::bail!("desktop.runtime must be an absolute path to a container CLI");
        }
        ImageRef::pinned(&self.image).map_err(|_| {
            anyhow::anyhow!("desktop.image must be pinned: name@sha256:<digest> or sha256:<id>")
        })?;
        for (key, value) in [
            ("memory_mib", self.memory_mib),
            ("cpu_millis", self.cpu_millis),
            ("pids", self.pids),
            ("tmpfs_mib", self.tmpfs_mib),
            ("wait_cap_ms", self.wait_cap_ms),
        ] {
            if value == 0 {
                anyhow::bail!("desktop.{key} must be greater than zero");
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn guest(&self) -> DesktopGuest {
        DesktopGuest {
            runtime: self.runtime.clone(),
            image: self.image.clone(),
            limits: GuestLimits {
                memory_mib: self.memory_mib,
                cpu_millis: self.cpu_millis,
                pids: self.pids,
                tmpfs_mib: self.tmpfs_mib,
            },
            wait_cap: Duration::from_millis(self.wait_cap_ms.into()),
            // The floor: a press per send. A run's door resolves the real
            // policy from the vault's standing grants before any call.
            policy: oneiron_browser::SendPolicy::default(),
        }
    }
}
