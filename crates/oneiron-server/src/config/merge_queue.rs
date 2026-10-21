//! `[merge_queue]`: the executor the queue checker runs a repository's
//! frozen check plan in (FIX 6868).
//!
//! File-only, like `[browser]`. Absent means isolated but unconfigured: a
//! check answers a configuration need naming its keys, and never runs on
//! the host. `checker_backend = "host"` is the operator's explicit opt-in to
//! run the trusted helper as a host child; an isolated attempt that fails
//! never falls back to it. Resource values are optional overrides of
//! `QUEUE_CHECK_DEFAULT_LIMITS`; no wall-time setting or timeout exists. The
//! config read validates shape only: a host that cannot run an isolated
//! guest starts all the same, and its checks say what they need.

use std::collections::BTreeMap;
use std::path::PathBuf;

use oneiron::merge_queue::{DEFAULT_QUEUE_CHECK_CONCURRENCY, QueueCheckLimits};
use serde::Deserialize;

/// Where the trusted helper sits in the checker image (the image contract,
/// crates/oneiron-container/guest/checker/README.md).
pub(crate) const ISOLATED_CHECK_HELPER: &str = "/usr/local/bin/oneiron-queue-check";

/// The guest limits a check runs under for each key the section leaves
/// absent, sized for the seed plan's `cargo check --locked --workspace
/// --all-features`. All of `/tmp/queue-check` (the source copy, the copied
/// dependency store and the target dir) is guest tmpfs, so it counts against
/// `memory_mib` as well as `tmpfs_mib`: the memory covers the compiler and a
/// full scratch. `cpu_millis` is a four-CPU cgroup quota, which in a
/// container also caps cargo's default job count. These are ceilings, not
/// reservations or required keys: an explicit key wins.
pub const QUEUE_CHECK_DEFAULT_LIMITS: QueueCheckLimits = QueueCheckLimits {
    memory_mib: 32_768,
    cpu_millis: 4000,
    pids: 1024,
    tmpfs_mib: 16_384,
};

/// Which executor runs a queue check.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckerBackend {
    /// An isolated session: Firecracker on a KVM host with it installed,
    /// else the OCI fenced container. The owner-ruled default.
    #[default]
    Isolated,
    /// The trusted helper as a host child, only on this explicit opt-in.
    Host,
}

/// What a check's guest may reach (CALL "checker network").
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckerNetwork {
    /// Every off-session destination is denied; a command uses its own
    /// isolated loopback alone.
    #[default]
    Deny,
}

impl CheckerNetwork {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
        }
    }
}

/// The `[merge_queue]` section.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MergeQueueCheckerConfig {
    #[serde(default)]
    pub checker_backend: CheckerBackend,
    /// A Docker-compatible container CLI, as an absolute path.
    pub runtime: Option<PathBuf>,
    /// The checker image, pinned: `name@sha256:<digest>` or `sha256:<id>`.
    pub image: Option<String>,
    /// The trusted helper's argv. Isolated: the image's own helper unless
    /// set. Host: required, with an absolute program.
    pub helper: Option<Vec<String>>,
    /// Immutable toolchain identities the image or host provides, by name.
    #[serde(default)]
    pub toolchain: BTreeMap<String, String>,
    /// Optional guest overrides of `QUEUE_CHECK_DEFAULT_LIMITS`.
    pub memory_mib: Option<u32>,
    pub cpu_millis: Option<u32>,
    pub pids: Option<u32>,
    pub tmpfs_mib: Option<u32>,
    #[serde(default)]
    pub network: CheckerNetwork,
    /// Checks of one repository run at once; past it the next one waits.
    pub queue_check_concurrency: Option<u32>,
}

impl MergeQueueCheckerConfig {
    /// Shape validation only.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if let Some(runtime) = &self.runtime
            && !runtime.is_absolute()
        {
            anyhow::bail!("merge_queue.runtime must be an absolute path to a container CLI");
        }
        if let Some(image) = &self.image {
            oneiron_container::ImageRef::pinned(image).map_err(|_| {
                anyhow::anyhow!(
                    "merge_queue.image must be pinned: name@sha256:<digest> or sha256:<id>"
                )
            })?;
        }
        if let Some(helper) = &self.helper
            && !helper
                .first()
                .is_some_and(|program| std::path::Path::new(program).is_absolute())
        {
            anyhow::bail!("merge_queue.helper must start with an absolute program");
        }
        for (key, value) in [
            ("memory_mib", self.memory_mib),
            ("cpu_millis", self.cpu_millis),
            ("pids", self.pids),
            ("tmpfs_mib", self.tmpfs_mib),
            ("queue_check_concurrency", self.queue_check_concurrency),
        ] {
            if value == Some(0) {
                anyhow::bail!("merge_queue.{key} must be greater than zero when set");
            }
        }
        Ok(())
    }

    /// The guest limits a check runs under: each override, else its
    /// `QUEUE_CHECK_DEFAULT_LIMITS` value. The one effective-limits hook;
    /// receipts carry what it returns.
    #[must_use]
    pub fn effective_limits(&self) -> QueueCheckLimits {
        let defaults = QUEUE_CHECK_DEFAULT_LIMITS;
        QueueCheckLimits {
            memory_mib: self.memory_mib.unwrap_or(defaults.memory_mib),
            cpu_millis: self.cpu_millis.unwrap_or(defaults.cpu_millis),
            pids: self.pids.unwrap_or(defaults.pids),
            tmpfs_mib: self.tmpfs_mib.unwrap_or(defaults.tmpfs_mib),
        }
    }

    /// The trusted helper's argv for the configured backend, or `None` for
    /// a host opt-in that names none.
    #[must_use]
    pub fn helper_argv(&self) -> Option<Vec<String>> {
        match (self.checker_backend, &self.helper) {
            (_, Some(helper)) => Some(helper.clone()),
            (CheckerBackend::Isolated, None) => Some(vec![ISOLATED_CHECK_HELPER.to_owned()]),
            (CheckerBackend::Host, None) => None,
        }
    }

    /// The checks of one repository that run at once.
    #[must_use]
    pub fn queue_check_concurrency(&self) -> u32 {
        self.queue_check_concurrency
            .unwrap_or(DEFAULT_QUEUE_CHECK_CONCURRENCY)
    }
}
