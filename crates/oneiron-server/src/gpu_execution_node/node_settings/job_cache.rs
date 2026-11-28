//! A template's kept job cache (FLEET-TOOL-PARITY row 5, [NODE-TEMPLATE-CACHE-DIR]; on pass 34
//! row P2's warm keys): the box's switch, the one path where a run sees its cache, and the check
//! of each template's `job_cache`.
//!
//! `[execution_node.job_cache]` is off by default (the Orchestrator, 28 Nov 15:31: behind a
//! setting, default off, until the owner rules). While it is off, a template that names a
//! `job_cache` is refused, and `install` writes the job unit as before. On, a template's
//! `job_cache` names one of its own `caches`: a run of it sees that key's cache entry writable at
//! `mount`, one run at a time. A run that starts while another holds it gets a fresh empty one
//! there (cold): it never waits and never shares.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{ExecutionNodeSettings, NodeTemplate};

/// Default of `mount`: one fixed path, so a build tool sees the same absolute paths in each run
/// (chosen by OPUS-LE-FLEET; the Engine's ACCEPT of 28 Nov 15:53).
pub const JOB_CACHE_MOUNT_DEFAULT: &str = "/var/cache/oneiron-job";

/// The trees a job cache's mount may not lie in: the kernel's and the service manager's, and the
/// job's private `/tmp`.
const JOB_CACHE_MOUNT_REFUSED: [&str; 5] = ["/proc", "/sys", "/dev", "/run", "/tmp"];

/// `[execution_node.job_cache]`: whether a run may write its template's kept cache, and where it
/// sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeJobCacheSettings {
    /// Whether a template may name a `job_cache`. Default false.
    #[serde(default)]
    pub writable: bool,
    /// Where a run sees its cache: absolute, outside the node's directories. Checked only while
    /// `writable` is on, so a file that read before still reads.
    #[serde(default = "job_cache_mount_default")]
    pub mount: PathBuf,
}

impl Default for NodeJobCacheSettings {
    fn default() -> Self {
        Self {
            writable: false,
            mount: job_cache_mount_default(),
        }
    }
}

fn job_cache_mount_default() -> PathBuf {
    PathBuf::from(JOB_CACHE_MOUNT_DEFAULT)
}

/// A template's job cache as the node's file names it now: its warm key, and the cache entry that
/// key's path names (an entry directly in the cache directory, as the warm check makes it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobCacheTarget {
    pub key: String,
    pub path: PathBuf,
}

impl ExecutionNodeSettings {
    /// The job cache of the template `template`, when this file lets runs write one
    /// (`job_cache.writable`) and the template names one; `None` otherwise.
    #[must_use]
    pub fn job_cache_target(&self, template: &str) -> Option<JobCacheTarget> {
        if !self.job_cache.writable {
            return None;
        }
        let template = self.templates.get(template)?;
        let key = template.job_cache.as_ref()?;
        Some(JobCacheTarget {
            key: key.clone(),
            path: template.warm.get(key)?.clone(),
        })
    }
}

impl NodeJobCacheSettings {
    /// While `writable` is on: `mount` is absolute and plain, not `/`, in none of the trees no
    /// mount may lie in, and neither in nor above one of `node_dirs` (the node's state, work and
    /// cache directories).
    pub(super) fn validate(&self, node_dirs: &[&Path]) -> Result<(), String> {
        if !self.writable {
            return Ok(());
        }
        let mount = self.mount.as_path();
        let plain = mount.is_absolute()
            && mount
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
        if !plain || mount.parent().is_none() {
            return Err(
                "execution_node.job_cache.mount must be an absolute path below / with no '.' or '..'"
                    .to_owned(),
            );
        }
        if let Some(tree) = JOB_CACHE_MOUNT_REFUSED
            .iter()
            .find(|tree| mount.starts_with(tree))
        {
            return Err(format!(
                "execution_node.job_cache.mount must not lie in {tree}"
            ));
        }
        if let Some(dir) = node_dirs
            .iter()
            .find(|dir| mount.starts_with(dir) || dir.starts_with(mount))
        {
            return Err(format!(
                "execution_node.job_cache.mount must lie neither in nor above the node's directory {}",
                dir.display()
            ));
        }
        Ok(())
    }
}

/// The check of `template`'s `job_cache`: only while `execution_node.job_cache.writable` is on,
/// and only one of the template's own `caches`.
pub(super) fn check_template_job_cache(
    template: &NodeTemplate,
    settings: &NodeJobCacheSettings,
) -> Result<(), String> {
    let Some(key) = &template.job_cache else {
        return Ok(());
    };
    if !settings.writable {
        return Err(format!(
            "job_cache {key:?} needs execution_node.job_cache.writable = true"
        ));
    }
    if !template.caches.contains(key) {
        return Err(format!(
            "job_cache {key:?} must be one of this template's caches"
        ));
    }
    Ok(())
}
