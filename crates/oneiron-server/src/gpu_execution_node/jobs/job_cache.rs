//! A template's kept job cache at the launch commit (FLEET-TOOL-PARITY row 5,
//! [NODE-TEMPLATE-CACHE-DIR]): which run holds it, and which keys `Node` reports held.
//!
//! The launch commit, under the admission lock, gives a run of a template that names a job cache
//! the kept cache when no other launched key without an end holds it and its entry is a directory
//! here (the engine makes the entry, and the cache directory, when absent). Every other run of it
//! runs cold, on a fresh empty directory in its payload: a run never waits for the cache and never
//! shares it. The choice goes into `launch.json` and the `Launching` record, so root's prepare
//! step binds what the engine chose and a restarted engine reads who holds it. A key a run holds
//! is reported `held`, and placement counts it warm on no machine where it is held.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::journal::NodeKey;
use crate::gpu_execution_node::node_settings::JobCacheTarget;

/// What a launch says of its template's job cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchCache {
    /// The template's job cache key.
    pub key: String,
    /// This run holds the kept cache; false: it runs on a fresh empty one (cold).
    pub kept: bool,
}

/// The job cache keys that launched keys without an end hold kept now.
#[must_use]
pub fn held_cache_keys<'a>(keys: impl IntoIterator<Item = &'a NodeKey>) -> BTreeSet<String> {
    keys.into_iter()
        .filter(|known| !known.is_ended())
        .filter_map(|known| known.launch.as_ref()?.cache.as_ref())
        .filter(|cache| cache.kept)
        .map(|cache| cache.key.clone())
        .collect()
}

/// The launch's cache for `target`: kept when no key of `keys` but `launching` holds it and its
/// entry is a directory here, else cold.
#[must_use]
pub fn launch_cache<'a>(
    target: &JobCacheTarget,
    keys: impl IntoIterator<Item = &'a NodeKey>,
    launching: &str,
) -> LaunchCache {
    let held = held_cache_keys(keys.into_iter().filter(|known| known.key != launching));
    LaunchCache {
        key: target.key.clone(),
        kept: !held.contains(&target.key) && entry_ready(&target.path),
    }
}

/// Whether the cache entry `path` is a directory and not a link: made, with its cache directory,
/// when absent.
fn entry_ready(path: &Path) -> bool {
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return false;
    }
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return false,
    }
    std::fs::symlink_metadata(path).is_ok_and(|found| found.file_type().is_dir())
}
