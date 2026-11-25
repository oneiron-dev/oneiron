//! The box's warm-key settings (pass 34, `34-compute-general/DESIGN.md` sections 4.1 and 6.3;
//! row P2): the directory the cache keys live in, the box's ceiling on the cache budget, and the
//! check of each template's warm keys.
//!
//! The ceiling's five figures are the box's most. The owner's machine policy
//! (`placement.cache.*`, row P0) may set each lower and never higher, and the node applies the
//! smaller of the two. The cache keys live directly in `cache_dir`, `<work_dir>/caches` when the
//! file names none. A box whose templates mark no cache removes nothing: the cache budget is the
//! owner's opt-in per template.
//!
//! A key names one thing on one machine: every template that maps it maps it to one path, and
//! no two keys share a path, or lie one inside the other, where either is a cache, so removing
//! one cache never removes what another key names.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use oneiron::machine_policy::CachePolicy;
use oneiron::warm_key::warm_key_valid;
use serde::{Deserialize, Serialize};

use super::{ExecutionNodeSettings, NodeTemplate};

/// The default ceiling on the bytes the cache keys hold together, in GiB (the pack, section 6):
/// the owner's key's default, so the two layers start equal.
pub const CACHE_CAP_GIB_DEFAULT: u64 = CachePolicy::DEFAULT.cap_gib;
/// The default idle time after which a cache key goes, in days.
pub const CACHE_IDLE_DAYS_DEFAULT: u32 = CachePolicy::DEFAULT.idle_days;
/// The default time after a use in which a cache key never goes for the cap, in hours.
pub const CACHE_PROTECT_HOURS_DEFAULT: u32 = CachePolicy::DEFAULT.protect_hours;
/// The default time a key an open order listed stays protected after the issuer's ask.
pub const CACHE_WANTED_HOLD_SECS_DEFAULT: u64 = CachePolicy::DEFAULT.wanted_hold_secs;
/// The default bound on the warm keys the node's table remembers.
pub const CACHE_KEYS_MAX_DEFAULT: u32 = CachePolicy::DEFAULT.keys_max;
/// The default time between two cache passes (the pack's two hours).
pub const CACHE_PASS_EVERY_SECS_DEFAULT: u64 = 7_200;

/// The most warm keys one template maps.
pub const TEMPLATE_WARM_KEYS_MAX: usize = 64;

/// The directory inside the cache directory that a pass moves a cache path into to take it out
/// of use: what it holds is removed after the admission lock is dropped, and again by the next
/// pass if that did not complete. No warm path may lie in it.
pub const EVICTED_DIR_NAME: &str = ".oneiron-evicted";

/// The cache directory's name inside `work_dir` when the file names no `cache_dir`.
pub const CACHE_DIR_NAME_DEFAULT: &str = "caches";

/// How the cache pass reads the node's file now: `None` when there is none or it does not
/// read.
pub type SettingsRead = std::sync::Arc<dyn Fn() -> Option<ExecutionNodeSettings> + Send + Sync>;

impl ExecutionNodeSettings {
    /// The directory the cache keys live in: `cache_dir`, else `<work_dir>/caches`.
    #[must_use]
    pub fn cache_root(&self) -> PathBuf {
        self.cache_dir
            .clone()
            .unwrap_or_else(|| self.work_dir.join(CACHE_DIR_NAME_DEFAULT))
    }

    /// Whether any template marks a cache: without one, the cache budget removes nothing.
    #[must_use]
    pub fn marks_caches(&self) -> bool {
        self.templates
            .values()
            .any(|template| !template.caches.is_empty())
    }
}

/// `[execution_node.cache]`: the box's ceiling on the cache budget, and the pass's cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCacheSettings {
    /// The most the cache keys hold together, in GiB; the least recently used go above it.
    #[serde(default = "cap_gib_default")]
    pub cap_gib: u64,
    /// A cache key unused this many days goes, whatever the total.
    #[serde(default = "idle_days_default")]
    pub idle_days: u32,
    /// A cache key used within this many hours never goes for the cap.
    #[serde(default = "protect_hours_default")]
    pub protect_hours: u32,
    /// How long after an issuer's ask a key its open orders listed stays protected.
    #[serde(default = "wanted_hold_secs_default")]
    pub wanted_hold_secs: u64,
    /// The most warm keys the node's table remembers.
    #[serde(default = "keys_max_default")]
    pub keys_max: u32,
    /// The time between two cache passes. Box only: a cadence, not a choice.
    #[serde(default = "pass_every_secs_default")]
    pub pass_every_secs: u64,
}

impl Default for NodeCacheSettings {
    fn default() -> Self {
        Self {
            cap_gib: CACHE_CAP_GIB_DEFAULT,
            idle_days: CACHE_IDLE_DAYS_DEFAULT,
            protect_hours: CACHE_PROTECT_HOURS_DEFAULT,
            wanted_hold_secs: CACHE_WANTED_HOLD_SECS_DEFAULT,
            keys_max: CACHE_KEYS_MAX_DEFAULT,
            pass_every_secs: CACHE_PASS_EVERY_SECS_DEFAULT,
        }
    }
}

fn cap_gib_default() -> u64 {
    CACHE_CAP_GIB_DEFAULT
}
fn idle_days_default() -> u32 {
    CACHE_IDLE_DAYS_DEFAULT
}
fn protect_hours_default() -> u32 {
    CACHE_PROTECT_HOURS_DEFAULT
}
fn wanted_hold_secs_default() -> u64 {
    CACHE_WANTED_HOLD_SECS_DEFAULT
}
fn keys_max_default() -> u32 {
    CACHE_KEYS_MAX_DEFAULT
}
fn pass_every_secs_default() -> u64 {
    CACHE_PASS_EVERY_SECS_DEFAULT
}

impl NodeCacheSettings {
    /// The figures in force: for each the smaller of this box's and the owner's machine policy
    /// (`placement.cache.*`, row P0), and the box's own pass cadence. `None`: the box alone.
    #[must_use]
    pub fn tightened(&self, owner: Option<&CachePolicy>) -> Self {
        let Some(owner) = owner else {
            return *self;
        };
        Self {
            cap_gib: self.cap_gib.min(owner.cap_gib),
            idle_days: self.idle_days.min(owner.idle_days),
            protect_hours: self.protect_hours.min(owner.protect_hours),
            wanted_hold_secs: self.wanted_hold_secs.min(owner.wanted_hold_secs),
            keys_max: self.keys_max.min(owner.keys_max).max(1),
            pass_every_secs: self.pass_every_secs,
        }
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.keys_max == 0 {
            return Err("execution_node.cache.keys_max must be at least 1".to_owned());
        }
        if self.pass_every_secs == 0 {
            return Err("execution_node.cache.pass_every_secs must be at least 1".to_owned());
        }
        Ok(())
    }
}

/// A path with no `.` or `..` component and no trailing separator: what it names is what it
/// reads as.
fn plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

/// The check of `template`'s warm keys against the box's cache directory `cache_root`: each key
/// of a warm key's form, at most [`TEMPLATE_WARM_KEYS_MAX`]; each path absolute and plain, and
/// none in the directory a pass moves removed caches into; each cache key one the template
/// maps, named once, whose path is an entry directly in `cache_root`.
pub(super) fn check_template_warm(
    template: &NodeTemplate,
    cache_root: &Path,
) -> Result<(), String> {
    let evicted = cache_root.join(EVICTED_DIR_NAME);
    if template.warm.len() > TEMPLATE_WARM_KEYS_MAX {
        return Err(format!(
            "warm maps {} keys, at most {TEMPLATE_WARM_KEYS_MAX}",
            template.warm.len()
        ));
    }
    for (key, path) in &template.warm {
        if !warm_key_valid(key) {
            return Err(format!(
                "warm key {key:?} is not <kind>:<name> of at most {} bytes",
                oneiron::warm_key::WARM_KEY_MAX_BYTES
            ));
        }
        if !plain_absolute(path) {
            return Err(format!(
                "warm key {key:?}: its path must be absolute with no '.' or '..'"
            ));
        }
        if path.starts_with(&evicted) {
            return Err(format!(
                "warm key {key:?}: its path lies in {}, where the cache pass moves what it removes",
                evicted.display()
            ));
        }
    }
    let mut seen = BTreeSet::new();
    for key in &template.caches {
        if !seen.insert(key) {
            return Err(format!("caches names {key:?} twice"));
        }
        let Some(path) = template.warm.get(key) else {
            return Err(format!("caches names {key:?}, which warm does not map"));
        };
        if path.parent() != Some(cache_root) {
            return Err(format!(
                "cache key {key:?}: its path must be an entry directly in execution_node.cache_dir ({})",
                cache_root.display()
            ));
        }
    }
    Ok(())
}

/// Every template that maps one warm key maps it to the same path, and either all of them
/// mark it a cache or none does; and no two keys, where either is a cache, have one path or
/// paths one inside the other: a key names one thing on one machine.
pub(super) fn check_warm_agreement(
    templates: &BTreeMap<String, NodeTemplate>,
) -> Result<(), String> {
    let mut first: BTreeMap<&str, (&str, &Path, bool)> = BTreeMap::new();
    for (name, template) in templates {
        for (key, path) in &template.warm {
            let cache = template.caches.contains(key);
            match first.get(key.as_str()) {
                None => {
                    first.insert(key, (name, path, cache));
                }
                Some((other, other_path, other_cache))
                    if *other_path != path.as_path() || *other_cache != cache =>
                {
                    return Err(format!(
                        "execution_node.templates.{name}: warm key {key:?} differs from template {other}'s (one path, and a cache in both or in neither)"
                    ));
                }
                Some(_) => {}
            }
        }
    }
    let keys: Vec<(&str, &Path, bool)> = first
        .iter()
        .map(|(key, (_, path, cache))| (*key, *path, *cache))
        .collect();
    for (index, (key, path, cache)) in keys.iter().enumerate() {
        for (other, other_path, other_cache) in &keys[index + 1..] {
            let nested = path.starts_with(other_path) || other_path.starts_with(path);
            if (*cache || *other_cache) && nested {
                return Err(format!(
                    "execution_node.templates: warm keys {key:?} and {other:?} name one path or one inside the other, and one is a cache: removing it would remove the other's files"
                ));
            }
        }
    }
    Ok(())
}
