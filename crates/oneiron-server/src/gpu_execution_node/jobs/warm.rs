//! Warm keys on the node (pass 34, `34-compute-general/DESIGN.md` sections 4.1 and 7.1 gap 6;
//! row P2): which warm keys this machine holds, the check before a launch that every input the
//! attempt lists is here, and the cache budget.
//!
//! - **What a key is here.** A template maps the keys it knows to paths (`warm`), and names
//!   which of them are caches (`caches`). An attempt lists the keys its work reads (the
//!   signed submit's `warm`, from the order). A key is present when its path exists.
//!   A key no template maps is remembered from use alone, a hint.
//! - **Before a launch** the stager checks each key the attempt lists that the template maps
//!   to a path that is not a cache: its path must exist, or the key ends at zero seconds as
//!   `LaunchRefused { warm_key_missing:<key> }`. Nothing is fetched. An absent cache is a cold
//!   start.
//! - **A key's last use** is when an attempt that listed it ended with exit 0. It is read from
//!   the journal under the admission lock, each ended key counted once, so a crash between an
//!   end and the table's write loses no use: the journal is the record, the table a summary
//!   kept past the journal's own retention.
//! - **The cache budget** ([`cache_plan`]) removes cache keys only: first those unused for the
//!   idle time, then the least recently used while the caches hold more than the cap, never one
//!   used within the protected time. It never removes a busy key: one that a key of the journal
//!   that has not ended lists or whose template maps it, or one that an open order on a live
//!   issuer lists (the issuer's `NodeWanting` ask, kept for `wanted_hold_secs`). Busy is decided,
//!   and each removed path renamed out of use, under the admission lock; the files are deleted
//!   after it is dropped. A path is removed only directly inside a cache directory that is the
//!   engine's alone, and only when the engine's account owns it.
//!
//! Lock order: the admission lock, then the warm lock; never the other way.

mod eviction;

pub mod cache_plan;
pub mod table;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{MutexGuard, PoisonError};

use oneiron::EntityId;
use oneiron::warm_key::{WANTED_WARM_KEYS_MAX, check_warm_keys};

pub use cache_plan::{CacheBudget, CacheEntry, Eviction, EvictionCause, cache_plan};
pub use table::{WARM_KEYS_FILE_NAME, WarmKeyRecord, WarmKeyTable};

use super::NodeJobs;
use super::journal::NodeKey;
use crate::gpu_execution_node::node_settings::{
    ExecutionNodeSettings, NodeCacheSettings, NodeTemplate,
};
use crate::gpu_execution_node::wire::{JobEnd, WarmKeyFact};

/// The reason a launch refusal carries for a listed input that is not here: the key follows
/// after a colon.
pub const WARM_KEY_MISSING: &str = "warm_key_missing";

/// One template's warm keys, for the stager: each key's path, and which are caches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemplateWarm {
    pub paths: BTreeMap<String, PathBuf>,
    pub caches: BTreeSet<String>,
}

impl TemplateWarm {
    /// The warm keys of `template`.
    #[must_use]
    pub fn of(template: &NodeTemplate) -> Self {
        Self {
            paths: template.warm.clone(),
            caches: template.caches.iter().cloned().collect(),
        }
    }

    /// The first key of `listed` that this template maps to a path that is not a cache and
    /// that does not exist now: the input the launch lacks.
    #[must_use]
    pub fn missing_input<'a>(&self, listed: &'a [String]) -> Option<&'a str> {
        listed
            .iter()
            .find(|key| {
                !self.caches.contains(*key)
                    && self
                        .paths
                        .get(*key)
                        .is_some_and(|path| !matches!(path.try_exists(), Ok(true)))
            })
            .map(String::as_str)
    }
}

/// One warm key as the node's file maps it, over all its templates (the file's check makes
/// every template that maps a key agree on its path and on whether it is a cache).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmPath {
    pub path: PathBuf,
    pub cache: bool,
}

/// Every warm key the node's templates map.
#[must_use]
pub fn warm_paths(settings: &ExecutionNodeSettings) -> BTreeMap<String, WarmPath> {
    let mut paths = BTreeMap::new();
    for template in settings.templates.values() {
        for (key, path) in &template.warm {
            paths.entry(key.clone()).or_insert_with(|| WarmPath {
                path: path.clone(),
                cache: template.caches.contains(key),
            });
        }
    }
    paths
}

/// The cache budget the box's ceiling gives. The owner's machine policy (row P0) may set each
/// figure lower: the node then applies the smaller.
#[must_use]
pub fn cache_budget(ceiling: &NodeCacheSettings) -> CacheBudget {
    CacheBudget {
        cap_bytes: ceiling.cap_gib.saturating_mul(1024 * 1024 * 1024),
        idle_ms: u64::from(ceiling.idle_days).saturating_mul(86_400_000),
        protect_ms: u64::from(ceiling.protect_hours).saturating_mul(3_600_000),
    }
}

/// One issuer's newest wanted list.
#[derive(Debug, Clone)]
struct WantedList {
    keys: BTreeSet<String>,
    at_ms: u64,
}

/// What the warm lock holds.
#[derive(Debug)]
pub(super) struct WarmState {
    table: WarmKeyTable,
    wanted: BTreeMap<EntityId, WantedList>,
    /// When this service opened: the first cache pass waits one wanted hold after it, so the
    /// issuers' lists are in before anything is removed.
    opened_ms: u64,
    last_pass_ms: Option<u64>,
    pass_running: bool,
}

impl WarmState {
    pub(super) fn open(state_dir: &Path, opened_ms: u64) -> Self {
        Self {
            table: WarmKeyTable::open(state_dir),
            wanted: BTreeMap::new(),
            opened_ms,
            last_pass_ms: None,
            pass_running: false,
        }
    }

    /// Counts each key of the journal that ended with exit 0 and has not been counted: each
    /// warm key it listed was used when it ended. Returns whether the table changed.
    fn count_ended<'a>(&mut self, keys: impl Iterator<Item = &'a NodeKey>) -> bool {
        let mut in_journal = BTreeSet::new();
        let mut changed = false;
        for known in keys {
            in_journal.insert(known.key.clone());
            if known.end != Some(JobEnd::Exited { code: 0 }) || self.table.counted(&known.key) {
                continue;
            }
            let listed = known
                .submit
                .as_ref()
                .map(|signed| signed.submit.warm.clone())
                .unwrap_or_default();
            self.table.used(&listed, known.updated_at_ms);
            self.table.count(&known.key);
            changed = true;
        }
        changed | self.table.retain_counted(|key| in_journal.contains(key))
    }

    /// The keys an open order on a live issuer listed within `hold_ms` of `now_ms`.
    fn wanted_now(&mut self, now_ms: u64, hold_ms: u64) -> BTreeSet<String> {
        self.wanted
            .retain(|_, list| list.at_ms.saturating_add(hold_ms) > now_ms);
        self.wanted
            .values()
            .flat_map(|list| list.keys.iter().cloned())
            .collect()
    }

    fn save(&self) {
        if let Err(error) = self.table.save() {
            tracing::warn!(%error, "warm keys: the table was not written; the next change tries again");
        }
    }
}

/// What one cache pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CachePassReport {
    /// The cache keys removed, in the order the plan chose them.
    pub removed: Vec<Eviction>,
    /// Cache keys the plan chose that were left, each with why.
    pub left: Vec<(String, String)>,
    /// What the cache keys hold after the pass.
    pub kept_bytes: u64,
}

impl NodeJobs {
    fn warm_lock(&self) -> MutexGuard<'_, WarmState> {
        self.shared
            .warm
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The issuer `issuer` asked `NodeWanting`: the warm keys of its open orders that may run
    /// here. The newest list of each issuer replaces its last one. A list that is not one of
    /// warm keys is ignored.
    pub fn warm_wanted(&self, issuer: EntityId, keys: &[String]) {
        if let Err(invalid) = check_warm_keys(keys, WANTED_WARM_KEYS_MAX) {
            tracing::warn!(%issuer, %invalid, "warm keys: an issuer's wanted list is not one of warm keys; it is ignored");
            return;
        }
        let at_ms = self.now().wall_ms;
        self.warm_lock().wanted.insert(
            issuer,
            WantedList {
                keys: keys.iter().cloned().collect(),
                at_ms,
            },
        );
    }

    /// The warm keys this node holds or has used, as `Node` reports them: every key a template
    /// maps, present or not, then the keys remembered from use alone.
    #[must_use]
    pub fn warm_facts(&self, settings: &ExecutionNodeSettings) -> Vec<WarmKeyFact> {
        let paths = warm_paths(settings);
        // The paths are read before any lock is taken.
        let present: BTreeMap<&str, bool> = paths
            .iter()
            .map(|(key, warm)| (key.as_str(), matches!(warm.path.try_exists(), Ok(true))))
            .collect();
        let now_ms = self.now().wall_ms;
        let book = self.lock();
        let mut warm = self.warm_lock();
        let mut changed = match book.journal.as_ref() {
            Some(journal) => warm.count_ended(journal.table().iter()),
            None => false,
        };
        drop(book);
        for (key, here) in &present {
            if *here {
                changed |= warm.table.found(key, now_ms);
            }
        }
        let keys_max = usize::try_from(settings.cache.keys_max).unwrap_or(usize::MAX);
        changed |= !warm
            .table
            .bound(keys_max, |key| paths.contains_key(key))
            .is_empty();
        if changed {
            warm.save();
        }
        let fact = |key: &str, record: Option<&WarmKeyRecord>| WarmKeyFact {
            key: key.to_owned(),
            present: present.get(key).copied().unwrap_or(false),
            mapped: paths.contains_key(key),
            cache: paths.get(key).is_some_and(|warm| warm.cache),
            bytes: record.map_or(0, |record| record.bytes),
            last_used_ms: record.map(|record| record.last_used_ms),
            uses: record.map_or(0, |record| record.uses),
        };
        let mut facts: Vec<WarmKeyFact> = paths
            .keys()
            .map(|key| fact(key, warm.table.get(key)))
            .collect();
        facts.extend(
            warm.table
                .records()
                .filter(|record| !paths.contains_key(&record.key))
                .map(|record| fact(&record.key, Some(record))),
        );
        facts
    }

    /// Starts a cache pass on its own thread when one is due: the box has a cache directory,
    /// one wanted hold has passed since this service opened, the last pass started at least
    /// `pass_every_secs` ago, and none runs now. The authority tick calls this; it never waits
    /// for the pass.
    pub fn cache_pass_if_due(&self, settings: &ExecutionNodeSettings) {
        if settings.cache_dir.is_none() {
            return;
        }
        let now_ms = self.now().wall_ms;
        {
            let mut warm = self.warm_lock();
            let hold_ms = settings.cache.wanted_hold_secs.saturating_mul(1000);
            let every_ms = settings.cache.pass_every_secs.saturating_mul(1000);
            let due = now_ms >= warm.opened_ms.saturating_add(hold_ms)
                && warm
                    .last_pass_ms
                    .is_none_or(|last| now_ms >= last.saturating_add(every_ms));
            if warm.pass_running || !due {
                return;
            }
            warm.pass_running = true;
            warm.last_pass_ms = Some(now_ms);
        }
        let jobs = self.clone();
        let settings = settings.clone();
        let spawned = std::thread::Builder::new()
            .name("node-cache-pass".to_owned())
            .spawn(move || {
                let report = jobs.cache_pass(&settings);
                if !report.removed.is_empty() || !report.left.is_empty() {
                    tracing::info!(
                        removed = report.removed.len(),
                        left = report.left.len(),
                        kept_bytes = report.kept_bytes,
                        "warm keys: the cache pass ended"
                    );
                }
                jobs.warm_lock().pass_running = false;
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, "warm keys: the cache pass did not start");
            self.warm_lock().pass_running = false;
        }
    }

    /// One cache pass now, on this thread, under the budget the box's ceiling gives.
    #[must_use]
    pub fn cache_pass(&self, settings: &ExecutionNodeSettings) -> CachePassReport {
        let budget = cache_budget(&settings.cache);
        self.cache_pass_under(settings, &budget)
    }

    /// One cache pass now, on this thread, under `budget`.
    #[must_use]
    pub fn cache_pass_under(
        &self,
        settings: &ExecutionNodeSettings,
        budget: &CacheBudget,
    ) -> CachePassReport {
        let Some(cache_dir) = settings.cache_dir.as_deref() else {
            return CachePassReport::default();
        };
        let Some(cache_dir) = eviction::trusted_cache_dir(cache_dir) else {
            return CachePassReport::default();
        };
        eviction::remove_evicted(&cache_dir);
        let paths = warm_paths(settings);
        // What each present cache path holds is measured before any lock is taken.
        let measured: BTreeMap<String, u64> = paths
            .iter()
            .filter(|(_, warm)| warm.cache)
            .filter_map(|(key, warm)| {
                eviction::measure(&warm.path).map(|bytes| (key.clone(), bytes))
            })
            .collect();
        let now_ms = self.now().wall_ms;
        let hold_ms = settings.cache.wanted_hold_secs.saturating_mul(1000);
        let mut report = CachePassReport::default();
        let mut renamed = Vec::new();
        {
            let book = self.lock();
            let Some(journal) = book.journal.as_ref() else {
                return report;
            };
            let mut warm = self.warm_lock();
            warm.count_ended(journal.table().iter());
            let mut busy = warm.wanted_now(now_ms, hold_ms);
            for known in journal.table().iter().filter(|known| !known.is_ended()) {
                if let Some(signed) = known.submit.as_ref() {
                    busy.extend(signed.submit.warm.iter().cloned());
                }
                let Some(reserve) = known.reserve.as_ref() else {
                    continue;
                };
                // Every key its template maps: a held key's run may read any.
                if let Some(template) = settings.templates.get(&reserve.pin.template) {
                    busy.extend(template.warm.keys().cloned());
                }
            }
            let mut entries = Vec::new();
            for (key, bytes) in &measured {
                warm.table.found(key, now_ms);
                warm.table.measured(key, *bytes);
                let last_used_ms = warm
                    .table
                    .get(key)
                    .map_or(now_ms, |record| record.last_used_ms);
                entries.push(CacheEntry {
                    key: key.clone(),
                    bytes: *bytes,
                    last_used_ms,
                    busy: busy.contains(key),
                });
            }
            let (plan, kept_bytes) = cache_plan(&entries, budget, now_ms);
            report.kept_bytes = kept_bytes;
            for eviction in plan {
                let Some(warm_path) = paths.get(&eviction.key) else {
                    continue;
                };
                match eviction::take_out_of_use(&cache_dir, &warm_path.path, now_ms) {
                    Ok(taken) => {
                        warm.table.measured(&eviction.key, 0);
                        tracing::info!(key = %eviction.key, path = %warm_path.path.display(), cause = %eviction.cause, "warm keys: a cache key is removed");
                        renamed.push(taken);
                        report.removed.push(eviction);
                    }
                    Err(why) => report.left.push((eviction.key.clone(), why)),
                }
            }
            let keys_max = usize::try_from(settings.cache.keys_max).unwrap_or(usize::MAX);
            warm.table.bound(keys_max, |key| paths.contains_key(key));
            warm.save();
        }
        for taken in renamed {
            eviction::remove_taken(&taken);
        }
        report
    }
}
