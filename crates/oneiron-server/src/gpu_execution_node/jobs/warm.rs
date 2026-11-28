//! Warm keys on the node (pass 34, `34-compute-general/DESIGN.md` sections 4.1 and 7.1 gap 6;
//! row P2): which warm keys this machine holds, the check before a launch that every input the
//! attempt lists is here, and the cache budget.
//!
//! - **What a key is here.** A template maps the keys it knows to paths (`warm`), and names
//!   which of them are caches (`caches`). A key names one thing on one machine: every template
//!   that maps it maps it to one path ([`warm_paths`]). An attempt lists the keys its work reads
//!   (the signed submit's `warm`, from the order). A key is present when its path exists. A key
//!   no template maps is remembered from use alone, a hint.
//! - **Before a launch** the stager checks each key the attempt lists that the node's file maps
//!   to a path that is not a cache: its path must exist, or the key ends at zero seconds as
//!   `LaunchRefused { warm_key_missing:<key> }` ([`missing_input`]). Nothing is fetched. An
//!   absent cache is a cold start.
//! - **A key's last use** is when an attempt that listed it ended with exit 0: the `Ended`
//!   record's time. It is read from the journal under the admission lock, each ended key
//!   counted once, so a crash between an end and the table's write loses no use: the journal is
//!   the record, the table a summary kept past the journal's own retention.
//! - **The cache budget** ([`cache_plan`]) removes cache keys only: first those unused for the
//!   idle time, then the least recently used while the caches hold more than the cap, never one
//!   used within the protected time. It never removes a busy key: one that a key of the journal
//!   that has not ended lists, or that the template it pinned maps, or one that an open order on
//!   a live issuer lists (the issuer's `NodeWanting` ask, kept for `wanted_hold_secs`). It
//!   removes nothing while a live key pins a template at a digest the file no longer holds (its
//!   map is not known), or while a live ask left keys out for its bound. Busy is decided, and
//!   each removed path moved out of use, under the admission lock; the files are deleted after
//!   it is dropped. A path is removed only directly inside a cache directory that is the
//!   engine's alone, and never when another key's path lies in it where the file system
//!   resolves that path or its lookup passes through it, reaches into it by another name, or
//!   when the node's state or work directory lies in it ([`eviction`]). The pass reads the
//!   node's file and the owner's cache figures again under the lock, resolves every path again
//!   there, and removes nothing when any of them changed while the pass measured, or no longer
//!   reads. A moved path is deleted only once the table that records the move is on disk,
//!   and nothing is deleted from the removed caches' directory while anything is deferred. Once
//!   the service closes ([`NodeJobs::close`]), no pass starts, and a running one stops at its
//!   next move or directory.
//!
//! Lock order: the admission lock, then the warm lock; never the other way. The table's file is
//! written after both are dropped.

mod eviction;

pub mod cache_plan;
pub mod table;

#[cfg(target_os = "linux")]
pub(crate) use eviction::remove_tree;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{MutexGuard, PoisonError};

use oneiron::EntityId;
use oneiron::warm_key::{WANTED_WARM_KEYS_MAX, WarmWanted, check_warm_keys};

pub use cache_plan::{CacheBudget, CacheEntry, Eviction, EvictionCause, cache_plan};
pub use table::{EvictedRecord, TableWrite, WARM_KEYS_FILE_NAME, WarmKeyRecord, WarmKeyTable};

use super::NodeJobs;
use super::journal::NodeKey;
pub use crate::gpu_execution_node::node_settings::SettingsRead;
use crate::gpu_execution_node::node_settings::{ExecutionNodeSettings, NodeCacheSettings};
use crate::gpu_execution_node::wire::{JobEnd, WarmKeyFact};

/// The reason a launch refusal carries for a listed input that is not here: the key follows
/// after a colon.
pub const WARM_KEY_MISSING: &str = "warm_key_missing";

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

/// The first key of `listed` that `paths` maps to a path that is not a cache and that does not
/// exist now: the input the launch lacks.
#[must_use]
pub fn missing_input<'a>(
    paths: &BTreeMap<String, WarmPath>,
    listed: &'a [String],
) -> Option<&'a str> {
    listed
        .iter()
        .find(|key| {
            paths
                .get(*key)
                .is_some_and(|warm| !warm.cache && !matches!(warm.path.try_exists(), Ok(true)))
        })
        .map(String::as_str)
}

/// Each template's digest in `settings`.
fn template_digests(settings: &ExecutionNodeSettings) -> BTreeMap<String, String> {
    settings
        .templates
        .iter()
        .filter_map(|(name, template)| template.digest().ok().map(|digest| (name.clone(), digest)))
        .collect()
}

/// Where the file system resolves each warm path of one reading of the node's file, and the
/// node's own directories, with what each lookup passes through: no move takes a cache that one
/// of them lies in or reaches into.
#[derive(Debug, Default, PartialEq, Eq)]
struct Resolved {
    warm: BTreeMap<String, eviction::Lookup>,
    /// The state directory (the journal, the warm-key table) and the work directory.
    service: Vec<eviction::Lookup>,
}

impl Resolved {
    /// # Errors
    ///
    /// A path does not resolve: what lies in a cache is then not known.
    fn read(settings: &ExecutionNodeSettings) -> Result<Self, String> {
        let warm: BTreeMap<String, eviction::Lookup> = warm_paths(settings)
            .into_iter()
            .map(|(key, warm)| match eviction::lookup(&warm.path) {
                Ok(found) => Ok((key, found)),
                Err(error) => Err(format!(
                    "the path of warm key {key} does not resolve: {error}"
                )),
            })
            .collect::<Result<_, String>>()?;
        let service: Vec<eviction::Lookup> = [
            ("state_dir", &settings.state_dir),
            ("work_dir", &settings.work_dir),
        ]
        .into_iter()
        .map(|(name, dir)| {
            eviction::lookup(dir)
                .map_err(|error| format!("the node's {name} does not resolve: {error}"))
        })
        .collect::<Result<_, String>>()?;
        Ok(Self { warm, service })
    }

    /// Every warm key's lookup but `key`'s.
    fn others(&self, key: &str) -> Vec<&eviction::Lookup> {
        self.warm
            .iter()
            .filter(|(other, _)| other.as_str() != key)
            .map(|(_, found)| found)
            .collect()
    }

    /// What no entry in `key`'s cache path may be: what every other key's lookup and each of
    /// the node's directories enters or ends at.
    fn guarded(&self, key: &str) -> BTreeSet<eviction::Identity> {
        eviction::guarded(self.others(key).into_iter().chain(&self.service))
    }
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
    /// The issuer's open orders list more keys than its ask carried.
    overflow: bool,
    at_ms: u64,
}

/// What the live issuers want kept now.
#[derive(Debug, Default)]
struct WantedNow {
    keys: BTreeSet<String>,
    overflow: bool,
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

    /// Counts each key of the journal that ended with exit 0, listed warm keys and has not been
    /// counted: each key it listed was used when it ended. Returns whether the table changed.
    fn count_ended<'a>(&mut self, keys: impl Iterator<Item = &'a NodeKey>) -> bool {
        let mut in_journal = BTreeSet::new();
        let mut changed = false;
        for known in keys {
            in_journal.insert(known.key.clone());
            if known.end != Some(JobEnd::Exited { code: 0 }) || self.table.counted(&known.key) {
                continue;
            }
            let Some(signed) = known
                .submit
                .as_ref()
                .filter(|signed| !signed.submit.warm.is_empty())
            else {
                continue;
            };
            let ended_at_ms = known.ended_at_ms.unwrap_or(known.updated_at_ms);
            self.table.used(&signed.submit.warm, ended_at_ms);
            self.table.count(&known.key);
            changed = true;
        }
        changed | self.table.retain_counted(|key| in_journal.contains(key))
    }

    /// What open orders on live issuers listed within `hold_ms` of `now_ms`.
    fn wanted_now(&mut self, now_ms: u64, hold_ms: u64) -> WantedNow {
        self.wanted
            .retain(|_, list| list.at_ms.saturating_add(hold_ms) > now_ms);
        let mut now = WantedNow::default();
        for list in self.wanted.values() {
            now.keys.extend(list.keys.iter().cloned());
            now.overflow |= list.overflow;
        }
        now
    }

    /// The table as it is now, to write after the locks are dropped.
    fn table_write(&mut self) -> Option<TableWrite> {
        match self.table.encode() {
            Ok(write) => Some(write),
            Err(error) => {
                tracing::warn!(%error, "warm keys: the table does not encode; the next change tries again");
                None
            }
        }
    }
}

/// Writes the table, with the warm lock dropped. Returns whether the file on disk holds this
/// change or a newer one, its directory synced.
fn write_table(write: Option<TableWrite>) -> bool {
    match write.map(TableWrite::write) {
        Some(Ok(())) => true,
        Some(Err(error)) => {
            tracing::warn!(%error, "warm keys: the table was not written; the next change tries again");
            false
        }
        None => false,
    }
}

/// What one cache pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CachePassReport {
    /// The cache keys moved out of use, in the order the plan chose them. Their files are
    /// deleted after the move; [`Self::not_deleted`] names those that were not.
    pub removed: Vec<Eviction>,
    /// Cache keys the plan chose that were left, each with why; the plan then went on without
    /// them.
    pub left: Vec<(String, String)>,
    /// Why the pass removed nothing, when it could not know what is busy.
    pub deferred: Option<String>,
    /// What the cache keys hold after the pass.
    pub kept_bytes: u64,
    /// Moved cache paths whose files were not deleted, by their names in the removed caches'
    /// directory, each with why: their disk is not free yet, and the next pass tries again.
    pub not_deleted: Vec<(String, String)>,
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
    pub fn warm_wanted(&self, issuer: EntityId, wanted: &WarmWanted) {
        if let Err(invalid) = check_warm_keys(&wanted.keys, WANTED_WARM_KEYS_MAX) {
            tracing::warn!(issuer = %issuer.to_hex(), %invalid, "warm keys: an issuer's wanted list is not one of warm keys; it is ignored");
            return;
        }
        let at_ms = self.now().wall_ms;
        self.warm_lock().wanted.insert(
            issuer,
            WantedList {
                keys: wanted.keys.iter().cloned().collect(),
                overflow: wanted.overflow,
                at_ms,
            },
        );
    }

    /// The warm keys this node holds or has used, as `Node` reports them: every key a template
    /// maps, present or not, then the keys remembered from use alone.
    #[must_use]
    pub fn warm_facts(
        &self,
        settings: &ExecutionNodeSettings,
        cache: &NodeCacheSettings,
    ) -> Vec<WarmKeyFact> {
        let paths = warm_paths(settings);
        // The paths are read before any lock is taken.
        let present: BTreeMap<&str, bool> = paths
            .iter()
            .map(|(key, warm)| (key.as_str(), matches!(warm.path.try_exists(), Ok(true))))
            .collect();
        let now_ms = self.now().wall_ms;
        let book = self.lock();
        // The job caches live keys hold kept now (FLEET-TOOL-PARITY row 5).
        let held = book
            .journal
            .as_ref()
            .map(|journal| super::job_cache::held_cache_keys(journal.table().iter()))
            .unwrap_or_default();
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
        let keys_max = usize::try_from(cache.keys_max).unwrap_or(usize::MAX);
        changed |= !warm
            .table
            .bound(keys_max, |key| paths.contains_key(key))
            .is_empty();
        let write = if changed { warm.table_write() } else { None };
        let fact = |key: &str, record: Option<&WarmKeyRecord>| WarmKeyFact {
            key: key.to_owned(),
            present: present.get(key).copied().unwrap_or(false),
            mapped: paths.contains_key(key),
            cache: paths.get(key).is_some_and(|warm| warm.cache),
            bytes: record.map_or(0, |record| record.bytes),
            last_used_ms: record.map(|record| record.last_used_ms),
            uses: record.map_or(0, |record| record.uses),
            held: held.contains(key),
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
        drop(warm);
        write_table(write);
        facts
    }

    /// Starts a cache pass on its own thread when one is due: the service has not closed, a
    /// template marks a cache, one wanted hold has passed since this service opened, the last
    /// pass started at least `pass_every_secs` ago, and none runs now. The authority tick calls
    /// this; it never waits for the pass, which reads the node's file through `settings_now`.
    pub fn cache_pass_if_due(
        &self,
        settings: &ExecutionNodeSettings,
        cache: &NodeCacheSettings,
        settings_now: SettingsRead,
    ) {
        if !settings.marks_caches() || self.service_closed() {
            return;
        }
        let now_ms = self.now().wall_ms;
        {
            let mut warm = self.warm_lock();
            let hold_ms = cache.wanted_hold_secs.saturating_mul(1000);
            let every_ms = cache.pass_every_secs.saturating_mul(1000);
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
        let cache = *cache;
        // `cache` was made from this tick's file: a reading whose cache figures or owner opt-in
        // differ from it is no reading, and the pass then removes nothing.
        let (tick_cache, tick_owner_policy) = (settings.cache, settings.owner_policy);
        let read = move || {
            settings_now()
                .filter(|now| now.cache == tick_cache && now.owner_policy == tick_owner_policy)
        };
        let spawned = std::thread::Builder::new()
            .name("node-cache-pass".to_owned())
            .spawn(move || {
                let report = jobs.cache_pass(&read, &cache);
                if !report.removed.is_empty()
                    || !report.left.is_empty()
                    || !report.not_deleted.is_empty()
                {
                    tracing::info!(
                        removed = report.removed.len(),
                        left = report.left.len(),
                        not_deleted = report.not_deleted.len(),
                        kept_bytes = report.kept_bytes,
                        "warm keys: the cache pass ended"
                    );
                }
                if let Some(why) = &report.deferred {
                    tracing::info!(%why, "warm keys: the cache pass removed nothing");
                }
                jobs.warm_lock().pass_running = false;
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, "warm keys: the cache pass did not start");
            self.warm_lock().pass_running = false;
        }
    }

    /// One cache pass now, on this thread, under the cache figures in force.
    #[must_use]
    pub fn cache_pass(
        &self,
        settings_now: &dyn Fn() -> Option<ExecutionNodeSettings>,
        cache: &NodeCacheSettings,
    ) -> CachePassReport {
        self.cache_pass_under(settings_now, cache, &cache_budget(cache))
    }

    /// One cache pass now, on this thread, under `budget`. `settings_now` reads the node's
    /// file: once before the pass measures, and once more under the admission lock, where the
    /// pass removes nothing unless the two readings map the same keys to the same paths with the
    /// same template digests, cache figures and owner opt-in. `cache` gives the wanted hold and
    /// the table's bound. Once the service has closed, it stops at its next move or directory.
    #[must_use]
    pub fn cache_pass_under(
        &self,
        settings_now: &dyn Fn() -> Option<ExecutionNodeSettings>,
        cache: &NodeCacheSettings,
        budget: &CacheBudget,
    ) -> CachePassReport {
        if self.service_closed() {
            return CachePassReport::default();
        }
        let Some(settings) = settings_now().filter(ExecutionNodeSettings::marks_caches) else {
            return CachePassReport::default();
        };
        let Some(cache_dir) = eviction::trusted_cache_dir(&settings.cache_root()) else {
            return CachePassReport::default();
        };
        let trash = match eviction::Trash::open(&cache_dir) {
            Ok(trash) => trash,
            Err(why) => {
                tracing::warn!(cache_dir = %cache_dir.display(), %why, "warm keys: the removed caches' directory is not the engine's alone; nothing is removed");
                return CachePassReport::default();
            }
        };
        let paths = warm_paths(&settings);
        let owners = eviction::EntryOwners::of(&settings.job_account);
        // Each template's digest, where each path resolves, and what each present cache path
        // holds, are read before any lock is taken.
        let digests = template_digests(&settings);
        let before = Resolved::read(&settings);
        let measured: BTreeMap<String, eviction::Measured> = paths
            .iter()
            .filter(|(_, warm)| warm.cache)
            .filter_map(|(key, warm)| {
                let guarded = before
                    .as_ref()
                    .map(|before| before.guarded(key))
                    .unwrap_or_default();
                eviction::measure(&warm.path, &guarded).map(|measured| (key.clone(), measured))
            })
            .collect();
        let now_ms = self.now().wall_ms;
        let hold_ms = cache.wanted_hold_secs.saturating_mul(1000);
        let mut report = CachePassReport::default();
        let (write, evicted, sweep) = {
            let book = self.lock();
            let Some(journal) = book.journal.as_ref() else {
                return report;
            };
            // The file and the owner's cache figures as they are now (`settings_now` gives no
            // reading when the figures differ from the pass's): a launch admitted after this
            // lock reads these.
            let current = settings_now();
            let unchanged = current.as_ref().is_some_and(|now| {
                now.cache_root() == settings.cache_root()
                    && now.job_account == settings.job_account
                    && now.cache == settings.cache
                    && now.owner_policy == settings.owner_policy
                    && warm_paths(now) == paths
                    && template_digests(now) == digests
            });
            if !unchanged {
                report.deferred = Some(
                    "the node's file or the owner's cache figures changed while the pass measured, or do not read"
                        .to_owned(),
                );
            }
            // Where each warm path of the file and each of the node's directories now resolves,
            // and what its lookup passes through: a move never takes a cache another key's path
            // overlaps or reaches into, or one the node's directories lie in, and nothing is
            // deleted while a warm path overlaps where removed caches go. A path that resolves
            // otherwise than when the pass measured (a link or a mount made meanwhile) defers.
            let resolved = match current.as_ref().map(Resolved::read) {
                Some(Ok(resolved)) => Some(resolved),
                Some(Err(why)) => {
                    report.deferred = Some(why);
                    None
                }
                None => None,
            };
            if unchanged && resolved.is_some() && resolved.as_ref() != before.as_ref().ok() {
                report.deferred = Some(
                    "a warm path or a directory of the node's resolves otherwise than when the pass measured"
                        .to_owned(),
                );
            }
            let sweep = resolved.as_ref().is_some_and(|resolved| {
                !resolved
                    .warm
                    .values()
                    .any(|found| trash.overlapped_by(found))
            });
            if resolved.is_some() && !sweep {
                report.deferred = Some("a warm key's path lies where removed caches go".to_owned());
            }
            let resolved = resolved.unwrap_or_default();
            let mut warm = self.warm_lock();
            warm.count_ended(journal.table().iter());
            let wanted = warm.wanted_now(now_ms, hold_ms);
            let mut busy = wanted.keys;
            if wanted.overflow {
                report.deferred = Some(
                    "an issuer's open orders list more warm keys than its ask carried".to_owned(),
                );
            }
            for known in journal.table().iter().filter(|known| !known.is_ended()) {
                if let Some(signed) = known.submit.as_ref() {
                    busy.extend(signed.submit.warm.iter().cloned());
                }
                let Some(reserve) = known.reserve.as_ref() else {
                    continue;
                };
                // Every key the template it pinned maps: a held key's run may read any.
                let pinned = &reserve.pin;
                match settings.templates.get(&pinned.template) {
                    Some(template)
                        if digests.get(pinned.template.as_str())
                            == Some(&pinned.template_digest) =>
                    {
                        busy.extend(template.warm.keys().cloned());
                    }
                    _ => {
                        report.deferred = Some(format!(
                            "the live key {} pins template {} at a digest the node's file does not hold now",
                            known.key, pinned.template
                        ));
                    }
                }
            }
            let mut entries = Vec::new();
            for (key, found) in &measured {
                warm.table.found(key, now_ms);
                warm.table.measured(key, found.bytes);
                let last_used_ms = warm
                    .table
                    .get(key)
                    .map_or(now_ms, |record| record.last_used_ms);
                entries.push(CacheEntry {
                    key: key.clone(),
                    bytes: found.bytes,
                    last_used_ms,
                    busy: busy.contains(key) || report.deferred.is_some(),
                });
            }
            // A key left (its move refused) keeps its bytes: plan again with it held, so the
            // next candidate is tried. Each round holds one more key, so the rounds end.
            let mut closed = false;
            loop {
                let (plan, _) = cache_plan(&entries, budget, now_ms);
                let mut refused = None;
                for chosen in plan {
                    if self.service_closed() {
                        closed = true;
                        break;
                    }
                    let protected = resolved.others(&chosen.key);
                    let taken = match (paths.get(&chosen.key), measured.get(&chosen.key)) {
                        (None, _) => Err("no template maps it now".to_owned()),
                        (Some(_), Some(found)) if found.aliased => Err(
                            "another warm key's path or one of the node's directories reaches into it by another name"
                                .to_owned(),
                        ),
                        (Some(_), found) if !found.is_some_and(|found| found.emptiable) => {
                            Err("the engine's account cannot empty a directory in it".to_owned())
                        }
                        (Some(warm_path), _) => trash.take(
                            &cache_dir,
                            &warm_path.path,
                            owners,
                            (protected.as_slice(), resolved.service.as_slice()),
                            warm.table.evicted_records(),
                            now_ms,
                        ),
                    };
                    match taken {
                        Ok(record) => {
                            warm.table.measured(&chosen.key, 0);
                            warm.table.evicted(record);
                            tracing::info!(key = %chosen.key, cause = %chosen.cause, "warm keys: a cache key is removed");
                            entries.retain(|entry| entry.key != chosen.key);
                            report.removed.push(chosen);
                        }
                        Err(why) => {
                            report.left.push((chosen.key.clone(), why));
                            refused = Some(chosen.key);
                            break;
                        }
                    }
                }
                let Some(refused) = refused.filter(|_| !closed) else {
                    break;
                };
                for entry in &mut entries {
                    entry.busy |= entry.key == refused;
                }
            }
            // What stays: every measured cache not moved, the plan's rest too when a close
            // stopped it.
            report.kept_bytes = entries
                .iter()
                .fold(0_u64, |kept, entry| kept.saturating_add(entry.bytes));
            let keys_max = usize::try_from(cache.keys_max).unwrap_or(usize::MAX);
            warm.table.bound(keys_max, |key| paths.contains_key(key));
            // Nothing is deleted while anything is deferred: what lies where removed caches go
            // is then not known for sure.
            let sweep = sweep && report.deferred.is_none() && !closed && !self.service_closed();
            let evicted: BTreeMap<String, EvictedRecord> = if sweep {
                warm.table
                    .evicted_records()
                    .iter()
                    .filter(|(_, record)| trash.holds(record))
                    .map(|(name, record)| (name.clone(), record.clone()))
                    .collect()
            } else {
                BTreeMap::new()
            };
            (warm.table_write(), evicted, sweep)
        };
        // A move is deleted only once the table that records it is on disk.
        if !write_table(write) {
            for name in evicted.keys() {
                report.not_deleted.push((
                    name.clone(),
                    "the table that records its move was not written".to_owned(),
                ));
            }
            return report;
        }
        // The moved paths, this pass's and any an earlier pass left, go now: each only when the
        // entry there is the one the move recorded.
        let stop = || self.service_closed();
        let mut deleted = Vec::new();
        for record in evicted.values() {
            if stop() {
                break;
            }
            match trash.delete(record, &stop) {
                Ok(()) => deleted.push(record.name.clone()),
                Err(why) => {
                    tracing::warn!(name = %record.name, %why, "warm keys: a removed cache path was not deleted; the next pass tries again");
                    report.not_deleted.push((record.name.clone(), why));
                }
            }
        }
        if sweep && !stop() {
            let unrecorded = trash.unrecorded(&evicted);
            if unrecorded > 0 {
                tracing::warn!(
                    unrecorded,
                    "warm keys: the removed caches' directory holds entries no pass recorded; they are left"
                );
            }
        }
        if !deleted.is_empty() {
            let mut warm = self.warm_lock();
            for name in &deleted {
                warm.table.deleted(name);
            }
            let write = warm.table_write();
            drop(warm);
            write_table(write);
        }
        report
    }
}
