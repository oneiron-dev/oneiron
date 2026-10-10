//! Regions kept for reuse, keyed by content hash: a blob is copied out of
//! the store once, then every later call passes the same sealed region.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron_organ_protocol::SharedRegion;

#[derive(Debug)]
struct Entry {
    region: Arc<SharedRegion>,
    last_use: u64,
}

#[derive(Debug, Default)]
struct Cache {
    bytes: u64,
    clock: u64,
    entries: HashMap<[u8; 32], Entry>,
}

#[derive(Debug)]
pub(crate) struct RegionCache {
    limit: u64,
    cache: Mutex<Cache>,
}

impl RegionCache {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            limit,
            cache: Mutex::new(Cache::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn get(&self, hash: &[u8; 32]) -> Option<Arc<SharedRegion>> {
        let mut cache = self.lock();
        cache.clock += 1;
        let clock = cache.clock;
        cache.entries.get_mut(hash).map(|entry| {
            entry.last_use = clock;
            Arc::clone(&entry.region)
        })
    }

    /// Keeps `region` unless it alone is over the limit; evicts the least
    /// recently used regions to make room. An evicted region lives on while
    /// a call still holds it.
    pub(crate) fn insert(&self, hash: [u8; 32], region: SharedRegion) -> Arc<SharedRegion> {
        let region = Arc::new(region);
        let len = region.len();
        if len > self.limit {
            return region;
        }
        let mut cache = self.lock();
        while cache.bytes + len > self.limit {
            let Some(oldest) = cache
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_use)
                .map(|(key, _)| *key)
            else {
                break;
            };
            if let Some(gone) = cache.entries.remove(&oldest) {
                cache.bytes -= gone.region.len();
            }
        }
        cache.clock += 1;
        let last_use = cache.clock;
        let entry = Entry {
            region: Arc::clone(&region),
            last_use,
        };
        if let Some(previous) = cache.entries.insert(hash, entry) {
            cache.bytes -= previous.region.len();
        }
        cache.bytes += len;
        region
    }

    /// Drops every kept region (the bench's cold-read rows use it).
    pub(crate) fn clear(&self) {
        let mut cache = self.lock();
        cache.entries.clear();
        cache.bytes = 0;
    }
}
