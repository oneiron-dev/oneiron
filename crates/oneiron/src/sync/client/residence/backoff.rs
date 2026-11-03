//! Per-object fetch backoff for residence upkeep (FIX 6691, FIX 5178): an
//! object this machine cannot open yet is asked for again on a doubling
//! wait from one upkeep tick, capped at an hour, and the wait clears the
//! moment the object lands. In memory only: a restart asks once more, and
//! a key the caller stops naming is pruned by it.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use crate::world_keys::SealedBundleGeneration;

/// The first wait after a miss: one upkeep tick (the sealed relay's 300 s).
const BASE: Duration = Duration::from_secs(300);
/// The longest wait between asks for an object that never opens.
const CAP: Duration = Duration::from_secs(3600);

/// The pad-object backoff of the generation upkeep (FIX 6691).
pub(crate) type PadObjectBackoff = Backoff<SealedBundleGeneration>;

/// When each key may be asked for again.
#[derive(Default)]
pub(crate) struct Backoff<K> {
    waits: HashMap<K, (Instant, Duration)>,
}

impl<K: Eq + Hash> Backoff<K> {
    /// Whether `key` may be asked for now.
    pub(crate) fn due(&self, key: &K) -> bool {
        self.waits
            .get(key)
            .is_none_or(|(at, _)| Instant::now() >= *at)
    }

    /// `key` was asked for and did not open: the next ask waits, doubled.
    pub(crate) fn missed(&mut self, key: K) {
        let wait = self
            .waits
            .get(&key)
            .map_or(BASE, |(_, wait)| (*wait * 2).min(CAP));
        self.waits.insert(key, (Instant::now() + wait, wait));
    }

    /// `key`'s object landed and opened: ask freely again.
    pub(crate) fn landed(&mut self, key: &K) {
        self.waits.remove(key);
    }

    /// Drops every key `keep` no longer names (a generation that moved).
    pub(crate) fn retain(&mut self, keep: impl Fn(&K) -> bool) {
        self.waits.retain(|key, _| keep(key));
    }
}
