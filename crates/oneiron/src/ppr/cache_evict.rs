//! Bounded, resumable eviction of the PPR cache for a serving host.
//!
//! [`cleanup_ppr_cache`](super::cleanup_ppr_cache) walks both tables in one
//! write transaction, so it holds the writer for the whole walk. A page here
//! reads at most `limit` rows in a read transaction, then deletes the rows that
//! still qualify in a short write transaction, so a foreground write waits for
//! one page at most. The walk covers the cache rows, then the dependency rows,
//! and goes on from its cursor. A cache row that no dependency names is left
//! to age out under the hard bound rather than found by a whole-table join.

use std::ops::Bound;

use super::cache_store::{
    CACHE_DEP_KEY_LEN, SEED_HASH_LEN, decode_dep_key, parse_cache_header, seed_is_live_for_ppr,
};
use crate::error::{Error, Result};
use crate::store::Store;

/// The cursor's first byte: which table the walk is in. The rest is the last
/// key the walk read.
const PHASE_CACHE: u8 = 0;
const PHASE_DEPS: u8 = 1;

/// What one page did.
#[derive(Debug, Default)]
pub(crate) struct PprEvictionPage {
    pub(crate) evicted: u64,
    pub(crate) deps_cleaned: u64,
    /// Where the next page starts; `None` once the walk is done.
    pub(crate) cursor: Option<Vec<u8>>,
}

/// Evicts one page: cache rows that are stale-flagged, malformed or older than
/// `max_age_secs`, then dependency rows that are malformed or name a missing
/// cache row, and the cache rows of seeds that are no longer live. A cursor
/// that does not decode starts the walk over.
pub(crate) fn evict_ppr_cache_page(
    store: &Store,
    cursor: Option<&[u8]>,
    limit: usize,
    max_age_secs: u64,
    now: u64,
) -> Result<PprEvictionPage> {
    match cursor.and_then(<[u8]>::split_first) {
        Some((&PHASE_DEPS, after)) => deps_page(store, after, limit),
        Some((&PHASE_CACHE, after)) => cache_page(store, after, limit, max_age_secs, now),
        _ => cache_page(store, &[], limit, max_age_secs, now),
    }
}

fn cache_row_expired(key: &[u8], value: &[u8], max_age_secs: u64, now: u64) -> Result<bool> {
    if key.len() != SEED_HASH_LEN {
        return Ok(true);
    }
    match parse_cache_header(value) {
        Ok((computed_at, _, stale)) => {
            Ok(stale != 0 || now.saturating_sub(computed_at) > max_age_secs)
        }
        Err(Error::CorruptedIndex(_)) => Ok(true),
        Err(err) => Err(err),
    }
}

fn after_bound(after: &[u8]) -> Bound<&[u8]> {
    if after.is_empty() {
        Bound::Unbounded
    } else {
        Bound::Excluded(after)
    }
}

fn cache_page(
    store: &Store,
    after: &[u8],
    limit: usize,
    max_age_secs: u64,
    now: u64,
) -> Result<PprEvictionPage> {
    let mut expired = Vec::new();
    let mut last = None;
    let mut read = 0;
    {
        let rtxn = store.env.read_txn()?;
        let range = (after_bound(after), Bound::Unbounded);
        for row in store.ppr_cache().range(&rtxn, &range)?.take(limit) {
            let (key, value) = row?;
            read += 1;
            if cache_row_expired(&key, &value, max_age_secs, now)? {
                expired.push(key.to_vec());
            }
            last = Some(key.to_vec());
        }
    }

    let mut page = PprEvictionPage::default();
    if !expired.is_empty() {
        let mut wtxn = store.env.write_txn()?;
        for key in &expired {
            // A walk refreshed since the read keeps its row.
            let still_expired = match store.ppr_cache().get(&wtxn, key)? {
                Some(value) => cache_row_expired(key, &value, max_age_secs, now)?,
                None => false,
            };
            if still_expired && store.ppr_cache().delete(&mut wtxn, key)? {
                page.evicted += 1;
            }
        }
        wtxn.commit()?;
    }
    page.cursor = Some(match last {
        Some(last) if read == limit => [&[PHASE_CACHE], last.as_slice()].concat(),
        _ => vec![PHASE_DEPS],
    });
    Ok(page)
}

/// What a dependency row needs.
enum DepFate {
    /// Malformed, or its cache row is gone: the row goes.
    Drop,
    /// Its seed is no longer live: the seed's cache row goes with it.
    DropSeed([u8; SEED_HASH_LEN]),
}

fn dep_fate(store: &Store, txn: &heed::RoTxn<'_>, key: &[u8]) -> Result<Option<DepFate>> {
    if key.len() != CACHE_DEP_KEY_LEN {
        return Ok(Some(DepFate::Drop));
    }
    let (entity_id, seed_hash) = match decode_dep_key(key) {
        Ok(decoded) => decoded,
        Err(Error::CorruptedIndex(_)) => return Ok(Some(DepFate::Drop)),
        Err(err) => return Err(err),
    };
    if store.ppr_cache().get(txn, &seed_hash)?.is_none() {
        return Ok(Some(DepFate::Drop));
    }
    if !seed_is_live_for_ppr(store, txn, &entity_id)? {
        return Ok(Some(DepFate::DropSeed(seed_hash)));
    }
    Ok(None)
}

fn deps_page(store: &Store, after: &[u8], limit: usize) -> Result<PprEvictionPage> {
    let mut doomed = Vec::new();
    let mut last = None;
    let mut read = 0;
    {
        let rtxn = store.env.read_txn()?;
        let range = (after_bound(after), Bound::Unbounded);
        for row in store.ppr_cache_deps.range(&rtxn, &range)?.take(limit) {
            let (key, _) = row?;
            read += 1;
            if dep_fate(store, &rtxn, &key)?.is_some() {
                doomed.push(key.to_vec());
            }
            last = Some(key.to_vec());
        }
    }

    let mut page = PprEvictionPage::default();
    if !doomed.is_empty() {
        let mut wtxn = store.env.write_txn()?;
        for key in &doomed {
            // Judged again under the writer: a row a write revived since the
            // read stays.
            match dep_fate(store, &wtxn, key)? {
                Some(DepFate::Drop) => {}
                Some(DepFate::DropSeed(seed_hash)) => {
                    if store.ppr_cache().delete(&mut wtxn, &seed_hash)? {
                        page.evicted += 1;
                    }
                }
                None => continue,
            }
            if store.ppr_cache_deps.delete(&mut wtxn, key)? {
                page.deps_cleaned += 1;
            }
        }
        wtxn.commit()?;
    }
    page.cursor = match last {
        Some(last) if read == limit => Some([&[PHASE_DEPS], last.as_slice()].concat()),
        _ => None,
    };
    Ok(page)
}
