//! One read-snapshot authority evaluator shared by Vault and the batch write door.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::store::Store;
use crate::{
    HostingPrivacyPosture,
    error::{Error, Result},
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The generation belongs to the snapshot, not to the most recent process-wide
/// write. An abort discards its generation update with its authority row.
const AUTHORITY_CACHE_GENERATION: crate::side_table::SideTable<(), u64, crate::side_table::Raw> =
    crate::side_table::SideTable::new(&crate::side_table::AUTHORITY_CACHE_GENERATION);

pub(crate) fn advance_authority_cache_generation(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let next = authority_cache_generation(store, txn)?
        .checked_add(1)
        .ok_or(Error::CorruptedIndex(
            "authority cache generation exhausted",
        ))?;
    AUTHORITY_CACHE_GENERATION.put(store, txn, &(), &next)?;
    Ok(())
}

fn authority_cache_generation(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u64> {
    AUTHORITY_CACHE_GENERATION
        .get(store, txn, &())
        .map(|value| value.unwrap_or(0))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorityCacheKey {
    generation: u64,
    now_secs: u64,
    posture: HostingPrivacyPosture,
    policy: AuthorityObservationPolicy,
    /// This install's pin, read in the same snapshot: a pin write also moves
    /// the generation, and the committed-fold probe rebuilds this key.
    pin: Option<PinnedRoot>,
}

/// An immutable verified fold attached to one authority generation. The
/// caller keeps its LMDB snapshot; this handle carries no transaction or
/// mutable state, and its cheap clone shares the exact decision image.
#[derive(Clone)]
pub(crate) struct AuthorityView {
    fold: Arc<AuthorityFold>,
    generation: u64,
}

impl AuthorityView {
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
}

impl std::ops::Deref for AuthorityView {
    type Target = AuthorityFold;

    fn deref(&self) -> &Self::Target {
        &self.fold
    }
}

pub(crate) struct AuthorityCachedFold {
    key: AuthorityCacheKey,
    next_deadline_secs: Option<u64>,
    view: AuthorityView,
    /// What the fold of a later generation resumes from.
    base: Option<Arc<super::fold_resume::FoldBase>>,
}

impl AuthorityCachedFold {
    fn matches(&self, key: AuthorityCacheKey) -> bool {
        self.key.generation == key.generation
            && self.key.posture == key.posture
            && self.key.policy == key.policy
            && self.key.pin == key.pin
            && key.now_secs >= self.key.now_secs
            && self
                .next_deadline_secs
                .is_none_or(|deadline| key.now_secs < deadline)
    }
}

fn authority_cache_key(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityCacheKey> {
    let floor = AUTHORITY_FIRST_SEEN
        .get_lenient(store, txn, &authority_first_seen_clock_key())?
        .unwrap_or(0);
    Ok(AuthorityCacheKey {
        generation: authority_cache_generation(store, txn)?,
        now_secs: authority_observation_secs(store, floor, store.clock.now_recorded_at()),
        posture,
        policy: authority_observation_policy_in_txn(store, txn)?,
        pin: super::pinned_root::read_pinned_root_in_txn(store, txn)?,
    })
}

fn cached_fold(store: &Store, key: AuthorityCacheKey) -> Option<AuthorityView> {
    store.authority_fold_cache.lock().ok().and_then(|cache| {
        cache
            .as_ref()
            .filter(|cached| cached.matches(key))
            .map(|cached| cached.view.clone())
    })
}

/// `build`'s value for `txn`'s authority generation, from `cache` when it
/// holds that generation. A value is cached only when its generation is the
/// committed one, so a write that aborts never publishes it, and a
/// transaction that staged an authority row reads past the cache.
pub(super) fn per_authority_generation<T>(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    cache: &std::sync::Mutex<Option<(u64, Arc<T>)>>,
    build: impl FnOnce() -> Result<T>,
) -> Result<Arc<T>> {
    let generation = authority_cache_generation(store, txn)?;
    let cached = cache.lock().ok().and_then(|cache| {
        cache
            .as_ref()
            .filter(|(cached, _)| *cached == generation)
            .map(|(_, value)| Arc::clone(value))
    });
    if let Some(value) = cached {
        return Ok(value);
    }
    let value = Arc::new(build()?);
    // A second read txn on this thread fails with MDB_BAD_RSLOT; see
    // `cache_fold_if_committed`.
    let committed = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                store
                    .env
                    .read_txn()
                    .ok()
                    .and_then(|committed| authority_cache_generation(store, &committed).ok())
            })
            .join()
            .ok()
            .flatten()
    });
    if committed == Some(generation)
        && let Ok(mut cache) = cache.lock()
    {
        *cache = Some((generation, Arc::clone(&value)));
    }
    Ok(value)
}

fn cache_fold_if_committed(
    store: &Store,
    key: AuthorityCacheKey,
    next_deadline_secs: Option<u64>,
    view: &AuthorityView,
    base: Option<super::fold_resume::FoldBase>,
) {
    // LMDB read transactions use a thread-local reader slot. Opening a
    // second read txn on this thread while the caller's snapshot is alive
    // fails with MDB_BAD_RSLOT. Check on a separate thread: an RwTxn's
    // uncommitted generation is invisible there, so aborts never publish.
    // This costs one small committed-row probe only on a full-fold miss.
    let visible = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                store
                    .env
                    .read_txn()
                    .ok()
                    .and_then(|committed| authority_cache_key(store, key.posture, &committed).ok())
                    .is_some_and(|committed| {
                        AuthorityCachedFold {
                            key,
                            next_deadline_secs,
                            view: view.clone(),
                            base: None,
                        }
                        .matches(committed)
                    })
            })
            .join()
            .unwrap_or(false)
    });
    if visible && let Ok(mut cache) = store.authority_fold_cache.lock() {
        *cache = Some(AuthorityCachedFold {
            key,
            next_deadline_secs,
            view: view.clone(),
            base: base.map(Arc::new),
        });
    }
}

/// Folds the stored AUTHORITY_LOG inside a CALLER-OWNED read transaction.
///
/// [`Vault::authority_fold`] opens its own transactions — including a WRITE
/// txn for the first-seen clock and the sidecar backfill — so it cannot be
/// called from inside an open transaction under LMDB's single-writer rule.
/// This variant writes nothing at all: no persisted clock write, no
/// backfill, no transaction of its own. It reproduces both write-side
/// effects in its snapshot instead.
///
/// The observation time is deliberately NOT the raw wall clock. Stale-roster
/// approval expiry is an AUTHORIZATION decision here — the facade's owner-verb
/// gate consumes this fold — so it runs on the same monotonic clock
/// [`Vault::authority_fold`] uses: the persisted floor read through `txn`,
/// raised through [`authority_observation_secs`]. On the raw wall clock a jump
/// backward below the persisted floor would revive an approval whose
/// stale-roster window had already expired. The derived value is not written
/// back — the floor advances only on write paths. No op waits on this clock:
/// the delayed-widen ceremony died 2026-08-05 (identity canon, "Device-key
/// widen ceremony (dead 2026-08-05)").
///
/// The other divergence the full fold hides is a MISSING sidecar — see
/// [`readonly_first_seen_for`] for how this fold reproduces the one-shot
/// migration without writing, and when it refuses instead.
pub(crate) fn authority_fold_readonly_for_store_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityFold> {
    Ok((*authority_view_readonly_for_store_in_txn(store, posture, txn)?).clone())
}

/// Cheap, snapshot-bound view for hot authorization callers. Cloning it only
/// increments an Arc; owned fold callers retain the compatible full value.
pub(super) fn authority_view_readonly_for_store_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityView> {
    let key = authority_cache_key(store, posture, txn)?;
    if let Some(fold) = cached_fold(store, key) {
        tracing::trace!(target: "oneiron::authority::cache", generation = fold.generation(), "exact authority fold cache hit");
        return Ok(fold);
    }
    // A miss resumes from the last committed generation's fold where it can.
    let base = store
        .authority_fold_cache
        .lock()
        .ok()
        .and_then(|cache| cache.as_ref().and_then(|cached| cached.base.clone()));
    let (view, next_deadline_secs, base) =
        fold_view_for_key(store, posture, txn, key, base.as_deref())?;
    cache_fold_if_committed(store, key, next_deadline_secs, &view, base);
    Ok(view)
}

/// This vault's own log folded as an install pinned to `pin` would fold it,
/// in the caller's snapshot: what a pin door compares before it moves the
/// pin, and the read under another admitter. Never cached, so the cached
/// view stays the stored pin's.
pub(super) fn authority_view_under_pin_for_store_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    pin: Option<PinnedRoot>,
) -> Result<AuthorityView> {
    let key = AuthorityCacheKey {
        pin,
        ..authority_cache_key(store, posture, txn)?
    };
    Ok(fold_view_for_key(store, posture, txn, key, None)?.0)
}

/// The full fold behind `key`, resumed from `base` where it can be, the next
/// stale-roster deadline it holds, and the base for the next generation.
fn fold_view_for_key(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    key: AuthorityCacheKey,
    base: Option<&super::fold_resume::FoldBase>,
) -> Result<(
    AuthorityView,
    Option<u64>,
    Option<super::fold_resume::FoldBase>,
)> {
    tracing::trace!(target: "oneiron::authority::cache", generation = key.generation, "full authority fold fallback");
    let mut first_seen_at_secs = BTreeMap::new();
    // Read once: all entries in this fold share one snapshot clock and marker.
    let backfilled = AUTHORITY_FIRST_SEEN_BACKFILLED.contains(
        store,
        txn,
        &authority_first_seen_backfill_key(),
    )?;
    let now_secs = key.now_secs;

    let entries = authority_log_rows_in_txn(store, txn)?
        .into_iter()
        .map(|(_, body)| decode_authority_log_entry_body(&body))
        .collect::<Result<Vec<_>>>()?;
    for entry in &entries {
        let hash = authority_entry_hash(entry)?;
        let first_seen = readonly_first_seen_for(store, txn, &hash, backfilled, now_secs)?;
        first_seen_at_secs.insert(hash, first_seen);
    }
    // Peer consent roots ride BOTH folds. This one authorizes, and a fold
    // used for authorization must never be weaker OR stronger than the one
    // used for truth: omitting them here would silently reject a lifecycle
    // entry the full fold accepts.
    let peer_consent_roots =
        crate::federation::admitted_peer_consent_roots_for_store_in_txn(store, txn)?;
    let observations = authority_local_observations_in_txn(store, txn, &entries)?;
    let (fold, base) = super::fold_resume::fold_stored_log(
        super::fold_resume::StoredLog {
            entries: &entries,
            first_seen_at_secs: &first_seen_at_secs,
            now_secs,
            peer_consent_roots: &peer_consent_roots,
            observations: &observations,
            posture,
            pin: key.pin.as_ref(),
        },
        base,
    );
    // The fold's only clock-sensitive transition is stale-roster approval
    // expiry, here and in the fold with no vouch that bounds this install's
    // view. Slip TTL is checked by each caller against its own snapshot
    // clock, not frozen into this authority view.
    let next_deadline_secs = next_stale_roster_deadline(
        &entries,
        &fold,
        &first_seen_at_secs,
        now_secs,
        key.policy.stale_roster_window_secs,
    )
    .into_iter()
    .chain(fold.install.no_vouch_deadline)
    .min();
    let view = AuthorityView {
        fold: Arc::new(fold),
        generation: key.generation,
    };
    Ok((view, next_deadline_secs, base))
}

/// First-seen seconds for ONE entry inside a readonly fold, reproducing the
/// one-shot migration's semantics without writing anything. The value feeds
/// only the stale-roster approval window.
///
/// Two states, two answers:
///
/// - backfill marker ABSENT — the migration has not run in a write txn yet,
///   so this vault has NO local record of when it first saw the row. The
///   header's `learned_at` is not a substitute: it is peer-written entity
///   metadata, and a claim of `learned_at = 0` would start a stale-roster
///   window in 1970. The answer is `now_secs` — the same value
///   [`Vault::backfill_authority_first_seen_sidecars`] will persist when it
///   next runs.
/// - marker PRESENT and the sidecar still missing, or the row present but
///   undecodable under EITHER marker state — the one-shot pass can never
///   regenerate it (it is gated by the marker, and it skips keys that
///   already hold a row), so the entry's stale-roster clock is unrecoverable
///   in place. Omitting the entry is not fail-closed: an approval with no
///   first-seen time never expires. Refuse the fold with
///   [`AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT`]; the facade turns that into an
///   invalid-state suspension of owner verbs rather than authorizing on a
///   fold it cannot compute.
fn readonly_first_seen_for(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    hash: &AuthorityEntryHash,
    backfilled: bool,
    now_secs: u64,
) -> Result<u64> {
    let corrupt = || Error::CorruptedIndex(AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT);
    // A decode failure (present but undecodable) and an absent row both surface as `Err`/`Ok`
    // here without distinguishing the LMDB-level case from the shape case, unlike the
    // pre-migration hand decode; in practice the only way to reach a non-8-byte row is exactly
    // the corruption this maps to.
    match AUTHORITY_FIRST_SEEN.get(store, txn, &authority_first_seen_sidecar_key(hash)) {
        Ok(Some(secs)) => Ok(secs),
        Ok(None) if backfilled => Err(corrupt()),
        Ok(None) => Ok(now_secs),
        Err(_) => Err(corrupt()),
    }
}

pub(super) fn authority_log_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(crate::EntityId, Vec<u8>)>> {
    let mut rows = Vec::new();
    for row in store.port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)? {
        let id = row?;
        let raw = store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::CorruptedIndex("type index row without entity"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Err(Error::CorruptedIndex("type index row kind mismatch"));
        }
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        rows.push((id, body.to_vec()));
    }
    Ok(rows)
}
