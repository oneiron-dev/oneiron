//! One read-snapshot authority evaluator shared by Vault and the batch write door.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::store::Store;
use crate::{
    HostingPrivacyPosture,
    error::{Error, RecordError, Result},
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

mod adopted;
mod arriving;
mod held_rows;
mod row_receipts;
#[cfg(feature = "sync")]
mod stored_records;

pub(super) use adopted::adopted_history_request_in_txn;
use adopted::fold_adopted_in_txn;
pub(super) use arriving::{ArrivingFold, authority_view_with_rows_for_store_in_txn};
use held_rows::HeldRows;
use row_receipts::RowReceipts;
#[cfg(feature = "sync")]
pub(crate) use stored_records::folded_vault_id_of_records;

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

pub(crate) fn authority_cache_generation(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u64> {
    AUTHORITY_CACHE_GENERATION
        .get(store, txn, &())
        .map(|value| value.unwrap_or(0))
}

/// How many key events changed which sealed rows open here (census L5-22
/// 1a-iii). A later generation's fold resumes from a cached base only when
/// both were folded at the same count: a base that counted a row as open
/// never resumes past its subject's retirement.
const AUTHORITY_OVERLAY_OPENNESS_EPOCH: crate::side_table::SideTable<
    (),
    u64,
    crate::side_table::Raw,
> = crate::side_table::SideTable::new(&crate::side_table::AUTHORITY_OVERLAY_OPENNESS_EPOCH);

fn authority_overlay_openness_epoch(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u64> {
    AUTHORITY_OVERLAY_OPENNESS_EPOCH
        .get(store, txn, &())
        .map(|value| value.unwrap_or(0))
}

/// Notes in `txn` that a key event changed which sealed rows open here (a
/// key installed, a subject retired): the openness epoch and the authority
/// cache generation move together, so no cached fold answers past it and no
/// later fold resumes from a base folded before it.
pub(crate) fn note_authority_overlay_openness_change_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let next = authority_overlay_openness_epoch(store, txn)?
        .checked_add(1)
        .ok_or(Error::CorruptedIndex(
            "authority overlay openness epoch exhausted",
        ))?;
    AUTHORITY_OVERLAY_OPENNESS_EPOCH.put(store, txn, &(), &next)?;
    advance_authority_cache_generation(store, txn)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorityCacheKey {
    generation: u64,
    /// The overlay openness epoch read in the same snapshot (census L5-22
    /// 1a-iii): it moves only with the generation, and gates resumption.
    openness_epoch: u64,
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
    /// The pacts this install holds inactive because their folded scope
    /// does not match the commitment under its live opening (FIX 11730,
    /// [`super::pact_openings`]).
    scope_commitment_mismatches: Arc<BTreeSet<[u8; 32]>>,
}

impl AuthorityView {
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    /// What `txn` holds over this view's signed log (FIX 22382): each
    /// agent-carried act whose Grant it holds refused (contract §4, FIX
    /// 4624, FIX 5660, [`super::carried_act`]), and each pact whose folded
    /// scope does not match its signed commitment under the live opening it
    /// holds (FIX 11730, [`super::pact_openings`]). Neither row moves the
    /// authority generation, so every read judges them in its own snapshot,
    /// a cache hit as a miss. `preserved_world_acts` answers the
    /// past-standing check of the refused world acts (FIX 4703), which reads
    /// the signed log alone. `memo` is what earlier reads of this view kept
    /// (FIX 23233): the last pact-opening answer, taken while `txn` reads
    /// the same opening rows, and the unread rows already logged.
    fn live_overlay(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        use_past_standing: bool,
        preserved_world_acts: impl FnOnce(&[AuthorityEntryHash]) -> Result<BTreeSet<AuthorityEntryHash>>,
        memo: &mut OverlayMemo,
    ) -> LiveOverlay {
        LiveOverlay {
            refused: super::carried_act::grant_refused_agent_acts(
                store,
                txn,
                &self.fold,
                use_past_standing,
                preserved_world_acts,
                &mut memo.logged,
            ),
            mismatched: super::pact_openings::scope_commitment_mismatches(
                store,
                txn,
                &self.fold,
                &mut memo.openings,
                &mut memo.logged,
            ),
        }
    }

    /// This view with `overlay` applied: each refused act held back, and
    /// each mismatched pact held inactive. The two touch disjoint parts of
    /// the fold. With neither, the view as it was.
    fn overlaid(self, overlay: &LiveOverlay) -> Self {
        if overlay.is_empty() {
            return self;
        }
        let mut fold = (*self.fold).clone();
        if !overlay.refused.is_empty() {
            super::carried_act::hold_back_agent_acts(&mut fold, &overlay.refused);
        }
        if overlay.mismatched.is_empty() {
            return Self {
                fold: Arc::new(fold),
                ..self
            };
        }
        super::pact_openings::hold_mismatched_pacts(&mut fold, &overlay.mismatched);
        Self {
            fold: Arc::new(fold),
            scope_commitment_mismatches: Arc::new(overlay.mismatched.clone()),
            ..self
        }
    }

    /// This view as `txn` reads it ([`Self::live_overlay`]), with nothing
    /// kept from or for another read: a view no cache holds.
    fn with_live_overlays(
        self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        use_past_standing: bool,
    ) -> Self {
        let overlay = self.live_overlay(
            store,
            txn,
            use_past_standing,
            |candidates| {
                super::past_grant_standing::preserved_world_acts(store, txn, &self.fold, candidates)
            },
            &mut OverlayMemo::default(),
        );
        self.overlaid(&overlay)
    }

    /// The pacts this install holds inactive for a scope commitment
    /// mismatch (FIX 11730): what a federation status reports as
    /// `scope_commitment_mismatch`.
    pub(crate) fn scope_commitment_mismatches(&self) -> &BTreeSet<[u8; 32]> {
        &self.scope_commitment_mismatches
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
    /// The signed log's fold alone, before any overlay a caller's snapshot
    /// judges (FIX 22382): a Grant's standing and a pact's live opening are
    /// rows no authority generation counts, so a hit applies them again
    /// ([`AuthorityView::live_overlay`]).
    view: AuthorityView,
    /// What the fold of a later generation resumes from.
    continuation: Option<Arc<AuthorityContinuation>>,
    /// The last view a hit made of `view` and the overlay it applied: a
    /// later hit whose snapshot reads the same overlay takes it instead of
    /// copying the fold again.
    overlaid: Option<(LiveOverlay, AuthorityView)>,
    /// The past-standing answer (FIX 4703) the last hit computed over
    /// `view`, with the NOW-refused world acts it was asked about. It reads
    /// the signed log alone (the held rows, the adopted image, causal
    /// points), so it holds for every snapshot of `key`'s generation; the
    /// Grant rows that choose those acts are read again on each hit.
    preserved_world_acts: Option<(Vec<AuthorityEntryHash>, BTreeSet<AuthorityEntryHash>)>,
    /// What the reads of `view` keep between them (FIX 23233): the last
    /// pact-opening answer, and the unread rows already logged at `key`'s
    /// generation.
    memo: OverlayMemo,
}

/// What the reads of one cached fold keep between them beside its view
/// (FIX 23233).
#[derive(Clone, Default)]
struct OverlayMemo {
    /// The last pact-opening answer, with the opening rows it was read
    /// under ([`super::pact_openings::scope_commitment_mismatches`]).
    openings: Option<super::pact_openings::OpeningAnswer>,
    logged: UnreadLogged,
}

/// The rows a fold's reads have logged as unread (FIX 23233): each agent
/// act's Grant and each pact's opening that did not read is logged once per
/// cached fold of an authority generation, not on every read. Every clone
/// shares one set, so concurrent reads of one cached fold log a row once
/// between them.
#[derive(Clone, Default)]
pub(super) struct UnreadLogged {
    rows: Arc<Mutex<UnreadRows>>,
}

/// The rows [`UnreadLogged`] has logged.
#[derive(Default)]
struct UnreadRows {
    grants: BTreeSet<AuthorityEntryHash>,
    openings: BTreeSet<[u8; 32]>,
}

impl UnreadLogged {
    /// Whether the unread Grant of the act at `entry` is to be logged now:
    /// the first time any read of this fold meets it.
    pub(super) fn first_grant(&self, entry: AuthorityEntryHash) -> bool {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .grants
            .insert(entry)
    }

    /// Whether pact `pact_id`'s unread opening is to be logged now: the
    /// first time any read of this fold meets it.
    pub(super) fn first_opening(&self, pact_id: [u8; 32]) -> bool {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .openings
            .insert(pact_id)
    }
}

/// The rows a caller's snapshot holds over a signed-log view
/// ([`AuthorityView::live_overlay`]).
#[derive(Clone, PartialEq, Eq)]
struct LiveOverlay {
    refused: Vec<AuthorityEntryHash>,
    mismatched: BTreeSet<[u8; 32]>,
}

impl LiveOverlay {
    fn is_empty(&self) -> bool {
        self.refused.is_empty() && self.mismatched.is_empty()
    }
}

/// A successful local-checkpoint coverage check, carried only in this cache.
#[derive(Clone, Copy)]
struct CheckpointCoverageProof {
    /// The head at which every covered hash was held. `None` proves that no
    /// checkpoint head existed then.
    head: Option<[u8; 32]>,
}

/// What a later generation's fold resumes from (OF-469): the last committed
/// fold's base, and the store id of each row it folded, so that fold reads
/// only the stored rows past it. It lives in this cache alone and reopens
/// empty: no row, checkpoint or format carries it.
pub(crate) struct AuthorityContinuation {
    base: super::fold_resume::FoldBase,
    /// Persistent, so the next continuation shares it and adds only the
    /// tail's (FIX 12308).
    ids: im::OrdMap<crate::EntityId, AuthorityEntryHash>,
    /// The highest store-order sequence this fold read (FIX 12369), where
    /// the fold read the whole stored log under a complete store-order
    /// index: its `ids` are then exactly the rows sequenced up to it, and
    /// the next fold range-scans only the rows past it. None where the
    /// index cannot vouch for that (an adopted image's fold, an incomplete
    /// index): the next fold takes the type-index scan.
    max_seq: Option<u64>,
    /// The last successful checkpoint coverage check. An unchanged head and
    /// a whole indexed baseline let the next fold reuse it instead of
    /// decoding every covered hash again.
    checkpoint_coverage: Option<CheckpointCoverageProof>,
}

impl AuthorityContinuation {
    fn of(
        base: super::fold_resume::FoldBase,
        max_seq: Option<u64>,
        checkpoint_coverage: CheckpointCoverageProof,
    ) -> Option<Self> {
        let ids = base
            .hashes()
            .map(|hash| Some((authority_log_entity_id_from_hash(hash).ok()?, *hash)))
            .collect::<Option<_>>()?;
        Some(Self {
            base,
            ids,
            max_seq,
            checkpoint_coverage: Some(checkpoint_coverage),
        })
    }

    /// [`Self::of`] for `base`, resumed from `baseline` past `tail`: only
    /// the tail's rows map anew (FIX 12282), into the baseline's shared map.
    fn past<'a>(
        baseline: &'a Self,
        base: super::fold_resume::FoldBase,
        tail: impl IntoIterator<Item = &'a AuthorityEntryHash>,
        max_seq: Option<u64>,
        checkpoint_coverage: CheckpointCoverageProof,
    ) -> Option<Self> {
        let mut ids = baseline.ids.clone();
        for hash in tail {
            ids.insert(authority_log_entity_id_from_hash(hash).ok()?, *hash);
        }
        Some(Self {
            base,
            ids,
            max_seq,
            checkpoint_coverage: Some(checkpoint_coverage),
        })
    }
}

/// The stored log's fold past a continuation.
enum AuthorityTailFold {
    /// The fold, the next stale-roster deadline it holds, and what the next
    /// generation's fold resumes from.
    Complete {
        view: AuthorityView,
        next_deadline_secs: Option<u64>,
        continuation: Option<AuthorityContinuation>,
    },
    /// History the fold needs and this vault does not hold: no fold answers.
    NeedHistory(AuthorityHistoryRequest),
}

impl AuthorityCachedFold {
    fn matches(&self, key: AuthorityCacheKey) -> bool {
        self.key.generation == key.generation
            && self.key.openness_epoch == key.openness_epoch
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
    // A damaged floor is no reading from zero (FIX 10106).
    let now_secs = authority_clock_reading_in_txn(store, txn, store.clock.now_recorded_at())?;
    Ok(AuthorityCacheKey {
        generation: authority_cache_generation(store, txn)?,
        openness_epoch: authority_overlay_openness_epoch(store, txn)?,
        now_secs,
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
    continuation: Option<AuthorityContinuation>,
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
                            continuation: None,
                            overlaid: None,
                            preserved_world_acts: None,
                            memo: OverlayMemo::default(),
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
            continuation: continuation.map(Arc::new),
            overlaid: None,
            preserved_world_acts: None,
            memo: OverlayMemo::default(),
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
pub(crate) fn authority_view_readonly_for_store_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityView> {
    let key = authority_cache_key(store, posture, txn)?;
    let use_past_standing = posture == store.privacy_posture;
    if let Some(fold) = cached_fold(store, key) {
        tracing::trace!(target: "oneiron::authority::cache", generation = fold.generation(), "exact authority fold cache hit");
        return Ok(apply_live_overlay(store, txn, key, fold, use_past_standing));
    }
    // A miss resumes from the last committed generation's fold where it can.
    let continuation = resumable_continuation(store, key.generation, key.openness_epoch);
    let (view, next_deadline_secs, continuation) =
        fold_view_for_key(store, posture, txn, key, continuation.as_deref())?;
    cache_fold_if_committed(store, key, next_deadline_secs, &view, continuation);
    // The miss's own read fills what the next hit takes (FIX 23233).
    Ok(apply_live_overlay(store, txn, key, view, use_past_standing))
}

/// The signed-log `view` behind `key` as `txn` reads it: the view the last
/// read made when `txn` reads the same overlay, else a new one. While the
/// cache holds `key`'s fold, what this read computed is kept there for the
/// next one: the overlaid view, the past-standing answer and the
/// [`OverlayMemo`].
fn apply_live_overlay(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: AuthorityCacheKey,
    view: AuthorityView,
    use_past_standing: bool,
) -> AuthorityView {
    let mut memo = store
        .authority_fold_cache
        .lock()
        .ok()
        .and_then(|cache| {
            cache
                .as_ref()
                .filter(|cached| cached.matches(key))
                .map(|cached| cached.memo.clone())
        })
        .unwrap_or_default();
    let overlay = view.live_overlay(
        store,
        txn,
        use_past_standing,
        |candidates| {
            let cached = store.authority_fold_cache.lock().ok().and_then(|cache| {
                cache
                    .as_ref()
                    .filter(|cached| cached.matches(key))
                    .and_then(|cached| cached.preserved_world_acts.as_ref())
                    .filter(|(asked, _)| asked.as_slice() == candidates)
                    .map(|(_, preserved)| preserved.clone())
            });
            if let Some(preserved) = cached {
                return Ok(preserved);
            }
            let preserved = super::past_grant_standing::preserved_world_acts(
                store, txn, &view.fold, candidates,
            )?;
            if let Ok(mut cache) = store.authority_fold_cache.lock()
                && let Some(cached) = cache.as_mut()
                && cached.matches(key)
            {
                cached.preserved_world_acts = Some((candidates.to_vec(), preserved.clone()));
            }
            Ok(preserved)
        },
        &mut memo,
    );
    if let Ok(mut cache) = store.authority_fold_cache.lock()
        && let Some(cached) = cache.as_mut()
        && cached.matches(key)
    {
        cached.memo = memo;
    }
    if overlay.is_empty() {
        return view;
    }
    let reused = store.authority_fold_cache.lock().ok().and_then(|cache| {
        cache
            .as_ref()
            .filter(|cached| cached.matches(key))
            .and_then(|cached| cached.overlaid.as_ref())
            .filter(|(made_from, _)| *made_from == overlay)
            .map(|(_, made)| made.clone())
    });
    if let Some(made) = reused {
        return made;
    }
    let made = view.overlaid(&overlay);
    if let Ok(mut cache) = store.authority_fold_cache.lock()
        && let Some(cached) = cache.as_mut()
        && cached.matches(key)
    {
        cached.overlaid = Some((overlay, made.clone()));
    }
    made
}

/// The cached continuation a fold at `generation` may resume from: only one
/// folded at that generation or an earlier one. A snapshot older than the
/// cached fold lacks rows that fold read, and would be refused as missing
/// history it never lost. A fold at another overlay openness epoch (census
/// L5-22 1a-iii) folds whole: the base judged rows a key event since
/// opened or closed.
fn resumable_continuation(
    store: &Store,
    generation: u64,
    openness_epoch: u64,
) -> Option<Arc<AuthorityContinuation>> {
    store.authority_fold_cache.lock().ok().and_then(|cache| {
        cache
            .as_ref()
            .filter(|cached| {
                cached.key.generation <= generation && cached.key.openness_epoch == openness_epoch
            })
            .and_then(|cached| cached.continuation.clone())
    })
}

/// The rows the continuation a fold in `txn` would resume from has folded:
/// a fold refuses as missing history any of them `txn` does not hold.
pub(super) fn resumed_hashes_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<AuthorityEntryHash>> {
    let generation = authority_cache_generation(store, txn)?;
    let openness_epoch = authority_overlay_openness_epoch(store, txn)?;
    Ok(resumable_continuation(store, generation, openness_epoch)
        .map(|continuation| continuation.ids.values().copied().collect())
        .unwrap_or_default())
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
    // Causal grant points use the installed pin, not this proposed pin.
    Ok(fold_view_for_key(store, posture, txn, key, None)?
        .0
        .with_live_overlays(store, txn, false))
}

/// The full fold behind `key`, resumed past `baseline` where it can be, the
/// next stale-roster deadline it holds, and what the next generation
/// resumes from. The view is the signed log's alone: the caller applies
/// [`AuthorityView::live_overlay`] in its own snapshot. History the vault
/// no longer holds fails closed: no fold, and the typed refusal names the
/// fold's request
/// ([`RecordError::AuthorityHistoryRequired`]);
/// [`Vault::authority_history_request`] names the same hashes.
fn fold_view_for_key(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    key: AuthorityCacheKey,
    baseline: Option<&AuthorityContinuation>,
) -> Result<(AuthorityView, Option<u64>, Option<AuthorityContinuation>)> {
    match fold_authority_checkpoint_tail_in_txn(
        store,
        posture,
        txn,
        key,
        baseline,
        &BTreeSet::new(),
        &BTreeMap::new(),
    )? {
        AuthorityTailFold::Complete {
            view,
            next_deadline_secs,
            continuation,
        } => Ok((view, next_deadline_secs, continuation)),
        AuthorityTailFold::NeedHistory(request) => Err(history_required(&request)),
    }
}

/// What a fold refuses with when it needs history this vault does not hold
/// (OF-469): the request's vault, checkpoint and missing hashes, ascending.
/// Every refusal for missing authority history is this one error.
pub(super) fn history_required(request: &AuthorityHistoryRequest) -> Error {
    Error::Record(RecordError::AuthorityHistoryRequired {
        vault_id: request.vault_id,
        checkpoint: request.checkpoint,
        missing: request.missing.iter().copied().collect(),
    })
}

/// Whether `error` is a fold's refusal for history this vault does not hold,
/// which an import of that history may close, rather than a fault.
pub(crate) fn is_history_incomplete(error: &Error) -> bool {
    matches!(
        error,
        Error::Record(RecordError::AuthorityHistoryRequired { .. })
    )
}

/// The request a fold's or door's refusal for missing history names
/// ([`history_required`]); None for any other error.
pub(super) fn history_required_request(error: &Error) -> Option<AuthorityHistoryRequest> {
    match error {
        Error::Record(RecordError::AuthorityHistoryRequired {
            vault_id,
            checkpoint,
            missing,
        }) => Some(AuthorityHistoryRequest {
            vault_id: *vault_id,
            checkpoint: *checkpoint,
            missing: missing.iter().copied().collect(),
        }),
        _ => None,
    }
}

/// [`fold_stored_tail_in_txn`] for this vault's own log. The withdrawal's
/// signed `SlipGrantRevoke` tombstones guest slips under that grant,
/// including one merged after withdrawal, from any replica (FIX-LIST 1978).
/// It reaches cached and uncached views, continuation bases and checkpoint
/// images through that same signed log.
fn fold_authority_checkpoint_tail_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    key: AuthorityCacheKey,
    baseline: Option<&AuthorityContinuation>,
    required: &BTreeSet<AuthorityEntryHash>,
    arriving: &BTreeMap<AuthorityEntryHash, FoldRow>,
) -> Result<AuthorityTailFold> {
    fold_stored_tail_in_txn(store, posture, txn, key, baseline, required, arriving)
}

/// The stored log's fold behind `key` past `baseline` (OF-469). The rows the
/// baseline folded are not read again: only the stored rows past it are
/// decoded and verified, and the fold resumes from the baseline where its
/// guards let it, else folds the whole stored log. When a row the baseline
/// folded, a row the local checkpoint covers or a `required` row is not
/// stored here, no fold answers: the request names each, with every parent
/// a stored row names and no stored row is, so one fetch closes each gap
/// known so far. A gap below a stored row alone is no such miss: the fold
/// holds the rows above it invalid, as it always has.
///
/// A vault that adopted a checkpoint image folds from that image instead
/// ([`fold_adopted_in_txn`]), and never folds the rows it holds in its
/// place: only once it holds every covered row does the stored log fold
/// whole again, where the image cannot answer.
///
/// Each `arriving` row folds as a stored row first seen now, though it is
/// not stored (FIX 2535): what a door judges an arriving row against, never
/// cached.
fn fold_stored_tail_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    key: AuthorityCacheKey,
    baseline: Option<&AuthorityContinuation>,
    required: &BTreeSet<AuthorityEntryHash>,
    arriving: &BTreeMap<AuthorityEntryHash, FoldRow>,
) -> Result<AuthorityTailFold> {
    if let Some(adopted) =
        super::checkpoint_adopt::cached_adopted_authority_checkpoint_in_txn(store, txn)?
        && let Some(fold) = fold_adopted_in_txn(
            store,
            posture,
            txn,
            key,
            adopted.as_ref(),
            required,
            arriving,
        )?
    {
        return Ok(fold);
    }
    // The baseline's rows are counted, not inserted (FIX 12331).
    let mut tail = Vec::new();
    let mut held = HeldRows::scan_in_txn(store, txn, baseline, &mut tail)?;
    let mut unstored = Vec::new();
    for (hash, row) in arriving {
        if held.insert(*hash) {
            tail.push((*hash, row.clone()));
            unstored.push(row.clone());
        }
    }
    let checkpoint_head = super::checkpoint::checkpoint_head_in_txn(store, txn)?;
    // A previous fold proved every hash covered by this same head was held.
    // Reuse that proof only when the indexed baseline is whole; any doubt
    // reads the coverage set exactly as before.
    let coverage_proven = baseline
        .and_then(|baseline| baseline.checkpoint_coverage)
        .is_some_and(|proof| proof.head == checkpoint_head)
        && held.holds_baseline();
    let checkpoint = if coverage_proven {
        None
    } else {
        super::checkpoint::checkpoint_head_coverage_in_txn(store, txn)?
    };
    // Each row a fold names is held: the baseline's by its count, every
    // other one by hash.
    let named_held = held.holds_baseline()
        && required
            .iter()
            .chain(checkpoint.iter().flat_map(|(_, covered)| covered))
            .all(|hash| held.contains(hash));
    if !named_held {
        let mut named = required.clone();
        if let Some((_, covered)) = &checkpoint {
            named.extend(covered.iter().copied());
        }
        if let Some(baseline) = baseline {
            named.extend(baseline.ids.values().copied());
        }
        let baseline_parents = baseline
            .into_iter()
            .flat_map(|baseline| baseline.base.parents())
            .filter(|(hash, _)| held.contains(hash))
            .flat_map(|(_, parents)| parents.iter().copied());
        let tail_parents = tail
            .iter()
            .flat_map(|(_, row)| row.parent_hashes().iter().copied());
        named.extend(baseline_parents.chain(tail_parents));
        named.retain(|hash| !held.contains(hash));
        return Ok(AuthorityTailFold::NeedHistory(AuthorityHistoryRequest {
            vault_id: baseline
                .and_then(|baseline| baseline.base.vault_id())
                .or_else(|| tail.iter().find_map(|(_, row)| row.vault_id())),
            checkpoint: checkpoint.map(|(head, _)| head).or(checkpoint_head),
            missing: named,
        }));
    }
    // Read once: all entries in this fold share one snapshot clock and marker.
    let backfilled = AUTHORITY_FIRST_SEEN_BACKFILLED.contains(
        store,
        txn,
        &authority_first_seen_backfill_key(),
    )?;
    let now_secs = key.now_secs;
    // Peer consent roots ride BOTH folds. This one authorizes, and a fold
    // used for authorization must never be weaker OR stronger than the one
    // used for truth: omitting them here would silently reject a lifecycle
    // entry the full fold accepts.
    let peer_consent_roots =
        crate::federation::admitted_peer_consent_roots_for_store_in_txn(store, txn)?;
    if let Some(baseline) = baseline {
        tracing::trace!(target: "oneiron::authority::cache", generation = key.generation, rows = tail.len(), "authority fold past the cached base");
        let tail: Vec<_> = tail.iter().map(|(hash, row)| (*hash, row)).collect();
        // Only the tail's receipts and an unpinned base row's are read, and
        // only those rows are visited (FIX 1854, FIX 12282).
        let receipts = RowReceipts::past_base_in_txn(
            store,
            txn,
            &baseline.base,
            &tail,
            arriving,
            backfilled,
            now_secs,
        )?;
        if let Some((fold, base)) = super::fold_resume::fold_stored_tail(
            super::fold_resume::StoredTail {
                tail: &tail,
                first_seen_at_secs: &receipts.first_seen_at_secs,
                now_secs,
                peer_consent_roots: &peer_consent_roots,
                observations: &receipts.observations,
                pinned: &receipts.pinned,
                posture,
                pin: key.pin.as_ref(),
            },
            &baseline.base,
        ) {
            // The base's first-seen seconds are every row's, the carried too.
            let next_deadline_secs = next_deadline(
                &fold,
                base.stale_roster_deadline(
                    &fold,
                    key.now_secs,
                    key.policy.stale_roster_window_secs,
                ),
            );
            return Ok(AuthorityTailFold::Complete {
                view: AuthorityView {
                    fold: Arc::new(fold),
                    generation: key.generation,
                    scope_commitment_mismatches: Arc::default(),
                },
                next_deadline_secs,
                continuation: AuthorityContinuation::past(
                    baseline,
                    base,
                    tail.iter().map(|(hash, _)| hash),
                    if baseline.max_seq.is_some() {
                        super::store_order::complete_max_in_txn(store, txn)?
                    } else {
                        None
                    },
                    CheckpointCoverageProof {
                        head: checkpoint_head,
                    },
                ),
            });
        }
    }
    tracing::trace!(target: "oneiron::authority::cache", generation = key.generation, "full authority fold fallback");
    let mut stored = authority_log_rows_in_txn(store, txn)?
        .into_iter()
        .map(|(_, body)| decode_stored_authority_fold_row(store, txn, &body))
        .collect::<Result<Vec<_>>>()?;
    stored.extend(unstored);
    let mut rows = Vec::with_capacity(stored.len());
    for row in &stored {
        let hash = row.hash()?;
        rows.push(super::fold_resume::RowMeta::of_row(Some(hash), row));
    }
    let RowReceipts {
        first_seen_at_secs,
        observations,
        pinned,
    } = RowReceipts::read_in_txn(store, txn, &rows, arriving, backfilled, now_secs)?;
    let (fold, base) = super::fold_resume::fold_stored_log(
        super::fold_resume::StoredLog {
            entries: &stored,
            first_seen_at_secs: &first_seen_at_secs,
            now_secs,
            peer_consent_roots: &peer_consent_roots,
            observations: &observations,
            posture,
            pin: key.pin.as_ref(),
        },
        None,
    );
    // The stale-roster window reads approvals alone: a row that passes
    // through holds none, so only the rows that opened reach it.
    let open: Vec<_> = stored.iter().filter_map(FoldRow::open).collect();
    let next_deadline_secs = next_deadline(
        &fold,
        next_stale_roster_deadline(
            &open,
            &fold,
            &first_seen_at_secs,
            key.now_secs,
            key.policy.stale_roster_window_secs,
        ),
    );
    let max_seq = super::store_order::complete_max_in_txn(store, txn)?;
    Ok(AuthorityTailFold::Complete {
        view: AuthorityView {
            fold: Arc::new(fold),
            generation: key.generation,
            scope_commitment_mismatches: Arc::default(),
        },
        next_deadline_secs,
        continuation: base.map(|base| base.with_pinned(pinned)).and_then(|base| {
            AuthorityContinuation::of(
                base,
                max_seq,
                CheckpointCoverageProof {
                    head: checkpoint_head,
                },
            )
        }),
    })
}

/// The next second `fold` changes on its own, with `stale_roster` the next
/// stale-roster deadline of its rows. The fold's only clock-sensitive
/// transition is stale-roster approval expiry, here and in the fold with no
/// vouch that bounds this install's view. Slip TTL is checked by each caller
/// against its own snapshot clock, not frozen into this authority view.
fn next_deadline(fold: &AuthorityFold, stale_roster: Option<u64>) -> Option<u64> {
    stale_roster
        .into_iter()
        .chain(fold.install.no_vouch_deadline)
        .min()
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
    Ok(readonly_first_seen_receipt(store, txn, hash, backfilled)?.unwrap_or(now_secs))
}

/// [`readonly_first_seen_for`]'s sidecar seconds: None where the marker is
/// absent and no sidecar holds the row, so the answer is the clock's.
fn readonly_first_seen_receipt(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    hash: &AuthorityEntryHash,
    backfilled: bool,
) -> Result<Option<u64>> {
    let corrupt = || Error::CorruptedIndex(AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT);
    // A decode failure (present but undecodable) and an absent row both surface as `Err`/`Ok`
    // here without distinguishing the LMDB-level case from the shape case, unlike the
    // pre-migration hand decode; in practice the only way to reach a non-8-byte row is exactly
    // the corruption this maps to.
    match AUTHORITY_FIRST_SEEN.get(store, txn, &authority_first_seen_sidecar_key(hash)) {
        Ok(Some(secs)) => Ok(Some(secs)),
        Ok(None) if backfilled => Err(corrupt()),
        Ok(None) => Ok(None),
        Err(_) => Err(corrupt()),
    }
}

pub(super) fn authority_log_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(crate::EntityId, Vec<u8>)>> {
    authority_log_ids_in_txn(store, txn)?
        .into_iter()
        .map(|id| Ok((id, authority_log_body_in_txn(store, txn, &id)?)))
        .collect()
}

/// The store ids of the AUTHORITY_LOG rows, in id order, read from the type
/// index alone.
pub(super) fn authority_log_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<crate::EntityId>> {
    let mut ids = Vec::new();
    for row in store.port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)? {
        ids.push(row?);
    }
    Ok(ids)
}

/// The signed body of the AUTHORITY_LOG row the type index names at `id`.
fn authority_log_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &crate::EntityId,
) -> Result<Vec<u8>> {
    let raw = store
        .port_entity_record(txn, id)?
        .map(|row| row.encode())
        .ok_or(Error::CorruptedIndex("type index row without entity"))?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
        return Err(Error::CorruptedIndex("type index row kind mismatch"));
    }
    let body = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(body.to_vec())
}

/// The row a stored AUTHORITY_LOG `body` holds. A sealed row whose
/// overlay record does not open here lands as structure
/// ([`FoldRow::PassThrough`]); every other decode fault is store damage and
/// answers `CorruptedIndex` (ARCH-0006a #list-read-built).
pub(super) fn decode_stored_authority_fold_row(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &[u8],
) -> Result<FoldRow> {
    crate::authority::decode_vault_authority_fold_row_in_txn(store, txn, body)
        .map_err(|_| Error::CorruptedIndex("stored authority log row"))
}
