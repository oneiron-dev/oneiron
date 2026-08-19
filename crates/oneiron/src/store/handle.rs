//! The vault handle shape: [`RawDatabases`], [`StoreCore`], [`StoreOwner`],
//! [`Store`], [`SessionStoreView`], and the `manifest_dbs!` accessor seam.
//! The canonical open sequence lives in [`super::open_gates`]; see the
//! module doc on [`crate::store`] for the gate order.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, Weak};

use heed::types::{Bytes, Str};
use heed::{Database, Env, RoTxn, RwTxn};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::off_record::OffRecordSessionRegistry;
use crate::overlay_db::{OverlayDb, OverlayStrDb};
use crate::registry::{ENTITY_TYPE_POLICY_MANIFEST, StructuralKindRegistration};

use super::*;

thread_local! {
    static ACTIVE_WRITE_TXN_DEPTH: Cell<usize> = const { Cell::new(0) };
    #[cfg(test)]
    static PANIC_ON_ACTIVE_WRITE_TXN: Cell<bool> = const { Cell::new(false) };
}

pub(crate) struct ActiveWriteTxnGuard;

impl Drop for ActiveWriteTxnGuard {
    fn drop(&mut self) {
        ACTIVE_WRITE_TXN_DEPTH.with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
    }
}

pub(crate) fn active_write_txn_guard() -> ActiveWriteTxnGuard {
    #[cfg(test)]
    PANIC_ON_ACTIVE_WRITE_TXN.with(|panic_on_txn| {
        assert!(
            !panic_on_txn.get(),
            "write transaction must not be opened by this path",
        );
    });
    ACTIVE_WRITE_TXN_DEPTH.with(|depth| {
        depth.set(depth.get().saturating_add(1));
    });
    ActiveWriteTxnGuard
}

pub(super) fn active_write_txn_depth() -> usize {
    ACTIVE_WRITE_TXN_DEPTH.with(Cell::get)
}

#[cfg(test)]
pub(crate) fn panic_on_active_write_txn_for_current_thread(enabled: bool) {
    PANIC_ON_ACTIVE_WRITE_TXN.with(|panic_on_txn| panic_on_txn.set(enabled));
}

pub struct RawDatabases {
    pub(crate) entities: Database<Bytes, Bytes>,
    pub(crate) edges_out: Database<Bytes, Bytes>,
    pub(crate) edges_in: Database<Bytes, Bytes>,
    pub(crate) vectors: Database<Bytes, Bytes>,
    pub(crate) hnsw_neighbors: Database<Bytes, Bytes>,
    pub(crate) hnsw_meta: Database<Bytes, Bytes>,
    pub(crate) text_postings: Database<Bytes, Bytes>,
    pub(crate) text_meta: Database<Bytes, Bytes>,
    pub(crate) text_forward: Database<Bytes, Bytes>,
    pub(crate) text_bm25_field_stats: Database<Bytes, Bytes>,
    pub(crate) text_doc_field_lengths: Database<Bytes, Bytes>,
    pub(crate) vault_meta: Database<Bytes, Bytes>,
    pub(crate) ppr_cache: Database<Bytes, Bytes>,
    pub(crate) ppr_cache_deps: Database<Bytes, Bytes>,
    pub(crate) type_index: Database<Bytes, Bytes>,
    pub(crate) temporal_occurred_start: Database<Bytes, Bytes>,
    pub(crate) temporal_occurred_end: Database<Bytes, Bytes>,
    pub(crate) temporal_learned: Database<Bytes, Bytes>,
    pub(crate) temporal_long_intervals: Database<Bytes, Bytes>,
    pub(crate) phonetic_index: Database<Bytes, Bytes>,
    pub(crate) phonetic_forward: Database<Bytes, Bytes>,
    pub(crate) short_ids: Database<Bytes, Bytes>,
    pub(crate) short_ids_reverse: Database<Bytes, Bytes>,
    pub(crate) sync_state: Database<Str, Bytes>,
    pub(crate) sync_queue: Database<Bytes, Bytes>,
    /// Generic background attempt records keyed by attempt id.
    pub(crate) attempt_records: Database<Bytes, Bytes>,
    /// Ready-attempt ordering index keyed by ready-at time then attempt id.
    pub(crate) attempt_ready: Database<Bytes, Bytes>,
    /// Advisory dedupe index keys mapped to attempt ids.
    pub(crate) attempt_dedupe: Database<Bytes, Bytes>,
}

/// Arc-shared substrate of an open vault (ARCH-0052 store split).
///
/// Everything here is safe to share across handles: the environment handle
/// (a plain [`Env`] clone), the raw database handles, and the process-shared
/// registries. The Drop-sensitive singletons live in [`StoreOwner`] — a
/// `StoreCore` clone deliberately carries none of them, so a session vault
/// handle (ONE-1727) can hold `Arc<StoreCore>` without duplicating close,
/// path-deregistration, or clock-domain-release responsibilities.
///
/// INVARIANT: no `Arc<StoreCore>` may outlive the owning [`StoreOwner`]. The
/// owner's always-on drop assertion enforces this at runtime; the session
/// lifecycle drains leases before releasing its owner-bound handle.
pub struct StoreCore {
    /// Shared environment handle used to open transactions. The close-on-
    /// last-clone semantics live in the owner's [`OwnedEnv`] (ONE-1142).
    pub(crate) env: Env,
    /// Raw handles; runtime access goes through the [`Store`] accessors.
    /// `pub(in crate::store)` so no code outside `crate::store` can bypass the
    /// [`OverlayDb`] seam — open-time machinery and accessor construction both
    /// live inside the store module.
    pub(in crate::store) raw: RawDatabases,
    /// Vault-scoped dynamic StructuralKind registry loaded from `vault_meta`.
    pub(crate) kind_registry: RwLock<HashMap<u8, StructuralKindRegistration>>,
    /// Process-local off-record session source of truth. It is intentionally
    /// absent from every named database, so process loss evaporates sessions.
    pub(crate) off_record_sessions: OffRecordSessionRegistry,
    /// Serializes reward-to-weight tuning so concurrent callers cannot lose
    /// a gradient step between read, compute, and persist.
    pub(in crate::store) retrieval_blend_tuning_lock: Mutex<()>,
    /// Process-local clock domain for monotonic authority first-seen windows.
    /// Read-only mirror; release-on-drop responsibility is the owner's.
    pub(crate) authority_clock_domain: usize,
}

/// Drop-sensitive singletons of an open vault; exactly one per open path
/// (ARCH-0052 store split). Deliberately NOT `Clone` and never Arc-shared:
/// duplicating any of these would corrupt the base vault (double clock-domain
/// release, premature path deregistration, early environment close).
pub struct StoreOwner {
    /// Always-on tripwire for the "no `Arc<StoreCore>` outlives the owner"
    /// invariant; see [`StoreCore`].
    pub(in crate::store) core: Weak<StoreCore>,
    /// Sole owner of the environment's close-on-last-clone semantics
    /// (ONE-1142).
    #[expect(
        dead_code,
        reason = "held for Drop only: OwnedEnv's close-on-last-clone must fire \
                  before _registered_path releases the vault root (ONE-1142)"
    )]
    pub(in crate::store) env: OwnedEnv,
    /// The clock domain this owner releases exactly once on drop.
    pub(in crate::store) authority_clock_domain: usize,
    // DROP-ORDER: keep this field after `env`. Fields drop in declaration
    // order, so the path registry releases the path only after [`OwnedEnv`]
    // has closed the LMDB environment — a reopen racing this drop can never
    // observe the path as free while the old environment is still live.
    pub(in crate::store) _registered_path: RegisteredPath,
}

/// LMDB environment and database handles for a vault.
///
/// Dropping the last handle to a `Store` (normally via the owning
/// [`crate::Vault`]) CLOSES the LMDB environment — see `OwnedEnv` for the
/// close-path rationale (ONE-1142).
///
/// Split per ARCH-0052: `Store` is the canonical per-vault VIEW — 28
/// [`OverlayDb`] accessors (pure passthrough; a session handle composes its
/// overlay at the same seam) over the Arc-shared [`StoreCore`], plus the
/// single-owner [`StoreOwner`]. `Store` derefs to [`StoreCore`] so
/// `store.env`/`store.kind_registry` field access is preserved.
pub struct Store {
    // DROP-ORDER: `core` is declared before `owner` so this handle's Arc
    // reference drops first; `owner` then closes the environment (its
    // `OwnedEnv` holds the last remaining `Env` clone) and finally releases
    // the registered path. `pub(in crate::store)` so no code outside
    // `crate::store` can clone the Arc past this handle's lifetime; deliberate
    // sharing arrives with the ONE-1727 session lease.
    pub(in crate::store) core: Arc<StoreCore>,
    pub(crate) entities: OverlayDb,
    pub(crate) edges_out: OverlayDb,
    pub(crate) edges_in: OverlayDb,
    pub(crate) vectors: OverlayDb,
    pub(crate) hnsw_neighbors: OverlayDb,
    pub(crate) hnsw_meta: OverlayDb,
    /// Fielded inverted index, opened with `DUP_SORT` (storage ABI v4 /
    /// ONE-299). Key: term bytes. Each duplicate data item is ONE posting
    /// entry `entity_id(16) | field_count(u8) | (field_id_u16_be |
    /// tf_u32_le)*`; LMDB keeps duplicates bytewise sorted, so items order
    /// by entity-id prefix and an index append never reads the list.
    pub(crate) text_postings: OverlayDb,
    pub(crate) text_meta: OverlayDb,
    pub(crate) text_forward: OverlayDb,
    /// BM25F per-field corpus stats.
    /// Key: `field_id` big-endian u16.
    /// Value: `[doc_count_u32_le | total_length_u64_le]`.
    pub(crate) text_bm25_field_stats: OverlayDb,
    /// Per-doc, per-field surface-token lengths used by the BM25F length
    /// normalization term. Key: entity_id (16B). Value: a flat
    /// `[(field_id_u16_be | length_u32_le)*]` list over present fields.
    pub(crate) text_doc_field_lengths: OverlayDb,
    /// Vault-level metadata (analyzer manifest, schema version, field
    /// schema hash). Read on `Vault::open` to gate index compatibility.
    pub(crate) vault_meta: OverlayDb,
    /// PPR cache rows. Values carry the final scores and, for current rows,
    /// the residual/frontier state needed to resume a deeper Forward-Push run.
    pub(crate) ppr_cache: OverlayDb,
    /// Reverse dependency index for PPR cache invalidation:
    /// `[entity_id | cache_key]`.
    pub(crate) ppr_cache_deps: OverlayDb,
    pub(crate) type_index: OverlayDb,
    pub(crate) temporal_occurred_start: OverlayDb,
    pub(crate) temporal_occurred_end: OverlayDb,
    pub(crate) temporal_learned: OverlayDb,
    pub(crate) temporal_long_intervals: OverlayDb,
    pub(crate) phonetic_index: OverlayDb,
    pub(crate) phonetic_forward: OverlayDb,
    pub(crate) short_ids: OverlayDb,
    pub(crate) short_ids_reverse: OverlayDb,
    /// CRDT Doc states, state vectors, pending updates, metadata. Present in
    /// EVERY build (ONE-1132): the delete path writes its CRDT-independent
    /// `pt:` pending-tombstone marker here unconditionally, so deletion
    /// durability never depends on the `sync` cargo feature.
    pub(crate) sync_state: OverlayStrDb,
    /// Offline update queue, embed job queue, and hard-delete sweep queue.
    pub(crate) sync_queue: OverlayDb,
    /// Generic background attempt records keyed by attempt id.
    pub(crate) attempt_records: OverlayDb,
    /// Ready-attempt ordering index keyed by ready-at time then attempt id.
    pub(crate) attempt_ready: OverlayDb,
    /// Advisory dedupe index keys mapped to attempt ids.
    pub(crate) attempt_dedupe: OverlayDb,
    pub(crate) owner: StoreOwner,
}

/// One logical session view over all 28 manifest accessors. Every accessor
/// shares the exact same overlay snapshot; constructing accessors one by one
/// would permit a torn union if the overlay changed between constructions.
/// The borrowed owner marker prevents any view from outliving `StoreOwner`.
#[allow(
    dead_code,
    reason = "ONE-1727 constructs the complete D1 view; ONE-1728 witness/retrieval consumes the remaining accessors"
)]
pub(crate) struct SessionStoreView<'store> {
    _owner: &'store StoreOwner,
    /// The overlay every accessor above stages into. Held so a staging site
    /// inside a base write transaction can install its segment (see
    /// [`SessionStoreView::install_txn_segment`]) without the caller having to
    /// carry the session handle alongside the view.
    overlay: Arc<crate::session_overlay::SessionOverlay>,
    pub(crate) entities: OverlayDb,
    pub(crate) edges_out: OverlayDb,
    pub(crate) edges_in: OverlayDb,
    pub(crate) vectors: OverlayDb,
    pub(crate) hnsw_neighbors: OverlayDb,
    pub(crate) hnsw_meta: OverlayDb,
    pub(crate) text_postings: OverlayDb,
    pub(crate) text_meta: OverlayDb,
    pub(crate) text_forward: OverlayDb,
    pub(crate) text_bm25_field_stats: OverlayDb,
    pub(crate) text_doc_field_lengths: OverlayDb,
    pub(crate) vault_meta: OverlayDb,
    pub(crate) ppr_cache: OverlayDb,
    pub(crate) ppr_cache_deps: OverlayDb,
    pub(crate) type_index: OverlayDb,
    pub(crate) temporal_occurred_start: OverlayDb,
    pub(crate) temporal_occurred_end: OverlayDb,
    pub(crate) temporal_learned: OverlayDb,
    pub(crate) temporal_long_intervals: OverlayDb,
    pub(crate) phonetic_index: OverlayDb,
    pub(crate) phonetic_forward: OverlayDb,
    pub(crate) short_ids: OverlayDb,
    pub(crate) short_ids_reverse: OverlayDb,
    pub(crate) sync_state: OverlayStrDb,
    pub(crate) sync_queue: OverlayDb,
    pub(crate) attempt_records: OverlayDb,
    pub(crate) attempt_ready: OverlayDb,
    pub(crate) attempt_dedupe: OverlayDb,
}

#[allow(
    dead_code,
    reason = "P4a lands the session telemetry seam whole; `record_retrieval_run_in_txn` has its \
              lib-target caller in ONE-1728's session `search_text`, and the finalize/delete/read \
              siblings get theirs from ONE-1729's session context-pack runs and ONE-1730's promote"
)]
impl SessionStoreView<'_> {
    /// Installs a write segment on the overlay this view stages into.
    ///
    /// Every session write needs an active segment on the calling thread —
    /// `SessionOverlay::stage_mutation` refuses without one — and the segment
    /// permit is acquired AFTER the base writer (`session_overlay`'s documented
    /// base -> segment order; the reverse is the ABBA path). A view therefore
    /// cannot install its segment at construction: the staging site installs it
    /// inside its own write transaction and commits the returned guard after
    /// the base commit returns.
    pub(crate) fn install_txn_segment(&self) -> Result<crate::session_overlay::TxnSegmentGuard> {
        self.overlay.install_txn_segment()
    }

    /// Mode-aware VaultMeta write half consumed by
    /// `OffRecordSession::vault_meta_put`. Reuses the existing raw key/value
    /// representation; this pins routing, not a new encoding.
    pub(crate) fn vault_meta_put_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        self.vault_meta.put(wtxn, key, value)
    }

    /// Composed VaultMeta read half consumed by
    /// `OffRecordSession::vault_meta_get` — overlay ∪ base.
    pub(crate) fn vault_meta_get_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .vault_meta
            .get(rtxn, key)?
            .map(std::borrow::Cow::into_owned))
    }
}

/// Generates [`ManifestDbs`] and its two implementations from ONE list of the
/// manifest's named databases, so the trait cannot drift from the structs: a
/// database renamed in `Store` or `SessionStoreView` and not here fails to
/// compile.
macro_rules! manifest_dbs {
    ($($name:ident: $ty:ty),+ $(,)?) => {
        /// The manifest's named databases, addressed uniformly by write target
        /// (ARCH-0052 D2, ONE-1728 K11).
        ///
        /// [`Store`] answers with canonical accessors that read and write base
        /// LMDB rows. [`SessionStoreView`] answers with composed accessors over
        /// one shared overlay snapshot: reads see overlay ∪ base, writes stage
        /// into the session overlay and evaporate at close.
        ///
        /// This is what "write-target parameterization" means in this codebase.
        /// An index writer generic over `&impl ManifestDbs` has ONE body serving
        /// both targets — the base path is byte-identical because it is
        /// literally the same code reaching the same accessors, not a copy that
        /// could drift. `OverlayDb` already decides base-vs-overlay internally,
        /// so no writer needs a target branch.
        #[allow(
            dead_code,
            reason = "the trait is generated from ONE list so it cannot drift from the structs; \
                      six accessors (ppr_cache_deps, sync_state, sync_queue, attempt_records, \
                      attempt_ready, attempt_dedupe) have no write-target-parameterized caller \
                      after P4a and are on the ONE-1728 seg-4 post-merge delete-list"
        )]
        pub(crate) trait ManifestDbs {
            $(fn $name(&self) -> &$ty;)+
        }

        impl ManifestDbs for Store {
            $(fn $name(&self) -> &$ty { &self.$name })+
        }

        impl ManifestDbs for SessionStoreView<'_> {
            $(fn $name(&self) -> &$ty { &self.$name })+
        }
    };
}

manifest_dbs! {
    entities: OverlayDb,
    type_index: OverlayDb,
    short_ids: OverlayDb,
    short_ids_reverse: OverlayDb,
    vault_meta: OverlayDb,
    vectors: OverlayDb,
    hnsw_neighbors: OverlayDb,
    hnsw_meta: OverlayDb,
    text_postings: OverlayDb,
    text_meta: OverlayDb,
    text_forward: OverlayDb,
    text_bm25_field_stats: OverlayDb,
    text_doc_field_lengths: OverlayDb,
    edges_out: OverlayDb,
    edges_in: OverlayDb,
    ppr_cache: OverlayDb,
    ppr_cache_deps: OverlayDb,
    temporal_occurred_start: OverlayDb,
    temporal_occurred_end: OverlayDb,
    temporal_learned: OverlayDb,
    temporal_long_intervals: OverlayDb,
    phonetic_index: OverlayDb,
    phonetic_forward: OverlayDb,
    sync_state: OverlayStrDb,
    sync_queue: OverlayDb,
    attempt_records: OverlayDb,
    attempt_ready: OverlayDb,
    attempt_dedupe: OverlayDb,
}

impl std::ops::Deref for Store {
    type Target = StoreCore;

    fn deref(&self) -> &StoreCore {
        &self.core
    }
}

impl Drop for StoreOwner {
    fn drop(&mut self) {
        assert!(
            self.core.strong_count() == 0,
            "an Arc<StoreCore> outlived its StoreOwner; the path registry \
             would release the vault root while the environment is still \
             live (ARCH-0052 store-split invariant)"
        );
        crate::authority::release_authority_clock_domain(self.authority_clock_domain);
    }
}

pub(super) fn seed_default_policy_manifest_in_txn(
    entities: &OverlayDb,
    type_index: &OverlayDb,
    temporal_occurred_start: &OverlayDb,
    temporal_learned: &OverlayDb,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    // Never overwrite a caller-chosen occupant at the published sentinel id:
    // the raw seed path cannot safely reconstruct and remove every index row.
    if entities.get(wtxn, id.as_bytes())?.is_some() {
        return Err(Error::CorruptedIndex("default policy manifest id occupied"));
    }
    let timestamp = crate::gate::DEFAULT_POLICY_MANIFEST_TIMESTAMP;
    let body = crate::gate::default_policy_manifest();
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&body);
    entities.put(wtxn, id.as_bytes(), &payload)?;
    type_index.put(
        wtxn,
        &Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, id),
        &[],
    )?;
    temporal_occurred_start.put(wtxn, &Store::encode_temporal_key(timestamp, id), &[])?;
    temporal_learned.put(wtxn, &Store::encode_temporal_key(timestamp, id), &[])?;
    Ok(())
}

impl Store {
    /// Captures one segment-aware snapshot and applies it to every database
    /// accessor in this logical read transaction.
    pub(crate) fn session_view(
        &self,
        overlay: Arc<crate::session_overlay::SessionOverlay>,
    ) -> Result<SessionStoreView<'_>> {
        use crate::session_overlay::OverlayKeyspace;

        let snapshot = Arc::new(overlay.snapshot()?);
        let db =
            |base, keyspace| OverlayDb::composed(base, overlay.clone(), snapshot.clone(), keyspace);
        Ok(SessionStoreView {
            _owner: &self.owner,
            overlay: overlay.clone(),
            entities: db(self.core.raw.entities, OverlayKeyspace::Entities),
            edges_out: db(self.core.raw.edges_out, OverlayKeyspace::EdgesOut),
            edges_in: db(self.core.raw.edges_in, OverlayKeyspace::EdgesIn),
            vectors: db(self.core.raw.vectors, OverlayKeyspace::Vectors),
            hnsw_neighbors: db(self.core.raw.hnsw_neighbors, OverlayKeyspace::HnswNeighbors),
            hnsw_meta: db(self.core.raw.hnsw_meta, OverlayKeyspace::HnswMeta),
            text_postings: db(self.core.raw.text_postings, OverlayKeyspace::TextPostings),
            text_meta: db(self.core.raw.text_meta, OverlayKeyspace::TextMeta),
            text_forward: db(self.core.raw.text_forward, OverlayKeyspace::TextForward),
            text_bm25_field_stats: db(
                self.core.raw.text_bm25_field_stats,
                OverlayKeyspace::TextBm25FieldStats,
            ),
            text_doc_field_lengths: db(
                self.core.raw.text_doc_field_lengths,
                OverlayKeyspace::TextDocFieldLengths,
            ),
            vault_meta: db(self.core.raw.vault_meta, OverlayKeyspace::VaultMeta),
            ppr_cache: db(self.core.raw.ppr_cache, OverlayKeyspace::PprCache),
            ppr_cache_deps: db(self.core.raw.ppr_cache_deps, OverlayKeyspace::PprCacheDeps),
            type_index: db(self.core.raw.type_index, OverlayKeyspace::TypeIndex),
            temporal_occurred_start: db(
                self.core.raw.temporal_occurred_start,
                OverlayKeyspace::TemporalOccurredStart,
            ),
            temporal_occurred_end: db(
                self.core.raw.temporal_occurred_end,
                OverlayKeyspace::TemporalOccurredEnd,
            ),
            temporal_learned: db(
                self.core.raw.temporal_learned,
                OverlayKeyspace::TemporalLearned,
            ),
            temporal_long_intervals: db(
                self.core.raw.temporal_long_intervals,
                OverlayKeyspace::TemporalLongIntervals,
            ),
            phonetic_index: db(self.core.raw.phonetic_index, OverlayKeyspace::PhoneticIndex),
            phonetic_forward: db(
                self.core.raw.phonetic_forward,
                OverlayKeyspace::PhoneticForward,
            ),
            short_ids: db(self.core.raw.short_ids, OverlayKeyspace::ShortIds),
            short_ids_reverse: db(
                self.core.raw.short_ids_reverse,
                OverlayKeyspace::ShortIdsReverse,
            ),
            sync_state: OverlayStrDb::composed(
                self.core.raw.sync_state,
                overlay.clone(),
                snapshot.clone(),
                OverlayKeyspace::SyncState,
            ),
            sync_queue: db(self.core.raw.sync_queue, OverlayKeyspace::SyncQueue),
            attempt_records: db(
                self.core.raw.attempt_records,
                OverlayKeyspace::AttemptRecords,
            ),
            attempt_ready: db(self.core.raw.attempt_ready, OverlayKeyspace::AttemptReady),
            attempt_dedupe: db(self.core.raw.attempt_dedupe, OverlayKeyspace::AttemptDedupe),
        })
    }
}
