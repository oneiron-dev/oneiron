//! In-memory session write-overlay substrate (ARCH-0052, D1).
//!
//! The overlay is independent of the durable off-record fence machinery. It
//! owns one structurally shared keyspace per database manifest slot, typed
//! journal entries, generation-stamped read/segment leases, and the byte
//! budget that bounds live overlay rows.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::rc::Rc;
use std::str;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use arc_swap::ArcSwap;
use xxhash_rust::xxh32::xxh32;

use crate::batch::{BatchOp, LONG_INTERVAL_THRESHOLD_SECS};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::temporal::TimeRange;

/// Write-transaction entry points that a session write path must wrap.
///
/// ONE-1726 supplies the segment mechanism only. Future session paths must
/// install it around `Vault::try_with_write_txn`/`with_write_txn`,
/// `BatchBuilder::commit`, facade `with_verified_actor_write_txn`/`witness`,
/// and the direct `env.write_txn()` clusters in `dreamer_runner`,
/// `attempt_queue`, `claim`, `deletion`, `connector_key`, `companion`,
/// `code_run`, and the remaining store/vault feature modules.
pub(crate) const SESSION_WRITE_TXN_ENTRY_POINTS: &[&str] = &[
    "Vault::try_with_write_txn / Vault::with_write_txn",
    "BatchBuilder::commit",
    "Memory::with_verified_actor_write_txn / Memory::witness",
    "direct env.write_txn(): dreamer_runner, attempt_queue, claim, deletion, connector_key, companion, code_run, and remaining feature modules",
];

const _: () = assert!(!SESSION_WRITE_TXN_ENTRY_POINTS.is_empty());

/// Leading sigil of every session-local short id (ARCH-0052 §7).
///
/// Base short ids are `<two lowercase letters><decimal digits>`, which is
/// exactly what the short-ref parsers accept. `s` is not a legal base prefix
/// (a base prefix is always two letters), so the room namespace sits OUTSIDE
/// the base grammar and a session alias can never collide with, or mask, a
/// durable one.
const SESSION_SHORT_ID_SIGIL: &str = "s";

/// Manifest slot identifying one of the 28 named databases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum OverlayKeyspace {
    Entities = 0,
    TypeIndex = 1,
    ShortIds = 2,
    ShortIdsReverse = 3,
    VaultMeta = 4,
    Vectors = 5,
    HnswNeighbors = 6,
    HnswMeta = 7,
    TextPostings = 8,
    TextMeta = 9,
    TextForward = 10,
    TextBm25FieldStats = 11,
    TextDocFieldLengths = 12,
    EdgesOut = 13,
    EdgesIn = 14,
    PprCache = 15,
    PprCacheDeps = 16,
    TemporalOccurredStart = 17,
    TemporalOccurredEnd = 18,
    TemporalLearned = 19,
    TemporalLongIntervals = 20,
    PhoneticIndex = 21,
    PhoneticForward = 22,
    SyncState = 23,
    SyncQueue = 24,
    AttemptRecords = 25,
    AttemptReady = 26,
    AttemptDedupe = 27,
}

impl OverlayKeyspace {
    const COUNT: usize = 28;

    const fn slot(self) -> usize {
        self as usize
    }

    pub(crate) const fn is_dupsort(self) -> bool {
        matches!(self, Self::TextPostings)
    }

    fn from_slot(slot: usize) -> Self {
        const ALL: [OverlayKeyspace; OverlayKeyspace::COUNT] = [
            OverlayKeyspace::Entities,
            OverlayKeyspace::TypeIndex,
            OverlayKeyspace::ShortIds,
            OverlayKeyspace::ShortIdsReverse,
            OverlayKeyspace::VaultMeta,
            OverlayKeyspace::Vectors,
            OverlayKeyspace::HnswNeighbors,
            OverlayKeyspace::HnswMeta,
            OverlayKeyspace::TextPostings,
            OverlayKeyspace::TextMeta,
            OverlayKeyspace::TextForward,
            OverlayKeyspace::TextBm25FieldStats,
            OverlayKeyspace::TextDocFieldLengths,
            OverlayKeyspace::EdgesOut,
            OverlayKeyspace::EdgesIn,
            OverlayKeyspace::PprCache,
            OverlayKeyspace::PprCacheDeps,
            OverlayKeyspace::TemporalOccurredStart,
            OverlayKeyspace::TemporalOccurredEnd,
            OverlayKeyspace::TemporalLearned,
            OverlayKeyspace::TemporalLongIntervals,
            OverlayKeyspace::PhoneticIndex,
            OverlayKeyspace::PhoneticForward,
            OverlayKeyspace::SyncState,
            OverlayKeyspace::SyncQueue,
            OverlayKeyspace::AttemptRecords,
            OverlayKeyspace::AttemptReady,
            OverlayKeyspace::AttemptDedupe,
        ];
        ALL[slot]
    }
}

#[derive(Clone)]
enum OverlayValue {
    Present(Vec<u8>),
    Tombstone,
}

#[derive(Clone, Default)]
struct DupDelta {
    delete_base: bool,
    present: BTreeMap<Vec<u8>, Vec<u8>>,
    deleted: BTreeSet<Vec<u8>>,
}

#[derive(Clone)]
enum KeyspaceState {
    Single {
        clear_base: bool,
        rows: BTreeMap<Vec<u8>, OverlayValue>,
    },
    DupSort {
        clear_base: bool,
        rows: BTreeMap<Vec<u8>, DupDelta>,
    },
}

impl KeyspaceState {
    fn empty(keyspace: OverlayKeyspace) -> Self {
        if keyspace.is_dupsort() {
            Self::DupSort {
                clear_base: false,
                rows: BTreeMap::new(),
            }
        } else {
            Self::Single {
                clear_base: false,
                rows: BTreeMap::new(),
            }
        }
    }

    fn cleared(keyspace: OverlayKeyspace) -> Self {
        match Self::empty(keyspace) {
            Self::Single { rows, .. } => Self::Single {
                clear_base: true,
                rows,
            },
            Self::DupSort { rows, .. } => Self::DupSort {
                clear_base: true,
                rows,
            },
        }
    }

    fn byte_size(&self) -> usize {
        match self {
            Self::Single { rows, .. } => rows
                .iter()
                .map(|(key, value)| {
                    key.len()
                        + match value {
                            OverlayValue::Present(value) => value.len(),
                            OverlayValue::Tombstone => 0,
                        }
                })
                .sum(),
            Self::DupSort { rows, .. } => rows
                .iter()
                .map(|(key, delta)| {
                    key.len()
                        + delta.present.keys().map(Vec::len).sum::<usize>()
                        + delta.present.values().map(Vec::len).sum::<usize>()
                        + delta.deleted.iter().map(Vec::len).sum::<usize>()
                })
                .sum(),
        }
    }
}

/// Semantic ownership tag on a typed journal entry (ARCH-0052 D4, K3).
///
/// This is the ONLY legal closure source for promotion (ONE-1730): promote
/// selects by role, never by inferring ownership from a type-index,
/// text-posting, short-id, temporal, or edge-index key. Index keys are shared
/// between turns by construction, so key-shaped selection drags siblings.
///
/// Role assignment is CLOSED — every staged op maps to exactly one role:
///
/// | role | staged op |
/// |---|---|
/// | [`Self::ConversationShell`] | the conversation shell put |
/// | [`Self::TurnPut`] | the TURN entity put |
/// | [`Self::MessagePartOf`] | each MESSAGE put and its `PartOf` edge |
/// | [`Self::SummaryDerivedFrom`] | the SUMMARY put and its `DerivedFrom` edge |
/// | [`Self::AttributionEdge`] | the `AuthoredBy` and `BelongsTo` edges |
/// | [`Self::TurnOwnedArtifact`] | every other turn-scoped op (BM25 `content` text ops, vector/HNSW rows) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalRole {
    TurnPut,
    MessagePartOf,
    SummaryDerivedFrom,
    AttributionEdge,
    ConversationShell,
    TurnOwnedArtifact,
}

/// One typed journal operation.
///
/// `scope` carries the owning conversation + turn; `learned_at` and `occurred`
/// are preserved from the witnessing write and never restamped, so promote
/// replays into the correct month window (ARCH-0052 D4).
#[derive(Clone)]
pub(crate) struct JournalEntry {
    /// Read by [`OverlaySnapshot::plan_promotion`] to cut ONE turn's closure
    /// out of the journal — the whole reason the scope is recorded at staging
    /// time rather than reconstructed from index keys later.
    pub(crate) scope: JournalScope,
    pub(crate) role: JournalRole,
    pub(crate) learned_at: u64,
    pub(crate) occurred: TimeRange,
    pub(crate) op: BatchOp,
}

#[derive(Clone)]
struct OverlayState {
    keyspaces: [Arc<KeyspaceState>; OverlayKeyspace::COUNT],
    journal: Arc<Vec<JournalEntry>>,
    bytes_used: usize,
}

impl OverlayState {
    fn empty() -> Self {
        Self {
            keyspaces: std::array::from_fn(|slot| {
                Arc::new(KeyspaceState::empty(OverlayKeyspace::from_slot(slot)))
            }),
            journal: Arc::new(Vec::new()),
            bytes_used: 0,
        }
    }

    fn recalculate_bytes(&mut self) {
        self.bytes_used = self
            .keyspaces
            .iter()
            .map(|state| state.byte_size())
            .chain(self.journal.iter().map(JournalEntry::byte_size))
            .fold(0_usize, usize::saturating_add);
    }
}

impl JournalEntry {
    fn byte_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(batch_op_payload_bytes(&self.op))
    }
}

#[derive(Clone)]
enum OverlayMutation {
    Put {
        keyspace: OverlayKeyspace,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        keyspace: OverlayKeyspace,
        key: Vec<u8>,
        base_backed: bool,
    },
    DeleteDuplicate {
        keyspace: OverlayKeyspace,
        key: Vec<u8>,
        value: Vec<u8>,
        base_backed: bool,
    },
    Clear {
        keyspace: OverlayKeyspace,
    },
}

/// Turn/conversation scope carried by each typed journal operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JournalScope {
    conversation: EntityId,
    turn: EntityId,
}

impl JournalScope {
    pub(crate) const fn new(conversation: EntityId, turn: EntityId) -> Self {
        Self { conversation, turn }
    }

    /// The turn this op belongs to. Promotion moves ONE turn at a time, so
    /// this is how the closure is cut out of the journal.
    pub(crate) const fn turn(&self) -> EntityId {
        self.turn
    }

    /// The conversation shell owning this op.
    pub(crate) const fn conversation(&self) -> EntityId {
        self.conversation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayLifecycleState {
    Live,
    Sealing,
    Sealed,
    Closing,
    Gone,
}

struct Lifecycle {
    state: OverlayLifecycleState,
    generation: u64,
    /// Monotonic counter bumped by every MODE publication — `seal_writes`
    /// (Live -> Sealed, the flip on-record) and `rearm` (Sealed -> Live, the
    /// K10 flip-back). A [`SessionWriteRoute`] records the value it was minted
    /// under and [`SessionWriteRoute::revalidate`] refuses a mismatch, so a
    /// route minted before the most recent flip can never stage or commit.
    /// Distinct from `generation`, which stamps LEASES and bumps at close.
    mode_generation: u64,
    leases: usize,
    segment_active: bool,
}

struct Lease {
    overlay: Arc<SessionOverlay>,
    #[allow(
        dead_code,
        reason = "segment generation is consumed once ONE-1728 installs production session writes"
    )]
    generation: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut lifecycle) = self.overlay.lifecycle.lock() {
            lifecycle.leases = lifecycle.leases.saturating_sub(1);
            if lifecycle.leases == 0 {
                self.overlay.lease_drained.notify_all();
            }
        }
    }
}

/// Which store a session write lands in for the session's CURRENT mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteTarget {
    /// `OffRecord` — rows stage into the overlay and evaporate at close.
    Overlay,
    /// `OnRecord` (post-flip) — rows take the ordinary base apply under the
    /// session's on-record continuation shell.
    Base,
}

/// The mode-aware write route (ARCH-0052 D5, K10).
///
/// Minted by `OffRecordSession::write_route()` under the session state lock, so
/// the target and the mode generation it records are the same publication.
/// Every apply route on the session write path carries the route it was
/// constructed with and revalidates it before staging or committing.
///
/// Fields are private to this module: `batch.rs` receives a route and NEVER
/// reads its fields — the route revalidates itself. That is why `revalidate`
/// lives here, in the fields' owner module, rather than at the call site.
pub(crate) struct SessionWriteRoute {
    overlay: Arc<SessionOverlay>,
    target: RouteTarget,
    mode_generation: u64,
}

impl SessionWriteRoute {
    /// Mints a route recording the overlay's currently published mode
    /// generation. Callers hold the session state lock across mint + the mode
    /// read so target and generation cannot disagree.
    pub(crate) fn mint(overlay: &Arc<SessionOverlay>, target: RouteTarget) -> Result<Self> {
        Ok(Self {
            overlay: overlay.clone(),
            target,
            mode_generation: overlay.mode_generation()?,
        })
    }

    /// Refuses with the typed stale-route family if this route was minted
    /// before the most recent mode publication (flip to `OnRecord`, or the
    /// K10 flip-back rearm). Read under the overlay's own state lock against
    /// freshly published state, so a route that survives this check is the
    /// route the current mode authorizes.
    ///
    /// The refusal reuses [`Error::OffRecordOverlayLeaseClosed`], carrying the
    /// route's recorded mode generation: a stale route names a mode epoch that
    /// no longer accepts writes, exactly as a stale lease names a closed
    /// overlay generation.
    pub(crate) fn revalidate(&self) -> Result<()> {
        if self.overlay.mode_generation()? == self.mode_generation {
            return Ok(());
        }
        Err(Error::OffRecordOverlayLeaseClosed {
            generation: self.mode_generation,
        })
    }

    /// Narrow query arm: which store this route resolves to. `batch.rs` may
    /// branch through this method, never through a field read.
    pub(crate) const fn target(&self) -> RouteTarget {
        self.target
    }

    /// The overlay this route stages into. Crate-private and used only by the
    /// session apply entry, which must stage through the same overlay the
    /// route was minted against.
    pub(crate) const fn overlay(&self) -> &Arc<SessionOverlay> {
        &self.overlay
    }
}

/// A generation-stamped, structurally shared overlay read view.
pub(crate) struct OverlaySnapshot {
    state: Arc<OverlayState>,
    _lease: Lease,
}

pub(crate) enum SnapshotLookup {
    Passthrough,
    Tombstone,
    Present(Vec<u8>),
}

pub(crate) enum SnapshotMergeRow {
    Single {
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    },
    Duplicate {
        key: Vec<u8>,
        identity: Vec<u8>,
        deleted: BTreeSet<Vec<u8>>,
        present: Option<Vec<u8>>,
    },
}

pub(crate) struct SnapshotMergePlan {
    pub(crate) clear_base: bool,
    pub(crate) deleted_keys: BTreeSet<Vec<u8>>,
    pub(crate) rows: Vec<SnapshotMergeRow>,
}

/// One turn's promotable closure, cut out of the typed journal by
/// [`OverlaySnapshot::plan_promotion`] (ARCH-0052 D4, ONE-1730).
///
/// The plan is pure data: it names WHAT to replay, and the promote
/// transaction decides how. Selection and durable commit are separate so the
/// caller can hold the per-session state lock across both and a failed commit
/// leaves the journal it was cut from untouched.
pub(crate) struct PromotePlan {
    /// The replay program, in journal-staging order — the shell put leads, so
    /// every later op refers to a row the base apply already materialized.
    pub(crate) ops: Vec<BatchOp>,
    /// Entity ids the replay materializes, in the same order.
    pub(crate) replayed: Vec<EntityId>,
    /// `(id, in-room alias)` for every promoted entity that carries one. The
    /// canonical half is read back from base after the replay.
    pub(crate) temporary_short_ids: Vec<(EntityId, String)>,
    /// Distinct journal `learned_at` values, ascending. These are the SOURCE
    /// windows the pickup markers are derived from — never a promote-time
    /// clock.
    pub(crate) source_learned_at: Vec<u64>,
    turn: EntityId,
    conversation: EntityId,
}

impl PromotePlan {
    /// The promoted turn — the receipt key and the pickup marker's id.
    pub(crate) const fn turn(&self) -> EntityId {
        self.turn
    }
}

/// The ONE closure-membership predicate, shared by selection and retirement so
/// the rows that were promoted are exactly the rows that retire.
fn journal_entry_in_closure(entry: &JournalEntry, turn: EntityId, conversation: EntityId) -> bool {
    match entry.role {
        JournalRole::ConversationShell => entry.scope.conversation() == conversation,
        JournalRole::AttributionEdge => {
            entry.scope.turn() == turn && attribution_edge_is_closure_internal(&entry.op)
        }
        JournalRole::TurnPut
        | JournalRole::MessagePartOf
        | JournalRole::SummaryDerivedFrom
        | JournalRole::TurnOwnedArtifact => entry.scope.turn() == turn,
    }
}

/// Whether an [`JournalRole::AttributionEdge`] op belongs to the promotable
/// closure (ARCH-0052 D4, ONE-1730).
///
/// ONE-1728 stages TWO kinds under that one role, and they differ in where
/// they point:
///
/// * `BelongsTo(message -> conversation shell)` — the shell is a closure
///   member, so this edge is internal to the subgraph being published and is
///   one of the ratified three (`PartOf`, `DerivedFrom`, `BelongsTo`).
/// * `AuthoredBy(message -> actor)` — the actor is a BASE identity the room
///   neither staged nor owns. Promoting it would attach the consented subgraph
///   to an entity outside it, which is exactly the closure boundary promote
///   exists to hold.
///
/// The authorship edge is not discarded: it stays an overlay row and a journal
/// entry for the rest of the room's life (the in-room view still resolves it)
/// and evaporates at close with everything else the user did not promote.
fn attribution_edge_is_closure_internal(op: &BatchOp) -> bool {
    matches!(
        op,
        BatchOp::Edge {
            kind: crate::edge::EdgeKind::BelongsTo,
            ..
        }
    )
}

/// Rebuilds one journaled op as the base apply must see it.
///
/// The ENTRY's `occurred`/`learned_at` ride into the rebuilt op — never
/// `unix_seconds_now()` — so a promoted row lands in the month window the turn
/// actually happened in. Edges become the timestamped PUBLIC arm for the same
/// reason: the plain `Edge` arm stamps `created_at` at apply time, which would
/// restamp the whole attribution set to the promote clock.
fn promotion_replay_op(entry: &JournalEntry) -> Result<BatchOp> {
    Ok(match &entry.op {
        BatchOp::Put {
            id,
            entity_type,
            data,
            allow_maintenance,
            allow_reserved_predicate,
            hub_sync_imported,
            ..
        } => BatchOp::Put {
            id: *id,
            entity_type: *entity_type,
            occurred: entry.occurred,
            learned_at: entry.learned_at,
            data: data.clone(),
            allow_maintenance: *allow_maintenance,
            allow_reserved_predicate: *allow_reserved_predicate,
            hub_sync_imported: *hub_sync_imported,
        },
        BatchOp::Edge {
            src,
            kind,
            tgt,
            weight,
            vad,
        } => BatchOp::PublicEdgeWithCreatedAt {
            src: *src,
            kind: *kind,
            tgt: *tgt,
            weight: *weight,
            created_at: entry.learned_at,
            vad: *vad,
        },
        // Text and Vector ride unchanged — only Put re-stamps the journaled
        // time range and only Edge re-arms, so these clone verbatim.
        BatchOp::Text { .. } | BatchOp::Vector { .. } => entry.op.clone(),
        BatchOp::ClaimCandidate { .. }
        | BatchOp::ReconcileLexicalQueryHints { .. }
        | BatchOp::Phonetic { .. }
        | BatchOp::PublicEdgeWithCreatedAt { .. }
        | BatchOp::EdgeWithCreatedAt { .. }
        | BatchOp::SetEdgeWeight { .. }
        | BatchOp::SetEdgeVad { .. }
        | BatchOp::Delete { .. }
        | BatchOp::DeleteEdge { .. } => {
            return Err(Error::InvariantViolation(
                "promotion replay found a journal op the session write path cannot stage",
            ));
        }
    })
}

impl OverlaySnapshot {
    pub(crate) fn lookup_single(&self, keyspace: OverlayKeyspace, key: &[u8]) -> SnapshotLookup {
        match self.state.keyspaces[keyspace.slot()].as_ref() {
            KeyspaceState::Single { clear_base, rows } => match rows.get(key) {
                Some(OverlayValue::Present(value)) => SnapshotLookup::Present(value.clone()),
                Some(OverlayValue::Tombstone) => SnapshotLookup::Tombstone,
                None if *clear_base => SnapshotLookup::Tombstone,
                None => SnapshotLookup::Passthrough,
            },
            KeyspaceState::DupSort { .. } => SnapshotLookup::Passthrough,
        }
    }

    pub(crate) fn merge_plan(
        &self,
        keyspace: OverlayKeyspace,
        include_key: impl Fn(&[u8]) -> bool,
    ) -> SnapshotMergePlan {
        match self.state.keyspaces[keyspace.slot()].as_ref() {
            KeyspaceState::Single { clear_base, rows } => SnapshotMergePlan {
                clear_base: *clear_base,
                deleted_keys: BTreeSet::new(),
                rows: rows
                    .iter()
                    .filter(|(key, _)| include_key(key))
                    .map(|(key, value)| SnapshotMergeRow::Single {
                        key: key.clone(),
                        value: match value {
                            OverlayValue::Present(value) => Some(value.clone()),
                            OverlayValue::Tombstone => None,
                        },
                    })
                    .collect(),
            },
            KeyspaceState::DupSort { clear_base, rows } => {
                let mut deleted_keys = BTreeSet::new();
                let mut merge_rows = Vec::new();
                for (key, delta) in rows.iter().filter(|(key, _)| include_key(key)) {
                    if delta.delete_base {
                        deleted_keys.insert(key.clone());
                    }
                    let mut by_identity = BTreeMap::<Vec<u8>, BTreeSet<Vec<u8>>>::new();
                    for value in &delta.deleted {
                        by_identity
                            .entry(duplicate_identity(value))
                            .or_default()
                            .insert(value.clone());
                    }
                    for identity in delta.present.keys() {
                        by_identity.entry(identity.clone()).or_default();
                    }
                    for (identity, deleted) in by_identity {
                        merge_rows.push(SnapshotMergeRow::Duplicate {
                            key: key.clone(),
                            present: delta.present.get(&identity).cloned(),
                            identity,
                            deleted,
                        });
                    }
                }
                SnapshotMergePlan {
                    clear_base: *clear_base,
                    deleted_keys,
                    rows: merge_rows,
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn merge_rows(
        &self,
        keyspace: OverlayKeyspace,
        base: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        match self.state.keyspaces[keyspace.slot()].as_ref() {
            KeyspaceState::Single { clear_base, rows } => {
                let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = if *clear_base {
                    BTreeMap::new()
                } else {
                    base.into_iter().collect()
                };
                for (key, value) in rows {
                    match value {
                        OverlayValue::Present(value) => {
                            merged.insert(key.clone(), value.clone());
                        }
                        OverlayValue::Tombstone => {
                            merged.remove(key);
                        }
                    }
                }
                merged.into_iter().collect()
            }
            KeyspaceState::DupSort { clear_base, rows } => {
                let mut merged: BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>> = BTreeMap::new();
                if !*clear_base {
                    for (key, value) in base {
                        merged
                            .entry(key)
                            .or_default()
                            .insert(duplicate_identity(&value), value);
                    }
                }
                for (key, delta) in rows {
                    let values = merged.entry(key.clone()).or_default();
                    if delta.delete_base {
                        values.clear();
                    }
                    for deleted in &delta.deleted {
                        let identity = duplicate_identity(deleted);
                        if values.get(&identity) == Some(deleted) {
                            values.remove(&identity);
                        }
                    }
                    for (identity, value) in &delta.present {
                        values.insert(identity.clone(), value.clone());
                    }
                    if values.is_empty() {
                        merged.remove(key);
                    }
                }
                merged
                    .into_iter()
                    .flat_map(|(key, values)| {
                        values.into_values().map(move |value| (key.clone(), value))
                    })
                    .collect()
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn row_count(&self, keyspace: OverlayKeyspace) -> usize {
        self.merge_rows(keyspace, Vec::new()).len()
    }

    /// Live overlay rows in `keyspace` whose key satisfies `include_key`.
    ///
    /// Tombstones are excluded: a masked base row is not an overlay row. Used
    /// by close's PRE-close census, which must count what is about to
    /// evaporate while it is still observable.
    pub(crate) fn live_row_count(
        &self,
        keyspace: OverlayKeyspace,
        include_key: impl Fn(&[u8]) -> bool,
    ) -> usize {
        self.merge_plan(keyspace, include_key)
            .rows
            .iter()
            .filter(|row| match row {
                SnapshotMergeRow::Single { value, .. } => value.is_some(),
                SnapshotMergeRow::Duplicate { present, .. } => present.is_some(),
            })
            .count()
    }

    /// Journal entries staging a TRANSCRIPT entity put — the turn, its
    /// messages, and its summary. Close reports these as `turns_deleted`
    /// alongside the legacy fenced-base PolicyDelete count, because an
    /// overlay-witnessed turn stops existing at close exactly as a
    /// hard-deleted fenced one does.
    ///
    /// Edge-only entries under the same roles do not count: a `PartOf` or
    /// `DerivedFrom` edge is not an entity that stopped existing.
    pub(crate) fn transcript_entity_put_count(&self) -> usize {
        self.state
            .journal
            .iter()
            .filter(|entry| {
                matches!(
                    entry.role,
                    JournalRole::TurnPut
                        | JournalRole::MessagePartOf
                        | JournalRole::SummaryDerivedFrom
                ) && matches!(entry.op, BatchOp::Put { .. })
            })
            .count()
    }

    /// Read view of the typed journal, in staging order.
    pub(crate) fn journal_entries(&self) -> &[JournalEntry] {
        &self.state.journal
    }

    /// Cuts ONE turn's promotable closure out of the typed journal
    /// (ARCH-0052 D4, ONE-1730).
    ///
    /// Selection reads journal METADATA only — the role tag and the scope the
    /// witnessing write recorded. It never consults a type-index,
    /// text-posting, short-id, temporal, or edge-index key: those keys are
    /// shared between turns by construction, so key-shaped selection would
    /// drag a sibling turn's rows into a promotion the user consented to for
    /// exactly one turn.
    ///
    /// The closure is: the requested turn's own scoped entries (its
    /// materialized TURN put, its `PartOf` MESSAGE puts, its `DerivedFrom`
    /// SUMMARY puts, its closure-internal attribution edges — see
    /// [`attribution_edge_is_closure_internal`] — and every op explicitly
    /// tagged as that turn's owned artifact) plus the room's one fresh
    /// CONVERSATION shell, which is selected by the shell role against the
    /// turn's OWN conversation. The shell is staged once per room, under the first
    /// witness's scope, so a later sibling turn would otherwise promote
    /// `BelongsTo` edges pointing at a conversation with no entity row.
    ///
    /// A turn with no materialized TURN put has nothing to promote and is
    /// refused: promotion replays a subgraph, and a closure with no turn body
    /// is not one.
    pub(crate) fn plan_promotion(&self, turn: EntityId) -> Result<PromotePlan> {
        let conversation = self
            .journal_entries()
            .iter()
            .find(|entry| {
                entry.role == JournalRole::TurnPut
                    && entry.scope.turn() == turn
                    && matches!(&entry.op, BatchOp::Put { id, .. } if *id == turn)
            })
            .map(|entry| entry.scope.conversation())
            .ok_or_else(|| Error::OffRecordTurnNotInJournal {
                turn_ref: turn.to_hex(),
            })?;

        let mut ops = Vec::new();
        let mut replayed = Vec::new();
        let mut source_learned_at = BTreeSet::new();
        for entry in self
            .journal_entries()
            .iter()
            .filter(|entry| journal_entry_in_closure(entry, turn, conversation))
        {
            if let BatchOp::Put { id, .. } = &entry.op {
                replayed.push(*id);
            }
            source_learned_at.insert(entry.learned_at);
            ops.push(promotion_replay_op(entry)?);
        }

        // In-room aliases, read from the overlay's OWN short-id tables. Base
        // short ids do not exist for these ids yet — the ordinary apply mints
        // them during the replay — so this half of the mapping can only come
        // from here.
        let mut temporary_short_ids = Vec::new();
        for id in &replayed {
            if let SnapshotLookup::Present(value) =
                self.lookup_single(OverlayKeyspace::ShortIdsReverse, id.as_bytes())
            {
                let (short_id, _content_hash) = parse_session_short_id_value(&value)?;
                temporary_short_ids.push((*id, short_id.to_owned()));
            }
        }

        Ok(PromotePlan {
            ops,
            replayed,
            temporary_short_ids,
            source_learned_at: source_learned_at.into_iter().collect(),
            turn,
            conversation,
        })
    }

    #[cfg(test)]
    pub(crate) fn journal_ops(&self, scope: JournalScope) -> Vec<BatchOp> {
        self.state
            .journal
            .iter()
            .filter(|entry| entry.scope == scope)
            .map(|entry| entry.op.clone())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn bytes_used(&self) -> usize {
        self.state.bytes_used
    }
}

struct TxnSegment {
    overlay: Arc<SessionOverlay>,
    generation: u64,
    preview: Arc<OverlayState>,
    mutations: Vec<OverlayMutation>,
    #[allow(
        dead_code,
        reason = "typed journal staging is consumed by ONE-1730 promotion"
    )]
    journal: Vec<JournalEntry>,
    journal_bytes: usize,
    _lease: Lease,
}

thread_local! {
    static ACTIVE_SEGMENT: RefCell<Option<TxnSegment>> = const { RefCell::new(None) };
}

static NEXT_OVERLAY_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Persistent-COW in-memory overlay shared by one live session.
pub(crate) struct SessionOverlay {
    state: ArcSwap<OverlayState>,
    lifecycle: Mutex<Lifecycle>,
    lease_drained: Condvar,
    segment_available: Condvar,
    budget_bytes: usize,
}

impl SessionOverlay {
    pub(crate) fn new(budget_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            state: ArcSwap::from_pointee(OverlayState::empty()),
            lifecycle: Mutex::new(Lifecycle {
                state: OverlayLifecycleState::Live,
                generation: NEXT_OVERLAY_GENERATION.fetch_add(1, Ordering::Relaxed),
                mode_generation: 0,
                leases: 0,
                segment_active: false,
            }),
            lease_drained: Condvar::new(),
            segment_available: Condvar::new(),
            budget_bytes,
        })
    }

    #[allow(
        dead_code,
        reason = "ONE-1726 budget oracle introspection; production admission uses the private field"
    )]
    pub(crate) const fn budget_bytes(&self) -> usize {
        self.budget_bytes
    }

    /// Lock-free taint-set membership exported through the registry's
    /// immutable session snapshot. Closed overlays retain this immutable
    /// state until the registry drops them, so close cannot create a false
    /// negative between classification and the write-door decision.
    pub(crate) fn contains_entity(&self, id: &EntityId) -> Result<bool> {
        let state = self.state.load();
        let KeyspaceState::Single { rows, .. } =
            state.keyspaces[OverlayKeyspace::Entities.slot()].as_ref()
        else {
            return Err(Error::InvariantViolation(
                "entities overlay keyspace unexpectedly uses DUP_SORT",
            ));
        };
        Ok(matches!(
            rows.get(id.as_bytes().as_slice()),
            Some(OverlayValue::Present(_))
        ))
    }

    pub(crate) fn has_entities(&self) -> Result<bool> {
        let state = self.state.load();
        let KeyspaceState::Single { rows, .. } =
            state.keyspaces[OverlayKeyspace::Entities.slot()].as_ref()
        else {
            return Err(Error::InvariantViolation(
                "entities overlay keyspace unexpectedly uses DUP_SORT",
            ));
        };
        Ok(rows
            .values()
            .any(|value| matches!(value, OverlayValue::Present(_))))
    }

    /// The currently published mode generation, read under the state lock.
    /// [`SessionWriteRoute`] is the only consumer.
    fn mode_generation(&self) -> Result<u64> {
        Ok(self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?
            .mode_generation)
    }

    /// Seals the overlay write path while leaving composed reads available.
    /// The transition first blocks new segment installers, then drains the one
    /// permitted active writer before publishing `Sealed`.
    ///
    /// The seal is permanent EXCEPT for the K10 flip-back: [`Self::rearm`]
    /// transitions `Sealed` -> `Live` when a session flips back to
    /// `OffRecord`. Every other state stays terminal.
    pub(crate) fn seal_writes(self: &Arc<Self>) -> Result<()> {
        let holds_active_segment = ACTIVE_SEGMENT.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|segment| Arc::ptr_eq(&segment.overlay, self))
        });
        if holds_active_segment {
            return Err(Error::InvariantViolation(
                "session overlay seal called while this thread holds an active txn segment",
            ));
        }

        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        match lifecycle.state {
            OverlayLifecycleState::Live => {
                lifecycle.state = OverlayLifecycleState::Sealing;
                self.segment_available.notify_all();
            }
            OverlayLifecycleState::Sealed => return Ok(()),
            OverlayLifecycleState::Sealing
            | OverlayLifecycleState::Closing
            | OverlayLifecycleState::Gone => {
                return Err(Error::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                });
            }
        }
        while lifecycle.segment_active {
            lifecycle = self.segment_available.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        lifecycle.state = OverlayLifecycleState::Sealed;
        lifecycle.mode_generation = next_mode_generation(lifecycle.mode_generation)?;
        Ok(())
    }

    /// K10 flip-back: re-enables overlay writes when a session returns to
    /// `OffRecord` mode. The ONLY legal transition is `Sealed` -> `Live`
    /// (`Live` IS the landed write-enabled state — no `Armed` variant exists;
    /// K10's "armed" prose names `Live`). Every other state — including a
    /// `Live` overlay that was never sealed — is refused, so rearm can never
    /// resurrect a closing or closed overlay.
    ///
    /// Publishing bumps the mode generation, so any [`SessionWriteRoute`]
    /// minted before the flip-back is refused by [`SessionWriteRoute::revalidate`]
    /// before it can stage. The room's earlier turns stay visible in-session
    /// and unextractable through base: rearm reopens the write door only, and
    /// touches no row.
    pub(crate) fn rearm(self: &Arc<Self>) -> Result<()> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state != OverlayLifecycleState::Sealed {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
        }
        lifecycle.state = OverlayLifecycleState::Live;
        lifecycle.mode_generation = next_mode_generation(lifecycle.mode_generation)?;
        Ok(())
    }

    pub(crate) fn snapshot(self: &Arc<Self>) -> Result<OverlaySnapshot> {
        let active = ACTIVE_SEGMENT.with(|slot| {
            let slot = slot.borrow();
            slot.as_ref().and_then(|segment| {
                Arc::ptr_eq(&segment.overlay, self)
                    .then(|| (segment.generation, segment.preview.clone()))
            })
        });

        if let Some((generation, state)) = active {
            let lease = self.acquire_existing_lease(generation)?;
            return Ok(OverlaySnapshot {
                state,
                _lease: lease,
            });
        }

        let lease = self.acquire_read_lease()?;
        let state = self.state.load_full();
        Ok(OverlaySnapshot {
            state,
            _lease: lease,
        })
    }

    #[allow(
        dead_code,
        reason = "ONE-1728 witness is the first lib-target session write transaction"
    )]
    pub(crate) fn install_txn_segment(self: &Arc<Self>) -> Result<TxnSegmentGuard> {
        ACTIVE_SEGMENT.with(|slot| {
            if slot.borrow().is_some() {
                return Err(Error::InvariantViolation(
                    "a session txn segment is already installed on this thread",
                ));
            }
            Ok(())
        })?;

        let lease = self.acquire_segment_lease()?;
        let generation = lease.generation;
        let snapshot = self.state.load_full();
        let segment = TxnSegment {
            overlay: self.clone(),
            generation,
            preview: snapshot,
            mutations: Vec::new(),
            journal: Vec::new(),
            journal_bytes: 0,
            _lease: lease,
        };
        let install_result = ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return Err(Error::InvariantViolation(
                    "a session txn segment is already installed on this thread",
                ));
            }
            *slot = Some(segment);
            Ok(())
        });
        if let Err(error) = install_result {
            self.release_segment_writer();
            return Err(error);
        }
        Ok(TxnSegmentGuard {
            overlay: self.clone(),
            finished: false,
            _not_send: PhantomData,
        })
    }

    pub(crate) fn put(
        self: &Arc<Self>,
        keyspace: OverlayKeyspace,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        self.reject_unbudgetable_payload(key, value)?;
        let mutation = OverlayMutation::Put {
            keyspace,
            key: key.to_vec(),
            value: value.to_vec(),
        };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    #[allow(
        dead_code,
        reason = "ONE-1728 witness/retrieval supplies the first lib-target overlay delete"
    )]
    pub(crate) fn delete(self: &Arc<Self>, keyspace: OverlayKeyspace, key: &[u8]) -> Result<()> {
        self.delete_with_base_backing(keyspace, key, true)
    }

    pub(crate) fn delete_with_base_backing(
        self: &Arc<Self>,
        keyspace: OverlayKeyspace,
        key: &[u8],
        base_backed: bool,
    ) -> Result<()> {
        let mutation = OverlayMutation::Delete {
            keyspace,
            key: key.to_vec(),
            base_backed,
        };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    pub(crate) fn delete_duplicate(
        self: &Arc<Self>,
        keyspace: OverlayKeyspace,
        key: &[u8],
        value: &[u8],
        base_backed: bool,
    ) -> Result<()> {
        self.reject_unbudgetable_payload(key, value)?;
        let mutation = OverlayMutation::DeleteDuplicate {
            keyspace,
            key: key.to_vec(),
            value: value.to_vec(),
            base_backed,
        };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    pub(crate) fn clear(self: &Arc<Self>, keyspace: OverlayKeyspace) -> Result<()> {
        let mutation = OverlayMutation::Clear { keyspace };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    /// Allocates this entity's session-local short id and content-hash byte
    /// (ARCH-0052 §7).
    ///
    /// In-room short ids are TEMPORARY PRESENTATION ALIASES. Canonical ids are
    /// allocated at promote (ONE-1730), so this counter draws from a
    /// session-scoped namespace held entirely in the overlay `ShortIds` /
    /// `ShortIdsReverse` keyspaces: the base `sid_counter:<type_byte>` rows and
    /// the base short-id tables are never read and never written, and every
    /// alias minted here evaporates at close.
    ///
    /// The alias is deliberately NOT format-compatible with a base short id.
    /// A base alias is `<two lowercase letters><decimal digits>`, and both
    /// short-ref parsers (`api/core.rs::parse_short_ref_parts`,
    /// `mcp.rs::validate_short_ref_parts`) accept exactly that shape. Minting
    /// session aliases in the same space would let a room alias collide with —
    /// and, through the composed overlay ∪ base read, MASK — a real base
    /// entity's alias for the length of the session. The `s` sigil puts the
    /// room namespace outside the base grammar, so a session alias cannot be
    /// mistaken for a durable one by any existing reader, and a caller that
    /// leaks one to a base door gets a clean parse rejection rather than a
    /// silent hit on the wrong entity.
    ///
    /// The content-hash byte uses the base scheme (`xxh32(data, 0) % 256`) so
    /// `Vault::hydrate_short_id`'s `(short_id, content_hash)` pairing behaves
    /// identically in-session.
    ///
    /// Re-allocating an id already aliased in this room returns the existing
    /// alias with a refreshed content hash, mirroring the base
    /// `plan_short_id_update` update arm: an alias is stable for the entity's
    /// lifetime in the room even as its body changes.
    pub(crate) fn alloc_session_short_id(
        self: &Arc<Self>,
        id: &EntityId,
        data: &[u8],
    ) -> Result<(String, u8)> {
        let content_hash = session_short_id_content_hash(data);
        let snapshot = self.snapshot()?;

        // An id already aliased in this room keeps its alias; only the
        // content-hash byte (part of the forward KEY) is refreshed, so the
        // stale forward row is retired first.
        if let SnapshotLookup::Present(existing) =
            snapshot.lookup_single(OverlayKeyspace::ShortIdsReverse, id.as_bytes())
        {
            let (short_id, old_content_hash) = parse_session_short_id_value(&existing)?;
            let short_id = short_id.to_owned();
            if old_content_hash != content_hash {
                self.delete_with_base_backing(
                    OverlayKeyspace::ShortIds,
                    &encode_session_short_id_forward_key(&short_id, old_content_hash),
                    false,
                )?;
            }
            self.put_session_short_id_rows(id, &short_id, content_hash)?;
            return Ok((short_id, content_hash));
        }

        // The room counter is the live alias count, read from the same
        // snapshot the allocation stages into: reverse rows are one-per-entity
        // and never deleted mid-room, so the next ordinal cannot collide with
        // an alias already minted in this segment.
        let next = snapshot
            .live_row_count(OverlayKeyspace::ShortIdsReverse, |_| true)
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session short id counter"))?;
        let short_id = format!("{SESSION_SHORT_ID_SIGIL}{next}");
        self.put_session_short_id_rows(id, &short_id, content_hash)?;
        Ok((short_id, content_hash))
    }

    /// Stages both session short-id rows, mirroring the base pair: forward
    /// `(short_id ‖ content_hash)` -> entity id, reverse entity id -> the same
    /// bytes as the forward key.
    fn put_session_short_id_rows(
        self: &Arc<Self>,
        id: &EntityId,
        short_id: &str,
        content_hash: u8,
    ) -> Result<()> {
        let forward_key = encode_session_short_id_forward_key(short_id, content_hash);
        self.put(OverlayKeyspace::ShortIds, &forward_key, id.as_bytes())?;
        self.put(
            OverlayKeyspace::ShortIdsReverse,
            id.as_bytes(),
            &forward_key,
        )
    }

    /// Stages one typed, role-tagged journal op into the active txn segment.
    ///
    /// The ONLY journal staging surface: every staged op carries its
    /// [`JournalRole`] and the witnessing write's own `learned_at`/`occurred`,
    /// so promote can never fall back on inferring ownership from index keys
    /// or on restamping the room clock.
    pub(crate) fn stage_journal_entry(self: &Arc<Self>, entry: JournalEntry) -> Result<()> {
        let incoming_bytes = entry.byte_size();
        ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(segment) = slot.as_mut() else {
                return Err(Error::InvariantViolation(
                    "session overlay write requires an active txn segment",
                ));
            };
            if !Arc::ptr_eq(&segment.overlay, self) {
                return Err(Error::InvariantViolation(
                    "the active txn segment belongs to another session overlay",
                ));
            }
            let current_bytes = segment
                .preview
                .bytes_used
                .checked_add(segment.journal_bytes)
                .ok_or(Error::ArithmeticOverflow("overlay staged byte count"))?;
            self.ensure_budget(current_bytes, incoming_bytes)?;
            segment.journal.push(entry);
            segment.journal_bytes = segment.journal_bytes.checked_add(incoming_bytes).ok_or(
                Error::ArithmeticOverflow("overlay staged journal byte count"),
            )?;
            Ok(())
        })
    }

    /// Retires a promoted closure from the live overlay (ARCH-0052 D4,
    /// ONE-1730). Called ONLY after the promote transaction commits.
    ///
    /// Every retired row is removed OUTRIGHT, never tombstoned. A tombstone
    /// masks the base row underneath, and the row underneath is now the
    /// promoted one — masking it would make the room lose sight of the turn it
    /// just published. Removal is therefore conditional on the key being
    /// PRESENT in the overlay: a delete of an absent key is exactly what the
    /// mutation path turns into a mask.
    ///
    /// Rows whose overlay copy is byte-identical to the base copy the replay
    /// just wrote — BM25 postings/stats, vector and HNSW rows — are left in
    /// place deliberately. Their keys and duplicate identities are the same on
    /// both sides, so the composed read returns one row either way, and the
    /// accumulator halves (`total_docs`, per-field lengths) are room-scoped
    /// counts that must keep answering for the room until it evaporates.
    ///
    /// The journal entries go with them, so a later close counts the promoted
    /// turn as published rather than as transcript that stopped existing.
    pub(crate) fn retire_promoted_closure(self: &Arc<Self>, plan: &PromotePlan) -> Result<()> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state == OverlayLifecycleState::Gone {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
        }
        let mut next = self.state.load_full().as_ref().clone();

        for op in &plan.ops {
            match op {
                BatchOp::Put {
                    id,
                    entity_type,
                    occurred,
                    learned_at,
                    ..
                } => {
                    drop_overlay_row(&mut next, OverlayKeyspace::Entities, id.as_bytes());
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::TypeIndex,
                        &Store::encode_type_key(*entity_type, id),
                    );
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::TemporalOccurredStart,
                        &Store::encode_temporal_key(occurred.start, id),
                    );
                    if occurred.start != occurred.end {
                        drop_overlay_row(
                            &mut next,
                            OverlayKeyspace::TemporalOccurredEnd,
                            &Store::encode_temporal_key(occurred.end, id),
                        );
                    }
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::TemporalLearned,
                        &Store::encode_temporal_key(*learned_at, id),
                    );
                    if occurred.end.saturating_sub(occurred.start) > LONG_INTERVAL_THRESHOLD_SECS {
                        drop_overlay_row(
                            &mut next,
                            OverlayKeyspace::TemporalLongIntervals,
                            &Store::encode_temporal_key(occurred.end, id),
                        );
                    }
                }
                BatchOp::PublicEdgeWithCreatedAt { src, kind, tgt, .. } => {
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::EdgesOut,
                        &Store::encode_edge_key(src, *kind, tgt),
                    );
                    drop_overlay_row(
                        &mut next,
                        OverlayKeyspace::EdgesIn,
                        &Store::encode_edge_key(tgt, *kind, src),
                    );
                }
                _ => {}
            }
        }

        // The in-room alias pair. The forward key is stored verbatim as the
        // reverse row's VALUE, so the pair retires without re-deriving a
        // content hash that the body may have moved past.
        for id in &plan.replayed {
            let forward_key = match next.keyspaces[OverlayKeyspace::ShortIdsReverse.slot()].as_ref()
            {
                KeyspaceState::Single { rows, .. } => match rows.get(id.as_bytes().as_slice()) {
                    Some(OverlayValue::Present(value)) => Some(value.clone()),
                    Some(OverlayValue::Tombstone) | None => None,
                },
                KeyspaceState::DupSort { .. } => None,
            };
            if let Some(forward_key) = forward_key {
                drop_overlay_row(&mut next, OverlayKeyspace::ShortIds, &forward_key);
                drop_overlay_row(&mut next, OverlayKeyspace::ShortIdsReverse, id.as_bytes());
            }
        }

        let turn = plan.turn;
        let conversation = plan.conversation;
        Arc::make_mut(&mut next.journal)
            .retain(|entry| !journal_entry_in_closure(entry, turn, conversation));
        next.recalculate_bytes();
        self.state.store(Arc::new(next));
        drop(lifecycle);
        Ok(())
    }

    pub(crate) fn close(self: &Arc<Self>) -> Result<()> {
        // A close nested inside this thread's own active segment would wait on a lease
        // that only this stack can release (the guard drops when it unwinds past here).
        // Fail fast — in the single-writer model close is a session-lifecycle op, never
        // nested inside an active write segment — leaving the overlay Live and usable.
        let holds_active_segment = ACTIVE_SEGMENT.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|segment| Arc::ptr_eq(&segment.overlay, self))
        });
        if holds_active_segment {
            return Err(Error::InvariantViolation(
                "session overlay close called while this thread holds an active txn segment",
            ));
        }

        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        match lifecycle.state {
            OverlayLifecycleState::Live | OverlayLifecycleState::Sealed => {
                lifecycle.state = OverlayLifecycleState::Closing;
                // Wake every installer parked on the segment permit so each re-checks the
                // terminal lifecycle state and returns the closed error instead of sleeping;
                // release_segment_writer's notify_one only ever wakes a single waiter.
                self.segment_available.notify_all();
            }
            OverlayLifecycleState::Sealing
            | OverlayLifecycleState::Closing
            | OverlayLifecycleState::Gone => {
                return Err(Error::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                });
            }
        }
        while lifecycle.leases != 0 {
            lifecycle = self.lease_drained.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        // Retain the immutable state as the registry's fail-closed membership
        // snapshot until the entry itself is unpublished. No read lease can
        // observe it after the lifecycle reaches Gone.
        lifecycle.generation = lifecycle
            .generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay generation"))?;
        lifecycle.state = OverlayLifecycleState::Gone;
        Ok(())
    }

    fn preflight_segment_mutation(self: &Arc<Self>, mutation: &OverlayMutation) -> Result<()> {
        ACTIVE_SEGMENT.with(|slot| {
            let slot = slot.borrow();
            let Some(segment) = slot.as_ref() else {
                return Err(Error::InvariantViolation(
                    "session overlay write requires an active txn segment",
                ));
            };
            if !Arc::ptr_eq(&segment.overlay, self) {
                return Err(Error::InvariantViolation(
                    "the active txn segment belongs to another session overlay",
                ));
            }
            let current_bytes = segment
                .preview
                .bytes_used
                .checked_add(segment.journal_bytes)
                .ok_or(Error::ArithmeticOverflow("overlay staged byte count"))?;
            let projected = project_mutation(&segment.preview, mutation)?;
            self.ensure_mutation_budget(
                current_bytes,
                segment.preview.bytes_used,
                projected.bytes_used,
            )
        })
    }

    fn stage_mutation(self: &Arc<Self>, mutation: OverlayMutation) -> Result<()> {
        ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(segment) = slot.as_mut() else {
                return Err(Error::InvariantViolation(
                    "session overlay write requires an active txn segment",
                ));
            };
            if !Arc::ptr_eq(&segment.overlay, self) {
                return Err(Error::InvariantViolation(
                    "the active txn segment belongs to another session overlay",
                ));
            }
            segment.preview = Self::apply_preflighted_to_state(
                segment.preview.clone(),
                std::slice::from_ref(&mutation),
                &[],
            )?;
            segment.mutations.push(mutation);
            Ok(())
        })
    }

    #[allow(
        dead_code,
        reason = "reachable through the ONE-1728 production session write path"
    )]
    fn acquire_segment_lease(self: &Arc<Self>) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        while lifecycle.segment_active {
            if lifecycle.state != OverlayLifecycleState::Live {
                return Err(Error::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                });
            }
            // Base writers are acquired before this permit (base -> segment). Commit
            // releases the base writer before applying/releasing this permit and never
            // reacquires it, so there is no reverse-order path and waiters make progress.
            lifecycle = self.segment_available.wait(lifecycle).map_err(|_| {
                Error::InvariantViolation("session overlay lifecycle mutex poisoned")
            })?;
        }
        if lifecycle.state != OverlayLifecycleState::Live {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        lifecycle.segment_active = true;
        Ok(Lease {
            overlay: self.clone(),
            generation: lifecycle.generation,
        })
    }

    #[allow(
        dead_code,
        reason = "reachable through the ONE-1728 production session write path"
    )]
    fn release_segment_writer(&self) {
        if let Ok(mut lifecycle) = self.lifecycle.lock() {
            lifecycle.segment_active = false;
            self.segment_available.notify_all();
        }
    }

    fn acquire_read_lease(self: &Arc<Self>) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if !matches!(
            lifecycle.state,
            OverlayLifecycleState::Live | OverlayLifecycleState::Sealed
        ) {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: lifecycle.generation,
            });
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        Ok(Lease {
            overlay: self.clone(),
            generation: lifecycle.generation,
        })
    }

    fn acquire_existing_lease(self: &Arc<Self>, generation: u64) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state == OverlayLifecycleState::Gone || lifecycle.generation != generation {
            return Err(Error::OffRecordOverlayLeaseClosed { generation });
        }
        lifecycle.leases = lifecycle
            .leases
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("session overlay lease count"))?;
        Ok(Lease {
            overlay: self.clone(),
            generation,
        })
    }

    #[allow(
        dead_code,
        reason = "reachable through the ONE-1728 production session write path"
    )]
    fn apply_segment(&self, segment: &TxnSegment) -> Result<()> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state == OverlayLifecycleState::Gone
            || lifecycle.generation != segment.generation
        {
            return Err(Error::OffRecordOverlayLeaseClosed {
                generation: segment.generation,
            });
        }
        let state = self.state.load_full();
        let next = Self::apply_preflighted_to_state(state, &segment.mutations, &segment.journal)?;
        self.state.store(next);
        Ok(())
    }

    // Budget failures belong exclusively to preflight, before the base commit.
    // This apply helper deliberately has no budget input or budget-error branch.
    fn apply_preflighted_to_state(
        state: Arc<OverlayState>,
        mutations: &[OverlayMutation],
        journal: &[JournalEntry],
    ) -> Result<Arc<OverlayState>> {
        let mut next = state.as_ref().clone();
        for mutation in mutations {
            next = project_mutation(&next, mutation)?;
        }
        for entry in journal {
            Arc::make_mut(&mut next.journal).push(entry.clone());
            next.recalculate_bytes();
        }
        Ok(Arc::new(next))
    }

    fn ensure_mutation_budget(
        &self,
        current_bytes: usize,
        old_mutation_bytes: usize,
        new_mutation_bytes: usize,
    ) -> Result<()> {
        let Some(net_increase) = new_mutation_bytes.checked_sub(old_mutation_bytes) else {
            return Ok(());
        };
        if net_increase == 0 {
            return Ok(());
        }
        self.ensure_budget(current_bytes, net_increase)
    }

    /// Reject a payload whose own bytes exceed the entire budget before it is cloned
    /// into an owned mutation. Any such mutation is unconditionally rejected by the
    /// net-delta preflight anyway (a single key of that size alone exceeds the budget),
    /// so this only fast-paths the guaranteed rejection while capping transient
    /// allocation at the budget. Admittable mutations have payload <= budget and are
    /// unaffected, so shrink/overwrite-at-cap admission is preserved.
    fn reject_unbudgetable_payload(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let payload_bytes = key
            .len()
            .checked_add(value.len())
            .ok_or(Error::ArithmeticOverflow("overlay payload byte count"))?;
        if payload_bytes > self.budget_bytes {
            return Err(Error::OffRecordOverlayFull {
                budget_bytes: self.budget_bytes,
                attempted_bytes: payload_bytes,
            });
        }
        Ok(())
    }

    fn ensure_budget(&self, current_bytes: usize, incoming_bytes: usize) -> Result<()> {
        let attempted_bytes = current_bytes
            .checked_add(incoming_bytes)
            .ok_or(Error::ArithmeticOverflow("overlay attempted byte count"))?;
        if attempted_bytes > self.budget_bytes {
            return Err(Error::OffRecordOverlayFull {
                budget_bytes: self.budget_bytes,
                attempted_bytes,
            });
        }
        Ok(())
    }
}

/// Content-hash byte for a session short id — the base scheme
/// (`xxh32(data, 0) % 256`, batch.rs `plan_short_id_update`), so
/// `hydrate_short_id`'s `(short_id, content_hash)` pairing is identical
/// in-session.
fn session_short_id_content_hash(data: &[u8]) -> u8 {
    (xxh32(data, 0) % 256) as u8
}

/// Encodes the session `ShortIds` forward key `(short_id ‖ content_hash)`,
/// the same byte shape the base tables use — the namespaces are separated by
/// the sigil inside `short_id`, not by a second key encoding.
fn encode_session_short_id_forward_key(short_id: &str, content_hash: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(short_id.len().saturating_add(1));
    key.extend_from_slice(short_id.as_bytes());
    key.push(content_hash);
    key
}

/// Splits a session `ShortIdsReverse` value back into `(short_id, content_hash)`.
fn parse_session_short_id_value(value: &[u8]) -> Result<(&str, u8)> {
    let Some((&content_hash, short_id_bytes)) = value.split_last() else {
        return Err(Error::CorruptedIndex("session short id value"));
    };
    let short_id = str::from_utf8(short_id_bytes)
        .map_err(|_| Error::CorruptedIndex("session short id value"))?;
    Ok((short_id, content_hash))
}

/// Advances the mode-publication counter. Overflow is a hard error rather than
/// a wrap: a wrapped counter could make a stale route revalidate.
fn next_mode_generation(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("session overlay mode generation"))
}

/// Removes one PRESENT overlay row outright, leaving no base mask.
///
/// The presence check is the whole point: [`apply_mutation`]'s delete arm
/// tombstones a key it does not already hold, which is correct for a room
/// hiding a base row and exactly wrong for retiring a row the room just
/// published. DUP_SORT keyspaces are not retired here (see
/// [`SessionOverlay::retire_promoted_closure`]), so this only touches
/// single-valued state.
fn drop_overlay_row(state: &mut OverlayState, keyspace: OverlayKeyspace, key: &[u8]) {
    if let KeyspaceState::Single { rows, .. } = Arc::make_mut(&mut state.keyspaces[keyspace.slot()])
        && matches!(rows.get(key), Some(OverlayValue::Present(_)))
    {
        rows.remove(key);
    }
}

fn project_mutation(state: &OverlayState, mutation: &OverlayMutation) -> Result<OverlayState> {
    let mut projected = state.clone();
    apply_mutation(&mut projected, mutation)?;
    projected.recalculate_bytes();
    Ok(projected)
}

/// RAII owner of the thread-local segment installed for one base write txn.
#[allow(
    dead_code,
    reason = "ONE-1728 witness is the first lib-target owner of a session write segment"
)]
pub(crate) struct TxnSegmentGuard {
    overlay: Arc<SessionOverlay>,
    finished: bool,
    _not_send: PhantomData<Rc<()>>,
}

#[allow(
    dead_code,
    reason = "ONE-1728 witness is the first lib-target committer of a session write segment"
)]
impl TxnSegmentGuard {
    /// Applies staged rows and typed journal entries after base commit.
    pub(crate) fn commit(mut self) -> Result<()> {
        let segment = ACTIVE_SEGMENT.with(|slot| slot.borrow_mut().take());
        let Some(segment) = segment else {
            return Err(Error::InvariantViolation(
                "session txn segment disappeared before commit",
            ));
        };
        if !Arc::ptr_eq(&segment.overlay, &self.overlay) {
            return Err(Error::InvariantViolation(
                "another session txn segment replaced the installed segment",
            ));
        }
        let result = self.overlay.apply_segment(&segment);
        self.finished = true;
        result
    }
}

impl Drop for TxnSegmentGuard {
    fn drop(&mut self) {
        if !self.finished {
            ACTIVE_SEGMENT.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot
                    .as_ref()
                    .is_some_and(|segment| Arc::ptr_eq(&segment.overlay, &self.overlay))
                {
                    slot.take();
                }
            });
        }
        self.overlay.release_segment_writer();
    }
}

fn apply_mutation(state: &mut OverlayState, mutation: &OverlayMutation) -> Result<()> {
    let keyspace = match mutation {
        OverlayMutation::Put { keyspace, .. }
        | OverlayMutation::Delete { keyspace, .. }
        | OverlayMutation::DeleteDuplicate { keyspace, .. }
        | OverlayMutation::Clear { keyspace } => *keyspace,
    };
    let slot = keyspace.slot();
    if matches!(mutation, OverlayMutation::Clear { .. }) {
        state.keyspaces[slot] = Arc::new(KeyspaceState::cleared(keyspace));
        return Ok(());
    }
    let keyspace_state = Arc::make_mut(&mut state.keyspaces[slot]);
    match (keyspace_state, mutation) {
        (KeyspaceState::Single { rows, .. }, OverlayMutation::Put { key, value, .. }) => {
            rows.insert(key.clone(), OverlayValue::Present(value.clone()));
        }
        (
            KeyspaceState::Single { clear_base, rows },
            OverlayMutation::Delete {
                key, base_backed, ..
            },
        ) => {
            let effective_base_backed = *base_backed && !*clear_base;
            if !effective_base_backed && matches!(rows.get(key), Some(OverlayValue::Present(_))) {
                rows.remove(key);
            } else {
                rows.insert(key.clone(), OverlayValue::Tombstone);
            }
        }
        (KeyspaceState::DupSort { rows, .. }, OverlayMutation::Put { key, value, .. }) => {
            let identity = duplicate_identity(value);
            let delta = rows.entry(key.clone()).or_default();
            delta.deleted.remove(value);
            delta.present.insert(identity, value.clone());
        }
        (KeyspaceState::DupSort { rows, .. }, OverlayMutation::Delete { key, .. }) => {
            rows.insert(
                key.clone(),
                DupDelta {
                    delete_base: true,
                    ..DupDelta::default()
                },
            );
        }
        (
            KeyspaceState::DupSort { clear_base, rows },
            OverlayMutation::DeleteDuplicate {
                key,
                value,
                base_backed,
                ..
            },
        ) => {
            let identity = duplicate_identity(value);
            let delta = rows.entry(key.clone()).or_default();
            let effective_base_backed = *base_backed && !*clear_base && !delta.delete_base;
            if delta.present.get(&identity) == Some(value) {
                delta.present.remove(&identity);
            }
            if effective_base_backed {
                delta.deleted.insert(value.clone());
            }
            // An overlay-only delete can empty the delta; a bare row still charges
            // key.len() toward the budget, so drop it (matches the Single path).
            let delta_is_empty =
                delta.present.is_empty() && delta.deleted.is_empty() && !delta.delete_base;
            if delta_is_empty {
                rows.remove(key);
            }
        }
        (KeyspaceState::Single { .. }, OverlayMutation::DeleteDuplicate { .. }) => {
            return Err(Error::InvariantViolation(
                "delete_one_duplicate used on a non-DUP_SORT overlay keyspace",
            ));
        }
        (_, OverlayMutation::Clear { .. }) => unreachable!("clear handled above"),
    }
    Ok(())
}

fn duplicate_identity(value: &[u8]) -> Vec<u8> {
    value.get(..16).unwrap_or(value).to_vec()
}

fn batch_op_payload_bytes(op: &BatchOp) -> usize {
    match op {
        BatchOp::Put { data, .. } => data.len(),
        BatchOp::ClaimCandidate {
            candidate,
            envelope,
            ..
        } => debug_bytes(candidate).saturating_add(debug_bytes(envelope)),
        BatchOp::ReconcileLexicalQueryHints { keep, .. } => {
            keep.len().saturating_mul(std::mem::size_of::<EntityId>())
        }
        BatchOp::Vector {
            vector,
            pending_embedding_token,
            ..
        } => vector
            .len()
            .saturating_mul(std::mem::size_of::<f32>())
            .saturating_add(pending_embedding_token.as_ref().map_or(0, Vec::len)),
        BatchOp::Text { fields, .. } => fields
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .sum(),
        BatchOp::Phonetic { codes, .. } => codes.iter().map(String::len).sum(),
        BatchOp::Edge { .. }
        | BatchOp::PublicEdgeWithCreatedAt { .. }
        | BatchOp::EdgeWithCreatedAt { .. }
        | BatchOp::SetEdgeWeight { .. }
        | BatchOp::SetEdgeVad { .. }
        | BatchOp::Delete { .. }
        | BatchOp::DeleteEdge { .. } => 0,
    }
}

fn debug_bytes(value: &impl std::fmt::Debug) -> usize {
    struct Counter(usize);

    impl std::fmt::Write for Counter {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            self.0 = self.0.saturating_add(value.len());
            Ok(())
        }
    }

    let mut counter = Counter(0);
    let _ = std::fmt::write(&mut counter, format_args!("{value:?}"));
    counter.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay_db::OverlayDb;
    use crate::temporal::TimeRange;
    use heed::types::Bytes;
    use heed::{Database, DatabaseFlags, Env, EnvOpenOptions};
    use std::sync::mpsc::{RecvTimeoutError, sync_channel};
    use std::time::{Duration, Instant};

    const CONCURRENCY_TIMEOUT: Duration = Duration::from_secs(1);

    fn put_op(data: Vec<u8>) -> BatchOp {
        BatchOp::Put {
            id: EntityId::now(),
            entity_type: 1,
            occurred: TimeRange { start: 1, end: 1 },
            learned_at: 1,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }
    }

    /// A journal entry carrying the role and timestamps a witness write would
    /// preserve; the budget/atomicity tests care about bytes, not the tag.
    fn journal_entry(scope: JournalScope, role: JournalRole, op: BatchOp) -> JournalEntry {
        JournalEntry {
            scope,
            role,
            learned_at: 1,
            occurred: TimeRange { start: 1, end: 1 },
            op,
        }
    }

    fn dupsort_test_db() -> (tempfile::TempDir, Env, Database<Bytes, Bytes>) {
        let dir = tempfile::tempdir().expect("session overlay test temp dir");
        // SAFETY: this test owns the freshly created directory and opens it
        // exactly once; the returned directory outlives the environment.
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(16 * 1024 * 1024)
                .max_dbs(1)
                .open(dir.path())
                .expect("open session overlay test env")
        };
        let mut wtxn = env.write_txn().expect("open setup write txn");
        let db = env
            .database_options()
            .types::<Bytes, Bytes>()
            .name("rows")
            .flags(DatabaseFlags::DUP_SORT)
            .create(&mut wtxn)
            .expect("create session overlay test database");
        wtxn.commit().expect("commit session overlay setup");
        (dir, env, db)
    }

    #[test]
    fn same_overlay_segments_serialize_across_threads() -> Result<()> {
        let budget = 7;
        let overlay = SessionOverlay::new(budget);
        let (first_installed_tx, first_installed_rx) = sync_channel(0);
        let (release_first_tx, release_first_rx) = sync_channel(0);
        let first_overlay = overlay.clone();
        let first = std::thread::spawn(move || -> Result<()> {
            let segment = first_overlay.install_txn_segment()?;
            first_overlay.put(OverlayKeyspace::Entities, b"a", &[1_u8; 3])?;
            first_installed_tx
                .send(())
                .expect("first install receiver remains live");
            release_first_rx
                .recv()
                .expect("first release sender remains live");
            segment.commit()
        });
        first_installed_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("first segment installs");

        let (second_attempting_tx, second_attempting_rx) = sync_channel(0);
        let (second_installed_tx, second_installed_rx) = sync_channel(0);
        let second_overlay = overlay.clone();
        let second = std::thread::spawn(move || -> Result<()> {
            second_attempting_tx
                .send(())
                .expect("second attempt receiver remains live");
            let segment = second_overlay.install_txn_segment()?;
            second_installed_tx
                .send(())
                .expect("second install receiver remains live");
            match second_overlay.put(OverlayKeyspace::Entities, b"b", &[2_u8; 3]) {
                Err(Error::OffRecordOverlayFull {
                    budget_bytes,
                    attempted_bytes,
                }) => {
                    assert_eq!(budget_bytes, budget);
                    assert_eq!(attempted_bytes, budget + 1);
                    segment.commit()
                }
                Err(other) => Err(other),
                Ok(()) => {
                    segment.commit()?;
                    Err(Error::InvariantViolation(
                        "serialized second segment escaped budget preflight",
                    ))
                }
            }
        });
        second_attempting_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("second thread reaches install");

        // Without the per-overlay permit, this arrives while both previews are
        // empty; both puts stage, and one of the later applies tears at the budget.
        let second_was_blocked = match second_installed_rx.recv_timeout(CONCURRENCY_TIMEOUT) {
            Err(RecvTimeoutError::Timeout) => true,
            Ok(()) => false,
            Err(RecvTimeoutError::Disconnected) => {
                panic!("second installer disconnected before reporting")
            }
        };
        release_first_tx
            .send(())
            .expect("first segment remains live until release");
        if second_was_blocked {
            second_installed_rx
                .recv_timeout(CONCURRENCY_TIMEOUT)
                .expect("second segment installs after first commit");
        }

        let first_apply = first.join().expect("first segment thread does not panic");
        let second_apply = second.join().expect("second segment thread does not panic");
        assert!(
            second_was_blocked,
            "second segment installed before the first segment finished"
        );
        match first_apply {
            Ok(()) => {}
            Err(Error::OffRecordOverlayFull { .. }) => {
                panic!("first post-commit apply returned OffRecordOverlayFull")
            }
            Err(other) => panic!("first post-commit apply failed: {other}"),
        }
        match second_apply {
            Ok(()) => {}
            Err(Error::OffRecordOverlayFull { .. }) => {
                panic!("second post-commit apply returned OffRecordOverlayFull")
            }
            Err(other) => panic!("second segment failed: {other}"),
        }
        let snapshot = overlay.snapshot()?;
        assert_eq!(snapshot.row_count(OverlayKeyspace::Entities), 1);
        assert_eq!(snapshot.bytes_used(), 4);
        Ok(())
    }

    #[test]
    fn close_wakes_all_blocked_segment_installers() -> Result<()> {
        let overlay = SessionOverlay::new(64);
        let (active_installed_tx, active_installed_rx) = sync_channel(0);
        let (release_active_tx, release_active_rx) = sync_channel(0);
        let active_overlay = overlay.clone();
        let active = std::thread::spawn(move || -> Result<()> {
            let segment = active_overlay.install_txn_segment()?;
            active_installed_tx
                .send(())
                .expect("active install receiver remains live");
            release_active_rx
                .recv()
                .expect("active release sender remains live");
            drop(segment);
            Ok(())
        });
        active_installed_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("active segment installs");

        let (first_attempting_tx, first_attempting_rx) = sync_channel(0);
        let (first_result_tx, first_result_rx) = sync_channel(0);
        let first_overlay = overlay.clone();
        let first_waiter = std::thread::spawn(move || {
            first_attempting_tx
                .send(())
                .expect("first attempt receiver remains live");
            let result = match first_overlay.install_txn_segment() {
                Err(Error::OffRecordOverlayLeaseClosed { .. }) => Ok(()),
                Err(other) => Err(other),
                Ok(segment) => {
                    drop(segment);
                    Err(Error::InvariantViolation(
                        "first blocked installer acquired a closing overlay",
                    ))
                }
            };
            first_result_tx
                .send(result)
                .expect("first result receiver remains live");
        });

        let (second_attempting_tx, second_attempting_rx) = sync_channel(0);
        let (second_result_tx, second_result_rx) = sync_channel(0);
        let second_overlay = overlay.clone();
        let second_waiter = std::thread::spawn(move || {
            second_attempting_tx
                .send(())
                .expect("second attempt receiver remains live");
            let result = match second_overlay.install_txn_segment() {
                Err(Error::OffRecordOverlayLeaseClosed { .. }) => Ok(()),
                Err(other) => Err(other),
                Ok(segment) => {
                    drop(segment);
                    Err(Error::InvariantViolation(
                        "second blocked installer acquired a closing overlay",
                    ))
                }
            };
            second_result_tx
                .send(result)
                .expect("second result receiver remains live");
        });

        first_attempting_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("first waiter reaches install");
        second_attempting_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("second waiter reaches install");

        let (close_result_tx, close_result_rx) = sync_channel(0);
        let closing_overlay = overlay.clone();
        let closer = std::thread::spawn(move || {
            close_result_tx
                .send(closing_overlay.close())
                .expect("close result receiver remains live");
        });

        let closing_deadline = Instant::now() + CONCURRENCY_TIMEOUT;
        loop {
            let state = overlay
                .lifecycle
                .lock()
                .expect("overlay lifecycle remains available")
                .state;
            if state == OverlayLifecycleState::Closing {
                break;
            }
            assert!(
                Instant::now() < closing_deadline,
                "closer did not transition the overlay to Closing"
            );
            std::thread::yield_now();
        }

        release_active_tx
            .send(())
            .expect("active segment remains live until release");
        first_result_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("first blocked installer wakes on close")?;
        second_result_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("second blocked installer wakes on close")?;
        close_result_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("closer returns after the active segment drains")?;

        active
            .join()
            .expect("active segment thread does not panic")?;
        first_waiter
            .join()
            .expect("first blocked installer does not panic");
        second_waiter
            .join()
            .expect("second blocked installer does not panic");
        closer.join().expect("closer thread does not panic");
        Ok(())
    }

    #[test]
    fn close_while_holding_own_segment_fails_fast() -> Result<()> {
        let overlay = SessionOverlay::new(64);
        let segment = overlay.install_txn_segment()?;

        match overlay.close() {
            Err(Error::InvariantViolation(message)) => assert_eq!(
                message,
                "session overlay close called while this thread holds an active txn segment"
            ),
            Err(other) => panic!("unexpected close error: {other}"),
            Ok(()) => panic!("same-thread close unexpectedly succeeded"),
        }

        drop(segment);
        let fresh_segment = overlay.install_txn_segment()?;
        let snapshot = overlay.snapshot()?;
        assert_eq!(snapshot.bytes_used(), 0);
        drop(snapshot);
        drop(fresh_segment);
        Ok(())
    }

    #[test]
    fn apply_is_budget_infallible_after_authoritative_preflight() -> Result<()> {
        let budget = 8;
        let overlay = SessionOverlay::new(budget);
        let segment = overlay.install_txn_segment()?;
        overlay.put(OverlayKeyspace::Entities, b"a", &[1_u8; 5])?;
        segment.commit()?;
        assert_eq!(overlay.snapshot()?.bytes_used(), 6);

        let segment = overlay.install_txn_segment()?;
        match overlay.put(OverlayKeyspace::Entities, b"b", &[2_u8; 2]) {
            Err(Error::OffRecordOverlayFull {
                budget_bytes,
                attempted_bytes,
            }) => {
                assert_eq!(budget_bytes, budget);
                assert_eq!(attempted_bytes, budget + 1);
            }
            Err(other) => panic!("unexpected preflight error: {other}"),
            Ok(()) => panic!("over-budget mutation escaped preflight"),
        }
        match segment.commit() {
            Ok(()) => {}
            Err(Error::OffRecordOverlayFull { .. }) => {
                panic!("empty post-preflight apply returned OffRecordOverlayFull")
            }
            Err(other) => panic!("empty post-preflight apply failed: {other}"),
        }
        assert_eq!(overlay.snapshot()?.bytes_used(), 6);

        // Production staging cannot create this state: preflight above rejects it.
        // Injecting it test-only proves the post-base-commit helper is structurally
        // budget-free and cannot construct OffRecordOverlayFull even at 9/8 bytes.
        let segment = overlay.install_txn_segment()?;
        ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let active = slot.as_mut().expect("the test segment is installed");
            active.mutations.push(OverlayMutation::Put {
                keyspace: OverlayKeyspace::Entities,
                key: b"b".to_vec(),
                value: vec![2_u8; 2],
            });
        });
        match segment.commit() {
            Ok(()) => {}
            Err(Error::OffRecordOverlayFull { .. }) => {
                panic!("post-commit apply reconstructed OffRecordOverlayFull")
            }
            Err(other) => panic!("post-commit apply failed: {other}"),
        }
        let snapshot = overlay.snapshot()?;
        assert_eq!(snapshot.row_count(OverlayKeyspace::Entities), 2);
        assert_eq!(snapshot.bytes_used(), budget + 1);
        Ok(())
    }

    #[test]
    #[allow(clippy::unnecessary_wraps)]
    fn different_overlays_keep_segment_concurrency_parallel() -> Result<()> {
        let first_overlay = SessionOverlay::new(64);
        let other_overlay = SessionOverlay::new(64);
        let (first_installed_tx, first_installed_rx) = sync_channel(0);
        let (release_first_tx, release_first_rx) = sync_channel(0);
        let held_overlay = first_overlay.clone();
        let first = std::thread::spawn(move || -> Result<()> {
            let segment = held_overlay.install_txn_segment()?;
            first_installed_tx
                .send(())
                .expect("first install receiver remains live");
            release_first_rx
                .recv()
                .expect("first release sender remains live");
            segment.commit()
        });
        first_installed_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("first overlay segment installs");

        let (other_attempting_tx, other_attempting_rx) = sync_channel(0);
        let (other_installed_tx, other_installed_rx) = sync_channel(0);
        let parallel_overlay = other_overlay;
        let other = std::thread::spawn(move || -> Result<()> {
            other_attempting_tx
                .send(())
                .expect("other attempt receiver remains live");
            let segment = parallel_overlay.install_txn_segment()?;
            other_installed_tx
                .send(())
                .expect("other install receiver remains live");
            segment.commit()
        });

        let (same_attempting_tx, same_attempting_rx) = sync_channel(0);
        let (same_installed_tx, same_installed_rx) = sync_channel(0);
        let contended_overlay = first_overlay;
        let same = std::thread::spawn(move || -> Result<()> {
            same_attempting_tx
                .send(())
                .expect("same-overlay attempt receiver remains live");
            let segment = contended_overlay.install_txn_segment()?;
            same_installed_tx
                .send(())
                .expect("same-overlay install receiver remains live");
            segment.commit()
        });
        other_attempting_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("other-overlay thread reaches install");
        same_attempting_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("same-overlay thread reaches install");

        let other_ran_in_parallel = match other_installed_rx.recv_timeout(CONCURRENCY_TIMEOUT) {
            Ok(()) => true,
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => {
                panic!("other-overlay installer disconnected before reporting")
            }
        };
        let same_was_blocked = match same_installed_rx.recv_timeout(CONCURRENCY_TIMEOUT) {
            Err(RecvTimeoutError::Timeout) => true,
            Ok(()) => false,
            Err(RecvTimeoutError::Disconnected) => {
                panic!("same-overlay installer disconnected before reporting")
            }
        };
        release_first_tx
            .send(())
            .expect("first overlay segment remains live until release");
        if !other_ran_in_parallel {
            other_installed_rx
                .recv_timeout(CONCURRENCY_TIMEOUT)
                .expect("other overlay eventually installs");
        }
        if same_was_blocked {
            same_installed_rx
                .recv_timeout(CONCURRENCY_TIMEOUT)
                .expect("same overlay installs after release");
        }

        match first.join().expect("first overlay thread does not panic") {
            Ok(()) => {}
            Err(other) => panic!("first overlay segment failed: {other}"),
        }
        match other.join().expect("other overlay thread does not panic") {
            Ok(()) => {}
            Err(other) => panic!("other overlay segment failed: {other}"),
        }
        match same.join().expect("same overlay thread does not panic") {
            Ok(()) => {}
            Err(other) => panic!("same overlay segment failed: {other}"),
        }
        assert!(
            other_ran_in_parallel,
            "a segment on another overlay was blocked by a global permit"
        );
        assert!(same_was_blocked, "the same-overlay permit was not held");
        Ok(())
    }

    #[test]
    fn put_rejects_budget_plus_one_before_staging() -> Result<()> {
        let budget = 64;
        let overlay = SessionOverlay::new(budget);
        let segment = overlay.install_txn_segment()?;
        let value = vec![0_u8; budget + 1];

        match overlay.put(OverlayKeyspace::Entities, b"k", &value) {
            Err(Error::OffRecordOverlayFull {
                budget_bytes,
                attempted_bytes,
            }) => {
                assert_eq!(budget_bytes, budget);
                assert_eq!(attempted_bytes, budget + 2);
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(()) => panic!("budget-plus-one put unexpectedly staged"),
        }
        assert_eq!(overlay.snapshot()?.bytes_used(), 0);
        drop(segment);
        Ok(())
    }

    #[test]
    fn payload_larger_than_budget_is_rejected_before_cloning() -> Result<()> {
        let budget = 8;
        let overlay = SessionOverlay::new(budget);
        let segment = overlay.install_txn_segment()?;
        let value = vec![0_u8; 64];

        match overlay.put(OverlayKeyspace::Entities, b"k", &value) {
            Err(Error::OffRecordOverlayFull {
                budget_bytes,
                attempted_bytes,
            }) => {
                assert_eq!(budget_bytes, budget);
                assert_eq!(attempted_bytes, 65);
            }
            Err(other) => panic!("unexpected put error: {other}"),
            Ok(()) => panic!("unbudgetable put unexpectedly staged"),
        }
        let snapshot = overlay.snapshot()?;
        assert_eq!(snapshot.bytes_used(), 0);
        assert_eq!(snapshot.row_count(OverlayKeyspace::Entities), 0);
        drop(snapshot);

        match overlay.delete_duplicate(OverlayKeyspace::TextPostings, b"k", &value, true) {
            Err(Error::OffRecordOverlayFull {
                budget_bytes,
                attempted_bytes,
            }) => {
                assert_eq!(budget_bytes, budget);
                assert_eq!(attempted_bytes, 65);
            }
            Err(other) => panic!("unexpected delete-duplicate error: {other}"),
            Ok(()) => panic!("unbudgetable delete-duplicate unexpectedly staged"),
        }
        let snapshot = overlay.snapshot()?;
        assert_eq!(snapshot.bytes_used(), 0);
        assert_eq!(snapshot.row_count(OverlayKeyspace::TextPostings), 0);
        drop(snapshot);
        drop(segment);
        Ok(())
    }

    #[test]
    fn dupsort_present_identity_keys_count_toward_budget_before_staging() -> Result<()> {
        let value = vec![7_u8; 16];
        let budget = b"t".len() + value.len();
        let overlay = SessionOverlay::new(budget);
        let segment = overlay.install_txn_segment()?;

        match overlay.put(OverlayKeyspace::TextPostings, b"t", &value) {
            Err(Error::OffRecordOverlayFull {
                budget_bytes,
                attempted_bytes,
            }) => {
                assert_eq!(budget_bytes, budget);
                assert_eq!(attempted_bytes, budget + value.len());
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(()) => panic!("DUP_SORT present identity key escaped the overlay budget"),
        }
        let snapshot = overlay.snapshot()?;
        assert_eq!(snapshot.row_count(OverlayKeyspace::TextPostings), 0);
        assert_eq!(snapshot.bytes_used(), 0);
        drop(segment);
        Ok(())
    }

    #[test]
    fn mutations_at_capacity_are_charged_by_net_byte_change() -> Result<()> {
        let budget = 8;
        let overlay = SessionOverlay::new(budget);
        let full_value = vec![7_u8; budget - b"k".len()];

        let segment = overlay.install_txn_segment()?;
        overlay.put(OverlayKeyspace::Entities, b"k", &full_value)?;
        segment.commit()?;
        assert_eq!(overlay.snapshot()?.bytes_used(), budget);

        let segment = overlay.install_txn_segment()?;
        overlay.put(OverlayKeyspace::Entities, b"k", b"x")?;
        assert_eq!(overlay.snapshot()?.bytes_used(), 2);
        segment.commit()?;

        let segment = overlay.install_txn_segment()?;
        overlay.put(OverlayKeyspace::Entities, b"k", &full_value)?;
        segment.commit()?;
        assert_eq!(overlay.snapshot()?.bytes_used(), budget);

        let segment = overlay.install_txn_segment()?;
        overlay.delete(OverlayKeyspace::Entities, b"k")?;
        assert_eq!(overlay.snapshot()?.bytes_used(), 1);
        match overlay.put(OverlayKeyspace::Entities, b"k", &[9_u8; 8]) {
            Err(Error::OffRecordOverlayFull {
                budget_bytes,
                attempted_bytes,
            }) => {
                assert_eq!(budget_bytes, budget);
                assert_eq!(attempted_bytes, budget + 1);
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(()) => panic!("net-increasing over-budget put unexpectedly staged"),
        }
        assert_eq!(overlay.snapshot()?.bytes_used(), 1);
        segment.commit()?;
        Ok(())
    }

    #[test]
    fn delete_removes_overlay_only_rows_but_retains_base_masks() -> Result<()> {
        let keyspace = OverlayKeyspace::Entities;
        let key = b"key";

        let overlay_only = SessionOverlay::new(64);
        let segment = overlay_only.install_txn_segment()?;
        overlay_only.put(keyspace, key, b"overlay")?;
        overlay_only.delete_with_base_backing(keyspace, key, false)?;
        segment.commit()?;
        let snapshot = overlay_only.snapshot()?;
        assert_eq!(snapshot.bytes_used(), 0);
        assert_eq!(snapshot.row_count(keyspace), 0);

        // delete -> re-put -> delete on a base-backed key must still end tombstoned:
        // base backing is read from the base row, not the intervening overlay Present.
        let base_backed = SessionOverlay::new(64);
        let segment = base_backed.install_txn_segment()?;
        base_backed.delete_with_base_backing(keyspace, key, true)?;
        base_backed.put(keyspace, key, b"replacement")?;
        base_backed.delete_with_base_backing(keyspace, key, true)?;
        segment.commit()?;
        let snapshot = base_backed.snapshot()?;
        assert_eq!(snapshot.bytes_used(), key.len());
        assert_eq!(
            snapshot.merge_rows(keyspace, vec![(key.to_vec(), b"base".to_vec())]),
            Vec::<(Vec<u8>, Vec<u8>)>::new()
        );
        Ok(())
    }

    #[test]
    fn delete_duplicate_removes_overlay_only_value_without_tombstone() -> Result<()> {
        let keyspace = OverlayKeyspace::TextPostings;
        let key = b"term";
        let mut base_value = vec![0_u8; 17];
        base_value[15] = 1;
        let mut overlay_value = vec![0_u8; 17];
        overlay_value[15] = 2;
        let (_dir, env, base) = dupsort_test_db();
        let mut setup_txn = env.write_txn()?;
        base.put(&mut setup_txn, key, &base_value)?;
        setup_txn.commit()?;

        let overlay = SessionOverlay::new(4096);
        let segment = overlay.install_txn_segment()?;
        overlay.put(keyspace, key, &overlay_value)?;
        overlay.delete_duplicate(keyspace, key, &overlay_value, false)?;
        segment.commit()?;

        let snapshot = overlay.snapshot()?;
        let KeyspaceState::DupSort { rows, .. } =
            snapshot.state.keyspaces[keyspace.slot()].as_ref()
        else {
            panic!("text postings overlay is not DUP_SORT");
        };
        assert!(
            rows.get(key.as_slice()).is_none(),
            "an emptied overlay-only delta is dropped, not left as a bare row"
        );
        assert_eq!(snapshot.bytes_used(), 0);
        assert!(snapshot.merge_plan(keyspace, |_| true).rows.is_empty());

        let view = OverlayDb::composed(base, overlay, Arc::new(snapshot), keyspace);
        let rtxn = env.read_txn()?;
        let values = view
            .get_duplicates(&rtxn, key)?
            .expect("different base posting remains visible")
            .map(|row| row.map(|(_, value)| value.into_owned()))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(values, vec![base_value]);
        Ok(())
    }

    #[test]
    fn delete_duplicate_retains_base_backed_tombstone() -> Result<()> {
        let keyspace = OverlayKeyspace::TextPostings;
        let key = b"term";
        let mut value = vec![0_u8; 17];
        value[15] = 1;
        let (_dir, env, base) = dupsort_test_db();
        let mut setup_txn = env.write_txn()?;
        base.put(&mut setup_txn, key, &value)?;
        setup_txn.commit()?;

        let overlay = SessionOverlay::new(4096);
        let segment = overlay.install_txn_segment()?;
        overlay.delete_duplicate(keyspace, key, &value, true)?;
        segment.commit()?;

        let snapshot = overlay.snapshot()?;
        let KeyspaceState::DupSort { rows, .. } =
            snapshot.state.keyspaces[keyspace.slot()].as_ref()
        else {
            panic!("text postings overlay is not DUP_SORT");
        };
        let delta = rows.get(key.as_slice()).expect("base mask is retained");
        assert!(delta.present.is_empty());
        assert_eq!(delta.deleted.iter().collect::<Vec<_>>(), vec![&value]);
        assert_eq!(snapshot.bytes_used(), key.len() + value.len());

        let view = OverlayDb::composed(base, overlay, Arc::new(snapshot), keyspace);
        let rtxn = env.read_txn()?;
        assert!(view.get_duplicates(&rtxn, key)?.is_none());
        Ok(())
    }

    #[test]
    fn over_budget_journal_entry_is_rejected_before_append() -> Result<()> {
        let budget = 64;
        let overlay = SessionOverlay::new(budget);
        let segment = overlay.install_txn_segment()?;
        let scope = JournalScope::new(EntityId::now(), EntityId::now());

        match overlay.stage_journal_entry(journal_entry(
            scope,
            JournalRole::TurnPut,
            put_op(vec![0_u8; budget + 1]),
        )) {
            Err(Error::OffRecordOverlayFull { budget_bytes, .. }) => {
                assert_eq!(budget_bytes, budget);
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(()) => panic!("over-budget journal entry unexpectedly staged"),
        }
        drop(segment);

        let snapshot = overlay.snapshot()?;
        assert_eq!(snapshot.journal_ops(scope).len(), 0);
        assert_eq!(snapshot.bytes_used(), 0);
        Ok(())
    }

    #[test]
    fn abort_reclaims_staged_journal_bytes() -> Result<()> {
        let overlay = SessionOverlay::new(4096);
        let segment = overlay.install_txn_segment()?;
        let scope = JournalScope::new(EntityId::now(), EntityId::now());
        overlay.stage_journal_entry(journal_entry(
            scope,
            JournalRole::TurnPut,
            put_op(vec![7_u8; 128]),
        ))?;
        drop(segment);

        let snapshot = overlay.snapshot()?;
        assert_eq!(snapshot.journal_ops(scope).len(), 0);
        assert_eq!(snapshot.bytes_used(), 0);
        Ok(())
    }

    #[test]
    fn stage_journal_without_segment_fails_closed() {
        let overlay = SessionOverlay::new(4096);
        let scope = JournalScope::new(EntityId::now(), EntityId::now());

        match overlay.stage_journal_entry(journal_entry(
            scope,
            JournalRole::TurnPut,
            BatchOp::Delete {
                id: EntityId::now(),
            },
        )) {
            Err(Error::InvariantViolation(message)) => assert_eq!(
                message,
                "session overlay write requires an active txn segment"
            ),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(()) => panic!("segment-less journal staging unexpectedly succeeded"),
        }
    }

    /// The namespace-separation contract. A session alias must not parse as a
    /// base short id, or a room alias could collide with — and, through the
    /// composed overlay ∪ base read, MASK — a real base entity's alias.
    /// Mirrors `api/core.rs::parse_short_ref_parts` /
    /// `mcp.rs::validate_short_ref_parts`: two lowercase letters then digits.
    fn parses_as_base_short_id(short_id: &str) -> bool {
        let bytes = short_id.as_bytes();
        bytes.len() >= 3
            && bytes[0].is_ascii_lowercase()
            && bytes[1].is_ascii_lowercase()
            && bytes[2..].iter().all(u8::is_ascii_digit)
    }

    #[test]
    fn session_short_ids_are_unique_and_outside_the_base_namespace() -> Result<()> {
        let overlay = SessionOverlay::new(4096);
        let segment = overlay.install_txn_segment()?;

        let mut seen = BTreeSet::new();
        for index in 0_u8..5 {
            let id = EntityId::now();
            let (short_id, content_hash) = overlay.alloc_session_short_id(&id, &[index])?;

            assert!(
                !parses_as_base_short_id(&short_id),
                "session alias {short_id} parses as a base short id"
            );
            assert!(
                short_id.starts_with(SESSION_SHORT_ID_SIGIL),
                "session alias {short_id} lacks the room sigil"
            );
            assert_eq!(content_hash, session_short_id_content_hash(&[index]));
            assert!(
                seen.insert(short_id.clone()),
                "session alias {short_id} was allocated twice in one room"
            );

            // Both rows land, and the forward row resolves back to the entity.
            let forward_key = encode_session_short_id_forward_key(&short_id, content_hash);
            let snapshot = overlay.snapshot()?;
            match snapshot.lookup_single(OverlayKeyspace::ShortIds, &forward_key) {
                SnapshotLookup::Present(value) => assert_eq!(value, id.as_bytes()),
                _ => panic!("forward session short-id row missing for {short_id}"),
            }
            match snapshot.lookup_single(OverlayKeyspace::ShortIdsReverse, id.as_bytes()) {
                SnapshotLookup::Present(value) => assert_eq!(value, forward_key),
                _ => panic!("reverse session short-id row missing for {short_id}"),
            }
        }

        drop(segment);
        Ok(())
    }

    /// Re-allocating keeps the alias stable and retires the stale forward row:
    /// the content hash is part of the forward KEY, so a body change would
    /// otherwise leave a second forward row resolving the same alias.
    #[test]
    fn reallocating_keeps_the_alias_and_retires_the_stale_forward_row() -> Result<()> {
        let overlay = SessionOverlay::new(4096);
        let segment = overlay.install_txn_segment()?;

        let id = EntityId::now();
        let (first, first_hash) = overlay.alloc_session_short_id(&id, b"body-one")?;
        let (second, second_hash) = overlay.alloc_session_short_id(&id, b"body-two")?;

        assert_eq!(first, second, "the room alias must be stable for an entity");
        assert_ne!(
            first_hash, second_hash,
            "fixture bodies must hash differently for this test to mean anything"
        );

        let snapshot = overlay.snapshot()?;
        // The stale row was overlay-only, so the delete REMOVES it outright
        // rather than tombstoning it — no wasted budget byte. `Passthrough`
        // then falls through to base, which by the sigil rule can never hold a
        // session alias, so the alias genuinely resolves to nothing.
        assert!(
            matches!(
                snapshot.lookup_single(
                    OverlayKeyspace::ShortIds,
                    &encode_session_short_id_forward_key(&first, first_hash),
                ),
                SnapshotLookup::Passthrough
            ),
            "the stale forward row survived a content change"
        );
        assert!(
            matches!(
                snapshot.lookup_single(
                    OverlayKeyspace::ShortIds,
                    &encode_session_short_id_forward_key(&second, second_hash),
                ),
                SnapshotLookup::Present(_)
            ),
            "the refreshed forward row is missing"
        );

        drop(segment);
        Ok(())
    }
}
