//! In-memory session write-overlay substrate (ARCH-0052, D1).
//!
//! The overlay is independent of the durable off-record fence machinery. It
//! owns one structurally shared keyspace per database manifest slot, typed
//! journal entries, generation-stamped read/segment leases, and the byte
//! budget that bounds live overlay rows.

// Substrate armed by ONE-1727 (the vault-level session view is its first
// non-test consumer); until then every item is exercised only by the cfg(test)
// forward oracle, so lib-target dead_code is expected across this module.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Production default used by the minimal session seam until vault-level
/// configuration and session construction land together in ONE-1727.
pub(crate) const DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

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
    "MemoryFacade::with_verified_actor_write_txn / MemoryFacade::witness",
    "direct env.write_txn(): dreamer_runner, attempt_queue, claim, deletion, connector_key, companion, code_run, and remaining feature modules",
];

const _: () = assert!(!SESSION_WRITE_TXN_ENTRY_POINTS.is_empty());

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

#[derive(Clone)]
struct JournalEntry {
    scope: JournalScope,
    op: BatchOp,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayLifecycleState {
    Live,
    Closing,
    Gone,
}

struct Lifecycle {
    state: OverlayLifecycleState,
    generation: u64,
    leases: usize,
    segment_active: bool,
}

struct Lease {
    overlay: Arc<SessionOverlay>,
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
    state: Mutex<Arc<OverlayState>>,
    lifecycle: Mutex<Lifecycle>,
    lease_drained: Condvar,
    segment_available: Condvar,
    budget_bytes: usize,
}

impl SessionOverlay {
    pub(crate) fn new(budget_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Arc::new(OverlayState::empty())),
            lifecycle: Mutex::new(Lifecycle {
                state: OverlayLifecycleState::Live,
                generation: NEXT_OVERLAY_GENERATION.fetch_add(1, Ordering::Relaxed),
                leases: 0,
                segment_active: false,
            }),
            lease_drained: Condvar::new(),
            segment_available: Condvar::new(),
            budget_bytes,
        })
    }

    pub(crate) const fn budget_bytes(&self) -> usize {
        self.budget_bytes
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

        let lease = self.acquire_live_lease()?;
        let state = self
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay state mutex poisoned"))?
            .clone();
        Ok(OverlaySnapshot {
            state,
            _lease: lease,
        })
    }

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
        let snapshot = match self.state.lock() {
            Ok(state) => state.clone(),
            Err(_) => {
                self.release_segment_writer();
                return Err(Error::InvariantViolation(
                    "session overlay state mutex poisoned",
                ));
            }
        };
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
    ) -> Result<()> {
        self.reject_unbudgetable_payload(key, value)?;
        let mutation = OverlayMutation::DeleteDuplicate {
            keyspace,
            key: key.to_vec(),
            value: value.to_vec(),
        };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    pub(crate) fn clear(self: &Arc<Self>, keyspace: OverlayKeyspace) -> Result<()> {
        let mutation = OverlayMutation::Clear { keyspace };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    pub(crate) fn stage_journal(self: &Arc<Self>, scope: JournalScope, op: BatchOp) -> Result<()> {
        let incoming_bytes = std::mem::size_of::<JournalEntry>()
            .checked_add(batch_op_payload_bytes(&op))
            .ok_or(Error::ArithmeticOverflow("overlay journal byte cost"))?;
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
            segment.journal.push(JournalEntry { scope, op });
            segment.journal_bytes = segment.journal_bytes.checked_add(incoming_bytes).ok_or(
                Error::ArithmeticOverflow("overlay staged journal byte count"),
            )?;
            Ok(())
        })
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
            OverlayLifecycleState::Live => {
                lifecycle.state = OverlayLifecycleState::Closing;
                // Wake every installer parked on the segment permit so each re-checks the
                // terminal lifecycle state and returns the closed error instead of sleeping;
                // release_segment_writer's notify_one only ever wakes a single waiter.
                self.segment_available.notify_all();
            }
            OverlayLifecycleState::Closing | OverlayLifecycleState::Gone => {
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
        *self
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay state mutex poisoned"))? =
            Arc::new(OverlayState::empty());
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

    fn release_segment_writer(&self) {
        if let Ok(mut lifecycle) = self.lifecycle.lock() {
            lifecycle.segment_active = false;
            self.segment_available.notify_one();
        }
    }

    fn acquire_live_lease(self: &Arc<Self>) -> Result<Lease> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state != OverlayLifecycleState::Live {
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay state mutex poisoned"))?;
        *state =
            Self::apply_preflighted_to_state(state.clone(), &segment.mutations, &segment.journal)?;
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

fn project_mutation(state: &OverlayState, mutation: &OverlayMutation) -> Result<OverlayState> {
    let mut projected = state.clone();
    apply_mutation(&mut projected, mutation)?;
    projected.recalculate_bytes();
    Ok(projected)
}

/// RAII owner of the thread-local segment installed for one base write txn.
pub(crate) struct TxnSegmentGuard {
    overlay: Arc<SessionOverlay>,
    finished: bool,
    _not_send: PhantomData<Rc<()>>,
}

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
            KeyspaceState::DupSort { rows, .. },
            OverlayMutation::DeleteDuplicate { key, value, .. },
        ) => {
            let identity = duplicate_identity(value);
            let delta = rows.entry(key.clone()).or_default();
            if delta.present.get(&identity) == Some(value) {
                delta.present.remove(&identity);
            }
            delta.deleted.insert(value.clone());
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
    use crate::temporal::TimeRange;
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

        match overlay.delete_duplicate(OverlayKeyspace::TextPostings, b"k", &value) {
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
    fn over_budget_journal_entry_is_rejected_before_append() -> Result<()> {
        let budget = 64;
        let overlay = SessionOverlay::new(budget);
        let segment = overlay.install_txn_segment()?;
        let scope = JournalScope::new(EntityId::now(), EntityId::now());

        match overlay.stage_journal(scope, put_op(vec![0_u8; budget + 1])) {
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
        overlay.stage_journal(scope, put_op(vec![7_u8; 128]))?;
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

        match overlay.stage_journal(
            scope,
            BatchOp::Delete {
                id: EntityId::now(),
            },
        ) {
            Err(Error::InvariantViolation(message)) => assert_eq!(
                message,
                "session overlay write requires an active txn segment"
            ),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(()) => panic!("segment-less journal staging unexpectedly succeeded"),
        }
    }
}
