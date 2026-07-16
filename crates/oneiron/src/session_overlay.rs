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
            }),
            lease_drained: Condvar::new(),
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
        let lease = self.acquire_live_lease()?;
        let generation = lease.generation;
        let snapshot = self
            .state
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay state mutex poisoned"))?
            .clone();
        let segment = TxnSegment {
            overlay: self.clone(),
            generation,
            preview: snapshot,
            mutations: Vec::new(),
            journal: Vec::new(),
            journal_bytes: 0,
            _lease: lease,
        };
        ACTIVE_SEGMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return Err(Error::InvariantViolation(
                    "a session txn segment is already installed on this thread",
                ));
            }
            *slot = Some(segment);
            Ok(())
        })?;
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
        let mutation = OverlayMutation::Put {
            keyspace,
            key: key.to_vec(),
            value: value.to_vec(),
        };
        self.preflight_segment_mutation(&mutation)?;
        self.stage_mutation(mutation)
    }

    pub(crate) fn delete(self: &Arc<Self>, keyspace: OverlayKeyspace, key: &[u8]) -> Result<()> {
        let mutation = OverlayMutation::Delete {
            keyspace,
            key: key.to_vec(),
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
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        match lifecycle.state {
            OverlayLifecycleState::Live => {
                lifecycle.state = OverlayLifecycleState::Closing;
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
            segment.preview = self.apply_to_state(
                segment.preview.clone(),
                std::slice::from_ref(&mutation),
                &[],
                true,
            )?;
            segment.mutations.push(mutation);
            Ok(())
        })
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
        *state = self.apply_to_state(state.clone(), &segment.mutations, &segment.journal, true)?;
        Ok(())
    }

    fn apply_to_state(
        &self,
        state: Arc<OverlayState>,
        mutations: &[OverlayMutation],
        journal: &[JournalEntry],
        enforce_budget: bool,
    ) -> Result<Arc<OverlayState>> {
        let mut next = state.as_ref().clone();
        for mutation in mutations {
            let projected = project_mutation(&next, mutation)?;
            if enforce_budget {
                self.ensure_mutation_budget(
                    next.bytes_used,
                    next.bytes_used,
                    projected.bytes_used,
                )?;
            }
            next = projected;
        }
        for entry in journal {
            if enforce_budget {
                self.ensure_budget(next.bytes_used, entry.byte_size())?;
            }
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
        if self.finished {
            return;
        }
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
        (KeyspaceState::Single { rows, .. }, OverlayMutation::Delete { key, .. }) => {
            rows.insert(key.clone(), OverlayValue::Tombstone);
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

    fn put_op(data: Vec<u8>) -> BatchOp {
        BatchOp::Put {
            id: EntityId::now(),
            entity_type: 1,
            occurred: TimeRange { start: 1, end: 1 },
            learned_at: 1,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
        }
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
