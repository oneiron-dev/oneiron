use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::error::{Error, Result};

use super::journal::JournalEntry;

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

    pub(super) const fn slot(self) -> usize {
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
pub(super) enum OverlayValue {
    Present(Vec<u8>),
    Tombstone,
}

#[derive(Clone, Default)]
pub(super) struct DupDelta {
    pub(super) delete_base: bool,
    pub(super) present: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(super) deleted: BTreeSet<Vec<u8>>,
}

#[derive(Clone)]
pub(super) enum KeyspaceState {
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
pub(super) struct OverlayState {
    pub(super) keyspaces: [Arc<KeyspaceState>; OverlayKeyspace::COUNT],
    pub(super) journal: Arc<Vec<JournalEntry>>,
    pub(super) bytes_used: usize,
}

impl OverlayState {
    pub(super) fn empty() -> Self {
        Self {
            keyspaces: std::array::from_fn(|slot| {
                Arc::new(KeyspaceState::empty(OverlayKeyspace::from_slot(slot)))
            }),
            journal: Arc::new(Vec::new()),
            bytes_used: 0,
        }
    }

    pub(super) fn recalculate_bytes(&mut self) {
        self.bytes_used = self
            .keyspaces
            .iter()
            .map(|state| state.byte_size())
            .chain(self.journal.iter().map(JournalEntry::byte_size))
            .fold(0_usize, usize::saturating_add);
    }
}

#[derive(Clone)]
pub(super) enum OverlayMutation {
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

/// Removes one PRESENT overlay row outright, leaving no base mask.
///
/// The presence check is the whole point: [`apply_mutation`]'s delete arm
/// tombstones a key it does not already hold, which is correct for a room
/// hiding a base row and exactly wrong for retiring a row the room just
/// published. DUP_SORT keyspaces are not retired here (see
/// [`SessionOverlay::retire_promoted_closure`]), so this only touches
/// single-valued state.
pub(super) fn drop_overlay_row(state: &mut OverlayState, keyspace: OverlayKeyspace, key: &[u8]) {
    if let KeyspaceState::Single { rows, .. } = Arc::make_mut(&mut state.keyspaces[keyspace.slot()])
        && matches!(rows.get(key), Some(OverlayValue::Present(_)))
    {
        rows.remove(key);
    }
}

pub(super) fn project_mutation(
    state: &OverlayState,
    mutation: &OverlayMutation,
) -> Result<OverlayState> {
    let mut projected = state.clone();
    apply_mutation(&mut projected, mutation)?;
    projected.recalculate_bytes();
    Ok(projected)
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

pub(super) fn duplicate_identity(value: &[u8]) -> Vec<u8> {
    value.get(..16).unwrap_or(value).to_vec()
}
