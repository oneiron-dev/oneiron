use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use zeroize::Zeroize;

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

// Values scrub at displacement, not only when their parent COW map dies.
impl Drop for OverlayValue {
    fn drop(&mut self) {
        if let Self::Present(bytes) = self {
            bytes.zeroize();
        }
    }
}

impl Drop for DupDelta {
    fn drop(&mut self) {
        for (mut identity, mut value) in std::mem::take(&mut self.present) {
            identity.zeroize();
            value.zeroize();
        }
        for mut value in std::mem::take(&mut self.deleted) {
            value.zeroize();
        }
    }
}

fn remove_owned_row<V>(rows: &mut BTreeMap<Vec<u8>, V>, key: &[u8]) {
    if let Some((mut key, value)) = rows.remove_entry(key) {
        key.zeroize();
        drop(value);
    }
}

fn dup_delta<'a>(rows: &'a mut BTreeMap<Vec<u8>, DupDelta>, key: &[u8]) -> &'a mut DupDelta {
    if !rows.contains_key(key) {
        rows.insert(key.to_vec(), DupDelta::default());
    }
    rows.get_mut(key).expect("inserted duplicate delta")
}

// A COW keyspace scrubs keys at its last Arc drop. Displaced values and
// deleted keys are scrubbed at their own earlier drop by the mutation arms.
impl Drop for KeyspaceState {
    fn drop(&mut self) {
        match self {
            Self::Single { rows, .. } => {
                for (mut key, value) in std::mem::take(rows) {
                    key.zeroize();
                    drop(value);
                }
            }
            Self::DupSort { rows, .. } => {
                for (mut key, delta) in std::mem::take(rows) {
                    key.zeroize();
                    drop(delta);
                }
            }
        }
    }
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
        if keyspace.is_dupsort() {
            Self::DupSort {
                clear_base: true,
                rows: BTreeMap::new(),
            }
        } else {
            Self::Single {
                clear_base: true,
                rows: BTreeMap::new(),
            }
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

// Segment mutations (including failed preflights and aborts) have their own
// allocations. Wipe those independently of the published COW keyspaces.
impl Drop for OverlayMutation {
    fn drop(&mut self) {
        match self {
            Self::Put { key, value, .. } | Self::DeleteDuplicate { key, value, .. } => {
                key.zeroize();
                value.zeroize();
            }
            Self::Delete { key, .. } => key.zeroize(),
            Self::Clear { .. } => {}
        }
    }
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
        remove_owned_row(rows, key);
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
            if let Some(old) = rows.get_mut(key) {
                *old = OverlayValue::Present(value.clone()); // old body scrubs on drop
            } else {
                rows.insert(key.clone(), OverlayValue::Present(value.clone()));
            }
        }
        (
            KeyspaceState::Single { clear_base, rows },
            OverlayMutation::Delete {
                key, base_backed, ..
            },
        ) => {
            let effective_base_backed = *base_backed && !*clear_base;
            if !effective_base_backed && matches!(rows.get(key), Some(OverlayValue::Present(_))) {
                remove_owned_row(rows, key);
            } else if let Some(old) = rows.get_mut(key) {
                *old = OverlayValue::Tombstone;
            } else {
                rows.insert(key.clone(), OverlayValue::Tombstone);
            }
        }
        (KeyspaceState::DupSort { rows, .. }, OverlayMutation::Put { key, value, .. }) => {
            let mut identity = duplicate_identity(value);
            let delta = dup_delta(rows, key);
            if let Some(mut deleted) = delta.deleted.take(value) {
                deleted.zeroize();
            }
            if let Some(old) = delta.present.get_mut(&identity) {
                old.zeroize();
                *old = value.clone();
                identity.zeroize();
            } else {
                delta.present.insert(identity, value.clone());
            }
        }
        (KeyspaceState::DupSort { rows, .. }, OverlayMutation::Delete { key, .. }) => {
            *dup_delta(rows, key) = DupDelta::default();
            dup_delta(rows, key).delete_base = true;
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
            let mut identity = duplicate_identity(value);
            let delta = dup_delta(rows, key);
            let effective_base_backed = *base_backed && !*clear_base && !delta.delete_base;
            if delta.present.get(&identity) == Some(value)
                && let Some((mut owned_identity, mut owned_value)) =
                    delta.present.remove_entry(&identity)
            {
                owned_identity.zeroize();
                owned_value.zeroize();
            }
            identity.zeroize();
            if effective_base_backed && !delta.deleted.contains(value) {
                delta.deleted.insert(value.clone());
            }
            let delta_is_empty =
                delta.present.is_empty() && delta.deleted.is_empty() && !delta.delete_base;
            if delta_is_empty {
                remove_owned_row(rows, key);
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

#[cfg(test)]
mod hygiene_tests {
    use super::*;

    use super::super::hygiene_tests::{allocation, observe_drop};

    fn seeded(space: OverlayKeyspace) -> OverlayState {
        let mutation = OverlayMutation::Put {
            keyspace: space,
            key: b"private-index-key".to_vec(),
            value: b"private-overlay-value".to_vec(),
        };
        project_mutation(&OverlayState::empty(), &mutation).expect("seed overlay")
    }

    fn owned_body(state: &OverlayState, space: OverlayKeyspace) -> &[u8] {
        match state.keyspaces[space.slot()].as_ref() {
            KeyspaceState::Single { rows, .. } => match rows.get(b"private-index-key".as_slice()) {
                Some(OverlayValue::Present(value)) => value,
                _ => panic!("missing single row"),
            },
            KeyspaceState::DupSort { rows, .. } => rows
                .get(b"private-index-key".as_slice())
                .expect("duplicate row")
                .present
                .values()
                .next()
                .expect("duplicate body"),
        }
    }

    #[test]
    fn cow_overwrite_and_remove_scrub_displaced_values_before_state_drop() {
        let original = seeded(OverlayKeyspace::Entities);
        let mut copy = original.clone();
        Arc::make_mut(&mut copy.keyspaces[OverlayKeyspace::Entities.slot()]);
        let ptr = allocation(owned_body(&copy, OverlayKeyspace::Entities));
        observe_drop(ptr, true, || {
            apply_mutation(
                &mut copy,
                &OverlayMutation::Put {
                    keyspace: OverlayKeyspace::Entities,
                    key: b"private-index-key".to_vec(),
                    value: b"replacement".to_vec(),
                },
            )
            .expect("overwrite");
        });
        assert_eq!(
            owned_body(&original, OverlayKeyspace::Entities),
            b"private-overlay-value"
        );
        let ptr = allocation(owned_body(&copy, OverlayKeyspace::Entities));
        observe_drop(ptr, true, || {
            apply_mutation(
                &mut copy,
                &OverlayMutation::Delete {
                    keyspace: OverlayKeyspace::Entities,
                    key: b"private-index-key".to_vec(),
                    base_backed: false,
                },
            )
            .expect("remove");
        });
        let ptr = allocation(owned_body(&original, OverlayKeyspace::Entities));
        observe_drop(ptr, true, || drop(original));
    }

    #[test]
    fn duplicate_remove_and_retirement_scrub_values_and_identity() {
        let original = seeded(OverlayKeyspace::TextPostings);
        let mut copy = original.clone();
        Arc::make_mut(&mut copy.keyspaces[OverlayKeyspace::TextPostings.slot()]);
        let ptr = allocation(owned_body(&copy, OverlayKeyspace::TextPostings));
        observe_drop(ptr, true, || {
            apply_mutation(
                &mut copy,
                &OverlayMutation::DeleteDuplicate {
                    keyspace: OverlayKeyspace::TextPostings,
                    key: b"private-index-key".to_vec(),
                    value: b"private-overlay-value".to_vec(),
                    base_backed: false,
                },
            )
            .expect("remove duplicate");
        });
        let ptr = allocation(owned_body(&original, OverlayKeyspace::TextPostings));
        observe_drop(ptr, true, || drop(original));

        let mut retiring = seeded(OverlayKeyspace::Entities);
        let ptr = allocation(owned_body(&retiring, OverlayKeyspace::Entities));
        observe_drop(ptr, true, || {
            drop_overlay_row(
                &mut retiring,
                OverlayKeyspace::Entities,
                b"private-index-key",
            );
        });
    }
}
