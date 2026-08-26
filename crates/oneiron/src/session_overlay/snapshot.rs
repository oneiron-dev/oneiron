use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

#[cfg(test)]
use super::journal::JournalScope;
use super::journal::{
    JournalEntry, JournalRole, PromotePlan, journal_entry_in_closure, promotion_replay_op,
};
use super::keyspace::{
    KeyspaceState, OverlayKeyspace, OverlayState, OverlayValue, duplicate_identity,
};
use super::overlay::Lease;
use super::short_id::parse_session_short_id_value;

/// A generation-stamped, structurally shared overlay read view.
pub(crate) struct OverlaySnapshot {
    pub(super) state: Arc<OverlayState>,
    pub(super) _lease: Lease,
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
