//! Revision-keyed publication lifecycle; one bounded owner per logical session.
//! Observer B only stages typed events. No vault or facade read occurs there.

use oneiron::memory::LiveQueryTrackerLimits;
use oneiron::memory::{IndexedPublication, RevisionRef};
use oneiron::sync::bridge::{MaterializedDiffSummary, OriginMark, RevisionEvent};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

type Key = (oneiron::EntityId, RevisionRef);

#[derive(Clone)]
pub(super) struct Invalidation {
    pub path: String,
    pub diff: MaterializedDiffSummary,
    pub contributors: Vec<OriginMark>,
    /// An original not yet represented by the indexed read. Other channels
    /// may observe it, but it cannot affect a View subscription's echo vote.
    pub live_only: bool,
}
struct Change {
    previous: Option<RevisionRef>,
    contributors: Vec<OriginMark>,
    unknown_mirror: bool,
}
#[derive(Default)]
struct State {
    limits: LiveQueryTrackerLimits,
    ready: VecDeque<Invalidation>,
    changes: BTreeMap<Key, Change>,
    waiting: BTreeMap<Key, IndexedPublication>,
    waiting_ticks: BTreeMap<Key, u8>,
    unavailable_at_open: BTreeSet<oneiron::EntityId>,
    settled: VecDeque<Key>,
    // Dedup history can be reclaimed without discarding pending work. A late
    // mirror of a reclaimed revision triggers a scoped resync at arrival.
    uncertain: BTreeSet<oneiron::EntityId>,
    uncertain_all: bool,
    lost: BTreeSet<String>,
}
#[derive(Default)]
pub(super) struct PublicationTracker {
    state: Mutex<State>,
}

impl PublicationTracker {
    pub(super) fn with_limits(limits: LiveQueryTrackerLimits) -> Self {
        Self {
            state: Mutex::new(State {
                limits,
                ..State::default()
            }),
        }
    }
    pub(super) fn record(&self, path: &str, diff: &MaterializedDiffSummary, by: &OriginMark) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut mirror_only = !diff.revision_events.is_empty();
        let live_only = !diff.revision_events.is_empty()
            && diff.revision_events.iter().all(|event| {
                matches!(event,
                RevisionEvent::Original(change) if change.revision != change.indexed_revision)
            });
        for event in &diff.revision_events {
            match event {
                RevisionEvent::Original(change) => {
                    mirror_only = false;
                    let Some(revision) = change.revision else {
                        state.retire_entity(change.entity);
                        continue;
                    };
                    if Some(revision) != change.indexed_revision {
                        let key = (change.entity, revision);
                        let tracked = state.changes.entry(key).or_insert_with(|| Change {
                            previous: change.previous_revision.or(change.indexed_revision),
                            contributors: Vec::new(),
                            unknown_mirror: false,
                        });
                        if tracked.unknown_mirror {
                            tracked.contributors.clear();
                            tracked.unknown_mirror = false;
                            tracked.previous = change.previous_revision.or(change.indexed_revision);
                        }
                        tracked.add(by);
                        state.try_waiting();
                    }
                }
                RevisionEvent::Mirror {
                    entity,
                    source_revision,
                } => {
                    let known = source_revision.is_some_and(|revision| {
                        let key = (*entity, revision);
                        state.changes.contains_key(&key) || state.settled.contains(&key)
                    });
                    if !known {
                        if source_revision.is_some()
                            && (state.uncertain_all || state.uncertain.contains(entity))
                        {
                            state.record_lost(format!("e:{}", entity.to_hex()));
                        } else {
                            mirror_only = false;
                            if let Some(revision) = source_revision {
                                let tracked = state
                                    .changes
                                    .entry((*entity, *revision))
                                    .or_insert_with(|| Change {
                                        previous: None,
                                        contributors: Vec::new(),
                                        unknown_mirror: true,
                                    });
                                tracked.add(by);
                                state.try_waiting();
                            }
                        }
                    }
                }
            }
        }
        if !mirror_only {
            let mut normalized = diff.clone();
            // Window transport publications still name `/entities/<id>` or
            // `/tombstones/<id>`; the read set names the entity document.
            for changed in &diff.containers {
                if (changed.contains("/entities/") || changed.contains("/tombstones/"))
                    && let Some(id) = changed.rsplit('/').next()
                    && let Ok(id) = oneiron::EntityId::from_hex(id)
                {
                    normalized.containers.push(format!("e:{}", id.to_hex()));
                }
            }
            normalized.containers.sort();
            normalized.containers.dedup();
            state.ready.push_back(Invalidation {
                path: path.to_owned(),
                diff: normalized,
                contributors: vec![by.clone()],
                live_only,
            });
        }
        state.bound();
    }

    pub(super) fn publish(&self, publication: IndexedPublication) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (publication.entity, publication.indexed);
        if state.settled.contains(&key) {
            return;
        }
        state.waiting.insert(key, publication);
        state.waiting_ticks.insert(key, 0);
        state.try_waiting();
        state.bound();
    }

    pub(super) fn mark_unavailable_at_open(&self, entities: &[oneiron::EntityId]) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for entity in entities {
            if !state.changes.keys().any(|(id, _)| id == entity) {
                state.unavailable_at_open.insert(*entity);
            }
        }
        state.bound();
    }

    pub(super) fn take(&self) -> (Vec<Invalidation>, BTreeSet<String>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.expire_missing();
        (
            state.ready.drain(..).collect(),
            std::mem::take(&mut state.lost),
        )
    }
}
impl Change {
    fn add(&mut self, by: &OriginMark) {
        if !self
            .contributors
            .iter()
            .any(|prior| prior.conn_id == by.conn_id && prior.origin == by.origin)
        {
            self.contributors.push(by.clone());
        }
    }
}
impl State {
    fn try_waiting(&mut self) {
        let keys: Vec<_> = self.waiting.keys().copied().collect();
        for key in keys {
            let Some(publication) = self.waiting.get(&key).copied() else {
                continue;
            };
            let mut cursor = publication.indexed;
            let mut chain = Vec::new();
            let mut seen = BTreeSet::new();
            while cursor != publication.previous_indexed
                && seen.insert(cursor)
                && chain.len() < self.limits.max_events
            {
                let Some(change) = self.changes.get(&(publication.entity, cursor)) else {
                    break;
                };
                chain.push((cursor, change.contributors.clone()));
                cursor = change.previous.unwrap_or(publication.previous_indexed);
            }
            if cursor != publication.previous_indexed {
                continue;
            }
            self.waiting.remove(&key);
            self.waiting_ticks.remove(&key);
            self.unavailable_at_open.remove(&publication.entity);
            let mut contributors = Vec::new();
            for (revision, marks) in chain {
                for mark in marks {
                    if !contributors.iter().any(|old: &OriginMark| {
                        old.conn_id == mark.conn_id && old.origin == mark.origin
                    }) {
                        contributors.push(mark);
                    }
                }
                self.changes.remove(&(publication.entity, revision));
                self.settled.push_back((publication.entity, revision));
            }
            let path = format!("e:{}", publication.entity.to_hex());
            self.ready.push_back(Invalidation {
                path: path.clone(),
                diff: MaterializedDiffSummary {
                    containers: vec![path],
                    bytes: 0,
                    revision_events: Vec::new(),
                },
                contributors,
                live_only: false,
            });
        }
    }
    fn retire_entity(&mut self, entity: oneiron::EntityId) {
        self.changes.retain(|(id, _), _| *id != entity);
        self.waiting.retain(|(id, _), _| *id != entity);
        self.waiting_ticks.retain(|(id, _), _| *id != entity);
        self.unavailable_at_open.remove(&entity);
        self.settled.retain(|(id, _)| *id != entity);
        self.uncertain.remove(&entity);
    }
    fn expire_missing(&mut self) {
        let keys: Vec<_> = self.waiting.keys().copied().collect();
        for key in keys {
            let ticks = self.waiting_ticks.entry(key).or_default();
            *ticks = ticks.saturating_add(1);
            if self.unavailable_at_open.contains(&key.0)
                || usize::from(*ticks) >= self.limits.receipt_grace_ticks
            {
                self.waiting.remove(&key);
                self.waiting_ticks.remove(&key);
                self.unavailable_at_open.remove(&key.0);
                self.record_lost(format!("e:{}", key.0.to_hex()));
            }
        }
    }

    fn record_lost(&mut self, path: String) {
        if self.lost.contains("*") {
            return;
        }
        if self.lost.len() >= self.limits.max_events {
            self.lost.clear();
            self.lost.insert("*".into()); // exact scoping is no longer representable
        } else {
            self.lost.insert(path);
        }
    }
    fn bound(&mut self) {
        while self.ready.len() + self.changes.len() + self.waiting.len() + self.settled.len()
            > self.limits.max_events
            || self.estimate_bytes() > self.limits.max_bytes
        {
            // Settled keys are dedup hints, not undelivered publication state.
            // Reclaim them first; a later mirror names its revision and then
            // requests a scoped gap if this owner no longer knows the source.
            if let Some(key) = self.settled.pop_front() {
                if self.uncertain.len() >= self.limits.max_events {
                    self.uncertain.clear();
                    self.uncertain_all = true;
                } else if !self.uncertain_all {
                    self.uncertain.insert(key.0);
                }
            } else if let Some(evicted) = self.ready.pop_front() {
                let entities: Vec<_> = evicted
                    .diff
                    .containers
                    .into_iter()
                    .filter(|path| path.starts_with("e:"))
                    .collect();
                if entities.is_empty() {
                    self.record_lost(evicted.path);
                } else {
                    for path in entities {
                        self.record_lost(path);
                    }
                }
            } else if let Some((&key, _)) = self.changes.first_key_value() {
                self.changes.remove(&key);
                self.record_lost(format!("e:{}", key.0.to_hex()));
            } else if let Some((&key, _)) = self.waiting.first_key_value() {
                self.waiting.remove(&key);
                self.waiting_ticks.remove(&key);
                self.record_lost(format!("e:{}", key.0.to_hex()));
            } else if let Some(&entity) = self.unavailable_at_open.first() {
                self.unavailable_at_open.remove(&entity);
                self.record_lost(format!("e:{}", entity.to_hex()));
            } else {
                break;
            }
        }
    }
    fn estimate_bytes(&self) -> usize {
        self.ready
            .iter()
            .map(|row| {
                row.path.len()
                    + row.diff.containers.iter().map(String::len).sum::<usize>()
                    + row.diff.revision_events.len().saturating_mul(128)
                    + row
                        .contributors
                        .iter()
                        .map(|mark| mark.origin.as_ref().map_or(0, String::len) + 64)
                        .sum::<usize>()
                    + 128
            })
            .sum::<usize>()
            + self
                .changes
                .values()
                .map(|row| {
                    64 + row
                        .contributors
                        .iter()
                        .map(|mark| mark.origin.as_ref().map_or(0, String::len) + 64)
                        .sum::<usize>()
                })
                .sum::<usize>()
            + self.waiting.len() * 80
            + self.unavailable_at_open.len() * 16
            + self.settled.len() * 40
            + self.uncertain.len() * 16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::memory::EntityRevisionChange;
    use oneiron::sync::bridge::RevisionEvent;

    fn id(byte: u8) -> oneiron::EntityId {
        oneiron::EntityId::from_bytes([byte; 16]).unwrap()
    }
    fn rev(byte: u8) -> RevisionRef {
        RevisionRef([byte; 16])
    }
    fn path(entity: oneiron::EntityId) -> String {
        format!("e:{}", entity.to_hex())
    }
    fn write(
        tracker: &PublicationTracker,
        entity: oneiron::EntityId,
        previous: RevisionRef,
        revision: RevisionRef,
        by: u32,
    ) {
        let path = path(entity);
        tracker.record(
            &path,
            &MaterializedDiffSummary {
                containers: vec![path.clone()],
                bytes: 0,
                revision_events: vec![RevisionEvent::Original(EntityRevisionChange {
                    entity,
                    previous_revision: Some(previous),
                    revision: Some(revision),
                    indexed_revision: Some(rev(0)),
                })],
            },
            &OriginMark {
                conn_id: Some(by),
                origin: Some(format!("conn:{by}")),
            },
        );
    }
    fn mirror(
        tracker: &PublicationTracker,
        entity: oneiron::EntityId,
        revision: Option<RevisionRef>,
    ) {
        let path = path(entity);
        tracker.record(
            &path,
            &MaterializedDiffSummary {
                containers: vec![path.clone()],
                bytes: 0,
                revision_events: vec![RevisionEvent::Mirror {
                    entity,
                    source_revision: revision,
                }],
            },
            &OriginMark {
                conn_id: None,
                origin: Some("bridge".into()),
            },
        );
    }
    fn published(
        tracker: &PublicationTracker,
        entity: oneiron::EntityId,
        previous: RevisionRef,
        indexed: RevisionRef,
    ) {
        tracker.publish(IndexedPublication {
            entity,
            previous_indexed: previous,
            indexed,
        });
    }
    fn own(mark: &OriginMark, conn: u32) -> bool {
        mark.conn_id == Some(conn)
            || mark.origin.as_deref() == Some(format!("conn:{conn}").as_str())
    }
    fn tails(tracker: &PublicationTracker) -> Vec<Invalidation> {
        let (rows, lost) = tracker.take();
        assert!(lost.is_empty());
        rows.into_iter()
            .filter(|row| row.diff.revision_events.is_empty())
            .collect()
    }
    #[test]
    fn timer_drain_and_mirror_schedules_keep_the_same_revision_contributors() {
        let entity = id(0x41);
        for order in [0, 1, 2, 3, 4, 5] {
            let tracker = PublicationTracker::default();
            if order == 3 || order == 5 {
                published(&tracker, entity, rev(0), rev(1));
                if order == 5 {
                    assert!(tails(&tracker).is_empty());
                }
            }
            write(&tracker, entity, rev(0), rev(1), 1);
            if order == 1 || order == 4 {
                // Deterministic drain/retention handoff before mirror delivery.
                assert!(tails(&tracker).is_empty());
            }
            if order == 4 {
                published(&tracker, entity, rev(0), rev(1));
            }
            mirror(&tracker, entity, Some(rev(1)));
            if order == 2 {
                assert!(tails(&tracker).is_empty());
            }
            if order != 3 && order != 4 && order != 5 {
                published(&tracker, entity, rev(0), rev(1));
            }
            let rows = tails(&tracker);
            assert_eq!(rows.len(), 1, "schedule {order}");
            assert!(
                rows[0].contributors.iter().all(|mark| own(mark, 1)),
                "schedule {order}"
            );
            assert!(!rows[0].contributors.is_empty());
        }
    }
}
