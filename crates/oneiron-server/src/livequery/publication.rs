//! Revision-keyed publication lifecycle; one bounded owner per logical session.
//! Observer B only stages typed events. No vault or facade read occurs there.

use oneiron::memory::{IndexedPublication, RevisionRef};
use oneiron::sync::bridge::{MaterializedDiffSummary, OriginMark, RevisionEvent};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

const MAX_EVENTS: usize = 1024;
const MAX_BYTES: usize = 64 * 1024;
type Key = (oneiron::EntityId, RevisionRef);

#[derive(Clone)]
pub(super) struct Invalidation {
    pub path: String,
    pub diff: MaterializedDiffSummary,
    pub contributors: Vec<OriginMark>,
}
struct Change {
    previous: Option<RevisionRef>,
    contributors: Vec<OriginMark>,
}
#[derive(Default)]
struct State {
    ready: VecDeque<Invalidation>,
    changes: BTreeMap<Key, Change>,
    waiting: BTreeMap<Key, IndexedPublication>,
    settled: VecDeque<Key>,
    lost: BTreeSet<String>,
}
#[derive(Default)]
pub(super) struct PublicationTracker {
    state: Mutex<State>,
}

impl PublicationTracker {
    pub(super) fn record(&self, path: &str, diff: &MaterializedDiffSummary, by: &OriginMark) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut mirror_only = !diff.revision_events.is_empty();
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
                        });
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
                        mirror_only = false;
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
        state.try_waiting();
        state.bound();
    }

    pub(super) fn take(&self) -> (Vec<Invalidation>, BTreeSet<String>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                && chain.len() < MAX_EVENTS
            {
                let Some(change) = self.changes.get(&(publication.entity, cursor)) else {
                    break;
                };
                chain.push((cursor, change.contributors.clone()));
                let Some(previous) = change.previous else {
                    break;
                };
                cursor = previous;
            }
            if cursor != publication.previous_indexed {
                continue;
            }
            self.waiting.remove(&key);
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
            });
        }
    }
    fn retire_entity(&mut self, entity: oneiron::EntityId) {
        self.changes.retain(|(id, _), _| *id != entity);
        self.waiting.retain(|(id, _), _| *id != entity);
        self.settled.retain(|(id, _)| *id != entity);
    }
    fn record_lost(&mut self, path: String) {
        if self.lost.contains("*") {
            return;
        }
        if self.lost.len() >= MAX_EVENTS {
            self.lost.clear();
            self.lost.insert("*".into()); // exact scoping is no longer representable
        } else {
            self.lost.insert(path);
        }
    }
    fn bound(&mut self) {
        while self.ready.len() + self.changes.len() + self.waiting.len() + self.settled.len()
            > MAX_EVENTS
            || self.estimate_bytes() > MAX_BYTES
        {
            if let Some(evicted) = self.ready.pop_front() {
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
            } else if let Some(key) = self.settled.pop_front() {
                self.record_lost(format!("e:{}", key.0.to_hex()));
            } else if let Some((&key, _)) = self.changes.first_key_value() {
                self.changes.remove(&key);
                self.record_lost(format!("e:{}", key.0.to_hex()));
            } else if let Some((&key, _)) = self.waiting.first_key_value() {
                self.waiting.remove(&key);
                self.record_lost(format!("e:{}", key.0.to_hex()));
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
            + self.waiting.len() * 64
            + self.settled.len() * 40
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
        for order in [0, 1, 2, 3, 4] {
            let tracker = PublicationTracker::default();
            if order == 3 {
                published(&tracker, entity, rev(0), rev(1));
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
            if order != 3 && order != 4 {
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
    #[test]
    fn bounded_loss_names_only_affected_dependencies() {
        let tracker = PublicationTracker::default();
        let unrelated = id(0x44);
        for n in 0..650_u16 {
            let mut bytes = [0x81; 16];
            bytes[14..].copy_from_slice(&n.to_be_bytes());
            let entity = oneiron::EntityId::from_bytes(bytes).unwrap();
            write(&tracker, entity, rev(0), rev(1), 1);
        }
        let (_, lost) = tracker.take();
        assert!(!lost.is_empty());
        assert!(!lost.contains(&path(unrelated)));
        assert!(!lost.contains("*"));
    }

    #[test]
    fn immediate_birth_metadata_supersession_and_delete_retire_exact_revisions() {
        let entity = id(0x43);
        let tracker = PublicationTracker::default();
        let path = path(entity);
        let immediate = |previous, revision, indexed, by| {
            tracker.record(
                &path,
                &MaterializedDiffSummary {
                    containers: vec![path.clone()],
                    bytes: 0,
                    revision_events: vec![RevisionEvent::Original(EntityRevisionChange {
                        entity,
                        previous_revision: previous,
                        revision,
                        indexed_revision: indexed,
                    })],
                },
                &OriginMark {
                    conn_id: Some(by),
                    origin: Some(format!("conn:{by}")),
                },
            );
        };
        immediate(None, Some(rev(1)), Some(rev(1)), 1); // birth
        immediate(Some(rev(1)), Some(rev(2)), Some(rev(2)), 1); // metadata-only
        assert_eq!(tracker.state.lock().unwrap().changes.len(), 0);
        tracker.take();
        immediate(Some(rev(2)), Some(rev(3)), Some(rev(2)), 1);
        immediate(Some(rev(3)), Some(rev(4)), Some(rev(2)), 2);
        tracker.take();
        published(&tracker, entity, rev(2), rev(4));
        let tail = tails(&tracker);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].contributors.len(), 2);
        assert!(tail[0].contributors.iter().any(|mark| own(mark, 1)));
        assert!(tail[0].contributors.iter().any(|mark| own(mark, 2)));
        immediate(Some(rev(4)), Some(rev(5)), Some(rev(4)), 1);
        immediate(Some(rev(5)), None, None, 1); // delete before idle
        assert!(tracker.state.lock().unwrap().changes.is_empty());
        assert!(tracker.state.lock().unwrap().waiting.is_empty());
    }

    #[test]
    fn old_publication_cannot_consume_newer_writer_and_late_mirror_is_not_foreign() {
        let entity = id(0x42);
        let tracker = PublicationTracker::default();
        write(&tracker, entity, rev(0), rev(1), 1);
        tails(&tracker);
        write(&tracker, entity, rev(1), rev(2), 2);
        published(&tracker, entity, rev(0), rev(1));
        mirror(&tracker, entity, Some(rev(1)));
        let first = tails(&tracker);
        assert_eq!(first.len(), 1);
        assert!(first[0].contributors.iter().all(|mark| own(mark, 1)));
        published(&tracker, entity, rev(1), rev(2));
        let second = tails(&tracker);
        assert_eq!(second.len(), 1);
        assert!(second[0].contributors.iter().all(|mark| own(mark, 2)));
        assert!(!second[0].contributors.iter().all(|mark| own(mark, 1)));
        mirror(&tracker, entity, None);
        let (independent, lost) = tracker.take();
        assert!(lost.is_empty());
        assert_eq!(independent.len(), 1);
        assert!(
            independent[0]
                .contributors
                .iter()
                .all(|mark| !own(mark, 1) && !own(mark, 2))
        );
    }
}
