//! The scoped temporal bound (ARCH-0004 #temporal-bound): how far a scoped
//! call's temporal channel widens, the rows its window holds, and the reader
//! whose candidate predicate decides which of them count (DEC-0005).

use std::collections::{HashMap, HashSet};
use std::ops::Bound;
use std::sync::{Mutex, MutexGuard};

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreRead, TimeAxis, TimelineQuery};
use crate::retrieval_depth::RetrievalDeadline;
use crate::store::StoreRead;

use super::channels::{
    TemporalCandidateScore, TemporalIndexCollectionContext, TemporalScoringContext,
    score_temporal_candidate, sort_temporal_candidate_scores, temporal_window,
};
use super::types::{
    EntityMetadataCache, ScoredEntity, SnapshotCandidateFilter, TEMPORAL_WIDENING_FLOOR,
    TEMPORAL_WIDENING_MULTIPLE, TemporalSearchConfig,
};

/// How many rows a temporal channel under a strict scope collects, scores
/// and returns before the scope narrows them: the entity count, as for the
/// other channels, but at most [`temporal_widening_bound`].
/// Unbounded, every scoped recall reads, scores and sorts every row of the
/// vault (ARCH-0004 #temporal-bound); bounded, its rankings may differ from
/// that scan only past the bound.
pub(super) fn scoped_temporal_channel_limit(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    requested: usize,
    scope_widening_active: bool,
) -> Result<usize> {
    if !scope_widening_active || requested == 0 {
        return Ok(requested);
    }
    let entity_count = usize::try_from(store.port_entity_count(rtxn)?)
        .map_err(|_| Error::IndexOverflow("entity count"))?;
    Ok(requested
        .max(entity_count)
        .min(temporal_widening_bound(requested)))
}

/// How far a scoped temporal channel asking for `requested` rows widens at
/// most: a fixed multiple of the request, with a floor.
pub(super) fn temporal_widening_bound(requested: usize) -> usize {
    requested
        .saturating_mul(TEMPORAL_WIDENING_MULTIPLE)
        .max(TEMPORAL_WIDENING_FLOOR)
}

/// The rows a temporal call's window holds once its rounds stop, best first
/// under the window's sigma, and the sigma the request settled on.
pub(super) struct TemporalWindow {
    pub(super) scored: Vec<TemporalCandidateScore>,
    pub(super) window: TemporalScoringContext,
    pub(super) request: TemporalScoringContext,
    /// How many of `scored` the bound keeps.
    pub(super) rows: usize,
}

impl TemporalWindow {
    /// The held rows' ids, best first under the window's sigma.
    pub(super) fn window_order(&self) -> Vec<EntityId> {
        self.scored.iter().map(|entry| entry.id).collect()
    }

    /// Scores and orders the held rows with the request's sigma. When the
    /// window grew past the round where sigma settled, its own sigma picked
    /// the rows; the request's scores and orders them.
    pub(super) fn rescore(
        &mut self,
        store: &StoreRead<'_>,
        rtxn: &RoTxn<'_>,
        config: &TemporalSearchConfig,
        metadata_cache: &mut EntityMetadataCache,
    ) -> Result<()> {
        if self.request.sigma == self.window.sigma {
            return Ok(());
        }
        for entry in &mut self.scored {
            let Some(meta) = metadata_cache.get(store, rtxn, &entry.id)? else {
                continue;
            };
            *entry = score_temporal_candidate(entry.id, meta, config, &self.request);
        }
        sort_temporal_candidate_scores(&mut self.scored);
        Ok(())
    }

    pub(super) fn into_scores(self) -> Vec<ScoredEntity> {
        self.scored
            .into_iter()
            .map(|entry| ScoredEntity {
                id: entry.id,
                score: entry.score,
            })
            .collect()
    }
}

/// The rows a temporal call's rounds have collected, in the order the
/// collectors found them: each axis nearest first, then the spanners best
/// first. A reader's counts ask about them in that order, so they ask first
/// about the rows the scope walk reaches first.
#[derive(Default)]
pub(super) struct TemporalCandidates {
    seen: HashSet<EntityId>,
    ids: Vec<EntityId>,
}

impl TemporalCandidates {
    pub(super) fn insert(&mut self, id: EntityId) {
        if self.seen.insert(id) {
            self.ids.push(id);
        }
    }

    pub(super) fn count(&self) -> usize {
        self.ids.len()
    }

    pub(super) fn ids(&self) -> &[EntityId] {
        &self.ids
    }
}

/// The rows a scoped call's reader may read: the call's candidate predicate,
/// asked at most once per row, by the channel's rounds and by the scope walk
/// after them alike. A row it refuses never counts toward either of the
/// channel's stops and never takes a place in its bounded rows, so whether
/// such a row exists cannot move what the reader gets back (DEC-0005: no
/// name, no count).
pub(super) struct ReadableRows<'p, 'f> {
    predicate: &'p SnapshotCandidateFilter<'f>,
    deadline: Option<&'p RetrievalDeadline>,
    answers: Mutex<HashMap<EntityId, bool>>,
}

impl<'p, 'f> ReadableRows<'p, 'f> {
    pub(super) fn new(
        predicate: &'p SnapshotCandidateFilter<'f>,
        deadline: Option<&'p RetrievalDeadline>,
    ) -> Self {
        Self {
            predicate,
            deadline,
            answers: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn reads(
        &self,
        store: &StoreRead<'_>,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if let Some(&reads) = self.answers()?.get(id) {
            return Ok(reads);
        }
        if let Some(deadline) = self.deadline {
            deadline.checkpoint()?;
        }
        let reads = (self.predicate)(store, rtxn, id)?;
        self.answers()?.insert(*id, reads);
        Ok(reads)
    }

    /// Whether the reader may read at least `count` of `ids`, asked in order.
    pub(super) fn read_at_least(
        &self,
        store: &StoreRead<'_>,
        rtxn: &RoTxn<'_>,
        ids: &[EntityId],
        count: usize,
    ) -> Result<bool> {
        if ids.len() < count {
            return Ok(false);
        }
        let mut readable = 0;
        for id in ids {
            if readable == count {
                break;
            }
            if self.reads(store, rtxn, id)? {
                readable += 1;
            }
        }
        Ok(readable == count)
    }

    fn answers(&self) -> Result<MutexGuard<'_, HashMap<EntityId, bool>>> {
        self.answers
            .lock()
            .map_err(|_| Error::InvariantViolation("temporal reader answers"))
    }
}

/// The cut the bound takes from a reader's rows, taken as the scope walk
/// reaches them: a row is in it when the reader may read it and fewer than
/// `bound` rows the reader may read rank above it in the window's order. A
/// row ranked inside the bound needs no count. Past it, the rows above are
/// asked once, in order, until the bound is full, so a walk that stops early
/// asks only about the rows it reached.
pub(super) struct WindowCut<'r, 'p, 'f> {
    reader: &'r ReadableRows<'p, 'f>,
    order: Vec<EntityId>,
    positions: HashMap<EntityId, usize>,
    bound: usize,
    /// How far down `order` the reader has been asked, how many of those
    /// rows it may read, and, once that reaches `bound`, where the cut ends.
    scan: Mutex<(usize, usize, Option<usize>)>,
}

impl<'r, 'p, 'f> WindowCut<'r, 'p, 'f> {
    fn new(reader: &'r ReadableRows<'p, 'f>, order: Vec<EntityId>, bound: usize) -> Self {
        let positions = order
            .iter()
            .enumerate()
            .map(|(position, id)| (*id, position))
            .collect();
        Self {
            reader,
            order,
            positions,
            bound,
            scan: Mutex::new((0, 0, None)),
        }
    }

    pub(super) fn keeps(
        &self,
        store: &StoreRead<'_>,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let Some(&position) = self.positions.get(id) else {
            return Ok(false);
        };
        if position >= self.bound {
            let mut scan = self
                .scan
                .lock()
                .map_err(|_| Error::InvariantViolation("temporal cut scan"))?;
            let (asked, readable, end) = &mut *scan;
            while end.is_none() && *asked < position {
                if self.reader.reads(store, rtxn, &self.order[*asked])? {
                    *readable += 1;
                    if *readable == self.bound {
                        *end = Some(*asked + 1);
                    }
                }
                *asked += 1;
            }
            // Past a full bound, a narrow scope's walk costs no more asks.
            if end.is_some_and(|stop| position >= stop) {
                return Ok(false);
            }
        }
        self.reader.reads(store, rtxn, id)
    }
}

/// A scoped temporal call for a reader: every row its window holds, best
/// first under the request's sigma, and the cut the bound takes from them,
/// for the scope walk to take as it goes. Taking it here instead would ask
/// the reader about every row inside the bound on every call.
pub(super) fn execute_temporal_for_reader<'r, 'p, 'f>(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    config: &TemporalSearchConfig,
    now: u64,
    metadata_cache: &mut EntityMetadataCache,
    deadline: Option<&RetrievalDeadline>,
    reader: &'r ReadableRows<'p, 'f>,
) -> Result<(Vec<ScoredEntity>, WindowCut<'r, 'p, 'f>)> {
    let Some(mut held) = temporal_window(
        store,
        rtxn,
        config,
        now,
        metadata_cache,
        deadline,
        Some(reader),
    )?
    else {
        return Ok((Vec::new(), WindowCut::new(reader, Vec::new(), 0)));
    };
    let cut = WindowCut::new(reader, held.window_order(), held.rows);
    held.rescore(store, rtxn, config, metadata_cache)?;
    Ok((held.into_scores(), cut))
}

/// Whether the widest window could add a row to one axis's nearest `cap`.
/// Each side of the anchor is read nearest first, so a side that already
/// holds `cap` rows inside the window keeps them over any farther row; only
/// a side short of it, with a row past the window but inside the widest one,
/// can add one. Without a widest window to probe, assume it can. A ring the
/// probe cannot read may hold a row too: the rounds then run as they would
/// without the probe, and a collection that reaches the ring meets its error.
pub(super) fn axis_can_grow(
    store: &StoreRead<'_>,
    axis: TimeAxis,
    rtxn: &RoTxn<'_>,
    collection: TemporalIndexCollectionContext<'_>,
    [forward_full, backward_full]: [bool; 2],
) -> bool {
    let Some((widest_start, widest_end)) = collection.widest else {
        return true;
    };
    let has_row = |start, end| {
        let query = TimelineQuery {
            axis,
            start,
            end,
            ..Default::default()
        };
        let first = store
            .port_entity_timeline(rtxn, query)
            .and_then(|mut rows| rows.next().transpose());
        !matches!(first, Ok(None))
    };
    (!forward_full
        && widest_end > collection.window_end
        && has_row(
            Bound::Excluded(collection.window_end),
            Bound::Included(widest_end),
        ))
        || (!backward_full
            && widest_start < collection.window_start
            && has_row(
                Bound::Included(widest_start),
                Bound::Excluded(collection.window_start),
            ))
}
