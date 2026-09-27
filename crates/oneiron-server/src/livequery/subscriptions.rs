//! Coarse derivation, retained rings and cumulative cursor acknowledgements.
use super::budget::{Budget, Reservation, value_bytes};
#[cfg(test)]
use super::budget::{HUB_BYTES, SESSION_BYTES};
use super::*;
use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) const LIVEQUERY_RING_CAPACITY: usize = 1024;
pub(super) const MAX_SUBSCRIPTIONS: usize = 128;
const MAX_RING_BYTES: usize = 8 * 1024 * 1024;

pub(crate) struct DerivedView {
    pub value: Value,
    pub cursor: Cursor,
    /// Trusted server-derived paths, never a client-provided read set.
    /// Include membership containers, not only current result ids, so
    /// an insertion into an empty view also invalidates it.
    pub dependencies: BTreeSet<String>,
}

/// Implementations must use one authority-bound facade, honor every view
/// constraint, and re-consult revocation before each derive/export. They
/// must not return raw full-window updates as app-tier data.
pub(crate) trait LiveQuerySource: Send + Sync {
    fn derive(&self, view: &ScopedView, channel: Channel) -> Result<DerivedView, AppError>;
    /// True only while this entity's live body is ahead of its indexed body.
    /// Called outside Observer B; births, metadata-only puts and edges need no
    /// delayed-origin retention.
    fn indexed_lag(&self, _path: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    /// Probe insertions and changed memberships not yet in the served read set.
    fn membership_changed(
        &self,
        _view: &ScopedView,
        _channel: Channel,
        _diff: &MaterializedDiffSummary,
    ) -> Result<bool, AppError> {
        Ok(false)
    }

    /// Validate/export the scoped document's updates since this VV. `false`
    /// means the cursor is past retention and requires full-state resync.
    fn can_resume(&self, cursor: &Cursor) -> Result<bool, AppError>;
    /// Retained, authority-scoped pushes outside the delivery ring.
    fn replay(
        &self,
        _view: &ScopedView,
        _channel: Channel,
        _cursor: &Cursor,
    ) -> Result<Option<Vec<Push>>, AppError> {
        Ok(None)
    }
    fn record(
        &self,
        _view: &ScopedView,
        _channel: Channel,
        _pushes: &[Push],
    ) -> Result<(), AppError> {
        Ok(())
    }
    fn retained_value(
        &self,
        _view: &ScopedView,
        _channel: Channel,
        _cursor: &Cursor,
    ) -> Result<Option<Value>, AppError> {
        Ok(None)
    }
    /// Local hard-delete publication precedes the destructive LMDB commit.
    /// Keep that invalidation until the read projection can observe the purge.
    fn ready(&self, _diff: &MaterializedDiffSummary, _by: &OriginMark) -> Result<bool, AppError> {
        Ok(true)
    }
}

/// Exercise Loro's real export door. Delta bytes remain server-side: a
/// subscription re-derives its authorized view, never leaks a window.
pub(crate) fn export_since(doc: &LoroDoc, cursor: &Cursor) -> Result<bool, AppError> {
    let vv = VersionVector::decode(&cursor.version_vector)
        .map_err(|_| AppError::bad_request("invalid cursor VV", Some("cursor")))?;
    let current = doc.oplog_vv();
    if !matches!(
        current.partial_cmp(&vv),
        Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
    ) {
        return Err(AppError::bad_request(
            "cursor is ahead of this document",
            Some("cursor"),
        ));
    }
    let shallow = doc.shallow_since_vv().to_vv();
    if !matches!(
        vv.partial_cmp(&shallow),
        Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
    ) {
        return Ok(false);
    }
    doc.export(ExportMode::updates(&vv))
        .map_err(|_| AppError::internal_server_error("cursor delta export failed"))?;
    Ok(true)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Push {
    pub subscription_id: u64,
    pub cursor: Cursor,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

impl Push {
    pub(crate) fn encode(&self) -> Result<Vec<Vec<u8>>, ProtocolError> {
        wire::push(self)
    }
}

struct Subscription {
    view: ScopedView,
    channel: Channel,
    origin: Option<String>,
    dependencies: BTreeSet<String>,
    current: blake3::Hash,
    metadata_bytes: usize,
    budget: Reservation,
    ring: VecDeque<Push>,
    bytes: usize,
    acked: Option<Cursor>,
    needs_resync: bool,
}

/// Owned by one bound logical session; keep this owner across socket
/// reconnects, but never reuse it for a different principal or claim set.
/// RPC results are deliberately absent from this state.
pub(crate) struct LiveQueries {
    source: Arc<dyn LiveQuerySource>,
    session_budget: Arc<Budget>,
    hub_budget: Arc<Budget>,
    state: Mutex<State>,
    invalidations: Mutex<VecDeque<(String, MaterializedDiffSummary, OriginMark)>>,
    index_origins: Mutex<BTreeMap<String, OriginMark>>,
    invalidation_gap: AtomicBool,
}

struct State {
    conn_id: u32,
    batch: u64,
    subs: BTreeMap<u64, Subscription>,
    index: BTreeMap<String, BTreeSet<u64>>,
}

impl State {
    fn reindex(&mut self) {
        self.index.clear();
        for (id, sub) in &self.subs {
            for path in &sub.dependencies {
                self.index.entry(path.clone()).or_default().insert(*id);
            }
        }
    }

    fn cursor(&mut self, mut cursor: Cursor) -> Result<Cursor, AppError> {
        self.batch = self
            .batch
            .checked_add(1)
            .ok_or_else(|| AppError::internal_server_error("live-query ordinal exhausted"))?;
        cursor.batch = self.batch;
        Ok(cursor)
    }
}

impl LiveQueries {
    #[cfg(test)]
    pub(crate) fn new(conn_id: u32, source: Arc<dyn LiveQuerySource>) -> Self {
        Self::with_budget(conn_id, source, Budget::new(HUB_BYTES))
    }

    #[cfg(test)]
    pub(super) fn with_budget(
        conn_id: u32,
        source: Arc<dyn LiveQuerySource>,
        hub_budget: Arc<Budget>,
    ) -> Self {
        Self::with_budgets(conn_id, source, Budget::new(SESSION_BYTES), hub_budget)
    }

    pub(super) fn with_budgets(
        conn_id: u32,
        source: Arc<dyn LiveQuerySource>,
        session_budget: Arc<Budget>,
        hub_budget: Arc<Budget>,
    ) -> Self {
        Self {
            source,
            session_budget,
            hub_budget,
            state: Mutex::new(State {
                conn_id,
                batch: 0,
                subs: BTreeMap::new(),
                index: BTreeMap::new(),
            }),
            invalidations: Mutex::new(VecDeque::new()),
            index_origins: Mutex::new(BTreeMap::new()),
            invalidation_gap: AtomicBool::new(false),
        }
    }

    pub(crate) fn control(&self, request: SubRequest) -> Result<Vec<Push>, AppError> {
        match request {
            SubRequest::Open {
                subscription_id,
                scoped_view,
                channel,
                cursor,
                origin,
            } => self.open(
                subscription_id,
                scoped_view,
                channel,
                cursor.as_ref(),
                origin,
            ),
            SubRequest::Ack {
                subscription_id,
                cursor,
            } => {
                self.ack(subscription_id, &cursor)?;
                Ok(Vec::new())
            }
            SubRequest::Close { subscription_id } => {
                self.close(subscription_id)?;
                Ok(Vec::new())
            }
        }
    }

    /// Called only after a fresh bind to the SAME authority has succeeded.
    pub(crate) fn reconnect(&self, conn_id: u32) -> Result<(), AppError> {
        self.state.lock().map_err(|_| state_error())?.conn_id = conn_id;
        Ok(())
    }

    pub(crate) fn open(
        &self,
        id: u64,
        view: ScopedView,
        channel: Channel,
        cursor: Option<&Cursor>,
        origin: Option<String>,
    ) -> Result<Vec<Push>, AppError> {
        if matches!(channel, Channel::MemoryBoard | Channel::Gap) {
            return Err(AppError::not_implemented("reserved subscription channel"));
        }
        if let Some(world) = &view.world_ref {
            oneiron::EntityId::from_hex(world)
                .map_err(|_| AppError::bad_request("invalid worldRef", Some("scopedView")))?;
        }
        let mut state = self.state.lock().map_err(|_| state_error())?;
        let mut latest = None;
        if let Some(sub) = state.subs.get_mut(&id) {
            if sub.view != view || sub.channel != channel {
                return Err(AppError::bad_request(
                    "subscription id is already open",
                    Some("subscriptionId"),
                ));
            }
            if let Some(cursor) = cursor {
                // A retained ring may predate an indexed publication. Re-read
                // the authorized view before returning it, even for an acked
                // cursor: the hub may not have drained the notice yet.
                if self.source.can_resume(cursor)? && !sub.needs_resync {
                    let derived = self.source.derive(&view, channel)?;
                    if fingerprint(&derived.value)? == sub.current {
                        if sub.acked.as_ref() == Some(cursor) {
                            sub.origin = origin;
                            return Ok(sub.ring.iter().cloned().collect());
                        }
                        if let Some(position) = sub.ring.iter().rposition(|p| &p.cursor == cursor) {
                            sub.origin = origin;
                            sub.ring.drain(..=position);
                            sub.bytes = push_bytes(sub.ring.make_contiguous())?;
                            sub.budget
                                .resize(sub.bytes.max(4096) + sub.metadata_bytes)?;
                            sub.acked = Some(cursor.clone());
                            return Ok(sub.ring.iter().cloned().collect());
                        }
                    }
                    latest = Some(derived);
                }
            } else {
                return Err(AppError::bad_request(
                    "subscription is already open",
                    Some("subscriptionId"),
                ));
            }
        } else if state.subs.len() >= MAX_SUBSCRIPTIONS {
            return Err(AppError::bad_request(
                "subscription limit exceeded",
                Some("subscriptionId"),
            ));
        }
        // The old ring must release its budget before replay plus the fresh
        // indexed tail reserve theirs. A failed replay leaves no stale owner.
        if state.subs.remove(&id).is_some() {
            state.reindex();
        }
        let derived = if let Some(derived) = latest {
            derived
        } else {
            self.source.derive(&view, channel)?
        };
        if let Some(cursor) = cursor
            && self.source.can_resume(cursor)?
            && let Some(mut replay) = self.source.replay(&view, channel, cursor)?
        {
            for push in &mut replay {
                push.subscription_id = id;
            }
            if let Some(last) = replay.last() {
                state.batch = state.batch.max(last.cursor.batch);
            }
            let previous = replay
                .iter()
                .rev()
                .find_map(|push| push.result.clone())
                .or(self.source.retained_value(&view, channel, cursor)?);
            if previous.as_ref().is_some_and(|last| last != &derived.value) {
                let catch_up = Push {
                    subscription_id: id,
                    cursor: state.cursor(derived.cursor.clone())?,
                    kind: "data",
                    result: Some(derived.value.clone()),
                };
                self.source
                    .record(&view, channel, std::slice::from_ref(&catch_up))?;
                replay.push(catch_up);
            }
            let bytes = push_bytes(&replay)?;
            if bytes <= MAX_RING_BYTES && replay.len() <= LIVEQUERY_RING_CAPACITY {
                let metadata_bytes = serde_json::to_vec(&(&view, &origin))
                    .map_err(|_| state_error())?
                    .len()
                    .saturating_mul(8)
                    + 4096;
                let budget = Reservation::new(
                    self.session_budget.clone(),
                    self.hub_budget.clone(),
                    bytes.max(4096) + metadata_bytes,
                )?;
                state.subs.insert(
                    id,
                    Subscription {
                        view,
                        channel,
                        origin,
                        dependencies: derived.dependencies,
                        current: fingerprint(&derived.value)?,
                        metadata_bytes,
                        budget,
                        ring: replay.iter().cloned().collect(),
                        bytes,
                        acked: Some(cursor.clone()),
                        needs_resync: false,
                    },
                );
                state.reindex();
                return Ok(replay);
            }
        }
        let next_cursor = state.cursor(derived.cursor)?;
        let mut pushes = Vec::new();
        if cursor.is_some() {
            pushes.push(Push {
                subscription_id: id,
                cursor: next_cursor.clone(),
                kind: "gap",
                result: None,
            });
        }
        pushes.push(Push {
            subscription_id: id,
            cursor: next_cursor.clone(),
            kind: "snapshot",
            result: Some(derived.value.clone()),
        });
        pushes.push(Push {
            subscription_id: id,
            cursor: next_cursor,
            kind: "eose",
            result: None,
        });
        let bytes = push_bytes(&pushes)?;
        if bytes > MAX_RING_BYTES {
            return Err(AppError::bad_request(
                "view snapshot too large",
                Some("scopedView"),
            ));
        }
        let metadata_bytes = serde_json::to_vec(&(&view, &origin))
            .map_err(|_| state_error())?
            .len()
            .saturating_mul(8)
            + 4096;
        let budget = Reservation::new(
            self.session_budget.clone(),
            self.hub_budget.clone(),
            bytes.max(4096) + metadata_bytes,
        )?;
        let current = fingerprint(&derived.value)?;
        self.source.record(&view, channel, &pushes)?;
        state.subs.insert(
            id,
            Subscription {
                view,
                channel,
                origin,
                dependencies: derived.dependencies,
                current,
                metadata_bytes,
                budget,
                ring: pushes.iter().cloned().collect(),
                bytes,
                acked: None,
                needs_resync: false,
            },
        );
        state.reindex();
        Ok(pushes)
    }

    /// Acks are cumulative and must name a cursor this sub actually sent.
    /// Unknown/future cursors cannot discard buffered history.
    pub(crate) fn ack(&self, id: u64, cursor: &Cursor) -> Result<(), AppError> {
        let mut state = self.state.lock().map_err(|_| state_error())?;
        let sub = state
            .subs
            .get_mut(&id)
            .ok_or_else(|| AppError::not_found("subscription", None))?;
        if sub.acked.as_ref() == Some(cursor) {
            return Ok(());
        }
        let position = sub
            .ring
            .iter()
            .rposition(|p| &p.cursor == cursor)
            .ok_or_else(|| AppError::bad_request("unknown ack cursor", Some("cursor")))?;
        sub.ring.drain(..=position);
        sub.bytes = push_bytes(sub.ring.make_contiguous())?;
        sub.budget
            .resize(sub.bytes.max(4096) + sub.metadata_bytes)?;
        sub.acked = Some(cursor.clone());
        Ok(())
    }

    pub(crate) fn close(&self, id: u64) -> Result<(), AppError> {
        let mut state = self.state.lock().map_err(|_| state_error())?;
        state.subs.remove(&id);
        state.reindex();
        Ok(())
    }

    pub(crate) fn buffered(&self) -> Result<Vec<Push>, AppError> {
        let state = self.state.lock().map_err(|_| state_error())?;
        Ok(state
            .subs
            .values()
            .flat_map(|sub| sub.ring.iter().cloned())
            .collect())
    }

    #[cfg(test)]
    pub(crate) fn pending(&self, id: u64) -> Result<Vec<Push>, AppError> {
        let state = self.state.lock().map_err(|_| state_error())?;
        let sub = state
            .subs
            .get(&id)
            .ok_or_else(|| AppError::not_found("subscription", None))?;
        self.source.derive(&sub.view, sub.channel)?;
        Ok(sub.ring.iter().cloned().collect())
    }

    fn materialized(
        &self,
        changes: &[(String, MaterializedDiffSummary, OriginMark)],
    ) -> Result<(), AppError> {
        let mut state = self.state.lock().map_err(|_| state_error())?;
        // Coarse re-derive sees CURRENT state, not intermediate event
        // states. Suppress only when EVERY affecting invalidation is our
        // own; an earlier own write must not swallow a later foreign one.
        let mut affected = BTreeMap::<u64, bool>::new();
        for (path, diff, by) in changes {
            for (dependency, ids) in &state.index {
                let relevant = dependency == path
                    || path
                        .strip_prefix(dependency.as_str())
                        .is_some_and(|tail| tail.starts_with('/'))
                    || dependency
                        .strip_prefix(path.as_str())
                        .is_some_and(|tail| tail.starts_with('/'))
                    || diff.containers.iter().any(|changed| changed == dependency);
                let membership = dependency.starts_with("membership:");
                if !relevant && !membership {
                    continue;
                }
                for id in ids {
                    if !relevant
                        && !self.source.membership_changed(
                            &state.subs[id].view,
                            state.subs[id].channel,
                            diff,
                        )?
                    {
                        continue;
                    }
                    let own = by.conn_id == Some(state.conn_id)
                        || (by.origin.is_some() && by.origin == state.subs[id].origin);
                    affected
                        .entry(*id)
                        .and_modify(|echo| *echo &= own)
                        .or_insert(own);
                }
            }
        }
        for (id, echo) in affected {
            let sub = &state.subs[&id];
            if sub.needs_resync {
                continue;
            }
            let derived = self.source.derive(&sub.view, sub.channel)?;
            let current = fingerprint(&derived.value)?;
            let changed = sub.current != current;
            let cursor = state.cursor(derived.cursor)?;
            let sub = state.subs.get_mut(&id).ok_or_else(state_error)?;
            sub.dependencies = derived.dependencies;
            sub.current = current;
            if echo || !changed {
                continue;
            }
            let push = Push {
                subscription_id: id,
                cursor: cursor.clone(),
                kind: "data",
                result: Some(derived.value),
            };
            self.source
                .record(&sub.view, sub.channel, std::slice::from_ref(&push))?;
            let bytes = push_bytes(std::slice::from_ref(&push))?;
            if sub.ring.len() >= LIVEQUERY_RING_CAPACITY
                || sub.bytes.saturating_add(bytes) > MAX_RING_BYTES
                || sub
                    .budget
                    .resize(sub.metadata_bytes + (sub.bytes + bytes).max(4096))
                    .is_err()
            {
                sub.ring.clear();
                let gap = Push {
                    subscription_id: id,
                    cursor,
                    kind: "gap",
                    result: None,
                };
                sub.bytes = push_bytes(std::slice::from_ref(&gap))?;
                sub.budget
                    .resize(sub.metadata_bytes + sub.bytes.max(4096))?;
                sub.ring.push_back(gap);
                sub.needs_resync = true;
            } else {
                sub.bytes += bytes;
                sub.ring.push_back(push);
            }
        }
        state.reindex();
        Ok(())
    }
}

impl LiveQueries {
    /// Drive from the server's subscription loop, OUTSIDE Observer B.
    /// Facade reads such as recall may persist retrieval telemetry; doing
    /// that inside the materializer callback would re-enter Loro.
    pub(crate) fn refresh(&self) -> Result<(), AppError> {
        let changes = {
            let mut pending = self.invalidations.lock().map_err(|_| state_error())?;
            std::mem::take(&mut *pending)
        };
        if self.invalidation_gap.swap(false, Ordering::AcqRel) {
            self.index_origins
                .lock()
                .map_err(|_| state_error())?
                .clear();
            self.require_resync();
            return Ok(());
        }
        if changes.is_empty() {
            return Ok(());
        }
        let mut ready = Vec::new();
        for (path, diff, by) in changes {
            match self.source.ready(&diff, &by) {
                Ok(true) => ready.push((path, diff, by)),
                Ok(false) => self.on_materialized(&path, &diff, &by),
                Err(error) => {
                    self.require_resync();
                    return Err(error);
                }
            }
        }
        if let Err(error) = self
            .retain_lagged_origins(&ready)
            .and_then(|()| self.materialized(&ready))
        {
            self.require_resync();
            return Err(error);
        }
        Ok(())
    }

    /// Retain only edits whose indexed body still lags. Scanning the already
    /// queued notices here avoids a vault read in Observer B's Loro callback.
    fn retain_lagged_origins(
        &self,
        changes: &[(String, MaterializedDiffSummary, OriginMark)],
    ) -> Result<(), AppError> {
        let mut origins = self.index_origins.lock().map_err(|_| state_error())?;
        let mut candidates = BTreeMap::<String, OriginMark>::new();
        for (path, diff, by) in changes {
            for changed in std::iter::once(path).chain(diff.containers.iter()) {
                if changed
                    .strip_prefix("e:")
                    .is_some_and(|id| oneiron::EntityId::from_hex(id).is_ok())
                {
                    candidates
                        .entry(changed.clone())
                        .and_modify(|prior| merge_origin(prior, by))
                        .or_insert_with(|| by.clone());
                }
            }
        }
        // Retire settled/deleted/superseded bodies, even if an idle pass never
        // sent a publication (births and metadata-only writes are examples).
        let paths: Vec<_> = origins.keys().cloned().collect();
        for path in paths {
            if !self.source.indexed_lag(&path)? {
                origins.remove(&path);
            }
        }
        for (path, by) in candidates {
            if self.source.indexed_lag(&path)? {
                origins
                    .entry(path)
                    .and_modify(|prior| merge_origin(prior, &by))
                    .or_insert(by);
            }
        }
        let bytes: usize = origins
            .iter()
            .map(|(path, by)| path.len() + by.origin.as_ref().map_or(0, String::len) + 64)
            .sum();
        if origins.len() > LIVEQUERY_RING_CAPACITY || bytes > 64 * 1024 {
            origins.clear();
            self.invalidation_gap.store(true, Ordering::Release);
            return Err(state_error());
        }
        Ok(())
    }

    fn require_resync(&self) {
        if let Ok(mut state) = self.state.lock() {
            for (id, sub) in &mut state.subs {
                if let Some(cursor) = sub
                    .ring
                    .back()
                    .map(|p| p.cursor.clone())
                    .or_else(|| sub.acked.clone())
                {
                    sub.ring.clear();
                    sub.ring.push_back(Push {
                        subscription_id: *id,
                        cursor,
                        kind: "gap",
                        result: None,
                    });
                    sub.bytes = push_bytes(sub.ring.make_contiguous()).unwrap_or(4096);
                    let _ = sub.budget.resize(sub.metadata_bytes + sub.bytes.max(4096));
                }
                sub.needs_resync = true;
            }
        }
    }
}

impl LiveQueries {
    pub(super) fn on_indexed_published(&self, path: &str, diff: &MaterializedDiffSummary) {
        // If index publication beats the timer, the contributing writes still
        // sit in the invalidation queue, not the retained lag map. Fold both.
        let queued = self
            .invalidations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(changed, diff, _)| {
                changed == path || diff.containers.iter().any(|item| item == path)
            })
            .map(|(_, _, by)| by.clone())
            .collect::<Vec<_>>();
        let cached = self
            .index_origins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(path);
        let mut contributors = cached.into_iter().chain(queued);
        let mut by = contributors.next().unwrap_or_default();
        for contributor in contributors {
            merge_origin(&mut by, &contributor);
        }
        self.enqueue_invalidation(path, diff, &by);
    }

    fn enqueue_invalidation(&self, path: &str, diff: &MaterializedDiffSummary, by: &OriginMark) {
        let Ok(mut pending) = self.invalidations.lock() else {
            self.invalidation_gap.store(true, Ordering::Release);
            return;
        };
        // Bound invalidation metadata independently of every subscription
        // ring. An overflow loses history explicitly, never silently.
        let bytes: usize = pending
            .iter()
            .map(|(path, diff, by)| {
                path.len()
                    + by.origin.as_ref().map_or(0, String::len)
                    + 128
                    + diff
                        .containers
                        .iter()
                        .map(|path| path.len() + 32)
                        .sum::<usize>()
            })
            .sum();
        let changed_paths = diff.containers.as_slice();
        let incoming = path.len()
            + by.origin.as_ref().map_or(0, String::len)
            + 128
            + changed_paths
                .iter()
                .map(|path| path.len() + 32 + 66)
                .sum::<usize>();
        if pending.len() >= LIVEQUERY_RING_CAPACITY || bytes.saturating_add(incoming) > 64 * 1024 {
            pending.clear();
            self.index_origins
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
            self.invalidation_gap.store(true, Ordering::Release);
            return;
        }
        // Entity-indexed subscriptions need the key delta even on an ordinary
        // commit. Bound it before cloning, and normalize deletion publications
        // that still originate from the window transport.
        let mut containers: BTreeSet<String> = changed_paths.iter().cloned().collect();
        for changed in changed_paths {
            if (changed.contains("/entities/") || changed.contains("/tombstones/"))
                && let Some(id) = changed.rsplit('/').next()
                && let Ok(id) = oneiron::EntityId::from_hex(id)
            {
                containers.insert(format!("e:{}", id.to_hex()));
            }
        }
        // A bridge mirror of the same entity blob is one write, not a
        // foreign contribution. A distinct bridge blob (or an edge change)
        // remains foreign. Match the committed blob, never merely the path.
        let mut origin = by.clone();
        if by.origin.as_deref() == Some(oneiron::sync::bridge::BRIDGE_ORIGIN)
            && !diff.entity_blob_hashes.is_empty()
        {
            let mut matched = Vec::new();
            for (entity, hash) in &diff.entity_blob_hashes {
                let found = pending.iter().rev().find(|(_, prior, previous)| {
                    previous.origin.as_deref() != Some(oneiron::sync::bridge::BRIDGE_ORIGIN)
                        && prior.entity_blob_hashes.get(entity) == Some(hash)
                });
                if let Some((_, _, previous)) = found {
                    matched.push(previous.clone());
                } else {
                    matched.clear();
                    break;
                }
            }
            if let Some(first) = matched.first() {
                origin = first.clone();
                for contributor in matched.iter().skip(1) {
                    merge_origin(&mut origin, contributor);
                }
            }
        }
        pending.push_back((
            path.to_owned(),
            MaterializedDiffSummary {
                containers: containers.into_iter().collect(),
                bytes: diff.bytes,

                entity_blob_hashes: diff.entity_blob_hashes.clone(),
            },
            origin,
        ));
    }
}

impl LiveQueryTee for LiveQueries {
    fn on_materialized(&self, path: &str, diff: &MaterializedDiffSummary, by: &OriginMark) {
        self.enqueue_invalidation(path, diff, by);
    }
}

fn merge_origin(prior: &mut OriginMark, next: &OriginMark) {
    if prior.conn_id != next.conn_id || prior.origin != next.origin {
        *prior = OriginMark::default();
    }
}

fn push_bytes(pushes: &[Push]) -> Result<usize, AppError> {
    pushes.iter().try_fold(0usize, |bytes, push| {
        bytes
            .checked_add(
                512 + push.cursor.document.capacity()
                    + push.cursor.version_vector.capacity()
                    + push.result.as_ref().map_or(0, value_bytes),
            )
            .ok_or_else(state_error)
    })
}

fn fingerprint(value: &Value) -> Result<blake3::Hash, AppError> {
    wire::packed(value)
        .map(|bytes| blake3::hash(&bytes))
        .map_err(|_| AppError::bad_request("view snapshot too large", Some("scopedView")))
}

fn state_error() -> AppError {
    AppError::internal_server_error("live-query state unavailable")
}
