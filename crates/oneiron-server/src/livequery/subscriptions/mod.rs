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
use std::time::{Duration, Instant};

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
    /// Cursors already issued whose payloads were coalesced away. Bodies
    /// never live here, but a delayed cumulative ACK still names a real push.
    coalesced: VecDeque<Cursor>,
    coalesced_bytes: usize,
    acked: Option<Cursor>,
    needs_resync: bool,
}

impl Subscription {
    /// Retire owner-feed payloads without retiring the exact cursors that
    /// named them. Capacity/budget overflow becomes an explicit gap, never a
    /// silent loss of ACK eligibility.
    fn coalesce_owner_ring(&mut self) -> Result<bool, AppError> {
        let mut added = Vec::new();
        let mut added_bytes = 0usize;
        for push in &self.ring {
            let cursor = &push.cursor;
            if self.acked.as_ref() == Some(cursor)
                || self.coalesced.back() == Some(cursor)
                || added.last() == Some(cursor)
            {
                continue;
            }
            added_bytes = added_bytes.saturating_add(cursor_size(cursor)?);
            added.push(cursor.clone());
        }
        let total = self.coalesced_bytes.saturating_add(added_bytes);
        if self.coalesced.len().saturating_add(added.len()) > LIVEQUERY_RING_CAPACITY
            || total > MAX_RING_BYTES
            || self
                .budget
                .resize(self.metadata_bytes + total.max(4096))
                .is_err()
        {
            self.coalesced.clear();
            self.coalesced_bytes = 0;
            self.ring.clear();
            self.bytes = 0;
            return Ok(false);
        }
        self.coalesced.extend(added);
        self.coalesced_bytes = total;
        self.ring.clear();
        self.bytes = 0;
        Ok(true)
    }

    fn recalculate_coalesced_bytes(&mut self) -> Result<(), AppError> {
        self.coalesced_bytes = self.coalesced.iter().try_fold(0usize, |total, cursor| {
            Ok::<usize, AppError>(total.saturating_add(cursor_size(cursor)?))
        })?;
        Ok(())
    }
}

fn cursor_size(cursor: &Cursor) -> Result<usize, AppError> {
    serde_json::to_vec(cursor)
        .map(|bytes| bytes.len())
        .map_err(|_| state_error())
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
    invalidation_gap: AtomicBool,
    last_owner_feed_poll: Mutex<Instant>,
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
            invalidation_gap: AtomicBool::new(false),
            last_owner_feed_poll: Mutex::new(Instant::now()),
        }
    }

    #[cfg(test)]
    pub(crate) fn owner_feed_poll_now(&self) {
        *self
            .last_owner_feed_poll
            .lock()
            .expect("owner feed poll lock") = Instant::now() - Duration::from_secs(2);
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
        // Owner-feed snapshots contain claim bodies. Never replay a retained
        // body after a reconnect: policy may have narrowed while this slip
        // remained live. A gap + newly scoped snapshot is the safe resume.
        if channel == Channel::OwnerFeed
            && let Some(sub) = state.subs.get(&id)
        {
            if sub.view != view || sub.channel != channel {
                return Err(AppError::bad_request(
                    "subscription id is already open",
                    Some("subscriptionId"),
                ));
            }
            if cursor.is_none() {
                return Err(AppError::bad_request(
                    "subscription is already open",
                    Some("subscriptionId"),
                ));
            }
            state.subs.remove(&id);
            state.reindex();
        }
        if let Some(sub) = state.subs.get_mut(&id) {
            if sub.view != view || sub.channel != channel {
                return Err(AppError::bad_request(
                    "subscription id is already open",
                    Some("subscriptionId"),
                ));
            }
            if let Some(cursor) = cursor {
                // Consult the source on reconnect even when the ring has
                // the cursor; retention and authority can both change.
                if self.source.can_resume(cursor)? && !sub.needs_resync {
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
        let derived = self.source.derive(&view, channel)?;
        if channel != Channel::OwnerFeed
            && let Some(cursor) = cursor
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
                        coalesced: VecDeque::new(),
                        coalesced_bytes: 0,
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
                coalesced: VecDeque::new(),
                coalesced_bytes: 0,
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
        if let Some(position) = sub.coalesced.iter().position(|issued| issued == cursor) {
            // The old body is gone, but this exact cursor was issued. ACK it
            // cumulatively without consuming the newer pending ring payload.
            sub.coalesced.drain(..=position);
            sub.recalculate_coalesced_bytes()?;
            sub.budget
                .resize(sub.metadata_bytes + (sub.bytes + sub.coalesced_bytes).max(4096))?;
            sub.acked = Some(cursor.clone());
            return Ok(());
        }
        let position = sub
            .ring
            .iter()
            .rposition(|p| &p.cursor == cursor)
            .ok_or_else(|| AppError::bad_request("unknown ack cursor", Some("cursor")))?;
        sub.ring.drain(..=position);
        // ACK of a newer ring cursor also consumes earlier coalesced cursors.
        sub.coalesced.retain(|issued| issued.batch > cursor.batch);
        sub.recalculate_coalesced_bytes()?;
        sub.bytes = push_bytes(sub.ring.make_contiguous())?;
        sub.budget
            .resize(sub.metadata_bytes + (sub.bytes + sub.coalesced_bytes).max(4096))?;
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
        let mut state = self.state.lock().map_err(|_| state_error())?;
        let owner_ids: Vec<_> = state
            .subs
            .iter()
            .filter_map(|(id, sub)| {
                (sub.channel == Channel::OwnerFeed && !sub.needs_resync).then_some(*id)
            })
            .collect();
        for id in owner_ids {
            let sub = &state.subs[&id];
            let derived = self.source.derive(&sub.view, sub.channel)?;
            let fingerprint = fingerprint(&derived.value)?;
            // Even a queued snapshot from before a policy change is unsafe.
            // Compare EVERY retained result with a fresh scoped projection,
            // not merely the last fingerprint, before socket delivery.
            if fingerprint != sub.current
                || sub.ring.iter().any(|push| {
                    push.result
                        .as_ref()
                        .is_some_and(|result| result != &derived.value)
                })
            {
                let cursor = state.cursor(derived.cursor)?;
                let push = Push {
                    subscription_id: id,
                    cursor: cursor.clone(),
                    kind: "data",
                    result: Some(derived.value),
                };
                let bytes = push_bytes(std::slice::from_ref(&push))?;
                let sub = state.subs.get_mut(&id).ok_or_else(state_error)?;
                sub.current = fingerprint;
                sub.dependencies = derived.dependencies;
                // Owner feeds are a coalesced latest-state projection. This
                // drops old bodies after either a local edit OR a policy
                // narrowing, then emits only the newly authorized value.
                // Neither transition requires the client to resubscribe.
                let retained = sub.coalesce_owner_ring()?;
                if retained
                    && bytes.saturating_add(sub.coalesced_bytes) <= MAX_RING_BYTES
                    && sub
                        .budget
                        .resize(sub.metadata_bytes + (bytes + sub.coalesced_bytes).max(4096))
                        .is_ok()
                {
                    sub.ring.push_back(push);
                    sub.bytes = bytes;
                } else {
                    // Only a true payload/cursor/budget overflow needs a gap.
                    sub.ring.clear();
                    sub.coalesced.clear();
                    sub.coalesced_bytes = 0;
                    sub.ring.push_back(Push {
                        subscription_id: id,
                        cursor,
                        kind: "gap",
                        result: None,
                    });
                    sub.bytes = push_bytes(sub.ring.make_contiguous())?;
                    sub.budget
                        .resize(sub.metadata_bytes + sub.bytes.max(4096))?;
                    sub.needs_resync = true;
                }
            }
        }
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
                    // The synthetic local-LMDB poll is not a Loro change.
                    // It must never re-derive unrelated recall/receipt subs.
                    if path == "owner-feed" && state.subs[id].channel != Channel::OwnerFeed {
                        continue;
                    }
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
            let retained = if sub.channel == Channel::OwnerFeed {
                // Retire the old body, not its issued cursor. A delayed ACK
                // remains valid until an explicit bounded-retention gap.
                sub.coalesce_owner_ring()?
            } else {
                true
            };
            if !retained
                || sub.ring.len() >= LIVEQUERY_RING_CAPACITY
                || sub
                    .bytes
                    .saturating_add(bytes)
                    .saturating_add(sub.coalesced_bytes)
                    > MAX_RING_BYTES
                || sub
                    .budget
                    .resize(
                        sub.metadata_bytes + (sub.bytes + bytes + sub.coalesced_bytes).max(4096),
                    )
                    .is_err()
            {
                sub.ring.clear();
                sub.coalesced.clear();
                sub.coalesced_bytes = 0;
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

mod delivery;

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
