//! Coarse derivation, retained rings and cumulative cursor acknowledgements.
use super::budget::{Budget, Reservation, value_bytes};
use super::*;
use crate::admission::Permit;
use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) const LIVEQUERY_RING_CAPACITY: usize = 1024;
/// The local path every notification view follows: notification puts and
/// marks commit to LMDB, so the refresh re-derives these views on its local
/// cadence, as it does the owner feed.
pub(crate) const NOTIFICATIONS_PATH: &str = "notifications";
const MAX_RING_BYTES: usize = 8 * 1024 * 1024;

pub(crate) struct DerivedView {
    pub value: Value,
    pub cursor: Cursor,
    /// Trusted server-derived paths, never a client-provided read set.
    /// Include membership containers, not only current result ids, so
    /// an insertion into an empty view also invalidates it.
    pub dependencies: BTreeSet<String>,
    /// The dependencies a view follows but serves at no index position, such
    /// as a TURN's messages, whose words a recall reads live. A change to one
    /// invalidates the view; its index neither pins the cursor nor holds a
    /// session that opens while it lags.
    pub followed: BTreeSet<String>,
}

/// Implementations must use one authority-bound facade, honor every view
/// constraint, and re-consult revocation before each derive/export. They
/// must not return raw full-window updates as app-tier data.
pub(crate) trait LiveQuerySource: Send + Sync {
    fn derive(&self, view: &ScopedView, channel: Channel) -> Result<DerivedView, AppError>;
    /// Entities already ahead of their index when this logical session opens.
    fn pending_at_open(
        &self,
        _dependencies: &BTreeSet<String>,
    ) -> Result<Vec<oneiron::EntityId>, AppError> {
        Ok(Vec::new())
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
    /// Whether a device-local world now keeps a row one of `pushes` names
    /// from this source's caller. Such a retained push never leaves this
    /// device again (DEC-0005): the subscription gets a gap and a fresh
    /// snapshot instead.
    fn withholds(&self, _pushes: &[Push]) -> Result<bool, AppError> {
        Ok(false)
    }
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
    /// The rows its result was derived from: the entity dependencies of that
    /// derivation. A release judges them again (DEC-0005); they never go on
    /// the wire.
    #[serde(skip)]
    pub rows: Vec<oneiron::EntityId>,
}

/// The rows a derivation read: its entity dependencies.
fn derived_rows(dependencies: &BTreeSet<String>) -> Vec<oneiron::EntityId> {
    dependencies
        .iter()
        .filter_map(|path| path.strip_prefix("e:"))
        .filter_map(|id| oneiron::EntityId::from_hex(id).ok())
        .collect()
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
    /// The subscription's turn under `limits.live_subscriptions`.
    turn: Option<Permit>,
}

impl Subscription {
    /// Retire every retained push for one gap at the last cursor sent: the
    /// client resubscribes and gets a fresh snapshot.
    fn resync(&mut self, id: u64) {
        if let Some(cursor) = self
            .ring
            .back()
            .map(|p| p.cursor.clone())
            .or_else(|| self.acked.clone())
        {
            self.ring.clear();
            self.coalesced.clear();
            self.coalesced_bytes = 0;
            self.ring.push_back(Push {
                subscription_id: id,
                cursor,
                kind: "gap",
                result: None,
                rows: Vec::new(),
            });
            self.bytes = push_bytes(self.ring.make_contiguous()).unwrap_or(4096);
            let _ = self
                .budget
                .resize(self.metadata_bytes + self.bytes.max(4096));
        }
        self.needs_resync = true;
    }

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
    budget: Arc<Budget>,
    state: Mutex<State>,
    tracker: super::publication::PublicationTracker,
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
        Self::with_budget(conn_id, source, Budget::of(64 * 1024 * 1024))
    }

    #[cfg(test)]
    pub(super) fn with_budget(
        conn_id: u32,
        source: Arc<dyn LiveQuerySource>,
        budget: Arc<Budget>,
    ) -> Self {
        Self::with_budget_limits(
            conn_id,
            source,
            budget,
            oneiron::memory::LiveQueryTrackerLimits::default(),
        )
    }

    pub(super) fn with_budget_limits(
        conn_id: u32,
        source: Arc<dyn LiveQuerySource>,
        budget: Arc<Budget>,
        limits: oneiron::memory::LiveQueryTrackerLimits,
    ) -> Self {
        Self {
            source,
            budget,
            state: Mutex::new(State {
                conn_id,
                batch: 0,
                subs: BTreeMap::new(),
                index: BTreeMap::new(),
            }),
            tracker: super::publication::PublicationTracker::with_limits(limits),
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
            } => self.open_in_turn(
                subscription_id,
                scoped_view,
                channel,
                cursor.as_ref(),
                origin,
                None,
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

    #[cfg(test)]
    pub(crate) fn open(
        &self,
        id: u64,
        view: ScopedView,
        channel: Channel,
        cursor: Option<&Cursor>,
        origin: Option<String>,
    ) -> Result<Vec<Push>, AppError> {
        self.open_in_turn(id, view, channel, cursor, origin, None)
    }

    /// Opens subscription `id` holding `turn`, its turn under
    /// `limits.live_subscriptions`; a reopen keeps the turn it held.
    pub(crate) fn open_in_turn(
        &self,
        id: u64,
        view: ScopedView,
        channel: Channel,
        cursor: Option<&Cursor>,
        origin: Option<String>,
        turn: Option<Permit>,
    ) -> Result<Vec<Push>, AppError> {
        if matches!(channel, Channel::MemoryBoard | Channel::Gap) {
            return Err(AppError::not_implemented("reserved subscription channel"));
        }
        if let Some(world) = &view.world_ref {
            oneiron::EntityId::from_hex(world)
                .map_err(|_| AppError::bad_request("invalid worldRef", Some("scopedView")))?;
        }
        let mut state = self.state.lock().map_err(|_| state_error())?;
        let new_subscription = !state.subs.contains_key(&id);
        let mut latest = None;
        // A reopened subscription keeps the turn it held.
        let mut turn = turn;
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
            if let Some(old) = state.subs.remove(&id) {
                turn = old.turn.or(turn);
            }
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
                // A retained ring may predate an indexed publication. Re-read
                // the authorized view before returning it, even for an acked
                // cursor: the hub may not have drained the notice yet.
                if self.source.can_resume(cursor)? && !sub.needs_resync {
                    let derived = self.source.derive(&view, channel)?;
                    let tail = if sub.acked.as_ref() == Some(cursor) {
                        Some(0)
                    } else {
                        sub.ring
                            .iter()
                            .rposition(|p| &p.cursor == cursor)
                            .map(|position| position + 1)
                    };
                    // A retained push that names a row a device-local world
                    // keeps since is not sent again: the resume falls to a
                    // gap and a fresh snapshot.
                    if fingerprint(&derived.value)? == sub.current
                        && let Some(tail) = tail
                        && !self.source.withholds(&sub.ring.make_contiguous()[tail..])?
                    {
                        sub.origin = origin;
                        if tail > 0 {
                            sub.ring.drain(..tail);
                            sub.bytes = push_bytes(sub.ring.make_contiguous())?;
                            sub.budget
                                .resize(sub.bytes.max(4096) + sub.metadata_bytes)?;
                            sub.acked = Some(cursor.clone());
                        }
                        return Ok(sub.ring.iter().cloned().collect());
                    }
                    latest = Some(derived);
                }
            } else {
                return Err(AppError::bad_request(
                    "subscription is already open",
                    Some("subscriptionId"),
                ));
            }
        }
        // The old ring must release its budget before replay plus the fresh
        // indexed tail reserve theirs. A failed replay leaves no stale owner.
        if let Some(old) = state.subs.remove(&id) {
            turn = old.turn.or(turn);
            state.reindex();
        }
        let derived = if let Some(derived) = latest {
            derived
        } else {
            self.source.derive(&view, channel)?
        };
        if new_subscription && channel == Channel::View {
            let served: BTreeSet<String> = derived
                .dependencies
                .difference(&derived.followed)
                .cloned()
                .collect();
            let missing = self.source.pending_at_open(&served)?;
            self.tracker.mark_unavailable_at_open(&missing);
        }
        if channel != Channel::OwnerFeed
            && let Some(cursor) = cursor
            && self.source.can_resume(cursor)?
            && let Some(mut replay) = self.source.replay(&view, channel, cursor)?
            && !self.source.withholds(&replay)?
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
                    rows: derived_rows(&derived.dependencies),
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
                let budget =
                    Reservation::new(self.budget.clone(), bytes.max(4096) + metadata_bytes)?;
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
                        turn,
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
                rows: Vec::new(),
            });
        }
        pushes.push(Push {
            subscription_id: id,
            cursor: next_cursor.clone(),
            kind: "snapshot",
            result: Some(derived.value.clone()),
            rows: derived_rows(&derived.dependencies),
        });
        pushes.push(Push {
            subscription_id: id,
            cursor: next_cursor,
            kind: "eose",
            result: None,
            rows: Vec::new(),
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
        let budget = Reservation::new(self.budget.clone(), bytes.max(4096) + metadata_bytes)?;
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
                turn,
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

    /// Takes the turn subscription `id` holds, if it is open with one.
    pub(crate) fn take_turn(&self, id: u64) -> Option<Permit> {
        self.state.lock().ok()?.subs.get_mut(&id)?.turn.take()
    }

    /// Gives `turn` back to subscription `id` if it is open without one;
    /// otherwise the turn goes back to its line.
    pub(crate) fn give_turn(&self, id: u64, turn: Permit) {
        if let Ok(mut state) = self.state.lock()
            && let Some(sub) = state.subs.get_mut(&id)
            && sub.turn.is_none()
        {
            sub.turn = Some(turn);
        }
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
                    rows: derived_rows(&derived.dependencies),
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
                        rows: Vec::new(),
                    });
                    sub.bytes = push_bytes(sub.ring.make_contiguous())?;
                    sub.budget
                        .resize(sub.metadata_bytes + sub.bytes.max(4096))?;
                    sub.needs_resync = true;
                }
            }
        }
        // Owner feeds were re-derived above. Any other ring is re-judged
        // right before it is sent: one that names a row a device-local world
        // keeps since its derivation is retired for a gap.
        for (id, sub) in &mut state.subs {
            if sub.channel != Channel::OwnerFeed
                && !sub.needs_resync
                && self.source.withholds(sub.ring.make_contiguous())?
            {
                sub.resync(*id);
            }
        }
        Ok(state
            .subs
            .values()
            .flat_map(|sub| sub.ring.iter().cloned())
            .collect())
    }

    /// Retires subscription `id` for a gap: its socket's release withheld a
    /// body it queued (DEC-0005). The client resubscribes for a fresh
    /// snapshot.
    pub(crate) fn retire(&self, id: u64) -> Result<(), AppError> {
        let mut state = self.state.lock().map_err(|_| state_error())?;
        if let Some(sub) = state.subs.get_mut(&id)
            && !sub.needs_resync
        {
            sub.resync(id);
        }
        Ok(())
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
        changes: &[(String, MaterializedDiffSummary, Vec<OriginMark>, bool)],
    ) -> Result<(), AppError> {
        let mut state = self.state.lock().map_err(|_| state_error())?;
        // Coarse re-derive sees CURRENT state, not intermediate event
        // states. Suppress only when EVERY affecting invalidation is our
        // own; an earlier own write must not swallow a later foreign one.
        let mut affected = BTreeMap::<u64, bool>::new();
        for (path, diff, contributors, live_only) in changes {
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
                    if *live_only && state.subs[id].channel == Channel::View {
                        continue;
                    }
                    // The synthetic local-LMDB poll is not a Loro change.
                    // It must never re-derive unrelated recall/receipt subs.
                    if path == "owner-feed" && state.subs[id].channel != Channel::OwnerFeed {
                        continue;
                    }
                    // Likewise the local notification poll re-derives only
                    // notification views.
                    if path == NOTIFICATIONS_PATH
                        && state.subs[id].channel != Channel::Notifications
                    {
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
                    let own = !contributors.is_empty()
                        && contributors.iter().all(|by| {
                            by.conn_id == Some(state.conn_id)
                                || (by.origin.is_some() && by.origin == state.subs[id].origin)
                        });
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
            let rows = derived_rows(&derived.dependencies);
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
                rows,
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
                    rows: Vec::new(),
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
