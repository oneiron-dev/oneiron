use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardRenderMode {
    Resident,
    Stream,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StreamConnectionId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardStreamFrame {
    pub epoch: u64,
    pub kind: FrameKind,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum FrameKind {
    Keyframe(String),
    Delta(Vec<DeltaRow>),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaRow {
    pub key: String,
    pub line: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardSnapshot {
    pub epoch: u64,
    pub keyframe: String,
    pub rows: BTreeMap<String, String>,
}
impl BoardSnapshot {
    pub fn as_keyframe(&self) -> BoardStreamFrame {
        BoardStreamFrame {
            epoch: self.epoch,
            kind: FrameKind::Keyframe(self.keyframe.clone()),
        }
    }
    pub fn frame_since(&self, previous: Option<&Self>) -> Option<BoardStreamFrame> {
        let Some(old) = previous else {
            return Some(self.as_keyframe());
        };
        if old.epoch != self.epoch || old.rows.keys().any(|k| !self.rows.contains_key(k)) {
            return Some(self.as_keyframe());
        }
        // Fence before ordering: post-fence collisions use last-write-wins,
        // matching the delta overlay's insertion semantics.
        let mut fenced_rows = BTreeMap::new();
        for (key, line) in self
            .rows
            .iter()
            .filter(|(key, line)| old.rows.get(*key) != Some(*line))
        {
            fenced_rows.insert(super::one_line_token(key), super::one_line_token(line));
        }
        let rows = fenced_rows
            .into_iter()
            .map(|(key, line)| DeltaRow { key, line })
            .collect::<Vec<_>>();
        (!rows.is_empty()).then_some(BoardStreamFrame {
            epoch: self.epoch,
            kind: FrameKind::Delta(rows),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameApplyOutcome {
    KeyframeTaken { previous_epoch: Option<u64> },
    DeltaApplied { rows: usize },
    IgnoredStale { held_epoch: Option<u64> },
    IgnoredUntilKeyframe { held_epoch: Option<u64> },
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AppliedStreamState {
    pub epoch: Option<u64>,
    pub keyframe: Option<String>,
    pub delta_overlay: BTreeMap<String, String>,
}
impl AppliedStreamState {
    pub fn apply(&mut self, frame: BoardStreamFrame) -> FrameApplyOutcome {
        match frame.kind {
            FrameKind::Keyframe(text) => {
                if self.epoch.is_some_and(|e| frame.epoch < e) {
                    return FrameApplyOutcome::IgnoredStale {
                        held_epoch: self.epoch,
                    };
                }
                let old = self.epoch;
                self.epoch = Some(frame.epoch);
                self.keyframe = Some(text);
                self.delta_overlay.clear();
                FrameApplyOutcome::KeyframeTaken {
                    previous_epoch: old,
                }
            }
            FrameKind::Delta(rows) => {
                if self.epoch != Some(frame.epoch) {
                    return if self.epoch.is_some_and(|e| frame.epoch < e) {
                        FrameApplyOutcome::IgnoredStale {
                            held_epoch: self.epoch,
                        }
                    } else {
                        FrameApplyOutcome::IgnoredUntilKeyframe {
                            held_epoch: self.epoch,
                        }
                    };
                }
                let n = rows.len();
                for row in rows {
                    self.delta_overlay.insert(
                        super::one_line_token(&row.key),
                        super::one_line_token(&row.line),
                    );
                }
                FrameApplyOutcome::DeltaApplied { rows: n }
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameEnqueueOutcome {
    Queued,
    ReplacedWithKeyframe,
    DroppedStale,
    DroppedUntilKeyframe,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SubscriptionScope {
    MyTasks,
    MyChildren,
    ConsultsToMe,
    Memories,
    Worlds,
    Presence,
    Counts,
}
impl SubscriptionScope {
    pub const ALL: [Self; 7] = [
        Self::MyTasks,
        Self::MyChildren,
        Self::ConsultsToMe,
        Self::Memories,
        Self::Worlds,
        Self::Presence,
        Self::Counts,
    ];
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryClass {
    Wake,
    Carrier,
    OnDemand,
}
impl DeliveryClass {
    pub const fn is_pushable(self) -> bool {
        matches!(self, Self::Wake | Self::Carrier)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryPolicy<A> {
    pub audience: A,
    pub class: DeliveryClass,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOwnTaskEvent {
    task_ref: String,
    actor_ref: String,
    event_ref: String,
}
impl VerifiedOwnTaskEvent {
    pub(crate) fn task_ref(&self) -> &str {
        &self.task_ref
    }
    pub(crate) fn actor_ref(&self) -> &str {
        &self.actor_ref
    }
    pub(crate) fn consultee_ref(&self) -> &str {
        &self.actor_ref
    }
    pub(crate) fn event_ref(&self) -> &str {
        &self.event_ref
    }
}
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WakeMintError {
    ConnectionMissing(StreamConnectionId),
    TaskMissing(String),
    NotOwnTask { task_ref: String, actor_ref: String },
}
#[allow(dead_code)]
pub(crate) trait OwnTaskProvenanceSource {
    fn routing_actor_for_own_task(
        &self,
        c: &StreamConnectionId,
        t: &str,
    ) -> Result<String, WakeMintError>;
}
#[allow(dead_code)]
pub(crate) fn mint_own_task_event(
    src: &dyn OwnTaskProvenanceSource,
    c: &StreamConnectionId,
    t: &str,
    e: &str,
) -> Result<VerifiedOwnTaskEvent, WakeMintError> {
    let actor = src.routing_actor_for_own_task(c, t)?;
    Ok(VerifiedOwnTaskEvent {
        task_ref: t.into(),
        actor_ref: actor,
        event_ref: e.into(),
    })
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildEvent {
    child_ref: String,
    parent_actor_ref: String,
    event_ref: String,
}
#[allow(dead_code)]
impl ChildEvent {
    pub(crate) fn child_ref(&self) -> &str {
        &self.child_ref
    }
    pub(crate) fn parent_actor_ref(&self) -> &str {
        &self.parent_actor_ref
    }
    pub(crate) fn event_ref(&self) -> &str {
        &self.event_ref
    }
}
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChildMintError {
    ChildMissing(String),
    ParentMissing(String),
    ProvenanceMismatch { child_ref: String },
}
#[allow(dead_code)]
pub(crate) trait ChildProvenanceSource {
    fn parent_actor_ref(&self, c: &str) -> Result<String, ChildMintError>;
}
#[allow(dead_code)]
pub(crate) fn mint_child_event(
    src: &dyn ChildProvenanceSource,
    c: &str,
    e: &str,
) -> Result<ChildEvent, ChildMintError> {
    let p = src.parent_actor_ref(c)?;
    Ok(ChildEvent {
        child_ref: c.into(),
        parent_actor_ref: p,
        event_ref: e.into(),
    })
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardEvent {
    ConsultArrived {
        event: VerifiedOwnTaskEvent,
        line: String,
    },
    OwnTaskFailed {
        event: VerifiedOwnTaskEvent,
        line: String,
    },
    OwnTaskDone {
        event: VerifiedOwnTaskEvent,
        delta: DeltaRow,
    },
    ChildDone {
        event: ChildEvent,
        delta: DeltaRow,
    },
    MemoriesChanged {
        event_ref: String,
    },
    PresenceChanged {
        event_ref: String,
    },
    WorldsChanged {
        event_ref: String,
    },
    CountsChanged {
        event_ref: String,
    },
}
impl BoardEvent {
    pub const fn class(&self) -> DeliveryClass {
        match self {
            Self::ConsultArrived { .. } | Self::OwnTaskFailed { .. } => DeliveryClass::Wake,
            Self::OwnTaskDone { .. } | Self::ChildDone { .. } => DeliveryClass::Carrier,
            _ => DeliveryClass::OnDemand,
        }
    }
    pub const fn subscription_scope(&self) -> SubscriptionScope {
        match self {
            Self::ConsultArrived { .. } => SubscriptionScope::ConsultsToMe,
            Self::OwnTaskFailed { .. } | Self::OwnTaskDone { .. } => SubscriptionScope::MyTasks,
            Self::ChildDone { .. } => SubscriptionScope::MyChildren,
            Self::MemoriesChanged { .. } => SubscriptionScope::Memories,
            Self::PresenceChanged { .. } => SubscriptionScope::Presence,
            Self::WorldsChanged { .. } => SubscriptionScope::Worlds,
            Self::CountsChanged { .. } => SubscriptionScope::Counts,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeEnvelope {
    pub event_ref: String,
    pub task_ref: String,
    pub actor_ref: String,
    pub line: String,
}
#[derive(Debug, Default)]
pub struct CarrierCoalesceBuffer {
    epoch: Option<u64>,
    pending_keyframe: Option<BoardStreamFrame>,
    rows: BTreeMap<String, DeltaRow>,
    superseded_intermediate_deltas: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoalesceOutcome {
    Inserted,
    Superseded,
    ReplacedEpoch,
    DroppedStale,
    DroppedUntilKeyframe,
}
impl CarrierCoalesceBuffer {
    pub fn push(&mut self, f: BoardStreamFrame) -> CoalesceOutcome {
        match f.kind {
            FrameKind::Keyframe(_) => {
                if self.epoch.is_some_and(|e| f.epoch < e) {
                    return CoalesceOutcome::DroppedStale;
                }
                self.epoch = Some(f.epoch);
                self.rows.clear();
                self.pending_keyframe = Some(f);
                CoalesceOutcome::ReplacedEpoch
            }
            FrameKind::Delta(rs) => {
                if self.epoch != Some(f.epoch) {
                    return match self.epoch {
                        None => CoalesceOutcome::DroppedUntilKeyframe,
                        Some(epoch) if f.epoch > epoch => CoalesceOutcome::DroppedUntilKeyframe,
                        Some(_) => CoalesceOutcome::DroppedStale,
                    };
                }
                let mut out = CoalesceOutcome::Inserted;
                for mut r in rs {
                    r.key = super::one_line_token(&r.key);
                    r.line = super::one_line_token(&r.line);
                    if self.rows.insert(r.key.clone(), r).is_some() {
                        self.superseded_intermediate_deltas += 1;
                        out = CoalesceOutcome::Superseded;
                    }
                }
                out
            }
        }
    }
    pub fn drain(&mut self) -> Option<BoardStreamFrame> {
        if let Some(k) = self.pending_keyframe.take() {
            return Some(k);
        }
        if self.rows.is_empty() {
            return None;
        }
        let rows = std::mem::take(&mut self.rows).into_values().collect();
        let epoch = self.epoch?;
        Some(BoardStreamFrame {
            epoch,
            kind: FrameKind::Delta(rows),
        })
    }
    pub const fn superseded_intermediate_deltas(&self) -> usize {
        self.superseded_intermediate_deltas
    }
}
#[derive(Debug)]
pub struct StreamConnectionState {
    pub mode: BoardRenderMode,
    pub actor_ref: String,
    pub allowed: BTreeSet<SubscriptionScope>,
    pub subscribed: BTreeSet<SubscriptionScope>,
    pub last_touched_at: u64,
    carrier: CarrierCoalesceBuffer,
    wakes: VecDeque<WakeEnvelope>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionError {
    ConnectionMissing(StreamConnectionId),
    OutsideAllowedSet {
        requested: BTreeSet<SubscriptionScope>,
        allowed: BTreeSet<SubscriptionScope>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionReceipt {
    pub connection: StreamConnectionId,
    pub active: BTreeSet<SubscriptionScope>,
}
#[derive(Debug, Default)]
pub struct RouteObservation {
    pub wake_enqueued: usize,
    pub carrier_enqueued: usize,
    pub on_demand_ignored: usize,
}
#[derive(Debug, Default)]
pub struct BoardStreamRegistry {
    connections: HashMap<StreamConnectionId, StreamConnectionState>,
}
impl BoardStreamRegistry {
    pub fn attach_connection(
        &mut self,
        c: StreamConnectionId,
        mode: BoardRenderMode,
        actor_ref: String,
        allowed: BTreeSet<SubscriptionScope>,
        now: u64,
    ) {
        let subscribed = match mode {
            BoardRenderMode::Stream => [
                SubscriptionScope::MyTasks,
                SubscriptionScope::MyChildren,
                SubscriptionScope::ConsultsToMe,
            ]
            .into_iter()
            .filter(|x| allowed.contains(x))
            .collect(),
            BoardRenderMode::Resident => allowed.clone(),
        };
        self.connections.insert(
            c,
            StreamConnectionState {
                mode,
                actor_ref,
                allowed,
                subscribed,
                last_touched_at: now,
                carrier: Default::default(),
                wakes: VecDeque::new(),
            },
        );
    }

    pub fn detach(&mut self, c: &StreamConnectionId) {
        self.connections.remove(c);
    }
    fn change(
        &mut self,
        c: &StreamConnectionId,
        sc: &BTreeSet<SubscriptionScope>,
        add: bool,
    ) -> Result<SubscriptionReceipt, SubscriptionError> {
        let st = self
            .connections
            .get_mut(c)
            .ok_or_else(|| SubscriptionError::ConnectionMissing(c.clone()))?;
        if !sc.is_subset(&st.allowed) {
            return Err(SubscriptionError::OutsideAllowedSet {
                requested: sc.clone(),
                allowed: st.allowed.clone(),
            });
        }
        for x in sc {
            if add {
                st.subscribed.insert(*x);
            } else {
                st.subscribed.remove(x);
            }
        }
        st.last_touched_at = st.last_touched_at.saturating_add(1);
        Ok(SubscriptionReceipt {
            connection: c.clone(),
            active: st.subscribed.clone(),
        })
    }
    pub fn subscribe(
        &mut self,
        c: &StreamConnectionId,
        s: &BTreeSet<SubscriptionScope>,
    ) -> Result<SubscriptionReceipt, SubscriptionError> {
        self.change(c, s, true)
    }
    pub fn unsubscribe(
        &mut self,
        c: &StreamConnectionId,
        s: &BTreeSet<SubscriptionScope>,
    ) -> Result<SubscriptionReceipt, SubscriptionError> {
        self.change(c, s, false)
    }
    pub fn enqueue(&mut self, c: &StreamConnectionId, f: BoardStreamFrame) -> FrameEnqueueOutcome {
        match self.connections.get_mut(c) {
            Some(st) => match st.carrier.push(f) {
                CoalesceOutcome::Inserted | CoalesceOutcome::Superseded => {
                    FrameEnqueueOutcome::Queued
                }
                CoalesceOutcome::ReplacedEpoch => FrameEnqueueOutcome::ReplacedWithKeyframe,
                CoalesceOutcome::DroppedStale => FrameEnqueueOutcome::DroppedStale,
                CoalesceOutcome::DroppedUntilKeyframe => FrameEnqueueOutcome::DroppedUntilKeyframe,
            },
            None => FrameEnqueueOutcome::DroppedUntilKeyframe,
        }
    }
    pub fn connection_state(&self, c: &StreamConnectionId) -> Option<&StreamConnectionState> {
        self.connections.get(c)
    }
    pub fn superseded_intermediate_deltas(&self, c: &StreamConnectionId) -> Option<usize> {
        Some(
            self.connections
                .get(c)?
                .carrier
                .superseded_intermediate_deltas(),
        )
    }
    pub fn next_carrier_payload(&mut self, c: &StreamConnectionId) -> Option<BoardStreamFrame> {
        self.connections.get_mut(c)?.carrier.drain()
    }
    pub fn next_wake(&mut self, c: &StreamConnectionId) -> Option<WakeEnvelope> {
        self.connections.get_mut(c)?.wakes.pop_front()
    }
    pub fn prune_idle_connections(&mut self, now: u64, timeout: u64) -> usize {
        let before = self.connections.len();
        self.connections
            .retain(|_, s| now.saturating_sub(s.last_touched_at) <= timeout);
        before - self.connections.len()
    }
    pub fn route_event(&mut self, e: BoardEvent) -> RouteObservation {
        let mut o = RouteObservation::default();
        let class = e.class();
        if !class.is_pushable() {
            o.on_demand_ignored = self.connections.len();
            return o;
        }
        for st in self.connections.values_mut() {
            if !st.subscribed.contains(&e.subscription_scope()) {
                continue;
            }
            let matches = match &e {
                BoardEvent::ConsultArrived { event, .. } => st.actor_ref == event.consultee_ref(),
                BoardEvent::OwnTaskFailed { event, .. } | BoardEvent::OwnTaskDone { event, .. } => {
                    st.actor_ref == event.actor_ref()
                }
                BoardEvent::ChildDone { event, .. } => st.actor_ref == event.parent_actor_ref(),
                _ => false,
            };
            if !matches {
                continue;
            }
            match e.clone() {
                BoardEvent::ConsultArrived { event, line }
                | BoardEvent::OwnTaskFailed { event, line } => {
                    st.wakes.push_back(WakeEnvelope {
                        event_ref: event.event_ref().into(),
                        task_ref: event.task_ref().into(),
                        actor_ref: event.actor_ref().into(),
                        line: super::one_line_token(&line),
                    });
                    o.wake_enqueued += 1;
                }
                BoardEvent::OwnTaskDone { delta, .. } | BoardEvent::ChildDone { delta, .. } => {
                    let Some(epoch) = st.carrier.epoch else {
                        continue;
                    };
                    let outcome = st.carrier.push(BoardStreamFrame {
                        epoch,
                        kind: FrameKind::Delta(vec![delta]),
                    });
                    if matches!(
                        outcome,
                        CoalesceOutcome::Inserted | CoalesceOutcome::Superseded
                    ) {
                        o.carrier_enqueued += 1;
                    }
                }
                _ => {}
            }
        }
        o
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn k(e: u64) -> BoardStreamFrame {
        BoardStreamFrame {
            epoch: e,
            kind: FrameKind::Keyframe(format!("k{e}")),
        }
    }
    fn d(e: u64, key: &str) -> BoardStreamFrame {
        BoardStreamFrame {
            epoch: e,
            kind: FrameKind::Delta(vec![DeltaRow {
                key: key.into(),
                line: "x".into(),
            }]),
        }
    }
    #[test]
    fn latest() {
        let mut s = AppliedStreamState::default();
        assert!(matches!(
            s.apply(k(47)),
            FrameApplyOutcome::KeyframeTaken { .. }
        ));
        assert!(matches!(
            s.apply(d(47, "a")),
            FrameApplyOutcome::DeltaApplied { rows: 1 }
        ));
        assert!(matches!(
            s.apply(d(48, "b")),
            FrameApplyOutcome::IgnoredUntilKeyframe { .. }
        ));
        s.apply(k(48));
        s.apply(k(47));
        assert_eq!(s.epoch, Some(48));
    }
    #[test]
    fn queue_barrier() {
        let c = StreamConnectionId("x".into());
        let mut r = BoardStreamRegistry::default();
        r.attach_connection(
            c.clone(),
            BoardRenderMode::Stream,
            "actor".into(),
            BTreeSet::new(),
            0,
        );
        r.enqueue(&c, k(1));
        r.enqueue(&c, d(1, "a"));
        r.enqueue(&c, k(1));
        assert!(matches!(
            r.next_carrier_payload(&c).unwrap().kind,
            FrameKind::Keyframe(_)
        ));
        assert!(r.next_carrier_payload(&c).is_none());
    }
    #[test]
    fn stale_lower_delta_is_ignored() {
        let mut state = AppliedStreamState::default();
        state.apply(k(47));
        assert!(matches!(
            state.apply(d(46, "old")),
            FrameApplyOutcome::IgnoredStale {
                held_epoch: Some(47)
            }
        ));
        assert!(state.delta_overlay.is_empty());
    }

    #[test]
    fn future_delta_is_discarded_not_replayed() {
        let mut state = AppliedStreamState::default();
        state.apply(k(47));
        assert!(matches!(
            state.apply(d(48, "future")),
            FrameApplyOutcome::IgnoredUntilKeyframe {
                held_epoch: Some(47)
            }
        ));
        assert_eq!(state.epoch, Some(47));
        state.apply(k(48));
        assert_eq!(state.epoch, Some(48));
        assert!(!state.delta_overlay.contains_key("future"));
    }

    #[test]
    fn frame_since_removal_falls_back_to_keyframe() {
        let mut old_rows = BTreeMap::new();
        old_rows.insert("removed".into(), "line".into());
        let old = BoardSnapshot {
            epoch: 4,
            keyframe: "old".into(),
            rows: old_rows,
        };
        let current = BoardSnapshot {
            epoch: 4,
            keyframe: "new".into(),
            rows: BTreeMap::new(),
        };
        assert!(matches!(
            current.frame_since(Some(&old)).unwrap().kind,
            FrameKind::Keyframe(_)
        ));
    }

    #[test]
    fn frame_since_deltas_are_key_sorted_and_fenced() {
        let old = BoardSnapshot {
            epoch: 4,
            keyframe: "old".into(),
            rows: BTreeMap::new(),
        };
        let mut rows = BTreeMap::new();
        rows.insert("z\n".into(), "line\r".into());
        rows.insert("a\t".into(), "line\n".into());
        let current = BoardSnapshot {
            epoch: 4,
            keyframe: "new".into(),
            rows,
        };
        let frame = current.frame_since(Some(&old)).unwrap();
        let FrameKind::Delta(rows) = frame.kind else {
            panic!("expected delta")
        };
        assert_eq!(
            rows.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
            vec!["a ", "z "]
        );
        assert!(
            rows.iter().all(|row| !row.key.contains(['\n', '\r', '\t'])
                && !row.line.contains(['\n', '\r', '\t']))
        );
        let mut state = AppliedStreamState::default();
        state.apply(k(4));
        state.apply(BoardStreamFrame {
            epoch: 4,
            kind: FrameKind::Delta(rows),
        });
        assert_eq!(state.delta_overlay.len(), 2);
        assert!(
            state
                .delta_overlay
                .keys()
                .all(|key| !key.contains(['\n', '\r', '\t']))
        );
    }

    fn permutations(items: &mut [usize], start: usize, output: &mut Vec<Vec<usize>>) {
        if start == items.len() {
            output.push(items.to_vec());
            return;
        }
        for index in start..items.len() {
            items.swap(start, index);
            permutations(items, start + 1, output);
            items.swap(start, index);
        }
    }

    #[test]
    fn epoch_permutations_never_decrease_and_deltas_match_held_epoch() {
        let frames = [k(47), d(47, "same"), d(46, "stale"), k(48), k(47)];
        let mut indices = [0, 1, 2, 3, 4];
        let mut orders = Vec::new();
        permutations(&mut indices, 0, &mut orders);
        assert_eq!(orders.len(), 120);
        for order in orders {
            let mut state = AppliedStreamState::default();
            let mut max_accepted_keyframe_epoch = None;
            for index in order {
                let frame = frames[index].clone();
                let epoch = frame.epoch;
                let is_delta = matches!(frame.kind, FrameKind::Delta(_));
                let held_before = state.epoch;
                let overlay_before = state.delta_overlay.clone();
                let outcome = state.apply(frame);
                if !is_delta && !matches!(outcome, FrameApplyOutcome::IgnoredStale { .. }) {
                    max_accepted_keyframe_epoch =
                        Some(max_accepted_keyframe_epoch.map_or(epoch, |max: u64| max.max(epoch)));
                    assert!(
                        state.epoch.expect("accepted keyframe holds epoch")
                            >= max_accepted_keyframe_epoch.expect("max epoch")
                    );
                }
                if is_delta && held_before != Some(epoch) {
                    assert!(matches!(
                        outcome,
                        FrameApplyOutcome::IgnoredStale { .. }
                            | FrameApplyOutcome::IgnoredUntilKeyframe { .. }
                    ));
                    assert_eq!(state.delta_overlay, overlay_before);
                }
            }
            assert_eq!(state.epoch, Some(48));
        }
    }

    #[test]
    fn fenced_key_collisions_are_unique_and_sorted_after_fencing() {
        let old = BoardSnapshot {
            epoch: 1,
            keyframe: "old".into(),
            rows: BTreeMap::new(),
        };
        let mut values = BTreeMap::new();
        values.insert("a\nz".into(), "first".into());
        values.insert("a\tz".into(), "last".into());
        values.insert("a x".into(), "middle".into());
        let current = BoardSnapshot {
            epoch: 1,
            keyframe: "new".into(),
            rows: values,
        };
        let FrameKind::Delta(rows) = current.frame_since(Some(&old)).expect("delta").kind else {
            panic!("delta")
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
            vec!["a x", "a z"]
        );
        assert_eq!(rows[1].line, "first");
    }

    #[test]
    fn snapshots() {
        let mut a = BTreeMap::new();
        a.insert("z".into(), "z".into());
        let mut b = a.clone();
        b.insert("a".into(), "a".into());
        let x = BoardSnapshot {
            epoch: 1,
            keyframe: "x".into(),
            rows: a,
        };
        let y = BoardSnapshot {
            epoch: 1,
            keyframe: "y".into(),
            rows: b,
        };
        assert!(matches!(
            y.frame_since(Some(&x)).unwrap().kind,
            FrameKind::Delta(_)
        ));
    }
    #[test]
    fn subscriptions_are_atomic_local_and_lifecycle_is_ephemeral() {
        let c = StreamConnectionId("a".into());
        let allowed = BTreeSet::from([SubscriptionScope::MyTasks]);
        let mut registry = BoardStreamRegistry::default();
        registry.attach_connection(c.clone(), BoardRenderMode::Stream, "a".into(), allowed, 5);
        let before = registry.connection_state(&c).unwrap().subscribed.clone();
        let requested = BTreeSet::from([SubscriptionScope::MyTasks, SubscriptionScope::Counts]);
        assert!(matches!(
            registry.subscribe(&c, &requested),
            Err(SubscriptionError::OutsideAllowedSet { .. })
        ));
        assert_eq!(registry.connection_state(&c).unwrap().subscribed, before);
        registry.detach(&c);
        assert!(registry.connection_state(&c).is_none());
        registry.attach_connection(
            c.clone(),
            BoardRenderMode::Stream,
            "a".into(),
            BTreeSet::from([SubscriptionScope::MyTasks]),
            0,
        );
        assert_eq!(registry.prune_idle_connections(11, 10), 1);
    }

    #[test]
    fn coalesce_fences_and_requires_keyframe() {
        let mut buffer = CarrierCoalesceBuffer::default();
        assert_eq!(
            buffer.push(d(1, "x")),
            CoalesceOutcome::DroppedUntilKeyframe
        );
        assert_eq!(buffer.push(k(1)), CoalesceOutcome::ReplacedEpoch);
        assert_eq!(
            buffer.push(BoardStreamFrame {
                epoch: 1,
                kind: FrameKind::Delta(vec![DeltaRow {
                    key: "x\n".into(),
                    line: "done\r".into()
                }])
            }),
            CoalesceOutcome::Inserted
        );
        let _ = buffer.drain();
        let FrameKind::Delta(rows) = buffer.drain().expect("delta").kind else {
            panic!()
        };
        assert_eq!(rows[0].key, "x ");
        assert_eq!(rows[0].line, "done ");
    }
    #[test]
    fn board_event_class_scope_totality_is_closed() {
        assert_eq!(SubscriptionScope::ALL.len(), 7);
        assert!(DeliveryClass::Wake.is_pushable());
        assert!(!DeliveryClass::OnDemand.is_pushable());
    }

    #[test]
    fn same_epoch_keyed_deltas_leave_last_row_per_key() {
        let mut buffer = CarrierCoalesceBuffer::default();
        buffer.push(k(7));
        let _ = buffer.drain();
        for line in ["one", "two", "three"] {
            buffer.push(BoardStreamFrame {
                epoch: 7,
                kind: FrameKind::Delta(vec![DeltaRow {
                    key: "task".into(),
                    line: line.into(),
                }]),
            });
        }
        let FrameKind::Delta(rows) = buffer.drain().unwrap().kind else {
            panic!()
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].line, "three");
    }
    struct OwnFixture;
    impl OwnTaskProvenanceSource for OwnFixture {
        fn routing_actor_for_own_task(
            &self,
            _: &StreamConnectionId,
            task: &str,
        ) -> Result<String, WakeMintError> {
            if task == "foreign" {
                Err(WakeMintError::NotOwnTask {
                    task_ref: task.into(),
                    actor_ref: "other".into(),
                })
            } else {
                Ok("actor".into())
            }
        }
    }
    struct ChildFixture;
    impl ChildProvenanceSource for ChildFixture {
        fn parent_actor_ref(&self, child: &str) -> Result<String, ChildMintError> {
            if child == "missing" {
                Err(ChildMintError::ChildMissing(child.into()))
            } else {
                Ok("actor".into())
            }
        }
    }
    #[test]
    fn provenance_mints_reject_foreign_and_bind_parent() {
        let c = StreamConnectionId("c".into());
        assert!(matches!(
            mint_own_task_event(&OwnFixture, &c, "foreign", "e"),
            Err(WakeMintError::NotOwnTask { .. })
        ));
        let child = mint_child_event(&ChildFixture, "child", "e").unwrap();
        assert_eq!(child.parent_actor_ref(), "actor");
        assert!(mint_child_event(&ChildFixture, "missing", "e").is_err());
    }
    #[test]
    fn on_demand_never_routes_in_any_mode() {
        for mode in [BoardRenderMode::Stream, BoardRenderMode::Resident] {
            let c = StreamConnectionId(format!("{mode:?}"));
            let mut r = BoardStreamRegistry::default();
            r.attach_connection(
                c.clone(),
                mode,
                "actor".into(),
                SubscriptionScope::ALL.into_iter().collect(),
                0,
            );
            let o = r.route_event(BoardEvent::MemoriesChanged {
                event_ref: "m".into(),
            });
            assert_eq!(o.wake_enqueued + o.carrier_enqueued, 0);
            assert!(r.next_wake(&c).is_none());
            assert!(r.next_carrier_payload(&c).is_none());
        }
    }
    #[test]
    fn event_variants_have_exact_class_and_scope() {
        let c = StreamConnectionId("c".into());
        let own = mint_own_task_event(&OwnFixture, &c, "own", "e").unwrap();
        let child = mint_child_event(&ChildFixture, "child", "e").unwrap();
        let cases = [
            (
                BoardEvent::ConsultArrived {
                    event: own.clone(),
                    line: "x".into(),
                },
                DeliveryClass::Wake,
                SubscriptionScope::ConsultsToMe,
            ),
            (
                BoardEvent::OwnTaskFailed {
                    event: own.clone(),
                    line: "x".into(),
                },
                DeliveryClass::Wake,
                SubscriptionScope::MyTasks,
            ),
            (
                BoardEvent::OwnTaskDone {
                    event: own,
                    delta: DeltaRow {
                        key: "x".into(),
                        line: "x".into(),
                    },
                },
                DeliveryClass::Carrier,
                SubscriptionScope::MyTasks,
            ),
            (
                BoardEvent::ChildDone {
                    event: child,
                    delta: DeltaRow {
                        key: "x".into(),
                        line: "x".into(),
                    },
                },
                DeliveryClass::Carrier,
                SubscriptionScope::MyChildren,
            ),
            (
                BoardEvent::MemoriesChanged {
                    event_ref: "x".into(),
                },
                DeliveryClass::OnDemand,
                SubscriptionScope::Memories,
            ),
            (
                BoardEvent::PresenceChanged {
                    event_ref: "x".into(),
                },
                DeliveryClass::OnDemand,
                SubscriptionScope::Presence,
            ),
            (
                BoardEvent::WorldsChanged {
                    event_ref: "x".into(),
                },
                DeliveryClass::OnDemand,
                SubscriptionScope::Worlds,
            ),
            (
                BoardEvent::CountsChanged {
                    event_ref: "x".into(),
                },
                DeliveryClass::OnDemand,
                SubscriptionScope::Counts,
            ),
        ];
        for (event, class, scope) in cases {
            assert_eq!(event.class(), class);
            assert_eq!(event.subscription_scope(), scope);
        }
    }
    #[test]
    fn repeated_subscription_changes_are_local_and_reattach_resets_defaults() {
        let first = StreamConnectionId("first".into());
        let second = StreamConnectionId("second".into());
        let allowed = BTreeSet::from([SubscriptionScope::MyTasks, SubscriptionScope::MyChildren]);
        let mut r = BoardStreamRegistry::default();
        r.attach_connection(
            first.clone(),
            BoardRenderMode::Resident,
            "actor".into(),
            allowed.clone(),
            0,
        );
        r.attach_connection(
            second.clone(),
            BoardRenderMode::Resident,
            "other".into(),
            allowed.clone(),
            0,
        );
        let defaults = allowed.clone();
        let children = BTreeSet::from([SubscriptionScope::MyChildren]);
        assert_eq!(
            r.unsubscribe(&first, &children).unwrap().active,
            BTreeSet::from([SubscriptionScope::MyTasks])
        );
        let first_add = r.subscribe(&first, &children).unwrap();
        assert_eq!(first_add.active, defaults);
        let second_add = r.subscribe(&first, &children).unwrap();
        assert_eq!(second_add.active, defaults);
        assert_eq!(second_add.connection, first);
        assert_eq!(r.connection_state(&second).unwrap().subscribed, defaults);
        let first_remove = r.unsubscribe(&first, &children).unwrap();
        assert_eq!(
            first_remove.active,
            BTreeSet::from([SubscriptionScope::MyTasks])
        );
        let second_remove = r.unsubscribe(&first, &children).unwrap();
        assert_eq!(
            second_remove.active,
            BTreeSet::from([SubscriptionScope::MyTasks])
        );
        assert_eq!(second_remove.connection, first);
        assert_eq!(r.connection_state(&second).unwrap().subscribed, defaults);
        r.detach(&first);
        r.attach_connection(
            first.clone(),
            BoardRenderMode::Stream,
            "actor".into(),
            allowed,
            0,
        );
        assert_eq!(r.connection_state(&first).unwrap().subscribed, defaults);
    }

    #[test]
    fn keyed_delta_property_preserves_last_value_each_key() {
        let updates = [("a", "0"), ("a", "1"), ("b", "0"), ("b", "1")];
        // Exhaust every sequence through length five, rather than checking one hand-picked trace.
        for length in 0..=5 {
            for encoded in 0..updates.len().pow(length) {
                let mut expected = BTreeMap::new();
                let mut buffer = CarrierCoalesceBuffer::default();
                buffer.push(k(1));
                let _ = buffer.drain();
                let mut trace = encoded;
                for _ in 0..length {
                    let (key, line) = updates[trace % updates.len()];
                    trace /= updates.len();
                    expected.insert(key.to_owned(), line.to_owned());
                    buffer.push(BoardStreamFrame {
                        epoch: 1,
                        kind: FrameKind::Delta(vec![DeltaRow {
                            key: key.into(),
                            line: line.into(),
                        }]),
                    });
                }
                let rows = match buffer.drain() {
                    Some(BoardStreamFrame {
                        kind: FrameKind::Delta(rows),
                        ..
                    }) => rows,
                    None if expected.is_empty() => Vec::new(),
                    other => panic!("unexpected coalesced frame: {other:?}"),
                };
                assert_eq!(
                    rows.len(),
                    expected.len(),
                    "encoded sequence {encoded}, length {length}: duplicate keys"
                );
                let actual = rows
                    .iter()
                    .map(|row| row.key.as_str())
                    .collect::<BTreeSet<_>>();
                assert_eq!(actual.len(), rows.len(), "duplicate raw drained keys");
                let actual = rows
                    .into_iter()
                    .map(|row| (row.key, row.line))
                    .collect::<BTreeMap<_, _>>();
                assert_eq!(
                    actual, expected,
                    "encoded sequence {encoded}, length {length}"
                );
            }
        }
    }

    #[test]
    fn route_event_requires_both_subscription_and_authoritative_actor_for_wakes_and_carriers() {
        let owner = StreamConnectionId("owner".into());
        let consultee = StreamConnectionId("consultee".into());
        let parent = StreamConnectionId("parent".into());
        let unsubscribed_owner = StreamConnectionId("unsubscribed-owner".into());
        let wrong_owner = StreamConnectionId("wrong-owner".into());
        let unsubscribed_parent = StreamConnectionId("unsubscribed-parent".into());
        let wrong_parent = StreamConnectionId("wrong-parent".into());
        let unsubscribed_consultee = StreamConnectionId("unsubscribed-consultee".into());
        let mut r = BoardStreamRegistry::default();
        for (connection, actor, scopes) in [
            (
                &owner,
                "owner",
                BTreeSet::from([SubscriptionScope::MyTasks]),
            ),
            (
                &consultee,
                "consultee",
                BTreeSet::from([SubscriptionScope::ConsultsToMe]),
            ),
            (
                &parent,
                "parent",
                BTreeSet::from([SubscriptionScope::MyChildren]),
            ),
            (&unsubscribed_owner, "owner", BTreeSet::new()),
            (
                &wrong_owner,
                "wrong",
                BTreeSet::from([SubscriptionScope::MyTasks]),
            ),
            (&unsubscribed_parent, "parent", BTreeSet::new()),
            (
                &wrong_parent,
                "wrong",
                BTreeSet::from([SubscriptionScope::MyChildren]),
            ),
            (&unsubscribed_consultee, "consultee", BTreeSet::new()),
        ] {
            r.attach_connection(
                connection.clone(),
                BoardRenderMode::Resident,
                actor.into(),
                scopes,
                0,
            );
        }
        // Every carrier candidate starts with a held epoch; otherwise a broken
        // actor/subscription guard could pass merely because it cannot enqueue yet.
        for connection in [
            &owner,
            &parent,
            &unsubscribed_owner,
            &wrong_owner,
            &unsubscribed_parent,
            &wrong_parent,
        ] {
            assert_eq!(
                r.enqueue(connection, k(1)),
                FrameEnqueueOutcome::ReplacedWithKeyframe
            );
            assert!(r.next_carrier_payload(connection).is_some());
        }
        assert_eq!(r.next_carrier_payload(&consultee), None);
        assert_eq!(r.next_carrier_payload(&unsubscribed_consultee), None);
        let owner_event = VerifiedOwnTaskEvent {
            task_ref: "own".into(),
            actor_ref: "owner".into(),
            event_ref: "wake-owner".into(),
        };
        let consult_event = VerifiedOwnTaskEvent {
            task_ref: "consult".into(),
            actor_ref: "consultee".into(),
            event_ref: "wake-consult".into(),
        };
        let child_event = ChildEvent {
            child_ref: "child".into(),
            parent_actor_ref: "parent".into(),
            event_ref: "carrier-child".into(),
        };
        assert_eq!(
            r.route_event(BoardEvent::OwnTaskFailed {
                event: owner_event.clone(),
                line: "failed".into()
            })
            .wake_enqueued,
            1
        );
        assert_eq!(
            r.route_event(BoardEvent::ConsultArrived {
                event: consult_event,
                line: "consult".into()
            })
            .wake_enqueued,
            1
        );
        assert_eq!(
            r.route_event(BoardEvent::OwnTaskDone {
                event: owner_event,
                delta: DeltaRow {
                    key: "owner".into(),
                    line: "done".into()
                }
            })
            .carrier_enqueued,
            1
        );
        assert_eq!(
            r.route_event(BoardEvent::ChildDone {
                event: child_event,
                delta: DeltaRow {
                    key: "child".into(),
                    line: "done".into()
                }
            })
            .carrier_enqueued,
            1
        );
        assert!(r.next_wake(&owner).is_some());
        assert!(r.next_wake(&consultee).is_some());
        assert!(r.next_carrier_payload(&owner).is_some());
        assert!(r.next_carrier_payload(&parent).is_some());
        for connection in [
            &unsubscribed_owner,
            &wrong_owner,
            &unsubscribed_parent,
            &wrong_parent,
            &unsubscribed_consultee,
        ] {
            assert!(r.next_wake(connection).is_none());
            assert!(r.next_carrier_payload(connection).is_none());
        }
    }
}
