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
/// Opaque per-instance wake-delivery key: harness kind plus canonicalized
/// harness config directory, derived host-side and stored verbatim.
///
/// This is an ephemeral delivery key, never an entity identifier. The engine
/// never parses a path, harness, vendor, or actor id out of it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HarnessInstanceKey(String);
impl HarnessInstanceKey {
    #[must_use]
    pub fn new(opaque: impl Into<String>) -> Self {
        Self(opaque.into())
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
/// Closed wake-adapter family. Layer 2 is harness-native, layer 3 is the hard
/// fallback; durable TASK/consult transport is the layer-1 correctness floor
/// and is deliberately not a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WakeAdapterKind {
    ClaudeCodeMonitor,
    CodexStopHook,
    TmuxSendKeys,
    BootPromptSpawn,
}
impl WakeAdapterKind {
    /// Delivery layer; numerically smaller is the stronger layer.
    #[must_use]
    pub const fn layer(self) -> u8 {
        match self {
            Self::ClaudeCodeMonitor | Self::CodexStopHook => 2,
            Self::TmuxSendKeys | Self::BootPromptSpawn => 3,
        }
    }
    /// Deterministic tie-break for over-complete same-layer capability sets.
    const fn same_layer_order(self) -> u8 {
        match self {
            Self::ClaudeCodeMonitor => 0,
            Self::CodexStopHook => 1,
            Self::TmuxSendKeys => 0,
            Self::BootPromptSpawn => 1,
        }
    }
}
/// Total preference order over one complete install snapshot.
fn ordered_candidates(installed: &BTreeSet<WakeAdapterKind>) -> Vec<WakeAdapterKind> {
    let mut candidates: Vec<_> = installed.iter().copied().collect();
    candidates.sort_by_key(|kind| (kind.layer(), kind.same_layer_order()));
    candidates
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeDeliveryOutcome {
    Delivered,
    Failed,
}
/// One coalesced, reportable wake-delivery unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeDispatch {
    pub instance: HarnessInstanceKey,
    pub dispatch_seq: u64,
    pub chosen: Option<WakeAdapterKind>,
    pub envelopes: Vec<WakeEnvelope>,
    /// Total envelopes folded into this one dispatch unit.
    pub coalesced: usize,
}
/// Cumulative in-memory diagnostics. Never a receipt, synced fact, metrics
/// entity, or retry row; connection teardown never decrements them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WakeDispatchObservations {
    pub dispatch_units_created: usize,
    pub envelopes_coalesced: usize,
    pub delivery_failures: usize,
    pub delivered_dispatches: usize,
    pub exhausted_dispatches: usize,
    pub exhausted_envelopes: usize,
    pub transport_only_dispatches: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindInstanceError {
    ConnectionMissing(StreamConnectionId),
    AlreadyBound {
        connection: StreamConnectionId,
        existing: HarnessInstanceKey,
        requested: HarnessInstanceKey,
    },
    InstallSetMismatch {
        connection: StreamConnectionId,
        instance: HarnessInstanceKey,
        existing: BTreeSet<WakeAdapterKind>,
        requested: BTreeSet<WakeAdapterKind>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceBindingReceipt {
    pub connection: StreamConnectionId,
    pub instance: HarnessInstanceKey,
    pub installed: BTreeSet<WakeAdapterKind>,
    pub idempotent_replay: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeReportDisposition {
    Delivered {
        envelopes: usize,
    },
    Reoffered {
        failed: WakeAdapterKind,
        next: WakeAdapterKind,
        envelopes: usize,
    },
    Exhausted {
        envelopes: usize,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeDeliveryReportError {
    ConnectionMissing(StreamConnectionId),
    NoActiveDispatch(StreamConnectionId),
    StaleDispatch {
        expected: u64,
        reported: u64,
    },
    KindMismatch {
        expected: WakeAdapterKind,
        reported: WakeAdapterKind,
    },
}
/// Ephemeral per-instance adapter state. The connection set is the private
/// ref-count: the entry lives while at least one attached connection binds it.
#[derive(Debug, Clone)]
struct InstanceAdapterState {
    installed: BTreeSet<WakeAdapterKind>,
    connections: BTreeSet<StreamConnectionId>,
}
/// One in-flight bundle, retained until a report resolves it. Its candidate
/// list is frozen at creation, so a later snapshot replacement cannot rewrite
/// an offer already in flight.
#[derive(Debug, Clone)]
struct PendingWakeDispatch {
    instance: HarnessInstanceKey,
    dispatch_seq: u64,
    candidates: Vec<WakeAdapterKind>,
    candidate_index: usize,
    envelopes: Vec<WakeEnvelope>,
}
impl PendingWakeDispatch {
    fn chosen(&self) -> Option<WakeAdapterKind> {
        self.candidates.get(self.candidate_index).copied()
    }
    fn as_public(&self) -> WakeDispatch {
        WakeDispatch {
            instance: self.instance.clone(),
            dispatch_seq: self.dispatch_seq,
            chosen: self.chosen(),
            envelopes: self.envelopes.clone(),
            coalesced: self.envelopes.len(),
        }
    }
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
    instance: Option<HarnessInstanceKey>,
    next_dispatch_seq: u64,
    wake_dispatch: Option<PendingWakeDispatch>,
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
    instances: BTreeMap<HarnessInstanceKey, InstanceAdapterState>,
    wake_observations: WakeDispatchObservations,
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
        // Re-attaching over a live connection replaces its state, so its old
        // instance reference must be released or the entry would outlive use.
        self.release_binding(&c);
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
                instance: None,
                next_dispatch_seq: 0,
                wake_dispatch: None,
            },
        );
    }

    /// Drop this connection's instance reference, removing the ephemeral
    /// instance entry once no attached connection references it.
    fn release_binding(&mut self, c: &StreamConnectionId) {
        let Some(instance) = self.connections.get(c).and_then(|s| s.instance.clone()) else {
            return;
        };
        if let Some(entry) = self.instances.get_mut(&instance) {
            entry.connections.remove(c);
            if entry.connections.is_empty() {
                self.instances.remove(&instance);
            }
        }
    }

    /// Teardown drops the connection together with its binding, queued wakes,
    /// and in-flight bundle. Cumulative observations are never decremented.
    pub fn detach(&mut self, c: &StreamConnectionId) {
        self.release_binding(c);
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
    /// Peek the head wake envelope: the in-flight dispatch's first envelope
    /// when one is in flight, otherwise the front queued envelope, and `None`
    /// for a missing or empty connection.
    ///
    /// This keeps ONE-1702's signature but is deliberately NON-DRAINING: it
    /// never pops, acknowledges, or exhausts an envelope, so a
    /// `while let Some(..) = registry.next_wake(&c)` drain loop spins forever.
    /// Production consumers use [`Self::next_wake_dispatch`] with
    /// [`Self::report_wake_delivery`]; an envelope leaves ephemeral delivery
    /// only on reported success, transport-only resolution, final fallback
    /// exhaustion, or connection detach/idle-prune teardown.
    pub fn next_wake(&mut self, c: &StreamConnectionId) -> Option<WakeEnvelope> {
        let st = self.connections.get(c)?;
        st.wake_dispatch
            .as_ref()
            .and_then(|d| d.envelopes.first())
            .or_else(|| st.wakes.front())
            .cloned()
    }
    /// Bind one attached connection to one instance install snapshot.
    ///
    /// `installed` is the complete snapshot computed by the connection/auth
    /// layer, never an incremental add. A bind from a different connection to
    /// an existing instance replaces that instance's snapshot for future
    /// dispatches; in-flight bundles keep the candidates they froze.
    pub fn bind_instance(
        &mut self,
        connection: &StreamConnectionId,
        instance: HarnessInstanceKey,
        installed: BTreeSet<WakeAdapterKind>,
    ) -> Result<InstanceBindingReceipt, BindInstanceError> {
        let Some(bound) = self.connections.get(connection).map(|s| s.instance.clone()) else {
            return Err(BindInstanceError::ConnectionMissing(connection.clone()));
        };
        if let Some(existing) = bound {
            if existing != instance {
                return Err(BindInstanceError::AlreadyBound {
                    connection: connection.clone(),
                    existing,
                    requested: instance,
                });
            }
            let current = self.instances.get(&instance).map(|e| e.installed.clone());
            if current.as_ref() != Some(&installed) {
                return Err(BindInstanceError::InstallSetMismatch {
                    connection: connection.clone(),
                    instance,
                    existing: current.unwrap_or_default(),
                    requested: installed,
                });
            }
            return Ok(InstanceBindingReceipt {
                connection: connection.clone(),
                instance,
                installed,
                idempotent_replay: true,
            });
        }
        // First bind for this connection: create or join the entry. Joining is
        // the last authenticated attach, so it replaces the snapshot.
        let entry =
            self.instances
                .entry(instance.clone())
                .or_insert_with(|| InstanceAdapterState {
                    installed: installed.clone(),
                    connections: BTreeSet::new(),
                });
        entry.installed.clone_from(&installed);
        entry.connections.insert(connection.clone());
        if let Some(st) = self.connections.get_mut(connection) {
            st.instance = Some(instance.clone());
        }
        Ok(InstanceBindingReceipt {
            connection: connection.clone(),
            instance,
            installed,
            idempotent_replay: false,
        })
    }
    /// Offer this connection's coalesced wake bundle.
    ///
    /// Re-polling an in-flight bundle returns it unchanged and counts nothing.
    /// Otherwise every currently queued wake is drained into one unit, which
    /// takes the connection's next sequence and freezes its candidates; wakes
    /// arriving afterwards stay queued for the next unit. An empty candidate
    /// list is the transport-only terminal state: it is reported as
    /// `chosen: None` and released immediately.
    pub fn next_wake_dispatch(&mut self, connection: &StreamConnectionId) -> Option<WakeDispatch> {
        let st = self.connections.get(connection)?;
        if let Some(pending) = &st.wake_dispatch {
            return Some(pending.as_public());
        }
        let instance = st.instance.clone()?;
        if st.wakes.is_empty() {
            return None;
        }
        let candidates = self
            .instances
            .get(&instance)
            .map_or_else(Vec::new, |e| ordered_candidates(&e.installed));
        let st = self.connections.get_mut(connection)?;
        let envelopes = st.wakes.drain(..).collect::<Vec<_>>();
        let dispatch_seq = st.next_dispatch_seq;
        st.next_dispatch_seq = st.next_dispatch_seq.saturating_add(1);
        let pending = PendingWakeDispatch {
            instance,
            dispatch_seq,
            candidates,
            candidate_index: 0,
            envelopes,
        };
        let dispatch = pending.as_public();
        self.wake_observations.dispatch_units_created += 1;
        self.wake_observations.envelopes_coalesced += dispatch.coalesced;
        if pending.candidates.is_empty() {
            self.wake_observations.transport_only_dispatches += 1;
            return Some(dispatch);
        }
        if let Some(st) = self.connections.get_mut(connection) {
            st.wake_dispatch = Some(pending);
        }
        Some(dispatch)
    }
    /// Resolve or degrade the in-flight bundle identified by
    /// `(connection, dispatch_seq, kind)`.
    ///
    /// A stale sequence, a forged kind, or a duplicate report after resolution
    /// changes nothing. Failure advances to the next frozen candidate and
    /// re-offers the exact same ordered envelopes; it never reconstructs an
    /// envelope from text or re-runs event provenance.
    pub fn report_wake_delivery(
        &mut self,
        connection: &StreamConnectionId,
        dispatch_seq: u64,
        kind: WakeAdapterKind,
        outcome: WakeDeliveryOutcome,
    ) -> Result<WakeReportDisposition, WakeDeliveryReportError> {
        let disposition = {
            let Some(st) = self.connections.get_mut(connection) else {
                return Err(WakeDeliveryReportError::ConnectionMissing(
                    connection.clone(),
                ));
            };
            let Some(pending) = st.wake_dispatch.as_mut() else {
                return Err(WakeDeliveryReportError::NoActiveDispatch(
                    connection.clone(),
                ));
            };
            if pending.dispatch_seq != dispatch_seq {
                return Err(WakeDeliveryReportError::StaleDispatch {
                    expected: pending.dispatch_seq,
                    reported: dispatch_seq,
                });
            }
            let Some(expected) = pending.chosen() else {
                return Err(WakeDeliveryReportError::NoActiveDispatch(
                    connection.clone(),
                ));
            };
            if expected != kind {
                return Err(WakeDeliveryReportError::KindMismatch {
                    expected,
                    reported: kind,
                });
            }
            let envelopes = pending.envelopes.len();
            match outcome {
                WakeDeliveryOutcome::Delivered => {
                    st.wake_dispatch = None;
                    WakeReportDisposition::Delivered { envelopes }
                }
                WakeDeliveryOutcome::Failed => {
                    pending.candidate_index += 1;
                    match pending.chosen() {
                        Some(next) => WakeReportDisposition::Reoffered {
                            failed: kind,
                            next,
                            envelopes,
                        },
                        None => {
                            st.wake_dispatch = None;
                            WakeReportDisposition::Exhausted { envelopes }
                        }
                    }
                }
            }
        };
        match &disposition {
            WakeReportDisposition::Delivered { .. } => {
                self.wake_observations.delivered_dispatches += 1;
            }
            WakeReportDisposition::Reoffered { .. } => {
                self.wake_observations.delivery_failures += 1;
            }
            WakeReportDisposition::Exhausted { envelopes } => {
                self.wake_observations.delivery_failures += 1;
                self.wake_observations.exhausted_dispatches += 1;
                self.wake_observations.exhausted_envelopes += envelopes;
            }
        }
        Ok(disposition)
    }
    #[must_use]
    pub const fn wake_dispatch_observations(&self) -> WakeDispatchObservations {
        self.wake_observations
    }
    pub fn prune_idle_connections(&mut self, now: u64, timeout: u64) -> usize {
        let expired = self
            .connections
            .iter()
            .filter(|(_, s)| now.saturating_sub(s.last_touched_at) > timeout)
            .map(|(c, _)| c.clone())
            .collect::<Vec<_>>();
        for connection in &expired {
            self.detach(connection);
        }
        expired.len()
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
            // ONE-1703: a peek over an empty queue stays empty on every call.
            assert!(r.next_wake(&c).is_none());
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
        // ONE-1703: `next_wake` is a non-draining peek, so a routed wake stays
        // queued and every repeated call observes the same envelope.
        assert!(r.next_wake(&owner).is_some());
        assert_eq!(r.next_wake(&owner), r.next_wake(&owner));
        assert_eq!(r.connection_state(&owner).unwrap().wakes.len(), 1);
        assert!(r.next_wake(&consultee).is_some());
        assert_eq!(r.next_wake(&consultee), r.next_wake(&consultee));
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

    fn wake_registry(connections: &[(&StreamConnectionId, &str)]) -> BoardStreamRegistry {
        let mut r = BoardStreamRegistry::default();
        for (connection, actor) in connections {
            r.attach_connection(
                (*connection).clone(),
                BoardRenderMode::Stream,
                (*actor).into(),
                BTreeSet::from([SubscriptionScope::MyTasks]),
                0,
            );
        }
        r
    }

    fn push_wake(r: &mut BoardStreamRegistry, actor: &str, event: &str) {
        r.route_event(BoardEvent::OwnTaskFailed {
            event: VerifiedOwnTaskEvent {
                task_ref: "task".into(),
                actor_ref: actor.into(),
                event_ref: event.into(),
            },
            line: "failed".into(),
        });
    }

    #[test]
    fn candidate_order_is_total_and_matches_derived_ord() {
        let full = BTreeSet::from([
            WakeAdapterKind::BootPromptSpawn,
            WakeAdapterKind::TmuxSendKeys,
            WakeAdapterKind::CodexStopHook,
            WakeAdapterKind::ClaudeCodeMonitor,
        ]);
        let expected = vec![
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeAdapterKind::CodexStopHook,
            WakeAdapterKind::TmuxSendKeys,
            WakeAdapterKind::BootPromptSpawn,
        ];
        assert_eq!(ordered_candidates(&full), expected);
        // The derived order and the (layer, same_layer_order) rank must never
        // drift into two silent sources of truth.
        assert_eq!(full.into_iter().collect::<Vec<_>>(), expected);
        assert_eq!(WakeAdapterKind::ClaudeCodeMonitor.layer(), 2);
        assert_eq!(WakeAdapterKind::CodexStopHook.layer(), 2);
        assert_eq!(WakeAdapterKind::TmuxSendKeys.layer(), 3);
        assert_eq!(WakeAdapterKind::BootPromptSpawn.layer(), 3);
    }

    #[test]
    fn install_set_mismatch_is_distinct_from_already_bound() {
        let c = StreamConnectionId("bind".into());
        let mut r = wake_registry(&[(&c, "actor")]);
        let one = HarnessInstanceKey::new("wake-instance:v1:claude-code:aaa");
        let two = HarnessInstanceKey::new("wake-instance:v1:claude-code:bbb");
        let monitor = BTreeSet::from([WakeAdapterKind::ClaudeCodeMonitor]);
        let ladder = BTreeSet::from([
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeAdapterKind::TmuxSendKeys,
        ]);
        assert_eq!(one.as_str(), "wake-instance:v1:claude-code:aaa");
        assert!(
            !r.bind_instance(&c, one.clone(), monitor.clone())
                .unwrap()
                .idempotent_replay
        );
        // Same connection, same instance, different set.
        assert_eq!(
            r.bind_instance(&c, one.clone(), ladder.clone()),
            Err(BindInstanceError::InstallSetMismatch {
                connection: c.clone(),
                instance: one.clone(),
                existing: monitor.clone(),
                requested: ladder,
            })
        );
        // Same connection, different instance.
        assert_eq!(
            r.bind_instance(&c, two.clone(), monitor.clone()),
            Err(BindInstanceError::AlreadyBound {
                connection: c.clone(),
                existing: one.clone(),
                requested: two,
            })
        );
        // Neither rejection changed the binding.
        assert!(r.bind_instance(&c, one, monitor).unwrap().idempotent_replay);
        let missing = StreamConnectionId("missing".into());
        assert_eq!(
            r.bind_instance(&missing, HarnessInstanceKey::new("x"), BTreeSet::new()),
            Err(BindInstanceError::ConnectionMissing(missing))
        );
    }

    #[test]
    fn next_wake_peeks_without_draining_and_unbound_never_dispatches() {
        let c = StreamConnectionId("peek".into());
        let mut r = wake_registry(&[(&c, "actor")]);
        push_wake(&mut r, "actor", "e1");
        let peeked = r.next_wake(&c);
        assert!(peeked.is_some());
        assert_eq!(peeked, r.next_wake(&c));
        assert_eq!(r.connection_state(&c).unwrap().wakes.len(), 1);
        // An unbound connection has no dispatch path and still no drain path.
        assert_eq!(r.next_wake_dispatch(&c), None);
        assert_eq!(r.connection_state(&c).unwrap().wakes.len(), 1);
        r.bind_instance(
            &c,
            HarnessInstanceKey::new("i"),
            BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
        )
        .unwrap();
        assert_eq!(r.next_wake_dispatch(&c).unwrap().coalesced, 1);
        // In flight, the peek clones the bundle's first envelope instead.
        assert_eq!(r.next_wake(&c), peeked);
        assert_eq!(r.next_wake(&c), peeked);
    }

    #[test]
    fn failure_reoffers_the_same_envelopes_at_the_next_layer() {
        let c = StreamConnectionId("degrade".into());
        let mut r = wake_registry(&[(&c, "actor")]);
        r.bind_instance(
            &c,
            HarnessInstanceKey::new("i"),
            BTreeSet::from([
                WakeAdapterKind::ClaudeCodeMonitor,
                WakeAdapterKind::TmuxSendKeys,
            ]),
        )
        .unwrap();
        push_wake(&mut r, "actor", "e1");
        push_wake(&mut r, "actor", "e2");
        let first = r.next_wake_dispatch(&c).unwrap();
        assert_eq!(first.chosen, Some(WakeAdapterKind::ClaudeCodeMonitor));
        assert_eq!(first.coalesced, 2);
        assert_eq!(
            r.report_wake_delivery(
                &c,
                first.dispatch_seq,
                WakeAdapterKind::ClaudeCodeMonitor,
                WakeDeliveryOutcome::Failed
            ),
            Ok(WakeReportDisposition::Reoffered {
                failed: WakeAdapterKind::ClaudeCodeMonitor,
                next: WakeAdapterKind::TmuxSendKeys,
                envelopes: 2,
            })
        );
        let reoffered = r.next_wake_dispatch(&c).unwrap();
        assert_eq!(reoffered.dispatch_seq, first.dispatch_seq);
        assert_eq!(reoffered.chosen, Some(WakeAdapterKind::TmuxSendKeys));
        // The exact same ordered envelopes are re-offered, never rebuilt.
        assert_eq!(reoffered.envelopes, first.envelopes);
        // The superseded kind can no longer resolve the bundle.
        assert_eq!(
            r.report_wake_delivery(
                &c,
                first.dispatch_seq,
                WakeAdapterKind::ClaudeCodeMonitor,
                WakeDeliveryOutcome::Delivered
            ),
            Err(WakeDeliveryReportError::KindMismatch {
                expected: WakeAdapterKind::TmuxSendKeys,
                reported: WakeAdapterKind::ClaudeCodeMonitor,
            })
        );
        assert_eq!(
            r.report_wake_delivery(
                &c,
                first.dispatch_seq,
                WakeAdapterKind::TmuxSendKeys,
                WakeDeliveryOutcome::Failed
            ),
            Ok(WakeReportDisposition::Exhausted { envelopes: 2 })
        );
        let o = r.wake_dispatch_observations();
        assert_eq!(o.dispatch_units_created, 1);
        assert_eq!(o.envelopes_coalesced, 2);
        assert_eq!(o.delivery_failures, 2);
        assert_eq!(o.exhausted_dispatches, 1);
        assert_eq!(o.exhausted_envelopes, 2);
        assert_eq!(o.delivered_dispatches, 0);
        assert_eq!(o.transport_only_dispatches, 0);
        assert_eq!(r.next_wake_dispatch(&c), None);
        assert_eq!(r.next_wake(&c), None);
    }

    #[test]
    fn success_drains_the_active_bundle_but_not_later_wakes() {
        let c = StreamConnectionId("drain".into());
        let mut r = wake_registry(&[(&c, "actor")]);
        r.bind_instance(
            &c,
            HarnessInstanceKey::new("i"),
            BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
        )
        .unwrap();
        push_wake(&mut r, "actor", "e1");
        let active = r.next_wake_dispatch(&c).unwrap();
        push_wake(&mut r, "actor", "later");
        // Re-polling returns the same unit and never absorbs the later wake.
        assert_eq!(r.next_wake_dispatch(&c), Some(active.clone()));
        assert_eq!(r.wake_dispatch_observations().dispatch_units_created, 1);
        assert_eq!(r.wake_dispatch_observations().envelopes_coalesced, 1);
        assert_eq!(
            r.report_wake_delivery(
                &c,
                active.dispatch_seq,
                WakeAdapterKind::TmuxSendKeys,
                WakeDeliveryOutcome::Delivered
            ),
            Ok(WakeReportDisposition::Delivered { envelopes: 1 })
        );
        let next = r.next_wake_dispatch(&c).unwrap();
        assert_eq!(next.dispatch_seq, active.dispatch_seq + 1);
        assert_eq!(next.coalesced, 1);
        assert_eq!(next.envelopes[0].event_ref, "later");
        assert_eq!(r.wake_dispatch_observations().delivered_dispatches, 1);
    }

    #[test]
    fn duplicate_report_cannot_resolve_a_newer_dispatch() {
        let c = StreamConnectionId("fence".into());
        let mut r = wake_registry(&[(&c, "actor")]);
        r.bind_instance(
            &c,
            HarnessInstanceKey::new("i"),
            BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
        )
        .unwrap();
        push_wake(&mut r, "actor", "a");
        let a = r.next_wake_dispatch(&c).unwrap();
        r.report_wake_delivery(
            &c,
            a.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Delivered,
        )
        .unwrap();
        // With no later bundle, the duplicate finds nothing active.
        assert_eq!(
            r.report_wake_delivery(
                &c,
                a.dispatch_seq,
                WakeAdapterKind::TmuxSendKeys,
                WakeDeliveryOutcome::Delivered
            ),
            Err(WakeDeliveryReportError::NoActiveDispatch(c.clone()))
        );
        push_wake(&mut r, "actor", "b");
        let b = r.next_wake_dispatch(&c).unwrap();
        assert_ne!(b.dispatch_seq, a.dispatch_seq);
        // Both bundles first choose the same kind, so only the per-connection
        // sequence fence separates them.
        assert_eq!(b.chosen, a.chosen);
        assert_eq!(
            r.report_wake_delivery(
                &c,
                a.dispatch_seq,
                WakeAdapterKind::TmuxSendKeys,
                WakeDeliveryOutcome::Delivered
            ),
            Err(WakeDeliveryReportError::StaleDispatch {
                expected: b.dispatch_seq,
                reported: a.dispatch_seq,
            })
        );
        assert_eq!(r.next_wake_dispatch(&c), Some(b));
        assert_eq!(r.wake_dispatch_observations().delivered_dispatches, 1);
    }

    #[test]
    fn rebinding_replaces_the_snapshot_without_rewriting_frozen_candidates() {
        let first = StreamConnectionId("first".into());
        let second = StreamConnectionId("second".into());
        let mut r = wake_registry(&[(&first, "actor"), (&second, "actor")]);
        let instance = HarnessInstanceKey::new("shared");
        let ladder = BTreeSet::from([
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeAdapterKind::TmuxSendKeys,
        ]);
        r.bind_instance(&first, instance.clone(), ladder.clone())
            .unwrap();
        let replay = r.bind_instance(&first, instance.clone(), ladder).unwrap();
        assert!(replay.idempotent_replay);
        push_wake(&mut r, "actor", "e1");
        let in_flight = r.next_wake_dispatch(&first).unwrap();
        assert_eq!(in_flight.chosen, Some(WakeAdapterKind::ClaudeCodeMonitor));
        // Last authenticated attach wins, for FUTURE dispatches only.
        let replaced = BTreeSet::from([WakeAdapterKind::BootPromptSpawn]);
        let rebind = r
            .bind_instance(&second, instance, replaced.clone())
            .unwrap();
        assert!(!rebind.idempotent_replay);
        assert_eq!(rebind.installed, replaced);
        // The in-flight bundle keeps the candidates it froze at creation.
        assert_eq!(
            r.report_wake_delivery(
                &first,
                in_flight.dispatch_seq,
                WakeAdapterKind::ClaudeCodeMonitor,
                WakeDeliveryOutcome::Failed
            ),
            Ok(WakeReportDisposition::Reoffered {
                failed: WakeAdapterKind::ClaudeCodeMonitor,
                next: WakeAdapterKind::TmuxSendKeys,
                envelopes: 1,
            })
        );
        // A dispatch created after the replacement freezes the new snapshot.
        assert_eq!(
            r.next_wake_dispatch(&second).unwrap().chosen,
            Some(WakeAdapterKind::BootPromptSpawn)
        );
    }

    #[test]
    fn two_instances_never_share_snapshots_or_wakes() {
        let a = StreamConnectionId("a".into());
        let b = StreamConnectionId("b".into());
        let mut r = wake_registry(&[(&a, "actor-a"), (&b, "actor-b")]);
        r.bind_instance(
            &a,
            HarnessInstanceKey::new("instance-a"),
            BTreeSet::from([
                WakeAdapterKind::ClaudeCodeMonitor,
                WakeAdapterKind::TmuxSendKeys,
            ]),
        )
        .unwrap();
        r.bind_instance(
            &b,
            HarnessInstanceKey::new("instance-b"),
            BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
        )
        .unwrap();
        push_wake(&mut r, "actor-a", "only-a");
        let dispatch = r.next_wake_dispatch(&a).unwrap();
        assert_eq!(dispatch.instance, HarnessInstanceKey::new("instance-a"));
        assert_eq!(dispatch.chosen, Some(WakeAdapterKind::ClaudeCodeMonitor));
        // A's wake never appears on B, and A's report never moves B.
        assert_eq!(r.next_wake_dispatch(&b), None);
        assert_eq!(r.next_wake(&b), None);
        r.report_wake_delivery(
            &a,
            dispatch.dispatch_seq,
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeDeliveryOutcome::Delivered,
        )
        .unwrap();
        assert_eq!(r.next_wake_dispatch(&b), None);
        push_wake(&mut r, "actor-b", "only-b");
        let other = r.next_wake_dispatch(&b).unwrap();
        assert_eq!(other.chosen, Some(WakeAdapterKind::TmuxSendKeys));
        assert_eq!(other.envelopes[0].event_ref, "only-b");
        // Sequences are per connection, not global.
        assert_eq!(other.dispatch_seq, 0);
    }

    #[test]
    fn teardown_clears_binding_and_wakes_without_decrementing_observations() {
        let held = StreamConnectionId("held".into());
        let idle = StreamConnectionId("idle".into());
        let mut r = wake_registry(&[(&held, "actor"), (&idle, "actor")]);
        let instance = HarnessInstanceKey::new("shared");
        let installed = BTreeSet::from([WakeAdapterKind::TmuxSendKeys]);
        r.bind_instance(&held, instance.clone(), installed.clone())
            .unwrap();
        r.bind_instance(&idle, instance, installed).unwrap();
        push_wake(&mut r, "actor", "e1");
        let dispatch = r.next_wake_dispatch(&held).unwrap();
        let before = r.wake_dispatch_observations();
        r.detach(&held);
        assert_eq!(r.next_wake(&held), None);
        assert_eq!(
            r.report_wake_delivery(
                &held,
                dispatch.dispatch_seq,
                WakeAdapterKind::TmuxSendKeys,
                WakeDeliveryOutcome::Delivered
            ),
            Err(WakeDeliveryReportError::ConnectionMissing(held))
        );
        // One connection leaving cannot delete a still-referenced instance.
        assert_eq!(r.instances.len(), 1);
        assert_eq!(r.wake_dispatch_observations(), before);
        // The idle prune takes the last reference, its binding, and its queue.
        assert_eq!(r.prune_idle_connections(11, 10), 1);
        assert!(r.instances.is_empty());
        assert_eq!(r.next_wake_dispatch(&idle), None);
        assert_eq!(r.wake_dispatch_observations(), before);
    }

    #[test]
    fn empty_install_set_yields_one_transport_only_dispatch() {
        let c = StreamConnectionId("transport".into());
        let mut r = wake_registry(&[(&c, "actor")]);
        assert!(
            r.bind_instance(&c, HarnessInstanceKey::new("i"), BTreeSet::new())
                .unwrap()
                .installed
                .is_empty()
        );
        push_wake(&mut r, "actor", "e1");
        let dispatch = r.next_wake_dispatch(&c).unwrap();
        assert_eq!(dispatch.chosen, None);
        assert_eq!(dispatch.coalesced, 1);
        let o = r.wake_dispatch_observations();
        assert_eq!(o.transport_only_dispatches, 1);
        assert_eq!(o.dispatch_units_created, 1);
        assert_eq!(o.envelopes_coalesced, 1);
        assert_eq!(o.exhausted_dispatches, 0);
        assert_eq!(o.exhausted_envelopes, 0);
        // The terminal unit is released at once: no report is possible.
        assert_eq!(
            r.report_wake_delivery(
                &c,
                dispatch.dispatch_seq,
                WakeAdapterKind::TmuxSendKeys,
                WakeDeliveryOutcome::Delivered
            ),
            Err(WakeDeliveryReportError::NoActiveDispatch(c.clone()))
        );
        assert_eq!(r.next_wake_dispatch(&c), None);
    }

    /// One durable TASK row plus the routing actor that owns it — the layer-1
    /// mailbox an adapter delivery accelerates but never replaces.
    struct MailboxRow {
        actor_ref: String,
        task_ref: crate::entity_id::EntityId,
    }

    /// The durable side of the ladder: a real vault whose TASK rows are
    /// re-read, never reconstructed, to prove the mailbox outlives every
    /// adapter attempt.
    struct DurableMailbox {
        vault: crate::Vault,
        rows: Vec<crate::entity_id::EntityId>,
        _dir: tempfile::TempDir,
    }

    impl DurableMailbox {
        fn open() -> Self {
            let dir = tempfile::tempdir().expect("temporary vault directory");
            let vault = crate::Vault::open(dir.path(), crate::config::VaultConfig::default())
                .expect("open mailbox vault");
            Self {
                vault,
                rows: Vec::new(),
                _dir: dir,
            }
        }

        /// Mint one harness-instance actor and its durable TASK row through
        /// the real `tasks.create` verb.
        ///
        /// The create runs on the PERSON actor's own `human` lane, because a
        /// fresh vault's seeded policy is what decides here: it grants `auto`
        /// to the `human` actor class for EVERY actor, while agent-class
        /// `auto` is reserved to the single first-party connector id. Minting
        /// these three seeds as agents would therefore park two of them as
        /// proposals — an artefact of the seeded ceiling, not a fact about
        /// the delivery ladder under test. The gate is still consulted on
        /// every mint and must still answer Auto; nothing here bypasses it,
        /// fabricates a receipt, or writes a TASK row directly.
        fn mint(&mut self, seed: u8) -> MailboxRow {
            use crate::edge::EdgeActorClass;
            use crate::registry::ENTITY_TYPE_PERSON;
            use crate::task_verb::TaskCreateSpec;
            use crate::temporal::TimeRange;

            let actor = crate::entity_id::EntityId::from_bytes([seed; 16])
                .expect("harness instance actor id");
            self.vault
                .put_entity(
                    &actor,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"harness-instance-actor",
                )
                .expect("store harness instance actor");
            let created = self
                .vault
                .memory(actor, EdgeActorClass::Human)
                .tasks_create(&TaskCreateSpec::new(
                    rmpv::Value::from("wake-mailbox"),
                    None,
                    None,
                    Some(120),
                ))
                .expect("mint durable mailbox row");
            assert!(created.effected);
            let task_ref = created.task_ref.expect("durable mailbox task ref");
            self.rows.push(task_ref);
            MailboxRow {
                actor_ref: actor.to_hex(),
                task_ref,
            }
        }

        /// Re-READ every minted row from the vault. Nothing here consults the
        /// ephemeral dispatch state, so a false answer means the durable
        /// transport actually lost the message.
        fn all_persisted(&self) -> bool {
            let live = self
                .vault
                .entities_by_type(crate::registry::ENTITY_TYPE_TASK)
                .expect("re-read durable mailbox rows");
            self.rows.iter().all(|row| live.contains(row))
        }
    }

    /// The wake ONE-1702 mints for a durable row. Its fields are private and
    /// have no crate-external construction path, which is exactly why this
    /// fixture lives in the owning module.
    fn mailbox_event(row: &MailboxRow, event: &str) -> VerifiedOwnTaskEvent {
        VerifiedOwnTaskEvent {
            task_ref: row.task_ref.to_hex(),
            actor_ref: row.actor_ref.clone(),
            event_ref: event.into(),
        }
    }

    /// The layer a report actually resolved on, or `None` when the bundle did
    /// not deliver.
    fn delivered_layer(
        chosen: Option<WakeAdapterKind>,
        disposition: &WakeReportDisposition,
    ) -> Option<u8> {
        match disposition {
            WakeReportDisposition::Delivered { .. } => chosen.map(WakeAdapterKind::layer),
            WakeReportDisposition::Reoffered { .. } | WakeReportDisposition::Exhausted { .. } => {
                None
            }
        }
    }

    fn attach_wake_connection(r: &mut BoardStreamRegistry, c: &StreamConnectionId, actor: &str) {
        r.attach_connection(
            c.clone(),
            BoardRenderMode::Stream,
            actor.into(),
            BTreeSet::from([SubscriptionScope::MyTasks, SubscriptionScope::ConsultsToMe]),
            0,
        );
    }

    /// Wake-adapter install + delivery observations.
    struct WakeAdapterInstall {
        /// Adapter installs performed (ONE for the hook-capable instance;
        /// the weak-hook instance gets NO adapter — it lands on the
        /// fallback layer of the 08b §5 r4v2 ladder; F16 canon correction).
        adapter_installs: usize,
        /// Distinct actor keys the TWO instances registered under
        /// (config-dir keying makes them two actors regardless of lane).
        distinct_actor_keys: usize,
        /// True iff the undelivered message stayed persisted in the vault
        /// mailbox until delivery (durable transport layer).
        mailbox_persisted_until_delivery: bool,
        /// Deliveries via a harness adapter (layer 2).
        deliveries_via_adapter: usize,
        /// Deliveries via the hard fallback (layer 3).
        deliveries_via_fallback: usize,
        /// True iff the hook-capable instance's wake was delivered through
        /// its installed adapter (layer 2 — the instance that owns the one
        /// adapter install).
        hook_capable_delivered_via_adapter: bool,
        /// True iff the weak-hook instance's wake was delivered through the
        /// hard fallback (layer 3 — it has no adapter to use).
        weak_hook_delivered_via_fallback: bool,
    }

    /// ONE-1703 fixture: two instances of the SAME harness under different
    /// config dirs — one with lifecycle hooks (gets the adapter install),
    /// one weak-hook (no adapter; fallback lane); send one wake to each.
    fn arm_wake_adapter_install() -> WakeAdapterInstall {
        let mut mailbox = DurableMailbox::open();
        let hook_row = mailbox.mint(0xE1);
        let weak_row = mailbox.mint(0xE2);
        let transport_row = mailbox.mint(0xE3);
        let hook_capable = StreamConnectionId("hook-capable".into());
        let weak_hook = StreamConnectionId("weak-hook".into());
        let mut r = BoardStreamRegistry::default();
        attach_wake_connection(&mut r, &hook_capable, &hook_row.actor_ref);
        attach_wake_connection(&mut r, &weak_hook, &weak_row.actor_ref);

        // ── Phase 1 · install per instance, one wake each, both delivered ──
        // Same harness, same lane, two config dirs: two instances, and the
        // hook-capable one is the only owner of a layer-2 adapter.
        let hook_instance = HarnessInstanceKey::new("wake-instance:v1:claude-code:/cfg/hooked");
        let weak_instance = HarnessInstanceKey::new("wake-instance:v1:claude-code:/cfg/weak");
        let hook_receipt = r
            .bind_instance(
                &hook_capable,
                hook_instance.clone(),
                BTreeSet::from([
                    WakeAdapterKind::ClaudeCodeMonitor,
                    WakeAdapterKind::TmuxSendKeys,
                ]),
            )
            .expect("bind hook-capable instance");
        let weak_receipt = r
            .bind_instance(
                &weak_hook,
                weak_instance,
                BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
            )
            .expect("bind weak-hook instance");
        let adapter_installs = [&hook_receipt, &weak_receipt]
            .into_iter()
            .flat_map(|receipt| receipt.installed.iter())
            .filter(|kind| kind.layer() == 2)
            .count();
        let distinct_actor_keys = [&hook_receipt, &weak_receipt]
            .into_iter()
            .map(|receipt| receipt.instance.as_str())
            .collect::<BTreeSet<_>>()
            .len();

        // Wakes mint only through the real ONE-1702 floor.
        assert_eq!(
            r.route_event(BoardEvent::OwnTaskFailed {
                event: mailbox_event(&hook_row, "hook-own-task-failed"),
                line: "attempt failed".into(),
            })
            .wake_enqueued,
            1
        );
        // Per-instance isolation: the hook-capable wake is invisible next door.
        assert_eq!(r.next_wake_dispatch(&weak_hook), None);
        assert_eq!(r.next_wake(&weak_hook), None);
        assert_eq!(
            r.route_event(BoardEvent::ConsultArrived {
                event: mailbox_event(&weak_row, "weak-consult-arrived"),
                line: "consult arrived".into(),
            })
            .wake_enqueued,
            1
        );

        let hook_dispatch = r
            .next_wake_dispatch(&hook_capable)
            .expect("hook-capable dispatch");
        assert_eq!(hook_dispatch.instance, hook_instance);
        assert_eq!(
            hook_dispatch.chosen,
            Some(WakeAdapterKind::ClaudeCodeMonitor)
        );
        assert_eq!(hook_dispatch.coalesced, 1);
        // Durable-row law: re-read the mailbox immediately before the report.
        let mut mailbox_persisted_until_delivery = mailbox.all_persisted();
        let hook_disposition = r
            .report_wake_delivery(
                &hook_capable,
                hook_dispatch.dispatch_seq,
                WakeAdapterKind::ClaudeCodeMonitor,
                WakeDeliveryOutcome::Delivered,
            )
            .expect("hook-capable delivery report");

        let weak_dispatch = r
            .next_wake_dispatch(&weak_hook)
            .expect("weak-hook dispatch");
        assert_eq!(weak_dispatch.chosen, Some(WakeAdapterKind::TmuxSendKeys));
        assert_eq!(weak_dispatch.coalesced, 1);
        assert_eq!(weak_dispatch.envelopes[0].event_ref, "weak-consult-arrived");
        mailbox_persisted_until_delivery &= mailbox.all_persisted();
        let weak_disposition = r
            .report_wake_delivery(
                &weak_hook,
                weak_dispatch.dispatch_seq,
                WakeAdapterKind::TmuxSendKeys,
                WakeDeliveryOutcome::Delivered,
            )
            .expect("weak-hook delivery report");
        // Success drains exactly the bundle it resolved.
        assert_eq!(r.next_wake(&hook_capable), None);
        assert_eq!(r.next_wake(&weak_hook), None);

        let hook_layer = delivered_layer(hook_dispatch.chosen, &hook_disposition);
        let weak_layer = delivered_layer(weak_dispatch.chosen, &weak_disposition);
        let mut install = WakeAdapterInstall {
            adapter_installs,
            distinct_actor_keys,
            mailbox_persisted_until_delivery,
            deliveries_via_adapter: [hook_layer, weak_layer]
                .into_iter()
                .flatten()
                .filter(|layer| *layer == 2)
                .count(),
            deliveries_via_fallback: [hook_layer, weak_layer]
                .into_iter()
                .flatten()
                .filter(|layer| *layer == 3)
                .count(),
            hook_capable_delivered_via_adapter: hook_layer == Some(2),
            weak_hook_delivered_via_fallback: weak_layer == Some(3),
        };

        // ── Phase 2 · the ladder degrades on NEW hook-capable wakes ────────
        // Only `mailbox_persisted_until_delivery` keeps accruing evidence
        // below; the other six observations are frozen at Phase 1.
        let before = r.wake_dispatch_observations();
        for event in ["degrade-1", "degrade-2"] {
            r.route_event(BoardEvent::OwnTaskFailed {
                event: mailbox_event(&hook_row, event),
                line: "attempt failed".into(),
            });
        }
        let degraded = r
            .next_wake_dispatch(&hook_capable)
            .expect("degrading dispatch");
        assert_eq!(degraded.chosen, Some(WakeAdapterKind::ClaudeCodeMonitor));
        assert_eq!(degraded.coalesced, 2);
        // Coalescing preserves the original queue order.
        assert_eq!(
            degraded
                .envelopes
                .iter()
                .map(|envelope| envelope.event_ref.as_str())
                .collect::<Vec<_>>(),
            ["degrade-1", "degrade-2"]
        );
        assert_eq!(
            r.report_wake_delivery(
                &hook_capable,
                degraded.dispatch_seq,
                WakeAdapterKind::ClaudeCodeMonitor,
                WakeDeliveryOutcome::Failed,
            ),
            Ok(WakeReportDisposition::Reoffered {
                failed: WakeAdapterKind::ClaudeCodeMonitor,
                next: WakeAdapterKind::TmuxSendKeys,
                envelopes: 2,
            })
        );
        install.mailbox_persisted_until_delivery &= mailbox.all_persisted();
        let reoffered = r
            .next_wake_dispatch(&hook_capable)
            .expect("re-offered dispatch");
        // The same unit, the same ordered envelopes, one layer lower.
        assert_eq!(reoffered.dispatch_seq, degraded.dispatch_seq);
        assert_eq!(reoffered.envelopes, degraded.envelopes);
        assert_eq!(reoffered.chosen, Some(WakeAdapterKind::TmuxSendKeys));
        assert_eq!(
            r.report_wake_delivery(
                &hook_capable,
                reoffered.dispatch_seq,
                WakeAdapterKind::TmuxSendKeys,
                WakeDeliveryOutcome::Failed,
            ),
            Ok(WakeReportDisposition::Exhausted { envelopes: 2 })
        );
        install.mailbox_persisted_until_delivery &= mailbox.all_persisted();
        // A neighbour instance is untouched by these reports.
        assert_eq!(r.next_wake_dispatch(&weak_hook), None);
        assert_eq!(r.next_wake(&weak_hook), None);
        let degraded_observations = r.wake_dispatch_observations();
        assert_eq!(
            degraded_observations.delivery_failures,
            before.delivery_failures + 2
        );
        assert_eq!(
            degraded_observations.dispatch_units_created,
            before.dispatch_units_created + 1
        );
        assert_eq!(
            degraded_observations.envelopes_coalesced,
            before.envelopes_coalesced + 2
        );
        assert_eq!(
            degraded_observations.exhausted_dispatches,
            before.exhausted_dispatches + 1
        );
        assert_eq!(
            degraded_observations.exhausted_envelopes,
            before.exhausted_envelopes + 2
        );
        assert_eq!(
            degraded_observations.delivered_dispatches,
            before.delivered_dispatches
        );
        assert_eq!(
            degraded_observations.transport_only_dispatches,
            before.transport_only_dispatches
        );

        // ── Phase 3 · a transport-only instance resolves at layer 1 alone ──
        let transport_only = StreamConnectionId("transport-only".into());
        attach_wake_connection(&mut r, &transport_only, &transport_row.actor_ref);
        r.bind_instance(
            &transport_only,
            HarnessInstanceKey::new("wake-instance:v1:codex:/cfg/bare"),
            BTreeSet::new(),
        )
        .expect("bind transport-only instance");
        r.route_event(BoardEvent::OwnTaskFailed {
            event: mailbox_event(&transport_row, "transport-only-failed"),
            line: "attempt failed".into(),
        });
        let terminal = r
            .next_wake_dispatch(&transport_only)
            .expect("transport-only dispatch");
        assert_eq!(terminal.chosen, None);
        assert_eq!(terminal.coalesced, 1);
        let transport_observations = r.wake_dispatch_observations();
        assert_eq!(
            transport_observations.transport_only_dispatches,
            degraded_observations.transport_only_dispatches + 1
        );
        assert_eq!(
            transport_observations.exhausted_dispatches,
            degraded_observations.exhausted_dispatches
        );
        assert_eq!(
            transport_observations.exhausted_envelopes,
            degraded_observations.exhausted_envelopes
        );
        // The row survives layer-2 failure, layer-3 failure, and the
        // transport-only resolution: layer 1 is the correctness floor.
        install.mailbox_persisted_until_delivery &= mailbox.all_persisted();

        // ── Phase 4 · N wakes coalesce into ONE unit; later arrivals wait ──
        let burst = ["burst-1", "burst-2", "burst-3"];
        for event in burst {
            r.route_event(BoardEvent::OwnTaskFailed {
                event: mailbox_event(&hook_row, event),
                line: "attempt failed".into(),
            });
        }
        let bundle = r
            .next_wake_dispatch(&hook_capable)
            .expect("coalesced dispatch");
        assert_eq!(bundle.coalesced, burst.len());
        assert_eq!(bundle.envelopes.len(), burst.len());
        r.route_event(BoardEvent::OwnTaskFailed {
            event: mailbox_event(&hook_row, "after-dispatch"),
            line: "attempt failed".into(),
        });
        let repolled = r
            .next_wake_dispatch(&hook_capable)
            .expect("re-polled dispatch");
        assert_eq!(repolled.dispatch_seq, bundle.dispatch_seq);
        assert_eq!(repolled.envelopes, bundle.envelopes);
        assert_eq!(
            r.connection_state(&hook_capable)
                .expect("hook-capable state")
                .wakes
                .len(),
            1
        );

        install
    }

    /// ONE-1703 · 08b §5 (r4v2): adapters install PER INSTANCE (config-dir
    /// keyed); the vault mailbox is the durable transport; "weak-hook CLIs
    /// land lower on the delivery ladder" — so the conforming shape here is
    /// exactly 1 adapter install + 1 adapter delivery + 1 fallback delivery
    /// across 2 distinct actor keys.
    #[test]
    fn wake_adapters_install_per_instance_over_durable_mailbox() {
        let install = arm_wake_adapter_install();
        assert_eq!(install.adapter_installs, 1);
        assert_eq!(install.distinct_actor_keys, 2);
        assert!(install.mailbox_persisted_until_delivery);
        assert_eq!(install.deliveries_via_adapter, 1);
        assert_eq!(install.deliveries_via_fallback, 1);
        assert!(install.hook_capable_delivered_via_adapter);
        assert!(install.weak_hook_delivered_via_fallback);
    }
}
