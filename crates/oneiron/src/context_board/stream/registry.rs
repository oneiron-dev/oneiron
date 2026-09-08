//! The board stream registry: connections, subscriptions and event routing.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use super::events::{
    BoardEvent, RouteObservation, SubscriptionError, SubscriptionReceipt, SubscriptionScope,
};
use super::frames::{
    BoardRenderMode, BoardStreamFrame, CarrierCoalesceBuffer, CoalesceOutcome, FrameEnqueueOutcome,
    FrameKind, StreamConnectionId,
};
use super::wake::{
    HarnessInstanceKey, InstanceAdapterState, PendingWakeDispatch, WakeDispatchObservations,
    WakeEnvelope,
};

#[derive(Debug)]
pub struct StreamConnectionState {
    pub mode: BoardRenderMode,
    pub actor_ref: String,
    pub allowed: BTreeSet<SubscriptionScope>,
    pub subscribed: BTreeSet<SubscriptionScope>,
    pub last_touched_at: u64,
    pub(super) carrier: CarrierCoalesceBuffer,
    pub(super) wakes: VecDeque<WakeEnvelope>,
    pub(super) instance: Option<HarnessInstanceKey>,
    pub(super) next_dispatch_seq: u64,
    pub(super) wake_dispatch: Option<PendingWakeDispatch>,
}

#[derive(Debug, Default)]
pub struct BoardStreamRegistry {
    pub(super) connections: HashMap<StreamConnectionId, StreamConnectionState>,
    pub(super) instances: BTreeMap<HarnessInstanceKey, InstanceAdapterState>,
    pub(super) wake_observations: WakeDispatchObservations,
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
        // The dispatch sequence is this connection's monotonic report fence, so
        // reattach carries it forward rather than restarting it. Binding, queue,
        // and in-flight bundle are still dropped; only the fence survives, which
        // is what keeps every sequence issued before the reattach stale against
        // every dispatch created after it on this same connection identity.
        let next_dispatch_seq = self.connections.get(&c).map_or(0, |s| s.next_dispatch_seq);
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
                next_dispatch_seq,
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
