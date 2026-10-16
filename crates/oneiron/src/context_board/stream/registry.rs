//! The board stream registry: connections, subscriptions and event routing.

use std::collections::{BTreeSet, HashMap, VecDeque};

use super::events::{
    BoardEvent, RouteObservation, SubscriptionError, SubscriptionReceipt, SubscriptionScope,
};
use super::frames::{
    BoardRenderMode, BoardStreamFrame, CarrierCoalesceBuffer, CoalesceOutcome, FrameEnqueueOutcome,
    FrameKind, StreamConnectionId,
};
use super::wake::WakeEnvelope;

/// Pending wakes one connection holds before the oldest is dropped.
const PENDING_WAKES_CAP: usize = 256;

#[derive(Debug)]
pub struct StreamConnectionState {
    pub mode: BoardRenderMode,
    pub actor_ref: String,
    pub allowed: BTreeSet<SubscriptionScope>,
    pub subscribed: BTreeSet<SubscriptionScope>,
    pub last_touched_at: u64,
    pub(super) carrier: CarrierCoalesceBuffer,
    pub(super) wakes: VecDeque<WakeEnvelope>,
}

#[derive(Debug, Default)]
pub struct BoardStreamRegistry {
    pub(super) connections: HashMap<StreamConnectionId, StreamConnectionState>,
    pub(super) published_tasks: super::publish::PublishedTasks,
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
        // Re-attaching over a live connection replaces its state and queue.
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

    /// Teardown drops the connection together with its queued wakes.
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

    /// The epoch of the last keyframe this connection's carrier lane took:
    /// the receiver ignores any frame older than it.
    #[must_use]
    pub fn carrier_epoch(&self, c: &StreamConnectionId) -> Option<u64> {
        self.connections
            .get(c)
            .and_then(|state| state.carrier.epoch)
    }

    /// Uses a credential connection's established keyframe epoch for its host
    /// wake connection. A refresh drops the wake carrier's older deltas; no
    /// synthetic keyframe or independent epoch is minted for the adapter.
    #[must_use]
    pub fn follow_carrier_epoch(
        &mut self,
        connection: &StreamConnectionId,
        baseline: &StreamConnectionId,
    ) -> bool {
        let Some(epoch) = self.carrier_epoch(baseline) else {
            return false;
        };
        let Some(state) = self.connections.get_mut(connection) else {
            return false;
        };
        if state.carrier.epoch.is_some_and(|held| held > epoch) {
            return false;
        }
        if state.carrier.epoch != Some(epoch) {
            state.carrier = CarrierCoalesceBuffer::default();
            state.carrier.epoch = Some(epoch);
        }
        true
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
        self.route_event_where(e, |_, _| true)
    }

    /// [`Self::route_event`] over the connections `admit` accepts.
    pub(super) fn route_event_where(
        &mut self,
        e: BoardEvent,
        admit: impl Fn(&StreamConnectionId, &StreamConnectionState) -> bool,
    ) -> RouteObservation {
        let mut o = RouteObservation::default();
        let class = e.class();
        if !class.is_pushable() {
            o.on_demand_ignored = self.connections.len();
            return o;
        }
        for (c, st) in &mut self.connections {
            if !admit(c, st) || !st.subscribed.contains(&e.subscription_scope()) {
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
                    // Wakes wait for a host-side adapter that may never come.
                    // The oldest goes first; the durable TASK still stands.
                    if st.wakes.len() >= PENDING_WAKES_CAP {
                        st.wakes.pop_front();
                    }
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
