//! The registry's wake half: binding, dispatch, reporting and fallback.

use std::collections::BTreeSet;

use super::frames::StreamConnectionId;
use super::registry::BoardStreamRegistry;
use super::wake::{
    BindInstanceError, HarnessInstanceKey, InstanceAdapterState, InstanceBindingReceipt,
    PendingWakeDispatch, WakeAdapterKind, WakeDeliveryOutcome, WakeDeliveryReportError,
    WakeDispatch, WakeDispatchObservations, WakeEnvelope, WakeReportDisposition,
    ordered_candidates,
};

impl BoardStreamRegistry {
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
}
