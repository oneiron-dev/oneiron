//! FIX 5661 C2a: the old home's delivery worker. It runs beside the
//! connection loop for the connection's whole life, outside every connect
//! attempt: once at start, on each residence upkeep tick (the 300-second
//! `SEALED_RELAY_INTERVAL_SECS`, whose first tick fires at each connect),
//! and when an election moves the home or the move this node recorded. Each
//! round reads the carrier's plan (`sync::home_handoff::delivery_plan`):
//! freeze for the move once every registered table is quiescent, deliver
//! the frozen handoff over the residence RPC lane to the endpoint captured
//! with the move and keep the target's verified ack, or first resolve where
//! the target stands (FIX 5931, and a second move before the first
//! adopted). Parts are the stored `HOME_HANDOFF_PART_BYTES` parts; calls run
//! within the residence operation budgets. No new socket protocol, constant
//! or cadence. A move with no handoff keeps today's local opening; this
//! worker only records why (Incomplete), never a wait.
//!
//! FIX 5661 C2b turns delivery on ([`HOME_HANDOFF_DELIVERY`]), with the new
//! home's ordering and the old home's drain on the host's driver. The worker
//! takes this node's state back, or supersedes, only once the target fenced
//! the handoff in its adopting writer (FIX 5931); the old home's tries run in
//! the host's own passes, and this worker only rechecks quiescence in the
//! final writer and freezes.

use std::convert::Infallible;
use std::sync::Arc;

use tokio::sync::mpsc;

use super::SyncConnection;
use crate::Vault;
use crate::sync::TransportError;
use crate::sync::client::{HandoffLane, SyncEvent, TargetCancel, TargetStanding};
use crate::sync::home_handoff::{
    self, DeliveryPlan, FrozenHandoff, HomeAck, HomeMove, IncompleteReason,
};

/// Whether this build delivers home handoffs (on since FIX 5661 C2b). Off,
/// the worker never runs a round and no move's route is captured.
const HOME_HANDOFF_DELIVERY: bool = true;

/// The target's answer to a cancel, or why it could not be read: no
/// endpoint captured for it, or no answer on it. An unread answer proves
/// nothing either way.
enum Standing {
    Answered(TargetCancel),
    Unread(IncompleteReason),
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> crate::Result<T> + Send + 'static,
) -> Result<T, TransportError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| TransportError::Storage("home handoff work stopped".into()))?
        .map_err(storage)
}

/// Records why the last move naming this node carried nothing.
async fn note(vault: &Arc<Vault>, reason: IncompleteReason) -> Result<(), TransportError> {
    let vault = Arc::clone(vault);
    blocking(move || home_handoff::record_unresolved(&vault, reason)).await
}

/// Keeps the target's ack once its machine's key verifies it.
async fn keep_ack(
    vault: &Arc<Vault>,
    frozen: &FrozenHandoff,
    ack: HomeAck,
) -> Result<(), TransportError> {
    let vault = Arc::clone(vault);
    let id = frozen.id;
    blocking(move || home_handoff::record_ack(&vault, &id, ack)).await
}

/// Captures the route of the move this node's election last recorded, at
/// the move. Off while delivery is off. A capture that fails is logged;
/// the move's delivery then finds no route and records that.
pub(super) fn capture_move_route(vault: &Vault, endpoint_of: impl FnOnce(u64) -> Option<String>) {
    if !HOME_HANDOFF_DELIVERY {
        return;
    }
    if let Err(error) = home_handoff::capture_route(vault, endpoint_of) {
        tracing::warn!(kind = ?error.kind(), "a home move's route was not captured");
    }
}

impl SyncConnection {
    /// Runs a delivery round at start, then each time the upkeep wakes it or
    /// an election moves the home or this node's recorded move. A federation
    /// lane runs none.
    pub(super) async fn run_home_handoff(
        &self,
        events: mpsc::UnboundedSender<SyncEvent>,
    ) -> Infallible {
        if !HOME_HANDOFF_DELIVERY || self.config.client_config.federation_peer.is_some() {
            return std::future::pending().await;
        }
        let vault = Arc::clone(self.manager.vault());
        let mut elections = vault.subscribe_proactivity_changes();
        let mut mark = home_handoff::election_mark(&vault).ok();
        loop {
            if let Err(error) = self.home_handoff_round(&vault).await {
                let _ = events.send(SyncEvent::Error(format!(
                    "Home handoff delivery failed: {error}"
                )));
            }
            loop {
                tokio::select! {
                    () = self.home_handoff_wake.notified() => break,
                    Ok(()) = elections.changed() => {
                        let now = home_handoff::election_mark(&vault).ok();
                        if now.is_some() && now == mark {
                            continue;
                        }
                        mark = now;
                        break;
                    }
                }
            }
        }
    }

    /// One round of the carrier's plan.
    async fn home_handoff_round(&self, vault: &Arc<Vault>) -> Result<(), TransportError> {
        let planned = Arc::clone(vault);
        match blocking(move || home_handoff::delivery_plan(&planned)).await? {
            DeliveryPlan::Idle => Ok(()),
            DeliveryPlan::Freeze(movement) => self.freeze(vault, movement).await,
            DeliveryPlan::Deliver(frozen) => self.deliver(vault, &frozen).await,
            DeliveryPlan::Reclaim(frozen) => self.reclaim(vault, &frozen).await,
            DeliveryPlan::Supersede(frozen, onward) => self.supersede(vault, &frozen, onward).await,
        }
    }

    /// Freezes for `movement` once every registered table is quiescent; a
    /// freeze wakes the next round at once, which delivers it.
    async fn freeze(&self, vault: &Arc<Vault>, movement: HomeMove) -> Result<(), TransportError> {
        let freezing = Arc::clone(vault);
        let frozen = blocking(move || {
            home_handoff::freeze_export(&freezing, &movement, &home_handoff::home_tables())
        })
        .await?;
        if frozen.is_some() {
            self.home_handoff_wake.notify_one();
        }
        Ok(())
    }

    /// The socket to `frozen`'s captured target, while it proves that
    /// machine.
    async fn lane(
        &self,
        vault: &Arc<Vault>,
        frozen: &FrozenHandoff,
    ) -> Result<Result<HandoffLane, IncompleteReason>, TransportError> {
        let Some(endpoint) = frozen.endpoint.as_deref() else {
            return Ok(Err(IncompleteReason::NoRoute));
        };
        let config = self.client_config();
        let target = frozen.movement.target.machine;
        Ok(HandoffLane::open(vault, &config, endpoint, target)
            .await?
            .ok_or(IncompleteReason::Unresolved))
    }

    /// FIX 5931: cancels `frozen` at its target, on its captured route. The
    /// target answers from its adopting writer: fenced there, it never lands
    /// after; adopted first, its ack.
    async fn standing(
        &self,
        vault: &Arc<Vault>,
        frozen: &FrozenHandoff,
    ) -> Result<Standing, TransportError> {
        let mut lane = match self.lane(vault, frozen).await? {
            Ok(lane) => lane,
            Err(reason) => return Ok(Standing::Unread(reason)),
        };
        Ok(match lane.cancel(&frozen.id, &frozen.digest).await {
            Ok(Some(answer)) => Standing::Answered(answer),
            Ok(None) | Err(_) => Standing::Unread(IncompleteReason::Unresolved),
        })
    }

    /// Delivers `frozen` to its captured target: the parts it lacks, in
    /// order, then the commit; keeps the ack. A target out of reach or not
    /// adopting yet waits for the next round; a move with no route records
    /// that.
    async fn deliver(
        &self,
        vault: &Arc<Vault>,
        frozen: &FrozenHandoff,
    ) -> Result<(), TransportError> {
        let mut lane = match self.lane(vault, frozen).await? {
            Ok(lane) => lane,
            Err(IncompleteReason::NoRoute) => return note(vault, IncompleteReason::NoRoute).await,
            Err(_) => return Ok(()),
        };
        let staged = match lane.status(&frozen.id, &frozen.digest).await? {
            Some(TargetStanding::Adopted(ack)) => return keep_ack(vault, frozen, ack).await,
            Some(TargetStanding::Staged(staged)) => staged,
            None => return Ok(()),
        };
        for index in staged..frozen.parts {
            let reading = Arc::clone(vault);
            let id = frozen.id;
            let part = blocking(move || home_handoff::frozen_part(&reading, &id, index)).await?;
            let next = index.saturating_add(1);
            match lane
                .part(&frozen.id, &frozen.digest, index, frozen.parts, &part)
                .await?
            {
                Some(position) if position >= next => {}
                Some(_) => {
                    return Err(TransportError::InvalidPayload(
                        "the home handoff's target lost a staged part",
                    ));
                }
                None => return Ok(()),
            }
        }
        match lane.commit(&frozen.id, &frozen.digest).await? {
            Some(ack) => keep_ack(vault, frozen, ack).await,
            None => Ok(()),
        }
    }

    /// FIX 5931: this node is home again before its target acked. Adopted
    /// there, it keeps the ack and stays history (its successor holds the
    /// state and hands it back); fenced there, it cancels and holds its
    /// state again; unread, it records why and stays frozen.
    async fn reclaim(
        &self,
        vault: &Arc<Vault>,
        frozen: &FrozenHandoff,
    ) -> Result<(), TransportError> {
        match self.standing(vault, frozen).await? {
            Standing::Answered(TargetCancel::Adopted(ack)) => keep_ack(vault, frozen, ack).await,
            Standing::Answered(TargetCancel::Fenced) => {
                let cancelling = Arc::clone(vault);
                let id = frozen.id;
                blocking(move || home_handoff::cancel_frozen(&cancelling, &id)).await
            }
            Standing::Unread(reason) => note(vault, reason).await,
        }
    }

    /// A to B to C before B acked: adopted at B, this node keeps the ack and
    /// B drains its own state onward; fenced at B, this node supersedes
    /// from its frozen state to C; unread, it records why and stays frozen,
    /// never exporting state it does not hold. With no machine known for C
    /// it records that and leaves B unfenced.
    async fn supersede(
        &self,
        vault: &Arc<Vault>,
        frozen: &FrozenHandoff,
        onward: Option<HomeMove>,
    ) -> Result<(), TransportError> {
        let Some(movement) = onward else {
            return note(vault, IncompleteReason::NoRoute).await;
        };
        match self.standing(vault, frozen).await? {
            Standing::Answered(TargetCancel::Adopted(ack)) => keep_ack(vault, frozen, ack).await,
            Standing::Answered(TargetCancel::Fenced) => {
                let superseding = Arc::clone(vault);
                let id = frozen.id;
                let sealed =
                    blocking(move || home_handoff::supersede_export(&superseding, &id, &movement))
                        .await?;
                if sealed.is_some() {
                    self.home_handoff_wake.notify_one();
                }
                Ok(())
            }
            Standing::Unread(reason) => note(vault, reason).await,
        }
    }
}
