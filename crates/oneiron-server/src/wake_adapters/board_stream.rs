//! STREAM frames for the production host wake handoff.
//!
//! The adapter selects delivery. This bridge uses the credential's existing
//! subscriptions and keyframe epoch in its existing per-instance carrier.
//! Setup/board.refresh supplies keyframes; no wake invents an epoch, a memory
//! push or replay state. Tool-response carriers are never taken here.

use std::collections::BTreeSet;

use oneiron::context_board::{
    BoardRenderMode, BoardStreamFrame, FrameKind, PendingDiaryReview, StreamConnectionId,
    SubscriptionScope, WakeEnvelope,
};
use serde::{Deserialize, Serialize};

use crate::mcp::McpResolvedActor;
use crate::server::SyncServer;

/// Process-local handoff to the host adapter, never persisted as frame replay.
#[derive(Default, Deserialize, Serialize)]
pub(crate) struct BoardDelivery {
    pub(crate) wakes: Vec<WakeEnvelope>,
    pub(crate) frames: Vec<BoardStreamFrame>,
}

impl BoardDelivery {
    /// Only notices selected by the host's existing adapters may carry rows.
    /// A review wake names no TASK, so it keeps no row.
    pub(super) fn retain_frames(&mut self) {
        let keys: BTreeSet<_> = self
            .wakes
            .iter()
            .filter(|wake| wake.review_ref.is_none())
            .map(|wake| format!("tasks:{}", wake.task_ref))
            .collect();
        self.frames.retain_mut(|frame| {
            let FrameKind::Delta(rows) = &mut frame.kind else {
                return false;
            };
            rows.retain(|row| keys.contains(&row.key));
            !rows.is_empty()
        });
    }
}

/// Whether one review wake still names `actor`'s own pending diary-read
/// review: the envelope is bound to `actor`, its id is that review's handle,
/// and the review row still waits on `actor`'s answer. The answer is yes or
/// no and nothing of the row, so it grants no read of the diary or the
/// review. A failed read drops the wake; the review stays in the inbox.
pub(crate) fn review_wake_pending(
    vault: &oneiron::Vault,
    actor: oneiron::EntityId,
    wake: &WakeEnvelope,
) -> bool {
    let Some(request) = wake
        .review_ref
        .as_deref()
        .and_then(|request| oneiron::EntityId::from_hex(request).ok())
    else {
        return false;
    };
    if wake.actor_ref != actor.to_hex()
        || wake.event_ref != PendingDiaryReview::wake_ref(actor, request)
    {
        return false;
    }
    match PendingDiaryReview::is_pending(vault, actor, request) {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "review wake could not be read again; dropped, the review stays in its agent's inbox");
            false
        }
    }
}

/// Runs on the poll's blocking worker. Re-read each TASK under the current
/// reader and use its current line, not queued text from before a refresh.
/// A review wake is read again as the reader's own pending review and rides
/// alone, with no `tasks:` row.
pub(crate) fn coalesced(
    server: &SyncServer,
    reader: &McpResolvedActor,
    wake_connection: &StreamConnectionId,
    wakes: Vec<WakeEnvelope>,
) -> BoardDelivery {
    let mut delivery = BoardDelivery::default();
    let mut registry = server.mcp_registry.blocking_lock();
    let connection = &reader.stream_connection;
    let actor_ref = reader.actor_ref.to_hex();
    let Some(state) = registry.streams_mut().connection_state(connection) else {
        return delivery;
    };
    if state.mode != BoardRenderMode::Stream || state.actor_ref != actor_ref {
        return delivery;
    }
    let subscribed = state.subscribed.clone();
    let Some(instance) = registry.streams_mut().connection_state(wake_connection) else {
        return delivery;
    };
    if instance.mode != BoardRenderMode::Stream || instance.actor_ref != actor_ref {
        return delivery;
    }
    let instance_subscribed = instance.subscribed.clone();
    let epoch = if registry
        .streams_mut()
        .follow_carrier_epoch(wake_connection, connection)
    {
        registry.streams_mut().carrier_epoch(wake_connection)
    } else {
        None
    };
    let mut seen = BTreeSet::new();
    for mut wake in wakes {
        if wake.actor_ref != actor_ref || !seen.insert(wake.event_ref.clone()) {
            continue;
        }
        if wake.review_ref.is_some() {
            let scope = SubscriptionScope::DiaryReviews;
            if subscribed.contains(&scope)
                && instance_subscribed.contains(&scope)
                && reader.subscription_ceiling.contains(&scope)
                && review_wake_pending(&server.vault, reader.actor_ref, &wake)
            {
                delivery.wakes.push(wake);
            }
            continue;
        }
        let event_prefix = format!("{}:", wake.task_ref);
        let scope = match wake
            .event_ref
            .strip_prefix(event_prefix.as_str())
            .and_then(|event| event.split_once(':'))
        {
            Some(("failed", _)) => SubscriptionScope::MyTasks,
            Some(("arrived", _)) => SubscriptionScope::ConsultsToMe,
            _ => continue,
        };
        if !subscribed.contains(&scope)
            || !instance_subscribed.contains(&scope)
            || !reader.subscription_ceiling.contains(&scope)
        {
            continue;
        }
        let Ok(task) = oneiron::EntityId::from_hex(&wake.task_ref) else {
            continue;
        };
        let Some(row) = crate::api::mcp_stream_task_row(&server.vault, reader, &task) else {
            continue;
        };
        wake.line.clone_from(&row.line);
        if let Some(epoch) = epoch {
            registry.enqueue_stream_frame(
                wake_connection,
                BoardStreamFrame {
                    epoch,
                    kind: FrameKind::Delta(vec![row]),
                },
            );
        }
        delivery.wakes.push(wake);
    }
    if epoch.is_some() {
        while let Some(frame) = registry.next_carrier_frame(wake_connection) {
            delivery.frames.push(frame);
        }
        // Ordinary CARRIER rows stay on the credential's next tool result.
        // Only the allowed wake TASKs ride the host's independent handoff.
        delivery.retain_frames();
    }
    delivery
}
