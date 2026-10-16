//! STREAM frames for the production host wake handoff.
//!
//! The adapter selects delivery. This bridge uses the credential's existing
//! subscriptions and keyframe epoch in its existing per-instance carrier.
//! Setup/board.refresh supplies keyframes; no wake invents an epoch, a memory
//! push or replay state. Tool-response carriers are never taken here.

use std::collections::BTreeSet;

use oneiron::context_board::{
    BoardRenderMode, BoardStreamFrame, FrameKind, StreamConnectionId, SubscriptionScope,
    WakeEnvelope,
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
    pub(super) fn retain_frames(&mut self) {
        let keys: BTreeSet<_> = self
            .wakes
            .iter()
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

/// Runs on the poll's blocking worker. Re-read each TASK under the current
/// reader and use its current line, not queued text from before a refresh.
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
