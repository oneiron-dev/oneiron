//! Host-owned stream timer and local presence relay. No durable partial queue.
use super::core::BroadcastPayload;
use crate::config::SyncServerConfig;
use oneiron::sync::{EphemeralStore, decode_ephemeral_states};
use std::sync::Arc;
use tokio::sync::broadcast;

pub(super) fn spawn_message_stream_producer(
    vault: &Arc<oneiron::Vault>,
    hub: &Arc<EphemeralStore>,
    outgoing: &broadcast::Sender<BroadcastPayload>,
    config: &SyncServerConfig,
) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let mut frames = vault.subscribe_message_stream_presence();
    let vault = Arc::downgrade(vault);
    let hub = Arc::downgrade(hub);
    let outgoing = outgoing.clone();
    let payload_limit = config.max_ephemeral_payload_bytes;
    let snapshot_limit = config.max_ephemeral_snapshot_bytes;
    let ttl = config.ephemeral_timeout_ms;
    runtime.spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let (Some(vault), Some(hub)) = (vault.upgrade(), hub.upgrade()) else { break; };
                    hub.remove_outdated();
                    match vault.pump_message_streams() {
                        Ok(report) => for (message, error) in report.refused {
                            tracing::warn!(?message, %error, "stream idle finalization refused; output retained");
                        },
                        Err(error) => tracing::warn!(%error, "stream idle pump refused"),
                    }
                }
                frame = frames.recv() => {
                    let frame = match frame {
                        Ok(frame) => frame,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    };
                    let Some(hub) = hub.upgrade() else { break; };
                    if let Some(frame) = apply_bounded_partial(&hub, &frame, payload_limit, snapshot_limit, ttl) {
                        let _ = crate::broadcast::broadcast(&outgoing, 0, frame);
                    }
                }
            }
        }
    });
}

fn apply_bounded_partial(
    hub: &EphemeralStore,
    frame: &[u8],
    payload_limit: usize,
    snapshot_limit: usize,
    ttl: i64,
) -> Option<Vec<u8>> {
    if frame.first() != Some(&oneiron::sync::TAG_EPHEMERAL) {
        return None;
    }
    let payload = &frame[1..];
    if payload.len() > payload_limit {
        return None;
    }
    let states = decode_ephemeral_states(payload).ok()?;
    if states.len() != 1 {
        return None;
    }
    hub.remove_outdated();
    let scratch = EphemeralStore::new(ttl);
    scratch.apply(&hub.encode_all()).ok()?;
    scratch.apply(payload).ok()?;
    if scratch.encode_all().len() > snapshot_limit {
        return None;
    }
    hub.apply(payload).ok()?;
    oneiron::sync::encode_ephemeral(&hub.encode(&states[0].key))
        .into_result()
        .ok()
}
