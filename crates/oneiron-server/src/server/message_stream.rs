//! Host-owned stream timer and local presence relay. No durable partial queue.
//! Each partial's trusted scope goes in its own store beside the hub
//! ([`MessageScopes`], FIX 9537).
use super::core::BroadcastPayload;
use super::presence::PresenceCharge;
use crate::config::SyncServerConfig;
use oneiron::sync::{EphemeralStore, ScopedPresenceFrame, decode_ephemeral_states};
use std::sync::Arc;
use tokio::sync::broadcast;

mod scoped;

pub(crate) use scoped::MessageScopes;

pub(super) fn spawn_message_stream_producer(
    vault: &Arc<oneiron::Vault>,
    hub: &Arc<EphemeralStore>,
    presence: &Arc<PresenceCharge>,
    scopes: &Arc<MessageScopes>,
    outgoing: &broadcast::Sender<BroadcastPayload>,
    config: &SyncServerConfig,
) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let mut frames = vault.subscribe_message_stream_presence();
    let vault = Arc::downgrade(vault);
    let hub = Arc::downgrade(hub);
    let presence = Arc::downgrade(presence);
    let scopes = Arc::downgrade(scopes);
    let outgoing = outgoing.clone();
    let payload_limit = config.max_ephemeral_payload_bytes;
    let ttl = config.ephemeral_timeout_ms;
    runtime.spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let (Some(vault), Some(hub), Some(presence), Some(scopes)) = (vault.upgrade(), hub.upgrade(), presence.upgrade(), scopes.upgrade()) else { break; };
                    presence.lock().expire(&hub);
                    scopes.expire(&hub);
                    match vault.pump_message_streams() {
                        Ok(report) => for (message, _) in report.refused {
                            tracing::warn!(?message, reason = "stream_finalization_refused", "stream idle finalization refused; output retained");
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
                    let (Some(hub), Some(presence), Some(scopes)) = (hub.upgrade(), presence.upgrade(), scopes.upgrade()) else { break; };
                    if let Some(frame) = apply_bounded_partial(&hub, &presence, &scopes, &frame, payload_limit, ttl) {
                        let _ = crate::broadcast::broadcast(&outgoing, 0, frame);
                    }
                }
            }
        }
    });
}

/// Applies one native presence frame to the hub, charged to the retained
/// line like a socket's (rule 5): past a full line it meets the memory floor
/// and is not kept. Its scope is recorded first, under its key.
fn apply_bounded_partial(
    hub: &EphemeralStore,
    presence: &PresenceCharge,
    scopes: &MessageScopes,
    partial: &ScopedPresenceFrame,
    payload_limit: usize,
    ttl: i64,
) -> Option<Vec<u8>> {
    let frame = &partial.frame;
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
    let mut charge = presence.lock();
    charge.expire(hub);
    let scratch = EphemeralStore::new(ttl);
    scratch.apply(&hub.encode_all()).ok()?;
    scratch.apply(payload).ok()?;
    if !charge.fit(scratch.encode_all().len()) {
        return None;
    }
    scopes.record(&states[0].key, partial.scope);
    hub.apply(payload).ok()?;
    drop(charge);
    oneiron::sync::encode_ephemeral(&hub.encode(&states[0].key))
        .into_result()
        .ok()
}
