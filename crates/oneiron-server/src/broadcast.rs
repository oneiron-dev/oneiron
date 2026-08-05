//! Broadcast group for multi-device fan-out with echo suppression.
//!
//! Broadcast group pattern with echo suppression. Key differences from typical implementations:
//! - Payloads include conn_id for echo suppression
//! - conn_id 0 = local/bridge writes (broadcast to all)
//! - conn_id >= 1 = specific connection (skip sender)
//! - Lossy broadcast: on `Lagged`, trigger per-window SyncStep resync

use tokio::sync::broadcast;

use crate::api::ReactiveChange;
use crate::protocol::{SyncMessage, parse_message, window_sub_tags};
use crate::server::BroadcastPayload;

/// A subscriber handle for a single WebSocket connection.
/// Wraps a broadcast receiver and filters out echo messages.
pub(crate) struct BroadcastSubscriber {
    /// The connection ID this subscriber belongs to.
    conn_id: u32,
    /// Receiver end of the broadcast channel.
    rx: broadcast::Receiver<BroadcastPayload>,
    /// Count of consecutive lag events for disconnect escalation.
    lag_count: u32,
}

impl BroadcastSubscriber {
    /// Creates a new subscriber for the given connection.
    pub(crate) fn new(conn_id: u32, tx: &broadcast::Sender<BroadcastPayload>) -> Self {
        Self {
            conn_id,
            rx: tx.subscribe(),
            lag_count: 0,
        }
    }

    /// Receives the next broadcast message, skipping echoes.
    ///
    /// Returns `Ok(Some(data))` for a message to forward, `Ok(None)` if the channel
    /// is closed, or `Err(BroadcastError::Lagged)` if the receiver fell behind.
    /// After 3 lags in rapid succession, returns `Err(BroadcastError::TooManyLags)`.
    pub(crate) async fn recv(&mut self) -> Result<Option<Vec<u8>>, BroadcastError> {
        loop {
            match self.rx.recv().await {
                Ok((sender_conn_id, data)) => {
                    // Reset lag counter on successful receive
                    self.lag_count = 0;

                    // Echo suppression: skip if this message originated from us
                    if sender_conn_id == self.conn_id {
                        continue;
                    }

                    return Ok(Some(data));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    self.lag_count += 1;
                    tracing::warn!(
                        conn_id = self.conn_id,
                        missed = n,
                        lag_count = self.lag_count,
                        "broadcast subscriber lagged"
                    );

                    if self.lag_count >= 3 {
                        return Err(BroadcastError::TooManyLags);
                    }

                    return Err(BroadcastError::Lagged(n));
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Ok(None);
                }
            }
        }
    }
}

/// Errors from broadcast subscriber.
#[derive(Debug)]
pub(crate) enum BroadcastError {
    /// Receiver fell behind; n messages were skipped.
    /// Connection should trigger per-window SyncStep resync.
    Lagged(u64),
    /// Too many lag events (>= 3 consecutive) — disconnect and force full reconnection.
    TooManyLags,
}

/// Subscriber that turns broadcast frames into persistent-change notices for
/// the in-process reactive local reads (ONE-1437, `api::reactive`) — which is
/// also its only caller, so it inherits that module's dead-code posture in the
/// non-test build.
///
/// Two things separate it from [`BroadcastSubscriber`], which stays exactly as
/// it is for WebSocket forwarding:
///
/// - **No echo suppression.** Every origin is observed, including `conn_id = 0`
///   local/bridge writes and frames the consumer's own connection sent. A
///   writer's own device must still refresh its LMDB-derived view, so the
///   sender connection id is deliberately discarded here.
/// - **No disconnect escalation.** Lag is a data-freshness problem for a local
///   read, not a connection fault: it surfaces as
///   [`ReactiveChange::InvalidateAll`] so the query re-reads coarsely instead
///   of tearing anything down.
pub(crate) struct ReactiveChangeSubscriber {
    /// Receiver end of the broadcast channel.
    rx: broadcast::Receiver<BroadcastPayload>,
}

impl ReactiveChangeSubscriber {
    /// Subscribes to every future frame on `tx`.
    pub(crate) fn new(tx: &broadcast::Sender<BroadcastPayload>) -> Self {
        Self { rx: tx.subscribe() }
    }

    /// Waits for the next persistent-change notice.
    ///
    /// Non-persistent frames are skipped inside the loop and never surface.
    /// Returns `None` once the channel is closed — terminal, but the caller's
    /// retained snapshot stays valid.
    pub(crate) async fn recv(&mut self) -> Option<ReactiveChange> {
        loop {
            match self.rx.recv().await {
                Ok((_sender_conn_id, data)) => {
                    if let Some(change) = persistent_change(&data) {
                        return Some(change);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::warn!(missed, "reactive change subscriber lagged");
                    return Some(ReactiveChange::InvalidateAll { missed });
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// Classifies one encoded frame as a persistent-store invalidation, or `None`.
///
/// Exactly two frame shapes can change what an LMDB read returns: a root-doc
/// update, and a WindowSync carrying the `UPDATE` sub-tag. Everything else —
/// ephemeral state, root version vectors, lease frames, WindowSync VV and
/// selector requests, malformed frames, unknown tags, and any future app-tier
/// frame this server does not parse — is negotiation or presence traffic that
/// must never trigger a re-query.
fn persistent_change(data: &[u8]) -> Option<ReactiveChange> {
    match parse_message(data) {
        Ok(SyncMessage::RootUpdate(_)) => Some(ReactiveChange::Root),
        Ok(SyncMessage::WindowSync {
            window_key,
            sub_tag,
            ..
        }) if sub_tag == window_sub_tags::UPDATE => Some(ReactiveChange::Window { window_key }),
        Ok(_) | Err(_) => None,
    }
}

/// Broadcasts an encoded message to all subscribers.
///
/// `conn_id` identifies the sender:
/// - 0 = local/bridge write (broadcast to all devices)
/// - >= 1 = specific connection (echo suppression skips sender)
pub(crate) fn broadcast(
    tx: &broadcast::Sender<BroadcastPayload>,
    conn_id: u32,
    data: Vec<u8>,
) -> Result<(), broadcast::error::SendError<BroadcastPayload>> {
    tx.send((conn_id, data))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn echo_suppression() {
        let (tx, _) = broadcast::channel::<BroadcastPayload>(16);

        let mut sub1 = BroadcastSubscriber::new(1, &tx);
        let mut sub2 = BroadcastSubscriber::new(2, &tx);

        // Send from conn_id 1
        broadcast(&tx, 1, vec![42]).unwrap();

        // Also send from conn_id 2
        broadcast(&tx, 2, vec![99]).unwrap();

        // sub1 should skip the message from conn_id 1 (echo) and get conn_id 2's
        let msg = sub1.recv().await.unwrap().unwrap();
        assert_eq!(msg, vec![99]);

        // sub2 should get the message from conn_id 1 (not echo)
        let msg = sub2.recv().await.unwrap().unwrap();
        assert_eq!(msg, vec![42]);
    }

    #[tokio::test]
    async fn bridge_writes_broadcast_to_all() {
        let (tx, _) = broadcast::channel::<BroadcastPayload>(16);

        let mut sub1 = BroadcastSubscriber::new(1, &tx);
        let mut sub2 = BroadcastSubscriber::new(2, &tx);

        // Send from conn_id 0 (bridge) — should reach all subscribers
        broadcast(&tx, 0, vec![77]).unwrap();

        let msg1 = sub1.recv().await.unwrap().unwrap();
        assert_eq!(msg1, vec![77]);

        let msg2 = sub2.recv().await.unwrap().unwrap();
        assert_eq!(msg2, vec![77]);
    }
}
