//! Broadcast group for multi-device fan-out with echo suppression.
//!
//! Broadcast group pattern with echo suppression. Key differences from typical implementations:
//! - Payloads include conn_id for echo suppression
//! - conn_id 0 = local/bridge writes (broadcast to all)
//! - conn_id >= 1 = specific connection (skip sender)
//! - Lossy broadcast: on `Lagged`, trigger per-window SyncStep resync

use tokio::sync::broadcast;

use crate::server::BroadcastPayload;

/// A subscriber handle for a single WebSocket connection.
/// Wraps a broadcast receiver and filters out echo messages.
pub struct BroadcastSubscriber {
    /// The connection ID this subscriber belongs to.
    conn_id: u32,
    /// Receiver end of the broadcast channel.
    rx: broadcast::Receiver<BroadcastPayload>,
    /// Count of consecutive lag events for disconnect escalation.
    lag_count: u32,
}

impl BroadcastSubscriber {
    /// Creates a new subscriber for the given connection.
    pub fn new(conn_id: u32, tx: &broadcast::Sender<BroadcastPayload>) -> Self {
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
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, BroadcastError> {
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

    /// Returns the connection ID for this subscriber.
    #[allow(dead_code)] // Used when WebSocket connected
    pub fn conn_id(&self) -> u32 {
        self.conn_id
    }
}

/// Errors from broadcast subscriber.
#[derive(Debug)]
pub enum BroadcastError {
    /// Receiver fell behind; n messages were skipped.
    /// Connection should trigger per-window SyncStep resync.
    Lagged(u64),
    /// Too many lag events (>= 3 consecutive) — disconnect and force full reconnection.
    TooManyLags,
}

/// Broadcasts an encoded message to all subscribers.
///
/// `conn_id` identifies the sender:
/// - 0 = local/bridge write (broadcast to all devices)
/// - >= 1 = specific connection (echo suppression skips sender)
pub fn broadcast(
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
