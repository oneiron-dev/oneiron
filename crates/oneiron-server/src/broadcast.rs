//! Broadcast group for multi-device fan-out with echo suppression.
//!
//! Broadcast group pattern with echo suppression. Key differences from typical implementations:
//! - Payloads include conn_id for echo suppression
//! - conn_id 0 = local/bridge writes (broadcast to all)
//! - conn_id >= 1 = specific connection (skip sender)
//! - Lossy broadcast: on `Lagged`, the socket is resynced, never closed for
//!   lag (rule 5; `handler::lag_resync`)

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::broadcast;

use crate::api::ReactiveChange;
use crate::protocol::{SyncMessage, parse_message};
use crate::server::BroadcastPayload;

/// How many connection sessions hold a [`BroadcastSubscriber`] now.
///
/// The channel's own receiver count is not this number: the host subscribes
/// for its own background work too (the cloud erase watch holds a receiver
/// for the whole serve), so that count never reads zero on a served host and
/// a managed reap could never find the vault quiescent (FIX 23314). Each
/// session counts itself here instead, for as long as its subscriber lives.
#[derive(Debug, Default)]
pub(crate) struct BroadcastSessions(Arc<AtomicUsize>);

impl BroadcastSessions {
    /// The sessions holding a subscriber now. It never reads low: a session
    /// is counted before it subscribes and released after its receiver drops.
    pub(crate) fn live(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// One session's place in [`BroadcastSessions`], released when it drops.
struct BroadcastSessionMark(Arc<AtomicUsize>);

impl BroadcastSessionMark {
    fn enter(sessions: &BroadcastSessions) -> Self {
        sessions.0.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(&sessions.0))
    }
}

impl Drop for BroadcastSessionMark {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A subscriber handle for a single WebSocket connection.
/// Wraps a broadcast receiver and filters out echo messages.
pub(crate) struct BroadcastSubscriber {
    /// The connection ID this subscriber belongs to.
    conn_id: u32,
    /// Receiver end of the broadcast channel.
    rx: broadcast::Receiver<BroadcastPayload>,
    /// Declared after `rx`, so it is released only after the receiver drops.
    _session: BroadcastSessionMark,
}

impl BroadcastSubscriber {
    /// Creates a new subscriber for the given connection, counted in
    /// `sessions` until it drops. The count is taken before it subscribes.
    pub(crate) fn new(
        conn_id: u32,
        tx: &broadcast::Sender<BroadcastPayload>,
        sessions: &BroadcastSessions,
    ) -> Self {
        let session = BroadcastSessionMark::enter(sessions);
        Self {
            conn_id,
            rx: tx.subscribe(),
            _session: session,
        }
    }

    /// Receives the next broadcast message, skipping echoes.
    ///
    /// Returns `Ok(Some(data))` for a message to forward, `Ok(None)` if the channel
    /// is closed, or `Err(BroadcastError::Lagged)` each time the receiver fell
    /// behind, however often: lag alone never ends a connection.
    pub(crate) async fn recv(&mut self) -> Result<Option<Vec<u8>>, BroadcastError> {
        loop {
            match self.rx.recv().await {
                Ok(BroadcastPayload::Resync { missed }) => {
                    return Err(BroadcastError::Lagged(missed));
                }
                Ok(BroadcastPayload::LocalDocs(_)) => continue,
                Ok(BroadcastPayload::Frame(sender_conn_id, data)) => {
                    // Echo suppression: skip if this message originated from us
                    if sender_conn_id == self.conn_id {
                        continue;
                    }

                    return Ok(Some(data));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        conn_id = self.conn_id,
                        missed = n,
                        "broadcast subscriber lagged"
                    );
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
    /// Receiver fell behind; n messages were skipped. The connection resyncs
    /// every subscription it holds.
    Lagged(u64),
}

/// Subscriber that turns broadcast frames into persistent-change notices for
/// the in-process reactive local reads (ONE-1437, `api::reactive`) — which is
/// also its only caller, so it inherits that module's dead-code posture in the
/// non-test build.
///
/// Unlike [`BroadcastSubscriber`], whose lag resyncs a WebSocket's
/// subscriptions, lag here surfaces as [`ReactiveChange::InvalidateAll`] so the
/// query re-reads coarsely: staleness is a data-freshness problem, not a
/// connection fault.
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
    /// Non-persistent frames are skipped inside the loop and never surface;
    /// the sender connection id is deliberately discarded — a writer's own
    /// device must still refresh its LMDB-derived view. Returns `None` once
    /// the channel is closed: terminal, but the caller's retained snapshot
    /// stays valid.
    pub(crate) async fn recv(&mut self) -> Option<ReactiveChange> {
        loop {
            match self.rx.recv().await {
                Ok(BroadcastPayload::Resync { missed }) => {
                    return Some(ReactiveChange::InvalidateAll { missed });
                }
                Ok(BroadcastPayload::LocalDocs(entities)) => {
                    return Some(ReactiveChange::Doc { entities });
                }
                Ok(BroadcastPayload::Frame(_, data)) => {
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
/// Root updates and entity-document UPDATE/STATE frames invalidate local
/// reads. Observer B sends entity IDs through `LocalDocs` after materializing
/// ledger changes, never as a synthetic peer frame. WindowSync (including
/// UPDATE), ephemeral state, negotiation and malformed frames do not carry
/// local document invalidations.
fn persistent_change(data: &[u8]) -> Option<ReactiveChange> {
    match parse_message(data) {
        Ok(SyncMessage::RootUpdate(_)) => Some(ReactiveChange::Root),
        Ok(SyncMessage::Doc {
            entity,
            kind:
                oneiron::sync::transport::document_sub_tags::UPDATE
                | oneiron::sync::transport::document_sub_tags::STATE,
            ..
        }) => Some(ReactiveChange::Doc {
            entities: vec![entity],
        }),
        Ok(SyncMessage::Batch(docs)) => {
            let entities: Vec<_> = docs
                .into_iter()
                .filter_map(|doc| match doc {
                    SyncMessage::Doc {
                        entity,
                        kind:
                            oneiron::sync::transport::document_sub_tags::UPDATE
                            | oneiron::sync::transport::document_sub_tags::STATE,
                        ..
                    } => Some(entity),
                    _ => None,
                })
                .collect();
            (!entities.is_empty()).then_some(ReactiveChange::Doc { entities })
        }
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
    tx.send(BroadcastPayload::Frame(conn_id, data))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn observer_b_local_docs_never_reach_peer_socket() {
        let (tx, _) = broadcast::channel::<BroadcastPayload>(8);
        let id = oneiron::EntityId::now();
        let mut peer = BroadcastSubscriber::new(1, &tx, &BroadcastSessions::default());
        let mut local = ReactiveChangeSubscriber::new(&tx);
        tx.send(BroadcastPayload::LocalDocs(vec![id])).unwrap();
        broadcast(&tx, 0, vec![42]).unwrap();
        assert_eq!(
            local.recv().await,
            Some(ReactiveChange::Doc { entities: vec![id] })
        );
        assert_eq!(peer.recv().await.unwrap(), Some(vec![42]));
    }

    /// FIX 23314: the host's own receivers are no sessions; a session counts
    /// from before it subscribes until its receiver is gone.
    #[test]
    fn only_session_subscribers_count_as_sessions() {
        let (tx, _) = broadcast::channel::<BroadcastPayload>(8);
        let sessions = BroadcastSessions::default();
        let host_watch = tx.subscribe();
        assert_eq!(tx.receiver_count(), 1);
        assert_eq!(sessions.live(), 0, "a host subscriber is no session");

        let first = BroadcastSubscriber::new(1, &tx, &sessions);
        let second = BroadcastSubscriber::new(2, &tx, &sessions);
        assert_eq!(sessions.live(), 2);
        drop(first);
        assert_eq!(sessions.live(), 1);
        assert_eq!(tx.receiver_count(), 2);
        drop(second);
        assert_eq!(sessions.live(), 0);
        assert_eq!(tx.receiver_count(), 1, "only the host subscriber is left");
        drop(host_watch);
    }
}
