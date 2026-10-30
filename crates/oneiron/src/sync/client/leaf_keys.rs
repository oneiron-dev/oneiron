//! A sync client's side of the custody carrier leaf-key frames (FIX 11785),
//! on its home's live socket. As executor it asks once per connection for
//! each leaf key secret custody waits on, and hands the answer or the failure
//! back to it; as holder it answers a request the home relays. A federation
//! lane carries none: a leaf-key frame there stays the unknown tag it was.
//! Nothing here outlives the connection, and no log line names more than the
//! tag, the request id, the two machines and the outcome.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use futures_util::{Sink, SinkExt};
use tokio_tungstenite::tungstenite::Message;

use super::SyncClient;
use crate::EntityId;
use crate::secret_custody::leaf_delivery::LeafKeyFailureCause;
use crate::sync::transport::{
    LEAF_KEY_RETRY, TAG_LEAF_KEY_ANSWER, TAG_LEAF_KEY_FAILURE, TAG_LEAF_KEY_REQUEST,
    TransportError, decode_leaf_key_answer, decode_leaf_key_failure, decode_leaf_key_request,
    encode_leaf_key_answer, encode_leaf_key_failure, encode_leaf_key_request, leaf_key_request_hex,
};

/// This connection's leaf-key requests: those sent on it, and those a failure
/// cleared, each held until it may go again. Started again at every connect.
#[derive(Default)]
pub(super) struct LeafKeySends {
    sent: HashSet<[u8; 32]>,
    held: HashMap<[u8; 32], Instant>,
}

impl SyncClient {
    /// One leaf-key frame from the home, `tag` and the bytes after it: the
    /// frames to send back.
    ///
    /// # Errors
    ///
    /// [`TransportError::UnknownTag`] on a federation lane; a frame that does
    /// not decode; [`TransportError::Storage`] where secret custody could not
    /// take an answer or a failure.
    pub(super) fn handle_leaf_key_frame(
        &mut self,
        tag: u8,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        if self.config.federation_peer.is_some() {
            return Err(TransportError::UnknownTag(tag));
        }
        match tag {
            TAG_LEAF_KEY_REQUEST => {
                let request = decode_leaf_key_request(payload)?;
                let id = request.request_id();
                let home = self.vault.peer_machine_stands(self.home_peer);
                let answered = self
                    .vault
                    .answer_leaf_key_request(&request, home)
                    .map_err(|error| error.to_string())
                    .and_then(|answer| {
                        encode_leaf_key_answer(&answer)
                            .into_result()
                            .map_err(|error| error.to_string())
                    });
                let (holder, executor) = (request.holder_machine(), request.executor_machine());
                let frame = match answered {
                    Ok(frame) => {
                        logged(tag, &id, holder, executor, "answered");
                        frame
                    }
                    Err(reason) => {
                        logged(tag, &id, holder, executor, "holder_refused");
                        let cause = LeafKeyFailureCause::HolderRefused(reason);
                        encode_leaf_key_failure(&id, &cause).into_result()?
                    }
                };
                Ok(vec![frame])
            }
            TAG_LEAF_KEY_ANSWER => {
                let answer = decode_leaf_key_answer(payload)?;
                let id = answer.request_id();
                let (holder, executor) = (answer.holder_machine(), answer.executor_machine());
                self.vault
                    .accept_leaf_key_answer(&answer)
                    .map_err(|error| {
                        TransportError::Storage(format!("accept leaf key answer: {error}"))
                    })?;
                logged(tag, &id, holder, executor, "accepted");
                Ok(Vec::new())
            }
            TAG_LEAF_KEY_FAILURE => {
                let (id, cause) = decode_leaf_key_failure(payload)?;
                let sends = &mut self.leaf_key_sends;
                sends.sent.remove(&id);
                sends.held.insert(id, Instant::now() + LEAF_KEY_RETRY);
                self.vault
                    .leaf_key_request_failed(id, &cause)
                    .map_err(|error| {
                        TransportError::Storage(format!("record leaf key failure: {error}"))
                    })?;
                tracing::info!(
                    tag,
                    request = %leaf_key_request_hex(&id),
                    outcome = "failed",
                    "leaf key request"
                );
                Ok(Vec::new())
            }
            _ => Err(TransportError::UnknownTag(tag)),
        }
    }

    /// The leaf-key requests this client owes its home now: each one secret
    /// custody lists pending that was not sent on this connection and is not
    /// held after a failure. A read that fails is reported and leaves the
    /// lane up.
    fn leaf_key_requests_due(&mut self) -> Vec<Vec<u8>> {
        if self.config.federation_peer.is_some() {
            return Vec::new();
        }
        let pending = match self.vault.pending_leaf_key_requests() {
            Ok(pending) => pending,
            Err(error) => {
                tracing::warn!(%error, "pending leaf key requests read failed");
                return Vec::new();
            }
        };
        let now = Instant::now();
        let ids: HashSet<[u8; 32]> = pending.iter().map(|request| request.request_id()).collect();
        let sends = &mut self.leaf_key_sends;
        sends.sent.retain(|id| ids.contains(id));
        sends.held.retain(|id, at| *at > now && ids.contains(id));
        let mut frames = Vec::new();
        for request in &pending {
            let id = request.request_id();
            if sends.sent.contains(&id) || sends.held.contains_key(&id) {
                continue;
            }
            let (holder, executor) = (request.holder_machine(), request.executor_machine());
            match encode_leaf_key_request(request).into_result() {
                Ok(frame) => {
                    sends.sent.insert(id);
                    frames.push(frame);
                    logged(TAG_LEAF_KEY_REQUEST, &id, holder, executor, "sent");
                }
                Err(_) => logged(TAG_LEAF_KEY_REQUEST, &id, holder, executor, "too_large"),
            }
        }
        frames
    }
}

/// Sends on `write`, the socket's send half, the leaf-key requests `client`
/// owes its home now: the steady loop's upkeep tick.
///
/// # Errors
///
/// A send that fails, as the loop's other sends report one.
pub(crate) async fn send_leaf_key_requests<S>(
    client: &mut SyncClient,
    write: &mut S,
) -> Result<(), String>
where
    S: Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    for frame in client.leaf_key_requests_due() {
        write
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|error| format!("Send failed: {error}"))?;
    }
    Ok(())
}

fn logged(tag: u8, id: &[u8; 32], holder: EntityId, executor: EntityId, outcome: &'static str) {
    tracing::debug!(
        tag,
        request = %leaf_key_request_hex(id),
        holder = %holder.to_hex(),
        executor = %executor.to_hex(),
        outcome,
        "leaf key request"
    );
}
