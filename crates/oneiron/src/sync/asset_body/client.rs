//! A sync client's side of the by-reference body transfers (FIX 5489), on
//! its own lanes. A federation lane lands no body this way, since its
//! imports take the federated admission: a body frame there stays the
//! unknown tag it was, and its upkeep sends none.

use std::time::Instant;

use futures_util::{Sink, SinkExt};
use tokio_tungstenite::tungstenite::Message;

use super::session::{ASSET_BODY_FRAMES_PER_POLL, with_manager_peer};
use crate::sync::client::SyncClient;
use crate::sync::transport::{MAX_DECODED_PAYLOAD_BYTES, TransportError};

/// The Data frames one upkeep tick of the client sends at most (a call, FIX
/// 5489): four polls' worth, 4 MiB a tick. It paces a send; it bounds no
/// body.
const CLIENT_FRAMES_PER_TICK: usize = 4 * ASSET_BODY_FRAMES_PER_POLL;

impl SyncClient {
    /// One body frame from the home, `tag` and the bytes after it: the
    /// frames to send back, the session's next ones with them.
    ///
    /// # Errors
    ///
    /// [`TransportError::UnknownTag`] on a federation lane and while the
    /// file plane is off; a frame that does not decode.
    pub(crate) fn handle_asset_body_frame(
        &mut self,
        tag: u8,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        if self.config.federation_peer.is_some() {
            return Err(TransportError::UnknownTag(tag));
        }
        let bodies = &mut self.asset_bodies;
        with_manager_peer(&self.manager, |peer| {
            let mut out = bodies.handle_frame(peer, tag, payload)?;
            out.extend(bodies.poll(
                peer,
                Instant::now(),
                ASSET_BODY_FRAMES_PER_POLL,
                MAX_DECODED_PAYLOAD_BYTES,
            )?);
            Ok(out)
        })
    }

    /// The body frames this client owes its home now. A scan that fails is
    /// reported and leaves the lane up.
    fn poll_asset_bodies(&mut self) -> Vec<Vec<u8>> {
        if self.config.federation_peer.is_some() {
            return Vec::new();
        }
        let bodies = &mut self.asset_bodies;
        let polled = with_manager_peer(&self.manager, |peer| {
            bodies.poll(
                peer,
                Instant::now(),
                CLIENT_FRAMES_PER_TICK,
                MAX_DECODED_PAYLOAD_BYTES,
            )
        });
        polled.unwrap_or_else(|error| {
            tracing::warn!(%error, "asset body poll failed");
            Vec::new()
        })
    }
}

/// Sends on `write`, the socket's send half, the body frames `client` owes
/// its home now: the steady loop's upkeep tick.
///
/// # Errors
///
/// A send that fails, as the loop's other sends report one.
pub(crate) async fn send_asset_bodies<S>(
    client: &mut SyncClient,
    write: &mut S,
) -> Result<(), String>
where
    S: Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    for frame in client.poll_asset_bodies() {
        write
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|error| format!("Send failed: {error}"))?;
    }
    Ok(())
}
