//! A sync client's side of the by-reference body transfers (FIX 5489), on
//! its own lanes and its federation lanes. On a federation lane it is the
//! receiving side (FIX 12118): it asks only for the bodies of the rows its
//! federated admission took, lands each at the federated tier, releases the
//! stamps a landing's birth applies, and serves no Want.

use std::sync::PoisonError;
use std::time::Instant;

use futures_util::{Sink, SinkExt};
use loro::LoroDoc;
use tokio_tungstenite::tungstenite::Message;

use super::session::{ASSET_BODY_FRAMES_PER_POLL, AssetBodyLane, with_manager_peer};
use crate::EntityId;
use crate::sync::client::SyncClient;
use crate::sync::transport::{MAX_DECODED_PAYLOAD_BYTES, TransportError};
use crate::sync::types::WindowKey;

/// The Data frames one upkeep tick of the client sends at most (a call, FIX
/// 5489): four polls' worth, 4 MiB a tick. It paces a send; it bounds no
/// body.
const CLIENT_FRAMES_PER_TICK: usize = 4 * ASSET_BODY_FRAMES_PER_POLL;

impl SyncClient {
    /// The lane this client moves bodies on: its home's own lane, or the
    /// receiving side of the federation peer it is bound to (FIX 12118).
    fn asset_body_lane(&self) -> AssetBodyLane {
        if self.config.federation_peer.is_some() {
            AssetBodyLane::FederationReceive {
                role: self.config.federation_admission_role,
            }
        } else {
            AssetBodyLane::OwnDevice
        }
    }

    /// One body frame from the home, `tag` and the bytes after it: the
    /// frames to send back, the session's next ones with them. On a
    /// federation lane, the stamps of each row a landed body birthed are
    /// released (FIX 12118).
    ///
    /// # Errors
    ///
    /// [`TransportError::UnknownTag`] while the file plane is off; a frame
    /// that does not decode.
    pub(crate) fn handle_asset_body_frame(
        &mut self,
        tag: u8,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let lane = self.asset_body_lane();
        let bodies = self
            .asset_bodies
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let (out, births) = with_manager_peer(&self.manager, lane, |peer| {
            let mut out = bodies.handle_frame(peer, tag, payload)?;
            out.extend(bodies.poll(
                peer,
                Instant::now(),
                ASSET_BODY_FRAMES_PER_POLL,
                MAX_DECODED_PAYLOAD_BYTES,
            )?);
            Ok::<_, TransportError>((out, bodies.take_federated_births()))
        })?;
        if !births.is_empty() {
            self.release_body_births(births);
        }
        Ok(out)
    }

    /// Owes the bodies `doc`, the live document of `window`, binds by
    /// reference for `rows`, the rows a federated import just admitted there
    /// (FIX 12118): the federation lane asks for those alone.
    ///
    /// # Errors
    ///
    /// [`TransportError::Storage`] for a storage error.
    pub(in crate::sync) fn owe_admitted_bodies(
        &mut self,
        window: &WindowKey,
        doc: &LoroDoc,
        rows: &[EntityId],
    ) -> Result<(), TransportError> {
        let lane = self.asset_body_lane();
        let bodies = self
            .asset_bodies
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        with_manager_peer(&self.manager, lane, |peer| bodies.note_rows(peer, window, doc, rows))
    }

    /// The body frames this client owes its home now. A scan that fails is
    /// reported and leaves the lane up.
    fn poll_asset_bodies(&mut self) -> Vec<Vec<u8>> {
        let lane = self.asset_body_lane();
        let bodies = self
            .asset_bodies
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let polled = with_manager_peer(&self.manager, lane, |peer| {
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
