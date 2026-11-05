//! A machine's side of the sealed world-update relay (DEC-0005 fix 8:
//! "A my-machines world on it still syncs. The cloud relays its sealed
//! updates between the owner's machines and cannot read them"; CLIP-SYNC = A,
//! FIX 12586), on its home's live socket.
//!
//! A world-window update this machine withholds from a home that may not read
//! the world goes sealed under that world's key into the outbox, when the
//! world is read on the owner's machines with sealed copies on the cloud and on
//! them. Once a home offers sealed updates on a connection, the outbox goes to
//! it, and the home stores and relays each update to the owner's other
//! machines. This machine takes every update after its cursor, opens those of
//! the worlds it reads, and imports each through its own-device window import.
//! Anything the relay cannot carry still rides the daily sealed bundle.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use futures_util::{Sink, SinkExt};
use tokio_tungstenite::tungstenite::Message;

use super::SyncClient;
use crate::authority::{EffectiveRead, EffectiveWorldPrivacy, PeerMachine, SealedCopies};
use crate::sync::residence::{
    SealedUpdateEpoch, SealedUpdateId, drop_sealed_update_outbox, put_sealed_update_cursor,
    put_sealed_update_outbox, sealed_update_cursor, sealed_update_outbox,
};
use crate::sync::transport::{
    MAX_DECODED_PAYLOAD_BYTES, SealedUpdateFrame, TAG_SEALED_UPDATE, TransportError,
    decode_sealed_update_frame, encode_sealed_update_frame,
};
use crate::sync::types::WindowKey;
use crate::world_keys::{WorldKey, open_world_update, seal_world_update, sealed_update_id};

/// How long this connection reuses the world keys it opened for sealed
/// updates before it opens them again.
const KEY_CACHE: Duration = Duration::from_secs(60);
/// How soon an update no cached key opens makes this connection open its
/// keys again, for a key minted since.
const KEY_REFRESH_FLOOR: Duration = Duration::from_secs(1);
/// How often a connection asks its home again for what it may have missed,
/// and offers again the outbox updates the home has not said it stored.
const SINCE_EVERY: Duration = Duration::from_secs(300);
/// How long a catch-up may go unanswered before a gap may ask again.
const CATCH_UP_PATIENCE: Duration = Duration::from_secs(60);
/// The most outbox updates one send offers.
const OUTBOX_SEND_BATCH: usize = 64;
/// Room a sealed update leaves in its frame for the frame's own fields.
const FRAME_ROOM: usize = 64;

/// This connection's place in the relay: whether and under which epoch its
/// home offered, what it sent, a catch-up in flight, and the world keys it
/// opened. Started again at every connect.
#[derive(Default)]
pub(super) struct SealedUpdateSession {
    offered: Option<SealedUpdateEpoch>,
    sent: HashSet<SealedUpdateId>,
    catching_up: Option<Instant>,
    last_since: Option<Instant>,
    keys: Option<(Instant, Vec<WorldKey>)>,
}

/// Whether `privacy` sends a world's updates sealed through a home that may
/// not read it: read on the owner's machines, with sealed copies on the cloud
/// and on them (CLIP-SYNC = A). A world read on one machine, or whose sealed
/// copies stay off the cloud, never goes through the relay (Engine call
/// CLIP-SYNC relay eligibility, CALLS.md).
#[must_use]
pub(crate) fn world_relays_sealed(privacy: &EffectiveWorldPrivacy) -> bool {
    privacy.read == EffectiveRead::MyMachines && privacy.sealed == SealedCopies::CloudAndMyMachines
}

fn frame(frame: &SealedUpdateFrame<'_>) -> Vec<u8> {
    encode_sealed_update_frame(frame)
}

impl SyncClient {
    /// The withheld-update hook: `update` of `window_key`, which this machine
    /// keeps from its home, goes sealed into the outbox when its world relays
    /// sealed and this machine has met a home that takes sealed updates. Any
    /// other update is left to the daily sealed bundle, as before. A fault is
    /// logged, never the caller's.
    pub(crate) fn relay_withheld_update(&self, window_key: &str, update: &[u8]) {
        if self.config.federation_peer.is_some() {
            return;
        }
        if let Err(error) = self.keep_sealed_update(window_key, update) {
            tracing::warn!(%error, "sealed world update not kept for the relay");
        }
    }

    fn keep_sealed_update(&self, window_key: &str, update: &[u8]) -> crate::error::Result<()> {
        let Some(world) = WindowKey::try_new(window_key).and_then(|key| key.world()) else {
            return Ok(());
        };
        if sealed_update_cursor(&self.vault)?.is_none()
            || !world_relays_sealed(&self.vault.world_privacy(world)?)
        {
            return Ok(());
        }
        let key = self.vault.world_key(world)?;
        let vault_id = self.vault.sealed_update_vault_id()?;
        let sealed = seal_world_update(
            &vault_id,
            &key,
            window_key,
            update,
            MAX_DECODED_PAYLOAD_BYTES - FRAME_ROOM,
        )?;
        let id = sealed_update_id(&vault_id, &key, window_key, update);
        put_sealed_update_outbox(&self.vault, &id, world, &sealed)
    }

    /// One sealed update frame from the home, the bytes after its tag: the
    /// frames to send back.
    ///
    /// # Errors
    /// [`TransportError::UnknownTag`] on a federation lane; a frame that does
    /// not decode, or one only a machine sends; [`TransportError::Storage`]
    /// where the cursor or the outbox could not be read or written.
    pub(super) fn handle_sealed_update_frame(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        if self.config.federation_peer.is_some() {
            return Err(TransportError::UnknownTag(TAG_SEALED_UPDATE));
        }
        let storage = |error: crate::error::Error| TransportError::Storage(error.to_string());
        let cursor = sealed_update_cursor(&self.vault).map_err(storage)?;
        match decode_sealed_update_frame(payload)? {
            SealedUpdateFrame::Offer { epoch, .. } => {
                if cursor.is_none_or(|(held, _)| held != epoch) {
                    put_sealed_update_cursor(&self.vault, &epoch, 0).map_err(storage)?;
                }
                // The catch-up and the outbox go at the steady loop's first
                // housekeeping tick, never inside the connect's first burst.
                self.sealed_updates = SealedUpdateSession {
                    offered: Some(epoch),
                    ..SealedUpdateSession::default()
                };
                Ok(Vec::new())
            }
            SealedUpdateFrame::Entry { epoch, seq, sealed } => {
                let Some((held, last)) = cursor else {
                    return Ok(Vec::new());
                };
                if held == epoch && Some(seq) == last.checked_add(1) {
                    self.take_sealed_update(sealed);
                    put_sealed_update_cursor(&self.vault, &epoch, seq).map_err(storage)?;
                    return Ok(Vec::new());
                }
                // A live update past a gap, or under another epoch: ask for
                // what lies between, once per catch-up.
                let asking = self
                    .sealed_updates
                    .catching_up
                    .is_none_or(|at| at.elapsed() > CATCH_UP_PATIENCE);
                if (held != epoch || seq > last) && asking {
                    self.sealed_updates.catching_up = Some(Instant::now());
                    return Ok(vec![frame(&SealedUpdateFrame::Since {
                        epoch: held,
                        after: last,
                    })]);
                }
                Ok(Vec::new())
            }
            SealedUpdateFrame::PageEntry { epoch, seq, sealed } => {
                let last = match cursor {
                    Some((held, last)) if held == epoch => last,
                    _ => 0,
                };
                if seq > last {
                    self.take_sealed_update(sealed);
                    put_sealed_update_cursor(&self.vault, &epoch, seq).map_err(storage)?;
                }
                Ok(Vec::new())
            }
            SealedUpdateFrame::CaughtUp {
                epoch,
                through,
                more,
            } => {
                let behind = match cursor {
                    Some((held, last)) if held == epoch => through > last,
                    _ => true,
                };
                if behind {
                    put_sealed_update_cursor(&self.vault, &epoch, through).map_err(storage)?;
                }
                if more {
                    self.sealed_updates.catching_up = Some(Instant::now());
                    return Ok(vec![frame(&SealedUpdateFrame::Since {
                        epoch,
                        after: through,
                    })]);
                }
                self.sealed_updates.catching_up = None;
                Ok(Vec::new())
            }
            SealedUpdateFrame::Stored { id, epoch, seq } => {
                drop_sealed_update_outbox(&self.vault, &id).map_err(storage)?;
                self.sealed_updates.sent.remove(&id);
                // The home pushes this machine's own update to the others
                // only: the cursor passes it here, so the next live update
                // is not a gap.
                if let Some((held, last)) = cursor
                    && held == epoch
                    && Some(seq) == last.checked_add(1)
                {
                    put_sealed_update_cursor(&self.vault, &epoch, seq).map_err(storage)?;
                }
                Ok(Vec::new())
            }
            SealedUpdateFrame::Since { .. } | SealedUpdateFrame::Put { .. } => Err(
                TransportError::InvalidPayload("a machine's sealed update frame from the home"),
            ),
        }
    }

    /// Opens `sealed` under a key of a world this machine reads and imports
    /// its update; an update of a world it does not read is passed over. A
    /// fault is logged: the daily sealed bundle still carries the world.
    fn take_sealed_update(&mut self, sealed: &[u8]) {
        if let Err(error) = self.import_sealed_update(sealed) {
            tracing::warn!(%error, "sealed world update not taken");
        }
    }

    fn import_sealed_update(&mut self, sealed: &[u8]) -> Result<(), String> {
        let vault_id = self
            .vault
            .sealed_update_vault_id()
            .map_err(|error| error.to_string())?;
        let mut opened = open_world_update(&vault_id, self.sealed_update_keys(KEY_CACHE)?, sealed)
            .map_err(|error| error.to_string())?;
        if opened.is_none() {
            opened = open_world_update(
                &vault_id,
                self.sealed_update_keys(KEY_REFRESH_FLOOR)?,
                sealed,
            )
            .map_err(|error| error.to_string())?;
        }
        let Some(opened) = opened else {
            return Ok(());
        };
        if WindowKey::try_new(opened.window_key.as_str()).and_then(|key| key.world())
            != Some(opened.world())
        {
            return Err("a sealed update's window is not its key's world".to_owned());
        }
        // The relay proves the sealer held the world's key, not which machine
        // it was: the bytes take the import a tier with no connection takes.
        self.import_own_device_window_update(
            &opened.window_key,
            &opened.update,
            PeerMachine::Unknown,
        )
        .map_err(|error| error.to_string())
    }

    /// The world keys this machine opens of the worlds it reads now, opened
    /// again once older than `fresh`.
    fn sealed_update_keys(&mut self, fresh: Duration) -> Result<&[WorldKey], String> {
        let stale = self
            .sealed_updates
            .keys
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= fresh);
        if stale {
            let keys = self
                .vault
                .bundle_reader_keys(None, false)
                .map_err(|error| error.to_string())?;
            self.sealed_updates.keys = Some((Instant::now(), keys));
        }
        Ok(self
            .sealed_updates
            .keys
            .as_ref()
            .map_or(&[][..], |(_, keys)| keys.as_slice()))
    }

    /// The outbox updates not sent on this connection, once its home offered,
    /// each of a world that still relays sealed; an update whose world no
    /// longer does leaves the outbox.
    fn sealed_update_puts_due(&mut self) -> Vec<Vec<u8>> {
        if self.sealed_updates.offered.is_none() {
            return Vec::new();
        }
        let rows = match sealed_update_outbox(
            &self.vault,
            OUTBOX_SEND_BATCH + self.sealed_updates.sent.len(),
        ) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "sealed update outbox read failed");
                return Vec::new();
            }
        };
        let mut frames = Vec::new();
        for row in rows {
            if frames.len() >= OUTBOX_SEND_BATCH {
                break;
            }
            if self.sealed_updates.sent.contains(&row.id) {
                continue;
            }
            match self.vault.world_privacy(row.world) {
                Ok(privacy) if world_relays_sealed(&privacy) => {}
                Ok(_) => {
                    if let Err(error) = drop_sealed_update_outbox(&self.vault, &row.id) {
                        tracing::warn!(%error, "sealed update outbox drop failed");
                    }
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "sealed update world settings read failed");
                    continue;
                }
            }
            frames.push(frame(&SealedUpdateFrame::Put {
                id: row.id,
                sealed: &row.sealed,
            }));
            self.sealed_updates.sent.insert(row.id);
        }
        frames
    }

    /// What this connection owes its home now: every [`SINCE_EVERY`], a
    /// catch-up from its cursor, with the outbox offered again from the
    /// start; and the outbox updates not yet sent.
    fn sealed_update_frames_due(&mut self) -> Vec<Vec<u8>> {
        let Some(epoch) = self.sealed_updates.offered else {
            return Vec::new();
        };
        let mut frames = Vec::new();
        let due = self
            .sealed_updates
            .last_since
            .is_none_or(|at| at.elapsed() >= SINCE_EVERY);
        let idle = self
            .sealed_updates
            .catching_up
            .is_none_or(|at| at.elapsed() > CATCH_UP_PATIENCE);
        if due && idle {
            match sealed_update_cursor(&self.vault) {
                Ok(cursor) => {
                    let after = cursor
                        .filter(|(held, _)| *held == epoch)
                        .map_or(0, |(_, after)| after);
                    frames.push(frame(&SealedUpdateFrame::Since { epoch, after }));
                    let session = &mut self.sealed_updates;
                    session.catching_up = Some(Instant::now());
                    session.last_since = Some(Instant::now());
                    session.sent.clear();
                }
                Err(error) => tracing::warn!(%error, "sealed update cursor read failed"),
            }
        }
        frames.extend(self.sealed_update_puts_due());
        frames
    }
}

/// Sends on `write`, the socket's send half, what `client` owes its home on
/// the sealed world-update relay now: the steady loop's housekeeping tick and
/// each node tick.
///
/// # Errors
///
/// A send that fails, as the loop's other sends report one.
pub(crate) async fn send_sealed_updates<S>(
    client: &mut SyncClient,
    write: &mut S,
) -> Result<(), String>
where
    S: Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    for frame in client.sealed_update_frames_due() {
        write
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|error| format!("Send failed: {error}"))?;
    }
    Ok(())
}
