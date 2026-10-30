//! One socket's by-reference body transfers (FIX 5489), both directions.
//!
//! Either peer asks the other for each body a window it follows binds by
//! reference and that it does not hold (Want), receives it into a spool in
//! ordered frames (Data) until the sender closes the attempt (End), lands it
//! through the window's ingest ladder, and answers whether it committed it
//! (Receipt). It serves the other's Want for the exact pair a window binds
//! now, from the body it holds. One transfer runs each way at a time; the
//! bodies still owed wait their turn, and an attempt that fails is asked for
//! again, from its first byte, [`ASSET_BODY_RETRY`] later. The window's
//! references are the restartable queue: a poll scans the socket's windows
//! again every [`ASSET_BODY_RETRY`], the first poll of a connection at once
//! ([`AssetBodySession::note_window`]). Nothing here holds a writer while it
//! waits on the network, and no body length is refused.
//!
//! A federation lane moves bodies one way ([`AssetBodyLane`], FIX 12118):
//! the granting side serves the bodies of the rows its selector admitted, the
//! receiving side asks for those of the rows its admission took and lands
//! them at the federated tier.
//!
//! Off the file plane no window binds a reference, nothing is owed or
//! served, and a body frame is the unknown tag it was.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use loro::LoroDoc;

use super::landing;
use super::references::{AssetBodyRef, bound_in, bound_refs};
use super::send::Sending;
use super::stored_body_is;
use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::store::{ASSET_FILE_PLANE, AssetBodySpool};
use crate::sync::WindowManager;
use crate::sync::bridge::Materializer;
use crate::sync::client::ImportTier;
use crate::sync::loro_support::{TombstoneIndex, map_get_bytes};
use crate::sync::selector::FederationAdmissionRole;
use crate::sync::transport::{
    ASSET_BODY_FRAME_BYTES, ASSET_BODY_RETRY, AssetBodyAddress, AssetBodyData, AssetBodyEnd,
    AssetBodyReceipt, AssetBodyWant, TAG_ASSET_BODY_DATA, TAG_ASSET_BODY_END,
    TAG_ASSET_BODY_RECEIPT, TAG_ASSET_BODY_WANT, TransportError, asset_body_frame_bytes,
    decode_asset_body_data, decode_asset_body_end, decode_asset_body_receipt,
    decode_asset_body_want, encode_asset_body_end, encode_asset_body_receipt,
    encode_asset_body_want,
};
use crate::sync::types::WindowKey;

/// The Data frames one poll sends at most, by default (a call, FIX 5489):
/// sixteen frames of [`ASSET_BODY_FRAME_BYTES`], one MiB. It paces a send
/// beside the socket's other traffic; it bounds no body.
pub const ASSET_BODY_FRAMES_PER_POLL: usize = 16;

/// The lane a session moves bodies on (FIX 12118): which way they go, and
/// the tier a body it receives lands at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetBodyLane {
    /// One of the owner's own lanes: each side asks for the bodies its
    /// windows bind that it lacks and serves the ones it holds; a body lands
    /// at the own-device tier.
    OwnDevice,
    /// A federation lane's granting side: it serves the bodies its windows,
    /// the copies the lane's selector admitted, bind, and asks for none.
    FederationGrant,
    /// A federation lane's receiving side: it asks only for the bodies of
    /// the rows its federated admission took (`AssetBodySession::note_rows`)
    /// and lands each at the federated tier under `role`; it serves none.
    FederationReceive { role: FederationAdmissionRole },
}

impl AssetBodyLane {
    /// Whether this side serves the other's Want.
    const fn serves(self) -> bool {
        !matches!(self, Self::FederationReceive { .. })
    }

    /// Whether this side asks for the bodies it owes.
    const fn asks(self) -> bool {
        !matches!(self, Self::FederationGrant)
    }

    /// Whether a poll scans every window this side follows for the bodies
    /// it owes: only an own lane owes every body its windows bind.
    const fn scans(self) -> bool {
        matches!(self, Self::OwnDevice)
    }

    /// The tier a body this side receives lands at.
    pub(super) const fn landing_tier(self) -> ImportTier {
        match self {
            Self::FederationReceive { role } => ImportTier::Federated(role),
            Self::OwnDevice | Self::FederationGrant => ImportTier::OwnDevice,
        }
    }
}

/// What a session reads its side through, as the socket that owns it
/// resolves it.
pub struct AssetBodyPeer<'a> {
    /// The lane the socket moves bodies on.
    pub lane: AssetBodyLane,
    pub vault: &'a Vault,
    /// The windows' materializer: the lease vault the window's receipts
    /// verify against, and the live queries a landed body notifies.
    pub materializer: &'a Materializer,
    /// The live document of a window this socket moves bodies for, under
    /// its scope; `None` for any other window.
    pub window: &'a dyn Fn(&WindowKey) -> Option<LoroDoc>,
    /// The windows this socket moves bodies for now, which a poll scans.
    pub windows: &'a dyn Fn() -> Vec<WindowKey>,
}

/// Runs `f` over the peer a sync client over `manager` is, on `lane`: its
/// vault, its lease vault, and the live documents its manager holds.
pub(crate) fn with_manager_peer<T>(
    manager: &WindowManager,
    lane: AssetBodyLane,
    f: impl FnOnce(&AssetBodyPeer<'_>) -> T,
) -> T {
    let window = |key: &WindowKey| manager.window(key).map(|loaded| loaded.doc.clone());
    let windows = || manager.loaded_keys();
    f(&AssetBodyPeer {
        lane,
        vault: manager.vault(),
        materializer: manager.materializer(),
        window: &window,
        windows: &windows,
    })
}

/// Lands `bytes`, every byte of the body `body` names, carried whole outside
/// any socket (an offline bundle, FIX 5532), as the row of its carrier in
/// `window` as `peer` reads it: the received body's own landing, from a
/// spool of those bytes. `false` when it did not land.
///
/// # Errors
///
/// The spool's errors, and the landing's.
pub(crate) fn land_carried_body(
    peer: &AssetBodyPeer<'_>,
    window: &WindowKey,
    body: &AssetBodyRef,
    bytes: &[u8],
) -> crate::error::Result<bool> {
    let mut spool = peer.vault.asset_body_spool(body.facts())?;
    if !bytes.is_empty() {
        spool.write_at(0, bytes)?;
    }
    landing::land(peer, window, body, spool)
}

/// A body this side is owed, and when it asks for it next.
struct Owed {
    body: AssetBodyRef,
    next_ask: Instant,
}

/// The body coming in.
struct Receiving {
    attempt: [u8; 16],
    window: WindowKey,
    body: AssetBodyRef,
    spool: AssetBodySpool,
}

/// One socket's body transfers. Make one per connection: a new connection
/// starts every transfer again from its first byte.
#[derive(Default)]
pub struct AssetBodySession {
    /// When a poll next scans the socket's windows; `None` before the first.
    next_scan: Option<Instant>,
    owed: HashMap<(WindowKey, EntityId), Owed>,
    /// The bodies this connection found held here, by owner and BLAKE3.
    held: HashSet<(EntityId, [u8; 32])>,
    receiving: Option<Receiving>,
    sending: Option<Sending>,
    /// The rows a received body birthed here on a federation lane's
    /// receiving side, for the caller to release their stamps (FIX 12118).
    births: Vec<(WindowKey, EntityId)>,
}

impl AssetBodySession {
    /// Owes every body `doc`, the live document of `window`, binds by
    /// reference that this side does not hold under its carrier's header,
    /// unless a tombstone or a delete here keeps the carrier from landing.
    /// Call it once a window's import is admitted, and for each window a
    /// connection follows when it opens. Owed bodies of `window` the
    /// document no longer binds are dropped.
    ///
    /// # Errors
    ///
    /// [`TransportError::Storage`] for a storage error.
    pub fn note_window(
        &mut self,
        peer: &AssetBodyPeer<'_>,
        window: &WindowKey,
        doc: &LoroDoc,
    ) -> Result<(), TransportError> {
        if !ASSET_FILE_PLANE {
            return Ok(());
        }
        let bound = bound_refs(doc);
        self.owed.retain(|(key, id), owed| {
            key != window
                || bound
                    .iter()
                    .any(|body| body.id == *id && *body == owed.body)
        });
        let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
        let entities = doc.get_map("entities");
        for body in bound {
            let carrier = map_get_bytes(&entities, &body.key()).unwrap_or_default();
            self.owe(peer, window, &tombstones, body, &carrier)?;
        }
        Ok(())
    }

    /// Owes the body of each of `rows` that `doc`, the live document of
    /// `window`, binds by reference and this side does not hold: the rows an
    /// import just admitted there, on a lane that owes no other (FIX 12118).
    ///
    /// # Errors
    ///
    /// [`TransportError::Storage`] for a storage error.
    pub(crate) fn note_rows(
        &mut self,
        peer: &AssetBodyPeer<'_>,
        window: &WindowKey,
        doc: &LoroDoc,
        rows: &[EntityId],
    ) -> Result<(), TransportError> {
        if !ASSET_FILE_PLANE {
            return Ok(());
        }
        let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
        let entities = doc.get_map("entities");
        for id in rows {
            if let Some(carrier) = map_get_bytes(&entities, &id.to_hex())
                && let Some(body) = bound_in(doc, id, &carrier)
            {
                self.owe(peer, window, &tombstones, body, &carrier)?;
            }
        }
        Ok(())
    }

    /// The rows a received body birthed here since the last take, on a
    /// federation lane's receiving side: the caller releases the stamps the
    /// peer's held lane keeps on them (FIX 12118).
    pub(crate) fn take_federated_births(&mut self) -> Vec<(WindowKey, EntityId)> {
        std::mem::take(&mut self.births)
    }

    /// Owes `body`, which `window` binds `carrier` with, unless a tombstone
    /// or a delete here keeps the carrier from landing, this side holds the
    /// body, or it is owed already.
    fn owe(
        &mut self,
        peer: &AssetBodyPeer<'_>,
        window: &WindowKey,
        tombstones: &TombstoneIndex,
        body: AssetBodyRef,
        carrier: &[u8],
    ) -> Result<(), TransportError> {
        let owed = (window.clone(), body.id);
        if tombstones.contains(&body.id)
            || self.held.contains(&(body.id, body.body_blake3))
            || self.owed.get(&owed).is_some_and(|known| known.body == body)
        {
            return Ok(());
        }
        if held_here(peer.vault, &body, carrier).map_err(storage)? {
            self.held.insert((body.id, body.body_blake3));
            return Ok(());
        }
        self.owed.insert(
            owed,
            Owed {
                body,
                next_ask: Instant::now(),
            },
        );
        Ok(())
    }

    /// Takes one body frame from the peer: `tag` and the bytes after it.
    /// Returns the frames to send back.
    ///
    /// # Errors
    ///
    /// [`TransportError::UnknownTag`] for any frame while the file plane is
    /// off, as before it; a frame that does not decode.
    pub fn handle_frame(
        &mut self,
        peer: &AssetBodyPeer<'_>,
        tag: u8,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        if !ASSET_FILE_PLANE {
            return Err(TransportError::UnknownTag(tag));
        }
        match tag {
            TAG_ASSET_BODY_WANT => self.serve(peer, &decode_asset_body_want(payload)?),
            TAG_ASSET_BODY_DATA => {
                self.receive(decode_asset_body_data(payload)?);
                Ok(Vec::new())
            }
            TAG_ASSET_BODY_END => self.close(peer, decode_asset_body_end(payload)?),
            TAG_ASSET_BODY_RECEIPT => {
                let receipt = decode_asset_body_receipt(payload)?;
                if self
                    .sending
                    .as_ref()
                    .is_some_and(|sending| sending.attempt() == receipt.attempt)
                {
                    self.sending = None;
                }
                if !receipt.committed {
                    tracing::debug!(
                        entity = %receipt.body.entity.to_hex(),
                        "peer refused an asset body this side sent"
                    );
                }
                Ok(Vec::new())
            }
            _ => Err(TransportError::UnknownTag(tag)),
        }
    }

    /// The frames to send now: at most `frames` Data frames of the body this
    /// side sends, and its End once the last byte went; then a Want for the
    /// next body this side is owed whose ask is due at `now`, once no body
    /// comes in. Every [`ASSET_BODY_RETRY`] it first scans the socket's
    /// windows for bodies owed ([`Self::note_window`]). `socket_max` is the
    /// socket's frame bound.
    ///
    /// # Errors
    ///
    /// A frame that does not encode, and a storage error in the scan.
    pub fn poll(
        &mut self,
        peer: &AssetBodyPeer<'_>,
        now: Instant,
        frames: usize,
        socket_max: usize,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let mut out = Vec::new();
        if !ASSET_FILE_PLANE {
            return Ok(out);
        }
        if peer.lane.scans() && self.next_scan.is_none_or(|next| next <= now) {
            self.next_scan = Some(now + ASSET_BODY_RETRY);
            for key in (peer.windows)() {
                if let Some(doc) = (peer.window)(&key) {
                    self.note_window(peer, &key, &doc)?;
                }
            }
        }
        if let Some(sending) = &mut self.sending {
            let sent = sending.poll(peer, frames, socket_max)?;
            out.extend(sent.frames);
            if sent.ended {
                self.sending = None;
            }
        }
        if self.receiving.is_none()
            && peer.lane.asks()
            && let Some(want) = self.ask(peer, now, socket_max)?
        {
            out.push(want);
        }
        Ok(out)
    }

    /// Serves `want`, stopping the send it replaces: the peer asks for one
    /// body at a time. A Want this side does not serve is ended at once, as
    /// is every Want on a lane that serves none.
    fn serve(
        &mut self,
        peer: &AssetBodyPeer<'_>,
        want: &AssetBodyWant,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let mut out = Vec::new();
        if let Some(stopped) = self.sending.take() {
            out.push(end(stopped.attempt(), false)?);
        }
        let opened = if peer.lane.serves() {
            Sending::open(peer, want)
        } else {
            Ok(None)
        };
        match opened {
            Ok(Some(sending)) => self.sending = Some(sending),
            Ok(None) => out.push(end(want.attempt, false)?),
            Err(error) => {
                let entity = want.body.entity.to_hex();
                tracing::warn!(%entity, %error, "asset body not served");
                out.push(end(want.attempt, false)?);
            }
        }
        Ok(out)
    }

    /// Spools one frame of the body coming in. A frame of an attempt this
    /// side gave up is dropped; one out of order, or one the spool cannot
    /// take, gives the attempt up, its body asked for again later.
    fn receive(&mut self, data: AssetBodyData<'_>) {
        let Some(receiving) = self
            .receiving
            .as_mut()
            .filter(|receiving| receiving.attempt == data.attempt)
        else {
            return;
        };
        if let Err(error) = receiving.spool.write_at(data.offset, data.bytes) {
            let entity = receiving.body.id.to_hex();
            tracing::warn!(%entity, %error, "asset body receive stopped");
            if let Some(receiving) = self.receiving.take() {
                self.ask_later(&receiving.window, &receiving.body);
            }
        }
    }

    /// Closes the attempt `end` names: a complete body lands, and the
    /// Receipt says whether it committed. A body that did not land is asked
    /// for again later.
    fn close(
        &mut self,
        peer: &AssetBodyPeer<'_>,
        end: AssetBodyEnd,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let Some(Receiving {
            attempt,
            window,
            body,
            spool,
        }) = self
            .receiving
            .take_if(|receiving| receiving.attempt == end.attempt)
        else {
            return Ok(Vec::new());
        };
        // On a federation lane's receiving side, a body that lands where no
        // row was stored is its row's birth (FIX 12118); a failed read counts
        // as stored, so nothing is released for it.
        let birth = matches!(peer.lane, AssetBodyLane::FederationReceive { .. })
            && matches!(stored(peer.vault, &body.id), Ok(false));
        let committed = end.complete
            && spool.received() == body.len
            && match landing::land(peer, &window, &body, spool) {
                Ok(landed) => landed,
                Err(error) => {
                    tracing::warn!(entity = %body.id.to_hex(), %error, "asset body did not land");
                    false
                }
            };
        if committed {
            self.owed.remove(&(window.clone(), body.id));
            self.held.insert((body.id, body.body_blake3));
            if birth {
                self.births.push((window.clone(), body.id));
            }
        } else {
            self.ask_later(&window, &body);
        }
        let receipt = encode_asset_body_receipt(&AssetBodyReceipt {
            attempt,
            body: address(&window, &body),
            committed,
        });
        Ok(vec![receipt.into_result()?])
    }

    /// The Want for the first owed body whose ask is due, its spool open.
    /// A body the window no longer binds is no longer owed, nor one that
    /// came here another way.
    fn ask(
        &mut self,
        peer: &AssetBodyPeer<'_>,
        now: Instant,
        socket_max: usize,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let mut due: Vec<(WindowKey, EntityId)> = self
            .owed
            .iter()
            .filter(|(_, owed)| owed.next_ask <= now)
            .map(|(key, _)| key.clone())
            .collect();
        while let Some(key) = due.pop() {
            let Some(owed) = self.owed.get_mut(&key) else {
                continue;
            };
            let carrier = (peer.window)(&key.0).and_then(|doc| {
                let carrier = map_get_bytes(&doc.get_map("entities"), &key.1.to_hex())?;
                (bound_in(&doc, &key.1, &carrier).as_ref() == Some(&owed.body)).then_some(carrier)
            });
            let Some(carrier) = carrier else {
                self.owed.remove(&key);
                continue;
            };
            let body = owed.body.clone();
            if held_here(peer.vault, &body, &carrier).map_err(storage)? {
                self.owed.remove(&key);
                self.held.insert((body.id, body.body_blake3));
                continue;
            }
            owed.next_ask = now + ASSET_BODY_RETRY;
            let spool = match peer.vault.asset_body_spool(body.facts()) {
                Ok(spool) => spool,
                Err(error) => {
                    let entity = body.id.to_hex();
                    tracing::warn!(%entity, %error, "asset body spool did not open");
                    continue;
                }
            };
            let (window, _) = key;
            let attempt: [u8; 16] = rand::random();
            let want = encode_asset_body_want(&AssetBodyWant {
                attempt,
                body: address(&window, &body),
                max_frame_bytes: asset_body_frame_bytes(ASSET_BODY_FRAME_BYTES as u32, socket_max)
                    as u32,
            })
            .into_result()?;
            self.receiving = Some(Receiving {
                attempt,
                window,
                body,
                spool,
            });
            return Ok(Some(want));
        }
        Ok(None)
    }

    /// Asks for `body` again [`ASSET_BODY_RETRY`] from now, while it is
    /// owed.
    fn ask_later(&mut self, window: &WindowKey, body: &AssetBodyRef) {
        if let Some(owed) = self
            .owed
            .get_mut(&(window.clone(), body.id))
            .filter(|owed| owed.body == *body)
        {
            owed.next_ask = Instant::now() + ASSET_BODY_RETRY;
        }
    }
}

/// Whether the row stored here for `body`'s owner holds that body under the
/// header of `carrier`, the carrier its window binds: the ladder would skip
/// it as an echo. A row a delete here fences is held too: it never lands.
fn held_here(vault: &Vault, body: &AssetBodyRef, carrier: &[u8]) -> crate::error::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    if vault.local_hard_delete_marker_exists_in_txn(&txn, &body.id)? {
        return Ok(true);
    }
    let Some(stored) =
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &body.id)?
    else {
        return Ok(false);
    };
    Ok(
        stored.get(..ENTITY_METADATA_HEADER_LEN) == carrier.get(..ENTITY_METADATA_HEADER_LEN)
            && stored_body_is(&vault.store, &txn, &body.id, &stored, &body.facts())?,
    )
}

/// Whether this vault stores a row at `id`.
fn stored(vault: &Vault, id: &EntityId) -> crate::error::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::ports::EntityStoreRead::port_entity_present(&vault.store, &txn, id)
}

/// `body`'s address in `window`, as the frames name it.
fn address(window: &WindowKey, body: &AssetBodyRef) -> AssetBodyAddress {
    AssetBodyAddress {
        window: window.as_str().to_owned(),
        entity: body.id,
        carrier_blake3: body.carrier_blake3,
        body_blake3: body.body_blake3,
        len: body.len,
    }
}

/// An End for `attempt`.
fn end(attempt: [u8; 16], complete: bool) -> Result<Vec<u8>, TransportError> {
    encode_asset_body_end(AssetBodyEnd { attempt, complete }).into_result()
}

fn storage(error: crate::error::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}
