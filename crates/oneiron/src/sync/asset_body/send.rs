//! The sending side of one by-reference body transfer (FIX 5489): a Want is
//! served only for the exact pair the window this socket moves bodies for
//! binds now, and only from the body the stored row holds under the
//! carrier's header, inline or in its file. The bytes go in ordered frames
//! a poll at a time, measured as they go; the End says whether every byte
//! went and its BLAKE3 is the reference's.

use std::io::Read;

use super::references::{AssetBodyRef, bound_in};
use super::session::AssetBodyPeer;
use super::stored_body_is;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead as _;
use crate::result_body::ResultBodyPin;
use crate::store::asset_file_in_txn;
use crate::sync::loro_support::{TombstoneIndex, map_get_bytes};
use crate::sync::transport::{
    AssetBodyData, AssetBodyEnd, AssetBodyWant, asset_body_frame_bytes, encode_asset_body_data,
    encode_asset_body_end,
};
use crate::sync::types::WindowKey;

/// Where the bytes come from.
enum Source {
    /// The body file, open: a file stays readable while held open.
    File(Box<dyn Read + Send>),
    /// The stored row, read by range at each poll while it keeps the
    /// carrier's header.
    Row([u8; ENTITY_METADATA_HEADER_LEN]),
}

/// One body this side sends.
pub(super) struct Sending {
    attempt: [u8; 16],
    body: AssetBodyRef,
    source: Source,
    sent: u64,
    hasher: blake3::Hasher,
    /// The most body bytes one Data frame may carry to the receiver.
    wanted: u32,
    _pin: Option<ResultBodyPin>,
}

/// What one poll of a send yields.
pub(super) struct Sent {
    pub(super) frames: Vec<Vec<u8>>,
    /// The End went: the send is over.
    pub(super) ended: bool,
}

impl Sending {
    /// The send `want` asks for, or `None` when this side does not serve it:
    /// a window this socket moves no body for, a pair the window does not
    /// bind now, a tombstoned or unreadable owner, or a stored row that does
    /// not hold the named body under the carrier's header.
    ///
    /// # Errors
    ///
    /// Storage and filesystem errors.
    pub(super) fn open(peer: &AssetBodyPeer<'_>, want: &AssetBodyWant) -> Result<Option<Self>> {
        let Some(window) = WindowKey::try_new(&want.body.window) else {
            return Ok(None);
        };
        let Some(doc) = (peer.window)(&window) else {
            return Ok(None);
        };
        let id = want.body.entity;
        let Some(carrier) = map_get_bytes(&doc.get_map("entities"), &id.to_hex()) else {
            return Ok(None);
        };
        let Some(body) = bound_in(&doc, &id, &carrier).filter(|body| {
            body.carrier_blake3 == want.body.carrier_blake3
                && body.body_blake3 == want.body.body_blake3
                && body.len == want.body.len
        }) else {
            return Ok(None);
        };
        if TombstoneIndex::build(&doc.get_map("tombstones")).contains(&id) {
            return Ok(None);
        }
        let vault = peer.vault;
        let txn = vault.store.env.read_txn()?;
        // The read door's admission: a withdrawn, stale or unpublished row
        // reads as absent.
        if vault.live_entity_in_txn(&vault.store, &txn, &id)?.is_none() {
            return Ok(None);
        }
        let Some(raw) = vault.store.port_entity_raw(&txn, &id)? else {
            return Ok(None);
        };
        let Some(header) = carrier
            .get(..ENTITY_METADATA_HEADER_LEN)
            .and_then(|header| <[u8; ENTITY_METADATA_HEADER_LEN]>::try_from(header).ok())
            .filter(|header| raw.get(..ENTITY_METADATA_HEADER_LEN) == Some(&header[..]))
        else {
            return Ok(None);
        };
        if !stored_body_is(&vault.store, &txn, &id, &raw, &body.facts())? {
            return Ok(None);
        }
        let (source, pin) =
            match asset_file_in_txn(&vault.store, &txn, &id, &raw[ENTITY_METADATA_HEADER_LEN..])? {
                Some(manifest) => {
                    let pin = vault.pin_result_body(manifest.facts.blake3);
                    let file = vault.admitted_asset_file_in_txn(&txn, &manifest)?;
                    (Source::File(Box::new(file)), Some(pin))
                }
                None => (Source::Row(header), None),
            };
        Ok(Some(Self {
            attempt: want.attempt,
            body,
            source,
            sent: 0,
            hasher: blake3::Hasher::new(),
            wanted: want.max_frame_bytes,
            _pin: pin,
        }))
    }

    /// The attempt this send answers.
    pub(super) const fn attempt(&self) -> [u8; 16] {
        self.attempt
    }

    /// The next `frames` Data frames at most, each within the receiver's
    /// bound and the socket's (`socket_max`), and the End once the last byte
    /// went. A read that fails ends the send incomplete; the receiver asks
    /// again later.
    ///
    /// # Errors
    ///
    /// A frame that does not encode.
    pub(super) fn poll(
        &mut self,
        peer: &AssetBodyPeer<'_>,
        frames: usize,
        socket_max: usize,
    ) -> std::result::Result<Sent, crate::sync::TransportError> {
        let size = asset_body_frame_bytes(self.wanted, socket_max) as u64;
        let mut sent = Sent {
            frames: Vec::new(),
            ended: false,
        };
        for _ in 0..frames.max(1) {
            if self.sent == self.body.len {
                let complete = *self.hasher.finalize().as_bytes() == self.body.body_blake3;
                return self.end(sent, complete);
            }
            let take = size.min(self.body.len - self.sent) as usize;
            let bytes = match self.read(peer, take) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let entity = self.body.id.to_hex();
                    tracing::warn!(%entity, %error, "asset body send stopped");
                    return self.end(sent, false);
                }
            };
            self.hasher.update(&bytes);
            sent.frames.push(
                encode_asset_body_data(&AssetBodyData {
                    attempt: self.attempt,
                    offset: self.sent,
                    bytes: &bytes,
                })
                .into_result()?,
            );
            self.sent += take as u64;
        }
        Ok(sent)
    }

    fn end(
        &self,
        mut sent: Sent,
        complete: bool,
    ) -> std::result::Result<Sent, crate::sync::TransportError> {
        sent.frames.push(
            encode_asset_body_end(AssetBodyEnd {
                attempt: self.attempt,
                complete,
            })
            .into_result()?,
        );
        sent.ended = true;
        Ok(sent)
    }

    /// The `take` bytes from where the send stands.
    fn read(&mut self, peer: &AssetBodyPeer<'_>, take: usize) -> Result<Vec<u8>> {
        match &mut self.source {
            Source::File(file) => {
                let mut bytes = vec![0; take];
                file.read_exact(&mut bytes)?;
                Ok(bytes)
            }
            Source::Row(header) => {
                let vault = peer.vault;
                let txn = vault.store.env.read_txn()?;
                let start = ENTITY_METADATA_HEADER_LEN as u64 + self.sent;
                let bytes = vault
                    .store
                    .port_entity_with_raw(&txn, &self.body.id, |raw| {
                        let range = usize::try_from(start)
                            .ok()
                            .and_then(|start| raw.get(start..start.checked_add(take)?));
                        Ok((raw.get(..ENTITY_METADATA_HEADER_LEN) == Some(&header[..]))
                            .then_some(range)
                            .flatten()
                            .map(<[u8]>::to_vec))
                    })?;
                bytes
                    .flatten()
                    .ok_or(Error::CorruptedIndex("asset body row changed while sent"))
            }
        }
    }
}
