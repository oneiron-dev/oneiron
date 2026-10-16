//! Home custody of private-world windows the home may not read (OF-534 G7,
//! DEC-0005 world privacy fix 8). A machine that reads the world seals each of
//! its windows (`WindowManager::export_sealed_residence_content`) and puts the
//! packet on the home's shelf; another machine that reads the world takes the
//! shelf's packets back in, in the order they arrived. The home opens nothing:
//! it files each packet under its tag, beside the window label its sender
//! names and the order it arrived in.
//!
//! The live packets of a window are its latest replacement and the updates put
//! after it. A sender that puts a replacement retires the window's packets it
//! had taken in before; a packet another machine put meanwhile stays live.
//! Every door serves only a machine whose proof stands here, and only for a
//! world that machine may read.

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::PeerMachine;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::sync::types::WindowKey;
use crate::world_keys::{SealedContentId, SealedResidenceContent};

use super::withheld_from_peer;

/// The home's label beside a shelved packet: u64be arrival ‖ window label.
/// Key: hex64 (tag) ":" hex64 (digest), the shelf's own key.
const LABEL_PREFIX: &str = "rsh:";
/// The home's next arrival number (u64be).
const NEXT_KEY: &str = "rsn";

/// The most entries one shelf listing returns.
pub const SEALED_SHELF_PAGE_MAX: usize = 256;

/// One live packet on the home's shelf, as a reader lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedShelfEntry {
    pub id: SealedContentId,
    /// The window the sender named; the packet's sealed binding must agree.
    pub window: WindowKey,
    /// The order the home took it in, from 1.
    pub seq: u64,
}

fn denied() -> Error {
    Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied)
}

fn label_key(id: &SealedContentId) -> String {
    format!("{LABEL_PREFIX}{}", id.to_hex())
}

fn decode_label(raw: &[u8]) -> Result<(u64, WindowKey)> {
    let (seq, window) = raw.split_at_checked(8).ok_or(Error::InvalidKey)?;
    let seq = u64::from_be_bytes(seq.try_into().map_err(|_| Error::InvalidKey)?);
    let window = std::str::from_utf8(window).map_err(|_| Error::InvalidKey)?;
    Ok((seq, WindowKey::try_new(window).ok_or(Error::InvalidKey)?))
}

/// The worlds kept off the machine `peer` proved. An unproved peer is refused:
/// sealed copies travel only between machines that stand here.
fn peer_withheld(vault: &Vault, peer: PeerMachine) -> Result<BTreeSet<EntityId>> {
    withheld_from_peer(vault, peer)?.ok_or_else(denied)
}

fn private_world(window: &WindowKey) -> Result<EntityId> {
    window.world().ok_or_else(denied)
}

/// Every label on the shelf with its live state, dropping the labels whose
/// packet the shelf no longer holds (expired, or purged with its world).
fn shelf_labels(vault: &Vault) -> Result<Vec<(SealedContentId, u64, WindowKey, bool)>> {
    let shelved: std::collections::BTreeMap<SealedContentId, bool> = vault
        .sealed_world_content_ids()?
        .into_iter()
        .map(|(id, retired)| (id, retired.is_some()))
        .collect();
    let labels: Vec<(String, Vec<u8>)> = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .sync_state
            .prefix_iter(&txn, LABEL_PREFIX)?
            .map(|row| row.map(|(key, value)| (key.to_string(), value.to_vec())))
            .collect::<std::result::Result<_, _>>()?
    };
    let mut out = Vec::with_capacity(labels.len());
    let mut stale = Vec::new();
    for (key, raw) in labels {
        let id = SealedContentId::from_hex(&key[LABEL_PREFIX.len()..]);
        match (id, decode_label(&raw)) {
            (Ok(id), Ok((seq, window))) if shelved.contains_key(&id) => {
                out.push((id, seq, window, shelved[&id]));
            }
            _ => stale.push(key),
        }
    }
    if !stale.is_empty() {
        vault.with_write_txn_grouped(|wtxn| {
            for key in &stale {
                vault.store.sync_state.delete(wtxn, key)?;
            }
            Ok(())
        })?;
    }
    out.sort_by_key(|(_, seq, _, _)| *seq);
    Ok(out)
}

/// Shelves one sealed packet of `window` from the machine `peer` proved, which
/// must read the window's world. Refused for an unproved peer, a base window,
/// a world kept off the sender, and a world whose sealed copies are off; L04's
/// shelf then refuses a packet of another vault or of a key whose pad is not
/// here. `retire_through`, when the packet is a replacement, is the last
/// arrival the sender had taken in: every live packet of the window up to it is
/// retired, to be purged 30 days on. Returns the packet's id and arrival.
///
/// # Errors
///
/// A refused sender, world or packet; storage errors.
pub fn shelve_sealed_window(
    vault: &Vault,
    peer: PeerMachine,
    window: &WindowKey,
    packet: &[u8],
    retire_through: Option<u64>,
) -> Result<(SealedContentId, u64)> {
    let world = private_world(window)?;
    if peer_withheld(vault, peer)?.contains(&world) {
        return Err(denied());
    }
    vault.require_sealed_copies(world)?;
    let packet = SealedResidenceContent::from_bytes(packet)?;
    let id = vault.store_sealed_world_content(&packet)?;
    let key = label_key(&id);
    let seq = vault.with_write_txn_grouped(|wtxn| {
        if let Some(raw) = vault.store.sync_state.get(wtxn, &key)? {
            let (seq, labelled) = decode_label(&raw)?;
            return if labelled == *window {
                Ok(seq)
            } else {
                Err(denied())
            };
        }
        let seq = match vault.store.sync_state.get(wtxn, NEXT_KEY)? {
            Some(raw) => u64::from_be_bytes(
                <[u8; 8]>::try_from(raw.as_ref()).map_err(|_| Error::InvalidKey)?,
            ),
            None => 1,
        };
        let mut label = seq.to_be_bytes().to_vec();
        label.extend_from_slice(window.as_str().as_bytes());
        vault.store.sync_state.put(wtxn, &key, &label)?;
        vault
            .store
            .sync_state
            .put(wtxn, NEXT_KEY, &seq.saturating_add(1).to_be_bytes())?;
        Ok(seq)
    })?;
    if let Some(through) = retire_through {
        for (other, other_seq, other_window, retired) in shelf_labels(vault)? {
            if !retired && other != id && other_seq <= through && other_window == *window {
                vault.retire_sealed_world_content(&other)?;
            }
        }
    }
    Ok((id, seq))
}

/// The live packets after arrival `after`, in arrival order, at most
/// [`SEALED_SHELF_PAGE_MAX`], of the worlds the machine `peer` proved may read.
///
/// # Errors
///
/// An unproved peer; storage errors.
pub fn sealed_shelf_after(
    vault: &Vault,
    peer: PeerMachine,
    after: u64,
) -> Result<Vec<SealedShelfEntry>> {
    let withheld = peer_withheld(vault, peer)?;
    Ok(shelf_labels(vault)?
        .into_iter()
        .filter(|(_, seq, window, retired)| {
            !retired
                && *seq > after
                && window
                    .world()
                    .is_some_and(|world| !withheld.contains(&world))
        })
        .take(SEALED_SHELF_PAGE_MAX)
        .map(|(id, seq, window, _)| SealedShelfEntry { id, window, seq })
        .collect())
}

/// One shelved packet's bytes and window, when the machine `peer` proved may
/// read its world. `None` for a packet not here and for a world kept off it.
///
/// # Errors
///
/// An unproved peer; storage errors.
pub fn sealed_shelf_packet(
    vault: &Vault,
    peer: PeerMachine,
    id: &SealedContentId,
) -> Result<Option<(WindowKey, Vec<u8>)>> {
    let withheld = peer_withheld(vault, peer)?;
    let label = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .sync_state
            .get(&txn, &label_key(id))?
            .map(|raw| decode_label(&raw))
            .transpose()?
    };
    let Some((_, window)) = label else {
        return Ok(None);
    };
    if window.world().is_none_or(|world| withheld.contains(&world)) {
        return Ok(None);
    }
    Ok(vault
        .sealed_world_content(id)?
        .map(|packet| (window, packet.into_bytes())))
}
