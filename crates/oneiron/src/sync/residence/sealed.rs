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
//! had taken in before; a packet another machine put meanwhile stays live. A
//! reader holding an update whose base it lacks asks the home for a
//! replacement of the window; another machine that seals it puts one, which
//! answers the ask.
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

/// A packet put in parts, staged on the home until its last part: u64be vault
/// second of its latest part ‖ the window label its sender named. Key: hex64
/// (blake3 of the whole packet). Each part beside it: key ":" hex16 (its
/// offset), holding the part's bytes.
const STAGE_PREFIX: &str = "rsu:";
/// How long a staged packet waits for its next part before the home drops it.
const STAGE_IDLE_SECS: u64 = 60 * 60;
/// The machines that asked for a replacement of one window, 16 bytes each.
/// Key: the window label. A replacement another machine shelves answers them.
const WANT_PREFIX: &str = "rsw:";

/// The most entries one shelf listing returns.
pub const SEALED_SHELF_PAGE_MAX: usize = 256;
/// The most packet bytes one put request carries; in base64 it stays under the
/// 8 MiB request bound. A larger packet is put in parts of this size.
pub const SEALED_PUT_PART_MAX: usize = 4 * 1024 * 1024;
/// The most packet bytes one read reply carries; in base64 it stays under the
/// 32 MiB reply bound.
pub const SEALED_READ_PART_MAX: usize = 16 * 1024 * 1024;
/// The largest packet the home stages or a reader takes in: a 1 GiB sealed body
/// and its envelopes.
pub const SEALED_PACKET_MAX: u64 = 1025 * 1024 * 1024;

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

/// Refuses an unproved peer, a base window, a world kept off the sender and a
/// world whose sealed copies are off.
fn admit_sender(vault: &Vault, peer: PeerMachine, window: &WindowKey) -> Result<()> {
    let world = private_world(window)?;
    if peer_withheld(vault, peer)?.contains(&world) {
        return Err(denied());
    }
    vault.require_sealed_copies(world)
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
/// here. `retire_through` is set exactly when the packet is a replacement, to
/// the last arrival the sender had taken in: every live packet of the window up
/// to it is retired, to be purged 30 days on, and the asks of other machines
/// for a replacement of the window are answered. Returns the packet's id and
/// arrival.
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
    admit_sender(vault, peer, window)?;
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
        if retire_through.is_some() {
            answer_wants_in(vault, wtxn, peer, window)?;
        }
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

fn stage_key(upload: &[u8; 32]) -> String {
    format!("{STAGE_PREFIX}{}", blake3::Hash::from(*upload).to_hex())
}

fn decode_stage(raw: &[u8]) -> Result<(u64, &[u8])> {
    let (at, window) = raw.split_at_checked(8).ok_or(Error::InvalidKey)?;
    Ok((
        u64::from_be_bytes(at.try_into().map_err(|_| Error::InvalidKey)?),
        window,
    ))
}

/// Stages one part of a sealed packet of `window` too large for one request,
/// from the machine `peer` proved; the sender and world are refused as
/// [`shelve_sealed_window`] refuses them. `upload` is the blake3 digest of the
/// whole packet. `offset` must be the bytes staged so far, and 0 starts the
/// packet over. A staged packet idle for an hour is dropped. Returns the bytes
/// staged.
///
/// # Errors
///
/// A refused sender or world; an empty or oversized part; an offset other than
/// the bytes staged, or a packet staged for another window; storage errors.
pub fn stage_sealed_part(
    vault: &Vault,
    peer: PeerMachine,
    window: &WindowKey,
    upload: &[u8; 32],
    offset: u64,
    part: &[u8],
) -> Result<u64> {
    admit_sender(vault, peer, window)?;
    let end = offset.checked_add(part.len() as u64).ok_or_else(denied)?;
    if part.is_empty() || part.len() > SEALED_PUT_PART_MAX || end > SEALED_PACKET_MAX {
        return Err(denied());
    }
    let key = stage_key(upload);
    vault.with_write_txn_grouped(|wtxn| {
        let now = vault.instant_in_txn(wtxn)?.secs();
        // Each staged packet whose header does not decode or has idled out,
        // and this one when it starts over.
        let mut dropped = Vec::new();
        let mut staged: Option<u64> = None;
        for row in vault.store.sync_state.prefix_iter(wtxn, STAGE_PREFIX)? {
            let (row_key, raw) = row?;
            let Some(head) = row_key.get(..key.len()) else {
                continue;
            };
            if row_key.len() != key.len() {
                if let Some(bytes) = staged.as_mut().filter(|_| head == key) {
                    *bytes += raw.len() as u64;
                }
                continue;
            }
            let idle =
                decode_stage(&raw).map_or(true, |(at, _)| at.saturating_add(STAGE_IDLE_SECS) < now);
            if head == key && offset > 0 && !idle {
                let (_, labelled) = decode_stage(&raw)?;
                if labelled != window.as_str().as_bytes() {
                    return Err(denied());
                }
                staged = Some(0);
            } else if head == key || idle {
                dropped.push(row_key.into_owned());
            }
        }
        if staged.unwrap_or(0) != offset {
            return Err(denied());
        }
        let parts: Vec<String> = {
            let mut parts = Vec::new();
            for head in &dropped {
                for row in vault.store.sync_state.prefix_iter(wtxn, head)? {
                    parts.push(row?.0.into_owned());
                }
            }
            parts
        };
        for row_key in &parts {
            vault.store.sync_state.delete(wtxn, row_key)?;
        }
        let mut header = now.to_be_bytes().to_vec();
        header.extend_from_slice(window.as_str().as_bytes());
        vault.store.sync_state.put(wtxn, &key, &header)?;
        vault
            .store
            .sync_state
            .put(wtxn, &format!("{key}:{offset:016x}"), part)?;
        Ok(end)
    })
}

/// Shelves the packet of `window` the machine `peer` staged under `upload`, as
/// [`shelve_sealed_window`] shelves a whole one, and drops its staged parts.
///
/// # Errors
///
/// No packet staged for `window` under `upload`, or staged bytes that are not
/// the packet `upload` names; whatever [`shelve_sealed_window`] refuses.
pub fn shelve_staged_sealed_window(
    vault: &Vault,
    peer: PeerMachine,
    window: &WindowKey,
    upload: &[u8; 32],
    retire_through: Option<u64>,
) -> Result<(SealedContentId, u64)> {
    admit_sender(vault, peer, window)?;
    let key = stage_key(upload);
    let packet = vault.with_write_txn_grouped(|wtxn| {
        let mut packet = Vec::new();
        let mut keys = Vec::new();
        let mut labelled = false;
        for row in vault.store.sync_state.prefix_iter(wtxn, &key)? {
            let (row_key, raw) = row?;
            if row_key.len() == key.len() {
                labelled = decode_stage(&raw)
                    .is_ok_and(|(_, labelled)| labelled == window.as_str().as_bytes());
            } else if row_key.get(key.len()..) == Some(format!(":{:016x}", packet.len()).as_str()) {
                packet.extend_from_slice(&raw);
            } else {
                labelled = false;
            }
            keys.push(row_key.into_owned());
        }
        for row_key in &keys {
            vault.store.sync_state.delete(wtxn, row_key)?;
        }
        Ok(labelled.then_some(packet))
    })?;
    let packet = packet.ok_or_else(denied)?;
    if blake3::hash(&packet).as_bytes() != upload {
        return Err(denied());
    }
    shelve_sealed_window(vault, peer, window, &packet, retire_through)
}

/// One slice of a shelved packet, at most [`SEALED_READ_PART_MAX`] bytes from
/// `offset`, with its window and whole length, when the machine `peer` proved
/// may read its world: a packet too large for one reply is read in slices.
/// `None` for a packet not here, a world kept off the peer, and an offset at or
/// past the packet's end.
///
/// # Errors
///
/// An unproved peer; storage errors.
pub fn sealed_shelf_packet_part(
    vault: &Vault,
    peer: PeerMachine,
    id: &SealedContentId,
    offset: u64,
) -> Result<Option<(WindowKey, u64, Vec<u8>)>> {
    let Some((window, packet)) = sealed_shelf_packet(vault, peer, id)? else {
        return Ok(None);
    };
    let Some(rest) = usize::try_from(offset)
        .ok()
        .and_then(|offset| packet.get(offset..))
        .filter(|rest| !rest.is_empty())
    else {
        return Ok(None);
    };
    let part = rest[..rest.len().min(SEALED_READ_PART_MAX)].to_vec();
    Ok(Some((window, packet.len() as u64, part)))
}

fn want_key(window: &WindowKey) -> String {
    format!("{WANT_PREFIX}{window}")
}

/// Answers every machine's ask for a replacement of `window` but the one
/// `peer` proved, whose own replacement lacks what it asked for.
fn answer_wants_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    peer: PeerMachine,
    window: &WindowKey,
) -> Result<()> {
    let key = want_key(window);
    let Some(askers) = vault
        .store
        .sync_state
        .get(wtxn, &key)?
        .map(|raw| raw.to_vec())
    else {
        return Ok(());
    };
    match peer {
        PeerMachine::Proven { machine, .. }
            if askers.chunks(16).any(|asker| asker == machine.as_bytes()) =>
        {
            vault.store.sync_state.put(wtxn, &key, machine.as_bytes())?;
        }
        _ => {
            vault.store.sync_state.delete(wtxn, &key)?;
        }
    }
    Ok(())
}

/// Records that the machine `peer` proved asks for a replacement of `window`:
/// it holds an update of the window whose base it lacks. Refused as
/// [`shelve_sealed_window`] refuses the sender and world. A replacement of the
/// window another machine shelves answers the ask.
///
/// # Errors
///
/// A refused machine or world; storage errors.
pub fn want_sealed_replacement(vault: &Vault, peer: PeerMachine, window: &WindowKey) -> Result<()> {
    admit_sender(vault, peer, window)?;
    let PeerMachine::Proven { machine, .. } = peer else {
        return Err(denied());
    };
    let key = want_key(window);
    vault.with_write_txn_grouped(|wtxn| {
        let mut askers = vault
            .store
            .sync_state
            .get(wtxn, &key)?
            .map(|raw| raw.to_vec())
            .filter(|raw| raw.len() % 16 == 0)
            .unwrap_or_default();
        if !askers.chunks(16).any(|asker| asker == machine.as_bytes()) {
            askers.extend_from_slice(machine.as_bytes());
            vault.store.sync_state.put(wtxn, &key, &askers)?;
        }
        Ok(())
    })
}

/// The windows some machine other than `peer` asked a replacement of, of the
/// worlds the machine `peer` proved may read, at most
/// [`SEALED_SHELF_PAGE_MAX`]: it puts a replacement of each it seals.
///
/// # Errors
///
/// An unproved peer; storage errors.
pub fn wanted_sealed_replacements(vault: &Vault, peer: PeerMachine) -> Result<Vec<WindowKey>> {
    let withheld = peer_withheld(vault, peer)?;
    let PeerMachine::Proven { machine, .. } = peer else {
        return Err(denied());
    };
    let txn = vault.store.env.read_txn()?;
    let mut wanted = Vec::new();
    for row in vault.store.sync_state.prefix_iter(&txn, WANT_PREFIX)? {
        let (key, askers) = row?;
        let Some(window) = WindowKey::try_new(&key[WANT_PREFIX.len()..]) else {
            continue;
        };
        if window
            .world()
            .is_some_and(|world| !withheld.contains(&world))
            && askers.chunks(16).any(|asker| asker != machine.as_bytes())
        {
            wanted.push(window);
            if wanted.len() == SEALED_SHELF_PAGE_MAX {
                break;
            }
        }
    }
    Ok(wanted)
}
