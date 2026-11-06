//! A NOTE authority's pending forks, carried to the owner's own devices on
//! the owner document lane (FIX 12789; ARCH-0032 sync and disclosure: an own
//! device receives a NOTE's edits, forks and head moves as document frames).
//!
//! The authority sends each pending fork it holds outside a bundle as one
//! [`document_sub_tags::NOTE_FORK_STATE`] frame, its record and its document,
//! then one [`document_sub_tags::NOTE_FORK_SET`] frame naming them all. It
//! sends them when a device subscribes to the NOTE and when its forks change
//! (a fork made or uploaded here, a decision, a bundle opened), never on an
//! ordinary edit. The frames ride the same owner lane, owner gate and
//! per-machine release as the NOTE's own text.
//!
//! A device installs each fork as the authority's, marking it, and the set
//! settles the marked ones: a marked fork the set no longer names was
//! decided, bundled or erased at the authority and goes here too. A fork
//! this device made carries no mark, so the set never takes it; once the
//! authority sends it back, it is the authority's like any other.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::documents::{NOTE_HEAD_DOC, NOTE_PROPOSAL_DOC, head_in, invalid};
use super::proposals::{NOTE_FORK, NoteFork};
use super::side_keys::HexPair;
use super::sync_rows::{NOTE_FORK_AUTHORITY, SYNC_DS_E, SYNC_QN_E};
use crate::side_table::HexId;
use crate::sync::transport::{document_sub_tags, encode_document};
use crate::{EntityId, Result, Vault};

/// The pending forks a NOTE's authority holds, as a set frame names them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteForkSet {
    forks: Vec<String>,
}

/// `[record length: u32 BE][record JSON][fork document]`.
fn encode_fork_state(fork: &NoteFork, document: &[u8]) -> Result<Vec<u8>> {
    let record = serde_json::to_vec(fork).map_err(|_| invalid("NOTE fork state"))?;
    let len = u32::try_from(record.len()).map_err(|_| invalid("NOTE fork state"))?;
    Ok([len.to_be_bytes().as_slice(), &record, document].concat())
}

fn decode_fork_state(payload: &[u8]) -> Result<(NoteFork, &[u8])> {
    let (len, rest) = payload
        .split_first_chunk::<4>()
        .ok_or(invalid("NOTE fork state"))?;
    let (record, document) = rest
        .split_at_checked(u32::from_be_bytes(*len) as usize)
        .ok_or(invalid("NOTE fork state"))?;
    let fork: NoteFork = serde_json::from_slice(record).map_err(|_| invalid("NOTE fork state"))?;
    Ok((fork, document))
}

/// The frames that carry `note`'s pending forks from this authority to an
/// own device: each fork's state, then the set. None from a replica, which
/// is no authority, and none for a row that is not a NOTE. A fork that cites
/// a source in one of the `withheld` worlds kept off that device is neither
/// sent nor named, so the device drops a copy it was sent before; so is a
/// fork whose document does not read.
///
/// # Errors
///
/// Storage errors, or a fork row that cannot be read.
pub(crate) fn authority_fork_frames_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    withheld: &BTreeSet<EntityId>,
) -> Result<Vec<Vec<u8>>> {
    if vault.get_entity_type_in_txn(txn, &note)? != Some(crate::registry::ENTITY_TYPE_NOTE)
        || SYNC_DS_E.contains(&vault.store, txn, &HexId(note))?
    {
        return Ok(Vec::new());
    }
    let mut frames = Vec::new();
    let mut set = Vec::new();
    let prefix = format!("{}:", note.to_hex());
    for (key, document) in NOTE_PROPOSAL_DOC.scan_from(&vault.store, txn, prefix.as_bytes())? {
        let id = (key.1).0;
        let Some(fork) = NOTE_FORK.get(&vault.store, txn, &id)? else {
            continue;
        };
        if fork.note != note || fork.fork != id || fork.decided || fork.proposal.is_some() {
            continue;
        }
        match cites_withheld(vault, txn, note, &document, withheld) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(error) => {
                tracing::warn!(%error, fork = %id.to_hex(), "a NOTE fork does not read");
                continue;
            }
        }
        set.push(id.to_hex());
        // A fork past the document frame stays named in the set, so a device
        // keeps the copy it holds.
        match encode_fork_state(&fork, &document).and_then(|payload| {
            encode_document(note, document_sub_tags::NOTE_FORK_STATE, &payload)
                .into_result()
                .map_err(|_| invalid("NOTE fork exceeds the document frame"))
        }) {
            Ok(frame) => frames.push(frame),
            Err(error) => {
                tracing::warn!(%error, fork = %id.to_hex(), "a NOTE fork was not sent to a device");
            }
        }
    }
    let set =
        serde_json::to_vec(&NoteForkSet { forks: set }).map_err(|_| invalid("NOTE fork set"))?;
    frames.push(
        encode_document(note, document_sub_tags::NOTE_FORK_SET, &set)
            .into_result()
            .map_err(|_| invalid("NOTE fork set exceeds the document frame"))?,
    );
    Ok(frames)
}

/// Whether the fork state frame `payload` of `note` carries a fork that cites
/// a claim or a source in one of the `withheld` worlds, read at the final
/// release door. A payload that does not read is an error, and the door
/// withholds it.
///
/// # Errors
///
/// A payload that does not read, and storage errors.
pub(crate) fn fork_state_cites_withheld(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    payload: &[u8],
    withheld: &BTreeSet<EntityId>,
) -> Result<bool> {
    let (_, document) = decode_fork_state(payload)?;
    cites_withheld(vault, txn, note, document, withheld)
}

/// Whether the fork document `document` of `note` cites a claim or a source
/// in one of the `withheld` worlds, as the NOTE's own text is judged.
fn cites_withheld(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    document: &[u8],
    withheld: &BTreeSet<EntityId>,
) -> Result<bool> {
    if withheld.is_empty() {
        return Ok(false);
    }
    for pin in super::document::NoteDocument::load(note, document)?.pins()? {
        for source in [pin.document, pin.claim] {
            if crate::settings::device_only_withholds(&vault.store, txn, withheld, &source)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Whether this vault holds `note` on the owner lane: an own device's
/// subscription row, which names no selector.
fn owner_replica(vault: &Vault, txn: &heed::RoTxn<'_>, note: EntityId) -> Result<bool> {
    Ok(SYNC_DS_E
        .get(&vault.store, txn, &HexId(note))?
        .is_some_and(|selector| selector.is_empty()))
}

/// Installs on this replica the pending fork of `note` its authority sent
/// in `payload`, as the authority's: its record, its document and its mark,
/// in one write. A queued upload of the same fork has nothing left to send.
///
/// # Errors
///
/// A frame for a NOTE this vault does not hold on the owner lane, or one
/// that was erased here; a record that is not a pending fork of `note`
/// outside a bundle, or names a head of it; a document that does not read
/// or cites an erased record; and storage errors.
pub(crate) fn install_authority_fork(vault: &Vault, note: EntityId, payload: &[u8]) -> Result<()> {
    let (fork, document) = decode_fork_state(payload)?;
    vault.with_write_txn_grouped(|txn| {
        if !owner_replica(vault, txn, note)? {
            return Err(invalid("unsolicited NOTE fork state"));
        }
        if vault.local_hard_delete_marker_exists_in_txn(txn, &note)? {
            return Err(invalid("NOTE was erased"));
        }
        if fork.note != note || fork.fork == note || fork.decided || fork.proposal.is_some() {
            return Err(invalid("NOTE fork state"));
        }
        if fork.fork == head_in(&vault.store, txn, note)?.0
            || NOTE_HEAD_DOC.contains(&vault.store, txn, &(note, fork.fork))?
        {
            return Err(invalid("NOTE fork state names a head"));
        }
        // An opener erased here keeps its pending fork gone, however late
        // the authority's copy arrives.
        let Some(fork) = fork.clone().carried_here(vault, txn)? else {
            return Ok(());
        };
        let doc = super::document::NoteDocument::load(note, document)?;
        super::citation_erase::validate_pins(vault, txn, &doc.pins()?)?;
        let key = HexPair(HexId(note), HexId(fork.fork));
        let digest = blake3::hash(document).as_bytes().to_vec();
        if NOTE_FORK_AUTHORITY.get(&vault.store, txn, &key)?.as_ref() == Some(&digest)
            && NOTE_FORK.get(&vault.store, txn, &fork.fork)?.as_ref() == Some(&fork)
        {
            return Ok(());
        }
        // The stamp tokens the document names keep their claims (FIX 11965).
        super::token_uses::record_token_uses_in_txn(vault, txn, note, &doc.doc, None)?;
        NOTE_FORK.put(&vault.store, txn, &fork.fork, &fork)?;
        NOTE_PROPOSAL_DOC.put(&vault.store, txn, &key, &document.to_vec())?;
        NOTE_FORK_AUTHORITY.put(&vault.store, txn, &key, &digest)?;
        SYNC_QN_E.delete(&vault.store, txn, &key)?;
        Ok(())
    })
}

/// Settles this replica's forks of `note` its authority sent against the
/// set it sent in `payload`: each marked fork the set no longer names goes,
/// its record, document and mark. A fork made here, unmarked, stays.
///
/// # Errors
///
/// A frame for a NOTE this vault does not hold on the owner lane, a set
/// that does not read, and storage errors.
pub(crate) fn settle_authority_forks(vault: &Vault, note: EntityId, payload: &[u8]) -> Result<()> {
    let set: NoteForkSet = serde_json::from_slice(payload).map_err(|_| invalid("NOTE fork set"))?;
    let mut held = BTreeSet::new();
    for fork in &set.forks {
        held.insert(EntityId::from_hex(fork).map_err(|_| invalid("NOTE fork set"))?);
    }
    vault.with_write_txn_grouped(|txn| {
        if !owner_replica(vault, txn, note)? {
            return Err(invalid("unsolicited NOTE fork set"));
        }
        let prefix = format!("{}:", note.to_hex());
        for key in NOTE_FORK_AUTHORITY.scan_keys(&vault.store, txn, prefix.as_bytes())? {
            let fork = (key.1).0;
            if held.contains(&fork) {
                continue;
            }
            NOTE_FORK_AUTHORITY.delete(&vault.store, txn, &key)?;
            NOTE_PROPOSAL_DOC.delete(&vault.store, txn, &key)?;
            if NOTE_FORK
                .get(&vault.store, txn, &fork)?
                .is_some_and(|row| row.note == note)
            {
                NOTE_FORK.delete(&vault.store, txn, &fork)?;
            }
        }
        Ok(())
    })
}
