//! Destination policy for text-plane admission and release. Machine standing
//! and world settings are read in the caller's transaction, not a subscription.

use crate::authority::{PeerMachine, WorldPrivacyView};
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::sync::transport::document_sub_tags;
use crate::{EntityId, Vault};

/// Refuse a document a peer's physical machine may not read, even when its
/// actor has a grant. The writer calls this before appending any peer edit.
pub fn admit_document_destination_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    peer: PeerMachine,
) -> Result<()> {
    if text_withheld_for_peer(vault, txn, id, peer)? {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::DocumentAdmissionDenied,
        ));
    }
    Ok(())
}

pub(crate) fn text_withheld(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<bool> {
    text_withheld_for_peer(vault, txn, id, PeerMachine::Unknown)
}

fn text_withheld_for_peer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    peer: PeerMachine,
) -> Result<bool> {
    let flagged = WorldPrivacyView::load_in(vault, txn)?.withheld_for_peer(peer)?;
    if crate::settings::device_only_withholds(&vault.store, txn, &flagged, &id)? {
        return Ok(true);
    }
    if vault.get_entity_type_in_txn(txn, &id)? == Some(crate::registry::ENTITY_TYPE_NOTE)
        && crate::note::text_withheld_by_worlds(vault, txn, id, &flagged)?
    {
        return Ok(true);
    }
    Ok(!crate::sync::selector::document_sources_readable_in_txn(
        vault, txn, id, &flagged,
    )?)
}

/// An unproven transport is an unknown destination, never an owned machine.
pub fn document_frame_withheld(vault: &Vault, frame: &[u8]) -> bool {
    document_frame_withheld_for_peer(vault, frame, PeerMachine::Unknown)
}

/// Recheck immediately before release. Requests and ACKs carry no text;
/// every state, update, operation and receipt is subject to the same policy.
pub fn document_frame_withheld_for_peer(vault: &Vault, frame: &[u8], peer: PeerMachine) -> bool {
    if frame.first() != Some(&crate::sync::transport::TAG_DOCUMENT) {
        return false;
    }
    let Ok(document) = crate::sync::transport::decode_document(&frame[1..]) else {
        return true;
    };
    if matches!(
        document.kind,
        document_sub_tags::REQUEST | document_sub_tags::ACK
    ) {
        return false;
    }
    (|| -> Result<bool> {
        let _accepting = vault.device_only_acceptance();
        let txn = vault.store.env.read_txn()?;
        text_withheld_for_peer(vault, &txn, document.entity, peer)
    })()
    .unwrap_or(true)
}
