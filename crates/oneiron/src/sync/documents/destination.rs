//! Destination policy for text-plane admission and release. Machine standing
//! and world settings are read in the caller's transaction, not a subscription.

use crate::authority::PeerMachine;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::sync::transport::document_sub_tags;
use crate::sync::window::Withhold;
use crate::{EntityId, Vault};

/// Refuse a document a peer's physical machine may not read, even when its
/// actor has a grant. The writer calls this before appending any peer edit.
pub fn admit_document_destination_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    peer: PeerMachine,
) -> Result<()> {
    admit_document_withhold_in_txn(vault, txn, id, Withhold::Peer(peer))
}

pub(super) fn admit_document_withhold_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    withhold: Withhold<'_>,
) -> Result<()> {
    if text_withheld_for(vault, txn, id, withhold)? {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::DocumentAdmissionDenied,
        ));
    }
    Ok(())
}

pub(crate) fn text_withheld(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<bool> {
    text_withheld_for(vault, txn, id, Withhold::Unknown)
}

fn text_withheld_for(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    withhold: Withhold<'_>,
) -> Result<bool> {
    let flagged = withhold.worlds_in(vault, txn)?;
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
    document_frame_withheld_for(vault, PeerMachine::Unknown, frame)
}

/// Recheck immediately before release. Requests, ACKs and a publication's
/// Refused receipt carry no text; every state, update, operation and other
/// receipt is subject to the same policy. A marked repo source's own frames
/// never leave (FIX 10872): sync is masked even to owner devices (FIX
/// 7608), so its text crosses only as its copy lineage, under its copy id,
/// judged as its source.
pub fn document_frame_withheld_for(vault: &Vault, peer: PeerMachine, frame: &[u8]) -> bool {
    if frame.first() != Some(&crate::sync::transport::TAG_DOCUMENT) {
        return false;
    }
    let Ok(document) = crate::sync::transport::decode_unsplit_document(&frame[1..]) else {
        return true;
    };
    if matches!(
        document.kind,
        document_sub_tags::REQUEST | document_sub_tags::ACK
    ) || (document.kind == document_sub_tags::ARTIFACT_RECEIPT
        && matches!(
            crate::artifact_hosting::ArtifactPublicationOutcome::from_receipt(document.payload),
            Some(crate::artifact_hosting::ArtifactPublicationOutcome::Refused)
        ))
    {
        return false;
    }
    if document.kind == document_sub_tags::WAITED_OUT {
        return crate::sync::transport::decode_document_waited_out(document.payload).is_err();
    }
    (|| -> Result<bool> {
        let _accepting = vault.device_only_acceptance();
        let txn = vault.store.env.read_txn()?;
        if marked_source_in_txn(vault, &txn, document.entity)? {
            return Ok(true);
        }
        // A copy stream's frame is judged as the marked source it stands
        // for: that source's worlds and sources (FIX 10872).
        let id = super::copy::judged_id_in_txn(vault, &txn, document.entity)?;
        if text_withheld_for(vault, &txn, id, Withhold::Peer(peer))? {
            return Ok(true);
        }
        // A NOTE fork's state carries the fork's own text: its citations are
        // judged again here against the worlds kept off this machine now,
        // however long the frame waited in the queue (FIX 12789).
        if document.kind == document_sub_tags::NOTE_FORK_STATE {
            let withheld = Withhold::Peer(peer).worlds_in(vault, &txn)?;
            return crate::note::fork_state_cites_withheld(
                vault,
                &txn,
                document.entity,
                document.payload,
                &withheld,
            );
        }
        Ok(false)
    })()
    .unwrap_or(true)
}

/// Whether `id` is a marked repo source here: a snapshot ASSET whose blob a
/// secret mark names (FIX 10872). Its frames carry the raw source's own
/// operations, which no peer may receive; a mark that does not decode keeps
/// its blob marked, and a read that fails withholds.
fn marked_source_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<bool> {
    if vault.get_entity_type_in_txn(txn, &id)? != Some(crate::registry::ENTITY_TYPE_ASSET) {
        return Ok(false);
    }
    Ok(
        crate::origin::secret_projection::index::RepoIndexMarks::read_scoped_in_txn(vault, txn)?
            .source_of(&id)
            .is_some(),
    )
}
