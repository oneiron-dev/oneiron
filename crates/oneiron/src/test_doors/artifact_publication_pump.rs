//! A synchronous device-to-server artifact publication pump for the FIX 295
//! unpublish test: the outbox pull the sync socket runs, without the socket.

use crate::artifact_hosting::{
    ArtifactPublicationCursor, ArtifactPublicationOutcome, ArtifactPublicationStep,
};
use crate::error::{Error, Result};
use crate::store::document_frame_tags::document_sub_tags;
use crate::sync::transport::decode_document;
use crate::{EntityId, Vault};

/// Pumps every publication the device's outbox owes to the server, in outbox
/// order, feeding each complete receipt back to the device, until the outbox
/// is quiet. The credential is always live, and nothing goes twice: a
/// `Staged` receipt stays owed but ends the pump, so the caller sees it in
/// the returned outcomes. Returns one (publication, outcome) per receipt the
/// server answered.
pub fn pump_artifact_publications(
    device: &Vault,
    server: &Vault,
) -> Result<Vec<(EntityId, ArtifactPublicationOutcome)>> {
    let mut cursor = ArtifactPublicationCursor::default();
    let mut outcomes = Vec::new();
    loop {
        match device.next_artifact_publication_step(&mut cursor, &|_: &[u8; 32]| false)? {
            ArtifactPublicationStep::Ready(part) => {
                let frame = decode_document(part.frame.get(1..).ok_or(
                    Error::InvariantViolation("artifact publication part frame"),
                )?)
                .map_err(|_| Error::InvariantViolation("artifact publication part frame"))?;
                if frame.kind != document_sub_tags::ARTIFACT_PUBLICATION {
                    return Err(Error::InvariantViolation("artifact publication part kind"));
                }
                cursor.released(&part, true);
                let receipt = server.import_artifact_publication(
                    frame.entity,
                    frame.payload,
                    |_: &heed::RwTxn<'_>| true,
                )?;
                let Some(receipt) = receipt else { continue };
                let receipt = decode_document(receipt.get(1..).ok_or(
                    Error::InvariantViolation("artifact publication receipt frame"),
                )?)
                .map_err(|_| Error::InvariantViolation("artifact publication receipt frame"))?;
                if receipt.kind != document_sub_tags::ARTIFACT_RECEIPT {
                    return Err(Error::InvariantViolation("artifact publication receipt kind"));
                }
                let outcome =
                    device.accept_artifact_publication_receipt(receipt.entity, receipt.payload)?;
                outcomes.push((receipt.entity, outcome));
            }
            ArtifactPublicationStep::ItemError { error, .. } => return Err(error),
            ArtifactPublicationStep::Idle => return Ok(outcomes),
        }
    }
}
