//! The training reservoir's input rows for the role-training door tests
//! (ROLE-TRAINING-RUN). A proposal the owner rewrote is finalized through
//! ED-00's own artifact, then marked amended under the reservoir's
//! eligibility key. No production writer marks that key yet (FIX
//! RESERVOIR-NO-PRODUCER), so the mark goes through the delta store's own
//! door here. It writes inputs only: no run, approval or result.

use crate::WriteActor;
use crate::edit_distance::delta::put_amendment_uncaptured_in_txn;
use crate::edit_distance::proposal_text::ProposalTextArtifact;
use crate::edit_distance::register_peer_actor;
use crate::edit_distance::reservoir::amendment_receipt_id;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// Finalizes one proposal holding `proposed` that `editor`, a human, rewrote
/// to `final_text`, marks it amended under the reservoir's key, and returns
/// the artifact's id. Its reservoir receipt is
/// [`amendment_receipt_id`] of that id.
pub fn keep_amended_pair(
    vault: &Vault,
    editor: &WriteActor,
    proposed: &str,
    final_text: &str,
) -> Result<EntityId> {
    let mut artifact = ProposalTextArtifact::open(vault, proposed, editor, None)?;
    register_peer_actor(vault, artifact.peer_id(), editor)?;
    artifact.edit_as(vault, editor, |text| {
        text.delete(0, text.len_unicode())
            .map_err(|_| Error::InvariantViolation("fixture proposal delete"))?;
        text.insert(0, final_text)
            .map_err(|_| Error::InvariantViolation("fixture proposal insert"))
    })?;
    let record = artifact.finalize(vault)?;
    let id = record.artifact_ref.entity_id();
    vault.with_write_txn(|wtxn| {
        put_amendment_uncaptured_in_txn(vault, wtxn, &amendment_receipt_id(id))?;
        Ok(())
    })?;
    Ok(id)
}
