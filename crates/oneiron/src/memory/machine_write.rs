//! Machine-author claim stamping after the facade resolves its final approval.
use super::*;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::write_envelope::{ClaimCandidate, MachineWriteSignature, WriteEnvelope};

impl Memory<'_> {
    pub(super) fn sign_machine_claim_in_txn(
        &self,
        wtxn: &heed::RoTxn<'_>,
        id: EntityId,
        candidate: &ClaimCandidate,
        envelope: &mut WriteEnvelope,
    ) -> crate::Result<()> {
        let Some((public_key, sign)) = self.machine_signer else {
            return Ok(());
        };
        let fold = self.vault.authority_fold_readonly_in_txn(wtxn)?;
        let vault_id = fold.vault_id.ok_or(Error::InvalidClaimBody(
            "machine signing requires a rooted vault",
        ))?;
        let body = candidate
            .clone()
            .into_claim_body(envelope, self.vault.default_facet_in_txn(wtxn)?);
        let transcript = crate::authority::machine_claim_transcript(&vault_id, &id, &body)?;
        *envelope = envelope
            .clone()
            .with_machine_signature(MachineWriteSignature {
                public_key,
                signature: sign(&transcript)?,
            });
        Ok(())
    }
}
