//! The owner's direct correction of their own claim (FIX 22041): a
//! replacement the vault's owner writes in person over a claim that owner
//! authored lands at once, as the owner's fresh write would, and closes the
//! prior head in the same write, with a receipt (DEC-0006 row 10; ARCH-0003
//! change policy). Every other replacement stays a create-versus-closure
//! proposal.

use super::resolve::ClaimWrite;
use super::*;

impl Memory<'_> {
    /// Whether `write`, under `envelope`, is its owner's direct correction.
    /// All of these hold: it replaces a prior head; it requests Auto, so it
    /// would land at once on its own (a seed, a held retry and a source that
    /// asks review request Proposed); this surface writes for no one else (no
    /// host origin, no machine signer), so no agent, daemon or extractor
    /// acting for the owner qualifies; the envelope's actor is this surface's
    /// own human actor and a live owner of the vault; the prior's
    /// authenticated author is that same person; the prior has landed (Auto
    /// or Approved); it is no want minted beside a stated one; no action is
    /// already parked on its id or on the prior's; it
    /// is no booking publication, whose owner confirms through its own door;
    /// and no manifest rule declares either predicate critical, so the
    /// critical confirmation stays where it is. The Gate still judges the
    /// write itself; a verdict that holds it resubmits it Proposed, and that
    /// retry is no correction.
    pub(super) fn owner_correction_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        write: &ClaimWrite<'_>,
        envelope: &crate::WriteEnvelope,
    ) -> Result<bool, Error> {
        let Some(old_id) = write.prior else {
            return Ok(false);
        };
        let actor = envelope.actor();
        if envelope.approval() != ClaimApprovalStatus::Auto
            || self.host_origin.is_some()
            || self.machine_signer.is_some()
            || actor.entity_ref() != self.actor
            || actor.actor_class() != EdgeActorClass::Human
            || write.beside_stated
            || write.input.predicate == crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE
            || self.vault.has_deferred_claim_in_txn(txn, &write.id)?
            || !crate::policy_model::is_live_vault_owner_in_txn(
                self.vault,
                txn,
                &actor.entity_ref(),
            )?
        {
            return Ok(false);
        }
        let Some(old) = self.vault.get_claim_in_txn(txn, &old_id)? else {
            return Ok(false);
        };
        // Only a landed fact is corrected at once. A parked prior, such as a
        // replacement still waiting on its own closure, keeps its proposal:
        // closing it here would leave its own prior current beside this one.
        if !matches!(
            old.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) || self.vault.has_deferred_claim_in_txn(txn, &old_id)?
        {
            return Ok(false);
        }
        let author =
            crate::batch::authenticated_claim_author_in_txn(&self.vault.store, txn, &old_id, &old)?;
        if author.map(WriteActor::entity_ref) != Some(actor.entity_ref()) {
            return Ok(false);
        }
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, txn)?;
        Ok(!policy.declares_predicate_critical(&old.predicate)
            && !policy.declares_predicate_critical(&write.input.predicate))
    }
}
