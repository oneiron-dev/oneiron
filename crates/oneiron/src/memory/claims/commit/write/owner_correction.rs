//! The owner's direct correction of their own claim (FIX 22041): a
//! replacement the vault's owner writes in person over a claim that owner
//! authored lands at once, as the owner's fresh write would, and closes the
//! prior head in the same write, with a receipt (DEC-0006 row 10; ARCH-0003
//! change policy). A claim of the owner's own agent closes the same way, as
//! the owner's ruling (OWNER-SUPERSEDES-OWN-AGENT-CLAIM, the lead's ruling B,
//! 13 Nov), and its receipt names the agent. Every other replacement stays a
//! create-versus-closure proposal.

use super::resolve::ClaimWrite;
use super::*;

/// Whose landed claim an owner's direct correction closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OwnerCorrection {
    /// The owner's own claim (FIX 22041).
    OwnClaim,
    /// A claim the owner's own agent authored: the owner's ruling over it,
    /// with that author kept for the receipt.
    OwnAgentClaim(WriteActor),
}

impl OwnerCorrection {
    /// The prior's author the receipt names as ruled over, if not the owner.
    pub(super) fn ruled_author(self) -> Option<WriteActor> {
        match self {
            Self::OwnClaim => None,
            Self::OwnAgentClaim(author) => Some(author),
        }
    }
}

impl Memory<'_> {
    /// Whether `write`, under `envelope`, is its owner's direct correction.
    /// All of these hold: it replaces a prior head; it requests Auto, so it
    /// would land at once on its own (a seed, a held retry and a source that
    /// asks review request Proposed); this surface writes for no one else (no
    /// host origin, no machine signer), so no agent, daemon or extractor
    /// acting for the owner qualifies; the envelope's actor is this surface's
    /// own human actor and a live owner of the vault; the prior's
    /// authenticated author is that same person, or that person's own agent
    /// while they are the vault's root owner (`owner_agent_author_in_txn`);
    /// the prior has landed (Auto or Approved); it is no want minted beside
    /// a stated one; no action is
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
    ) -> Result<Option<OwnerCorrection>, Error> {
        let Some(old_id) = write.prior else {
            return Ok(None);
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
            return Ok(None);
        }
        let Some(old) = self.vault.get_claim_in_txn(txn, &old_id)? else {
            return Ok(None);
        };
        // Only a landed fact is corrected at once. A parked prior, such as a
        // replacement still waiting on its own closure, keeps its proposal:
        // closing it here would leave its own prior current beside this one.
        if !matches!(
            old.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) || self.vault.has_deferred_claim_in_txn(txn, &old_id)?
        {
            return Ok(None);
        }
        let author =
            crate::batch::authenticated_claim_author_in_txn(&self.vault.store, txn, &old_id, &old)?;
        let correction = match author {
            Some(author) if author.entity_ref() == actor.entity_ref() => OwnerCorrection::OwnClaim,
            Some(author)
                if super::super::authorship::owner_agent_author_in_txn(
                    self.vault, txn, actor, author,
                )? =>
            {
                OwnerCorrection::OwnAgentClaim(author)
            }
            _ => return Ok(None),
        };
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, txn)?;
        Ok((!policy.declares_predicate_critical(&old.predicate)
            && !policy.declares_predicate_critical(&write.input.predicate))
        .then_some(correction))
    }
}
