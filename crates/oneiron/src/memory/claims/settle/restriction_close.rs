//! A settlement by no person never lifts a restriction (RULING
//! RESTRICTION-HOLDER-SETTLE = A; RESTRICTION-CLOSE-BY-CURATOR-APPROVAL;
//! HANDED-ON-SLIP-PERSON Q1 = A). A handle acts as no person when its class
//! is not Human, or when the credential it presented was handed on to
//! another key ([`Memory::acts_as_own_person`]). The owner's proof answers
//! for the owner, never for the key that holds his handed-on slip, so the
//! owner doors that settle a proposal ask this too: `vault.claims.settle` on
//! both its arms, a restore group's members, and a run review's members.

use super::*;

/// Whether settling the open proposal `id`, whose body is `body`, by `action`
/// in place, superseding no head, closes a claim that restricts someone's
/// access ([`crate::federation::claim_removal_widens_in`]): a decline closes
/// the proposal itself (a Proposed `comm.do_not_contact` already restricts),
/// except a parked retract's decline (`parked_retract`), which closes
/// nothing; an approval completes the action parked on the claim, and an
/// approved curator finding applies its rung to its target.
pub(super) fn settle_in_place_lifts_restriction_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    parked_retract: bool,
    action: GateConsentBundleAction,
) -> crate::Result<bool> {
    match action {
        GateConsentBundleAction::Decline => {
            Ok(!parked_retract && crate::federation::claim_removal_widens_in(vault, txn, body)?)
        }
        GateConsentBundleAction::Approve => {
            if crate::dreamer_runner::maintenance::curator_finding_lifts_restriction_in(
                vault, txn, body,
            )? {
                return Ok(true);
            }
            vault.deferred_close_lifts_restriction_in_txn(txn, id, body)
        }
    }
}

/// The refusal of a settler that acts as no person, on a settlement that
/// closes a claim restricting someone's access. The proposal stays open for
/// a person who holds a covering Grant, or for the owner on his own
/// credential.
pub(super) fn restriction_close_needs_a_person(actor: WriteActor) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{} ({}) acts as no person here (an agent, or a person's slip handed on to another \
             key), so it may not settle a proposal whose settlement closes a claim that \
             restricts someone's access: a widening always asks a person",
            actor.entity_ref().to_hex(),
            actor.actor_class().gate_actor_class(),
        ),
        &[
            "The proposal stays open: a person who holds a covering review Grant, or the vault \
             owner, settles it on their own credential.",
        ],
    )
}

impl Memory<'_> {
    /// Refuses, when this handle acts as no person, a settlement of the open
    /// proposal `id` by `action` in place, superseding no head, that closes a
    /// claim restricting someone's access. A run review settles each claim
    /// member in place, so it asks this before each one.
    ///
    /// # Errors
    ///
    /// `FORBIDDEN` for such a settlement by no person; a store failure.
    pub(in crate::memory) fn require_person_for_restriction_close_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        action: GateConsentBundleAction,
        actor: WriteActor,
    ) -> MemoryResult<()> {
        if self.acts_as_own_person() {
            return Ok(());
        }
        let Some(body) = self.vault.get_claim_in_txn(txn, id)? else {
            return Ok(());
        };
        let parked_retract = body.lifecycle == ClaimLifecycleStatus::Active
            && self.vault.claim_retract_is_parked_in_txn(txn, id)?;
        if settle_in_place_lifts_restriction_in(self.vault, txn, id, &body, parked_retract, action)?
        {
            return Err(restriction_close_needs_a_person(actor));
        }
        Ok(())
    }
}
