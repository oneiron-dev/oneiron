//! The owner's proof re-proved at the publication of a soft delete whose own
//! scrub committed first (FIX MEMORY-DELETE-OWNER-PROOF-NOT-REVALIDATED-AT-COMMIT,
//! review round 1 of #9608). When that delete is the owner's delete of their
//! own PERSON, its scrub left the PERSON a deleted shell, which no person
//! check passes and no slip of its holder survives (RULING
//! DELETED-ACTOR-SLIP-AUTH = A). The publication then re-proves what a
//! revocation since the scrub changes, with that PERSON taken as live, as the
//! gated delete re-proves the owner deleting itself (L9-52 (b),
//! `OwnerRow::DeletingItself`).

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};

use super::{AuthenticatedOwner, host_action_lapse};

impl AuthenticatedOwner {
    /// [`Self::revalidate_in_txn`] at the publication of a delete whose own
    /// scrub of `scrubbed` committed before it.
    ///
    /// When `scrubbed` is this owner's own PERSON, every check of
    /// [`Self::revalidate_person_in_txn`] and [`Self::revalidate_in_txn`]
    /// runs as there, and only the reads of that PERSON's row read it as
    /// live: the proof is this vault's and carries no person credential; a
    /// host action still holds in full (the posture, the root, its mint
    /// signer's active binding of this owner, the owner-verb rule with
    /// [`crate::memory::OwnerRow::DeletingItself`]) except that PERSON's
    /// liveness; each slip it carried (the bound credential, the request's
    /// slip) still stands in full except its holder's deleted row; the owner
    /// key still proves the owner's acts; and the owner census, this PERSON
    /// taken as live, still names this owner
    /// ([`Vault::is_vault_owner_deleting_own_person_in_txn`]). Any other
    /// `scrubbed` re-proves through [`Self::revalidate_in_txn`], so a PERSON
    /// another request deleted is never taken as live here.
    pub(crate) fn revalidate_after_own_scrub_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        scrubbed: &EntityId,
    ) -> Result<EntityId> {
        if *scrubbed != self.actor {
            return self.revalidate_in_txn(vault, txn);
        }
        self.check_vault(vault)?;
        if self.person_credential.is_some() {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "a person credential carries no owner authority",
            )));
        }
        if let Some(action) = &self.host_action {
            action
                .holds_after_own_scrub_in(vault, txn, scrubbed)
                .map_err(host_action_lapse)?;
        }
        if let Some(credential) = self.credential.as_deref()
            && !vault.capability_slip_is_live_after_own_scrub_in_txn(txn, credential, scrubbed)?
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "owner credential is no longer live",
            )));
        }
        if let Some(key) = &self.owner_key {
            let hosted = vault.privacy_posture() == crate::HostingPrivacyPosture::Hosted;
            if !vault
                .authority_view_readonly_in_txn(txn)?
                .proves_owner_acts(key, hosted)
            {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "the owner key this owner proved with no longer proves the owner's acts",
                )));
            }
        }
        if let Some(credential) = self.request_credential.as_deref()
            && !vault.capability_slip_is_live_after_own_scrub_in_txn(txn, credential, scrubbed)?
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "request credential is no longer live",
            )));
        }
        if !vault.is_vault_owner_deleting_own_person_in_txn(txn, &self.actor)? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "authenticated actor is no longer an owner of this vault",
            )));
        }
        Ok(self.actor)
    }
}
