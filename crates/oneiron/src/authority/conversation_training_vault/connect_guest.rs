//! A Connect guest's two reads of conversation learning (FIX 5538; L02
//! 04:5x): the vault's setting and its own opt-out, on its own live
//! grant-bound slip. A guest carries no person credential, so neither of the
//! person doors takes it; these take the slip, and read the guest's
//! standing in their own transaction each time, so a revoked guest stops
//! reading on its next request. Neither shows another person's opt-out, and
//! neither writes: the setting stays the admin's.

use super::{ConversationLearningView, NOT_READER};
use crate::Vault;
use crate::authority::{VerifiedSlip, authority_refused};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The Connect guest `proof` proves here, read in `txn`: the holder of its
/// own untransferred slip, live now, whose Connect grant stands for it, and
/// who stands as a live Connect guest. `None` for any other proof.
fn connect_guest_of_slip_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proof: &VerifiedSlip,
) -> Result<Option<EntityId>> {
    let claims = proof.claims();
    let (Some(grant), Ok(guest)) = (
        claims
            .grant_ref
            .as_deref()
            .and_then(|grant| EntityId::from_hex(grant).ok()),
        EntityId::from_hex(&claims.holder_ref),
    ) else {
        return Ok(None);
    };
    if proof.is_transferred()
        || !vault.capability_slip_is_live_in_txn(txn, proof)?
        || !crate::federation::connect_grant_stands_in_txn(vault, txn, &grant, &guest)?
        || !crate::federation::connect_guest_standing_in_txn(vault, txn, guest)?
    {
        return Ok(None);
    }
    Ok(Some(guest))
}

impl Vault {
    /// The vault's setting, for a Connect guest on its own live grant-bound
    /// slip: what [`Self::conversation_learning_view`] answers a member.
    ///
    /// # Errors
    /// A refusal when the slip is no longer a live Connect guest's here;
    /// storage faults, and history this vault lacks, as the fold reads them.
    pub fn conversation_learning_view_for_connect_guest(
        &self,
        proof: &VerifiedSlip,
    ) -> Result<ConversationLearningView> {
        let txn = self.store.env.read_txn()?;
        let guest = connect_guest_of_slip_in_txn(self, &txn, proof)?
            .ok_or_else(|| authority_refused(NOT_READER))?;
        if !self.conversation_learning_reader_in_txn(&txn, guest)? {
            return Err(authority_refused(NOT_READER));
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        self.setting_view_in_txn(&txn, &fold)
    }

    /// The Connect guest's own opt-out, on its own live grant-bound slip:
    /// what [`Self::conversation_training_view`] answers a person, for the
    /// slip's holder alone.
    ///
    /// # Errors
    /// A refusal when the slip is no longer a live Connect guest's here;
    /// storage faults, and history this vault lacks, as the fold reads them.
    pub fn conversation_training_view_for_connect_guest(
        &self,
        proof: &VerifiedSlip,
    ) -> Result<crate::authority::ConversationTrainingView> {
        let txn = self.store.env.read_txn()?;
        let guest = connect_guest_of_slip_in_txn(self, &txn, proof)?
            .ok_or_else(|| authority_refused(NOT_READER))?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(crate::authority::conversation_training::opt_out_view(
            &fold, guest,
        ))
    }
}
