use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::secret_custody::{SecretPurposeQuestion, purpose_questions_in_txn};
use crate::{EntityId, Vault};

impl Vault {
    /// Pending purpose questions for this actual Clipboard record, under one
    /// owner-checked snapshot. No secret value or clipboard text is returned.
    /// Known text substitutions file no new found-key note, so repeated copies
    /// of a known key do not raise another question.
    pub fn clipboard_secret_purpose_questions_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        clip: EntityId,
    ) -> Result<Vec<SecretPurposeQuestion>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let world = super::clipboard_world_id()?;
        if !self.clipboard_world_exists_in_txn(&txn, world)?
            || self.clipboard_claim_raw_in_txn(&txn, clip)?.is_none()
        {
            return Ok(Vec::new());
        }
        purpose_questions_in_txn(self, &txn, &clip)
    }
}
