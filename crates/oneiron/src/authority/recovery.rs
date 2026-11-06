//! Lost-owner authority recovery from material explicitly enrolled before loss.

use super::*;
use crate::store::recovery_kit::RestoredKitSecret;
use crate::world_keys::RecoveryAuthoritySigner;
use crate::{Result, Vault};

impl Vault {
    /// Rebuild the kit's distinct authority key for this vault and hand its
    /// authority to `new_device`. The key must have been explicitly enrolled
    /// before loss and still stand under the ordinary authority fold.
    ///
    /// No current owner proof, old host secret, current kit pin or world-key
    /// restoration grants authority here. The existing ReRoot path checks the
    /// live signer and fresh successor, joins its frontier and counts the move.
    /// All of that, including the vault identity used for derivation, shares one
    /// write transaction. An error commits no recovery or frontier join.
    pub fn recover_owner_authority_from_kit(
        &self,
        secret: RestoredKitSecret,
        new_device: DeviceAuthority,
    ) -> Result<AuthorityLogEntry> {
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let signer = RecoveryAuthoritySigner::from_restored_kit(secret, &vault_id)?;
        let sign = |transcript: &[u8]| signer.sign_authority_transcript(transcript);
        let entry = self.re_root_authority_in_txn(
            &mut txn,
            new_device,
            (
                signer.authority_key(),
                Some(FrontierSigner::Callback(signer.public_key(), &sign)),
            ),
            &sign,
        )?;
        txn.commit()?;
        Ok(entry)
    }
}
