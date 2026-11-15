//! Lost-owner authority recovery from material explicitly enrolled before loss.

use super::*;
use crate::store::recovery_kit::RestoredKitSecret;
use crate::world_keys::RecoveryAuthoritySigner;
use crate::{Result, Vault};

/// On a hosted vault a ReRoot revokes the custodial root, and every slip the
/// host minted stops verifying; while the roster holds a live owner key the
/// root's door serves with the two ordinary ops instead (Engine NOTE 15 Nov
/// 22:10; WAYBACK-E2 = A). Nothing was written.
const HOSTED_FOLD_REROOT: &str = "a ReRoot on a hosted vault ends the host's service while the \
                                  roster holds a live owner key; recover with the root's door, \
                                  which enrols the new key and revokes the lost ones; nothing \
                                  was written";

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
    ///
    /// It is a self-hosted vault's door, for a lost host root. On a hosted
    /// fold it refuses while the roster holds a live owner key, the custodial
    /// root included: [`Vault::recover_owner_root`] serves there with the
    /// two ordinary ops, and the host's service stands (pass 27 R4).
    pub fn recover_owner_authority_from_kit(
        &self,
        secret: RestoredKitSecret,
        new_device: DeviceAuthority,
    ) -> Result<AuthorityLogEntry> {
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        if self.hosted_fold(&fold)
            && fold
                .roster
                .values()
                .any(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
        {
            return Err(authority_refused(HOSTED_FOLD_REROOT));
        }
        let signer = RecoveryAuthoritySigner::from_restored_kit(secret, &vault_id)?;
        let sign = |transcript: &[u8]| signer.sign_authority_transcript(transcript);
        let signer_key = signer.authority_key();
        let (entry, rows) = self.re_root_authority_in_txn(
            &mut txn,
            new_device,
            (
                &signer_key,
                Some(FrontierSigner::Callback(&signer_key, &sign)),
            ),
            &sign,
        )?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(entry)
    }

    /// Whether `fold` is a hosted vault's: this install folds it under the
    /// hosted posture, or its roster names a provider's key (`ROLE_CLOUD` or
    /// the `CloudCustodial` tier), as a device's replica of a hosted vault
    /// or a stopped hosted vault opened under another posture does.
    fn hosted_fold(&self, fold: &AuthorityFold) -> bool {
        self.privacy_posture() == crate::HostingPrivacyPosture::Hosted
            || fold.roster.values().any(|device| {
                device.roles & ROLE_CLOUD != 0 || device.tier == AuthorityTier::CloudCustodial
            })
    }
}
