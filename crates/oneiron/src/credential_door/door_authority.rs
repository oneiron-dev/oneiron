//! Canonical mint witnesses, atomic spend, and one-shot mint composition.

use super::door_types::{CredentialDoorError, DoorResult, log_unreachable};
use super::{CredentialDoorService, DoorCredential};
use crate::secret_lease::VaultInstant;

#[cfg(test)]
fn check_log_available() -> DoorResult<()> {
    if super::authority_log_fault_hook::take_log_unreachable() {
        return Err(CredentialDoorError::AuthorityLogUnreachable);
    }
    Ok(())
}

impl CredentialDoorService {
    pub(super) fn witness_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        credential: &DoorCredential,
    ) -> DoorResult<()> {
        use super::door_credential::DoorGrant;
        match &credential.grant {
            DoorGrant::Capability(verified) => {
                #[cfg(test)]
                check_log_available()?;
                let fold = self
                    .vault()
                    .authority_fold_readonly_in_txn(txn)
                    .map_err(log_unreachable)?;
                let claims = verified.claims();
                if fold.vault_id != Some(claims.vault_id) || !fold.slip_is_live(&claims.slip_id) {
                    return Err(CredentialDoorError::AuthorityRejected);
                }
                claims
                    .witness_pact(&fold)
                    .map_err(|_| CredentialDoorError::AuthorityRejected)
            }
            DoorGrant::Checkout { ticket, .. } => {
                self.witness_checkout_in_txn(txn, credential, ticket)
            }
            #[cfg(test)]
            DoorGrant::Witnessed(_) => {
                if credential.is_single_use() {
                    Err(CredentialDoorError::AuthorityRejected)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Commits authority admission and any spend BEFORE an external effect.
    /// Failure after spending may burn a token; it never makes it reusable.
    pub(super) fn authorize(
        &self,
        credential: &DoorCredential,
        verb: &str,
        record: &str,
        channel: &str,
        now: VaultInstant,
    ) -> DoorResult<()> {
        let mut txn = self
            .vault()
            .store
            .env
            .write_txn()
            .map_err(log_unreachable)?;
        self.witness_in_txn(&txn, credential)?;
        if credential.capability_identity().is_some() {
            // A verified verb set is exact. Class consent cannot widen it.
            credential.evaluate(verb, record, channel, now)?;
        } else {
            self.evaluate_with_consent_in_txn(&mut txn, credential, verb, record, channel, now)?;
        }
        self.consume_single_use(&mut txn, credential)?;
        txn.commit().map_err(log_unreachable)
    }
}
