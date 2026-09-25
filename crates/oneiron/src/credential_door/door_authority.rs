//! Checkout witnesses and consent admission under the committing writer.

use super::door_types::{DoorResult, log_unreachable};
use super::{CredentialDoorService, DoorCredential};
use crate::secret_lease::VaultInstant;

impl CredentialDoorService {
    pub(super) fn witness_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        credential: &DoorCredential,
    ) -> DoorResult<()> {
        use super::door_credential::DoorGrant;
        match &credential.grant {
            DoorGrant::Checkout { ticket, .. } => {
                self.witness_checkout_in_txn(txn, credential, ticket)
            }
            #[cfg(test)]
            DoorGrant::Witnessed(_) => Ok(()),
        }
    }

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
        self.evaluate_with_consent_in_txn(&mut txn, credential, verb, record, channel, now)?;
        txn.commit().map_err(log_unreachable)
    }
}
