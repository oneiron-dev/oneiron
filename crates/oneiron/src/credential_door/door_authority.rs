//! Checkout witnesses and consent admission under the committing writer.

use super::door_types::{DoorResult, log_unreachable};
use super::{CredentialDoorService, DoorCredential};

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

    /// Witnesses the checkout and evaluates or spends consent under one
    /// writer, at a channel and instant the caller admitted.
    #[cfg(test)]
    pub(super) fn authorize(
        &self,
        credential: &DoorCredential,
        verb: &str,
        record: &str,
        channel: &str,
        now: crate::secret_lease::VaultInstant,
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

    /// Authorizes one effect of `effector` under ONE writer: the instant and
    /// the dial's admission are read there, then the checkout is witnessed
    /// and consent evaluated or spent, so all four commit against one state
    /// (FIX 9776).
    pub(super) fn authorize_in_writer(
        &self,
        credential: &DoorCredential,
        verb: &str,
        record: &str,
        effector: &str,
    ) -> DoorResult<()> {
        let mut txn = self
            .vault()
            .store
            .env
            .write_txn()
            .map_err(log_unreachable)?;
        let admitted = self.admit_scope_in_txn(&txn, effector)?;
        self.witness_in_txn(&txn, credential)?;
        self.evaluate_with_consent_in_txn(
            &mut txn,
            credential,
            verb,
            record,
            admitted.effector().as_str(),
            admitted.instant(),
        )?;
        txn.commit().map_err(log_unreachable)
    }
}
