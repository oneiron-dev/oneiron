//! Human per-message approval for delegated Gmail sends.
use super::support::verify_deletion_authority_in_txn;
use super::{Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::channel_identity_provider::gmail_send::{
    GmailMessageApproval, GmailSendMessage, approval_key, send_binding,
};

impl Memory<'_> {
    /// Records a single approval bound to an immutable message and sender identity.
    /// A consumed intent is never re-armed, even by another approval.
    pub fn approve_gmail_message(
        &self,
        intent_ref: &str,
        identity: EntityId,
        message: &GmailSendMessage,
    ) -> MemoryResult<()> {
        let key = approval_key(intent_ref)?;
        let digest = message.digest(identity)?;
        self.with_verified_actor_write_txn(|txn| {
            verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class)?;
            send_binding(self.vault, txn, identity)?;
            if self.vault.store.vault_meta.get(txn, &key)?.is_some() {
                return Err(MemoryError::bad_request(
                    "Gmail intent already approved or consumed",
                ));
            }
            let approval = GmailMessageApproval {
                identity: identity.to_hex(),
                approver: self.actor.to_hex(),
                digest,
                consumed: false,
            };
            let bytes = serde_json::to_vec(&approval)
                .map_err(|_| MemoryError::bad_request("Invalid Gmail approval"))?;
            self.vault.store.vault_meta.put(txn, &key, &bytes)?;
            Ok(())
        })
    }
}
