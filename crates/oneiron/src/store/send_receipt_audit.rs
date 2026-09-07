//! Append-only send receipt audit storage.

use heed::RwTxn;

use super::Store;
use super::outbound_send_receipt::send_receipt_audit_key;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

impl Store {
    /// Appends one attempt receipt without allowing its evidence to be replaced.
    /// An identical write is harmless; reusing an identity for other bytes fails.
    pub(crate) fn append_send_receipt_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        task_id: &EntityId,
        receipt_id: &str,
        value: &[u8],
    ) -> Result<()> {
        let key = send_receipt_audit_key(task_id, receipt_id);
        if let Some(existing) = self.vault_meta.get(wtxn, &key)? {
            if existing.as_ref() != value {
                return Err(Error::InvariantViolation("send receipt identity reused"));
            }
            return Ok(());
        }
        self.vault_meta.put(wtxn, &key, value)?;
        Ok(())
    }
}
