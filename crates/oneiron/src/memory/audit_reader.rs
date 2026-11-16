//! The reader of an audit door (RULING AUDIT-READ-POWER-LIST = B; Engine
//! RULINGs AUDITREAD-GRANT-HOME = A and AUDITREAD-DOOR-LIST = A): the vault's
//! owner, or a bound actor that holds the one audit_read power.

use super::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, verify_actor_binding_in_txn,
};
use crate::access_grant::{AuditHolder, AuditReader};

impl Memory<'_> {
    /// The reader of the audit door `verb`: the vault owner, on the proof
    /// [`Self::embedded_owner`] admits, else this handle's own bound actor,
    /// on the credential the handle presents, while it holds a live
    /// audit_read power. The door admits the holder again in its own read
    /// ([`AuditReader`]), credential and power both, so a revoke or an
    /// expiry of either refuses at the next read. A transport handle that
    /// presents no credential of its own reads as no holder. Every other
    /// caller gets the owner door's own refusal, as before the power existed.
    ///
    /// # Errors
    /// `FORBIDDEN` for a caller that is neither the owner nor a live holder;
    /// a binding that does not verify; or a read that fails.
    pub fn audit_reader(&self, verb: &str) -> MemoryResult<AuditReader> {
        let refused = match self.embedded_owner(verb) {
            Ok(owner) => return Ok(AuditReader::Owner(owner)),
            Err(refused) if refused.code == MEMORY_CODE_FORBIDDEN => refused,
            Err(error) => return Err(error),
        };
        let Some(holder) = self.audit_holder(verb) else {
            return Err(refused);
        };
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
        verify_actor_binding_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        if holder.admits_in_txn(self.vault, &txn)? {
            Ok(AuditReader::Holder(holder))
        } else {
            Err(refused)
        }
    }

    /// Whether this handle reads the audit door `verb` as a live audit_read
    /// holder in `txn`, the door's own read: on the credential it presents,
    /// rechecked there, while its actor holds the power
    /// ([`AuditHolder::admits_in_txn`]). A door whose own reader check
    /// admits the owner or a row's own actor asks it for anyone else.
    ///
    /// # Errors
    /// The authority fold, the grant row or the clock does not read.
    pub(crate) fn audit_read_holder_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        verb: &str,
    ) -> MemoryResult<bool> {
        match self.audit_holder(verb) {
            Some(holder) => Ok(holder.admits_in_txn(self.vault, txn)?),
            None => Ok(false),
        }
    }

    /// This handle's actor as the holder that reads the audit door `verb`,
    /// on the credential the handle presents. A transport handle that
    /// presents none is no holder.
    fn audit_holder(&self, verb: &str) -> Option<AuditHolder> {
        let credential = self.presented_credential();
        if credential.is_none() && !self.native_invocation() {
            return None;
        }
        Some(AuditHolder::of(
            self.actor,
            self.actor_class,
            credential,
            verb,
        ))
    }
}
