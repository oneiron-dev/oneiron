//! The reader of an audit door (RULING AUDIT-READ-POWER-LIST = B; Engine
//! RULINGs AUDITREAD-GRANT-HOME = A and AUDITREAD-DOOR-LIST = A): the vault's
//! owner, or a bound actor that holds the one audit_read power.

use super::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, verify_actor_binding_in_txn,
};
use crate::access_grant::{AuditHolder, AuditReader};

impl Memory<'_> {
    /// The reader of the audit door `verb`: the vault owner, on the proof
    /// [`Self::embedded_owner`] admits, else this handle's own bound actor
    /// while it holds a live audit_read power. The door admits the holder
    /// again in its own read ([`AuditReader`]), so a revoke or an expiry
    /// refuses at the next read. Every other caller gets the owner door's
    /// own refusal, as before the power existed.
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
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
        verify_actor_binding_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        if self.vault.audit_read_live_in_txn(&txn, self.actor)? {
            Ok(AuditReader::Holder(AuditHolder::of(self.actor)))
        } else {
            Err(refused)
        }
    }
}
