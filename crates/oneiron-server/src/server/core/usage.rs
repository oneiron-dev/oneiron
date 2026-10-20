//! The usage meter the trusted host binds to this vault before work starts.
use std::sync::Arc;

use super::SyncServer;

impl SyncServer {
    /// Enables durable usage facts for the owner the trusted host resolved.
    /// The vault id comes from the authority log, never an HTTP payload.
    /// Bind before starting work so every admission has attribution. Each
    /// admitted model call is priced from this vault's model registry as it
    /// reads at admission.
    pub fn with_usage_metering(
        self,
        owner: impl Into<String>,
    ) -> Result<Self, crate::usage::UsageError> {
        let vault_id = self.vault.authority_fold()?.vault_id.ok_or(
            crate::usage::UsageError::InvalidField {
                field: "vaultId",
                message: "usage metering requires an authority-log genesis",
            },
        )?;
        let vault_id = vault_id.iter().map(|byte| format!("{byte:02x}")).collect();
        let usage = crate::runtime::VaultUsage::new(
            self.usage_ledger.clone(),
            owner.into(),
            vault_id,
            Arc::clone(&self.vault),
        )?;
        self.run_receipts.meter(usage);
        Ok(self)
    }

    #[must_use]
    pub fn vault_usage(&self) -> Option<Arc<crate::runtime::VaultUsage>> {
        self.run_receipts.usage()
    }
}
