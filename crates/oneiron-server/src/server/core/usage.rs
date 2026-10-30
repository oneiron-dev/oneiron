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

    /// Buffers one retrieval meter row for a recall that answered Ok:
    /// `RetrievalQueries`, quantity 1, the asked effort in `detail`, under a
    /// host-minted request id. Takes only the buffer's lock: no write, no txn.
    /// Without a bound usage meter there is no billing owner to attribute the
    /// row to, so the recall records nothing, as a settled call does (FIX
    /// 11011).
    pub(crate) fn push_retrieval_meter(&self, effort: &str) {
        let Some(usage) = self.vault_usage() else {
            return;
        };
        let request = oneiron::EntityId::now().to_hex();
        self.retrieval_buffer.push(crate::usage::MeterRow {
            owner: usage.owner().to_owned(),
            vault_id: usage.vault_id().to_owned(),
            metric: crate::usage::OperationalMetric::RetrievalQueries,
            idempotency_key: crate::usage::retrieval_key(&request),
            quantity: 1,
            occurred_at: oneiron_vault_contract::now_ts(),
            detail: Some(effort.to_owned()),
        });
    }

    /// Writes the recall doors' buffered retrieval rows in one grouped write,
    /// if any. Serve calls it at stop, before the vault closes; the buffer's
    /// drop is the backstop for paths that stop elsewhere (FIX 11011).
    pub(crate) fn flush_retrieval_meters(&self) {
        self.retrieval_buffer.flush();
    }

    /// Starts the retrieval-meter flush worker once: every
    /// [`crate::usage::RETRIEVAL_FLUSH_SECS`] it writes what the recall doors
    /// buffered in one grouped write. Started where the window receipts start;
    /// an empty buffer takes no write, and a failed flush keeps its rows for
    /// the next tick (FIX 11011).
    pub(crate) fn start_retrieval_meter_flush(server: &Arc<SyncServer>) {
        // Like the window receipts: router construction may happen before its
        // runtime exists, so the first runtime-backed request retries this
        // start.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if !server.retrieval_buffer.claim_flusher() {
            return;
        }
        let weak = Arc::downgrade(server);
        runtime.spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                crate::usage::RETRIEVAL_FLUSH_SECS,
            ));
            loop {
                tick.tick().await;
                let Some(server) = weak.upgrade() else {
                    break;
                };
                // The grouped write runs off the runtime's workers: a write
                // that waits for the vault's writer holds back only the tick.
                let _ = tokio::task::spawn_blocking(move || server.retrieval_buffer.flush()).await;
            }
        });
    }
}
