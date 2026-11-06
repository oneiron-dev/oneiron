//! The usage meter the trusted host binds to this vault before work starts.
use std::sync::Arc;

use super::SyncServer;

use crate::models::NativeUsage;

impl SyncServer {
    /// Selects native custody before work starts, using this vault's actual
    /// writer lease and the original usage owner. This neither creates nor
    /// replenishes a grant. The trusted host delivers original allocations
    /// through `persistent_allocation_ledger`, never a reflected live balance.
    pub fn with_native_usage_metering(
        mut self,
        owner: impl Into<String>,
    ) -> Result<Self, oneiron::llm::run_admission::AllocationStoreError> {
        let owner = owner.into();
        {
            let _installation = self.native_usage.installation();
            if let Some(native) = self.native_usage.current() {
                Self::check_native_owner(&native, &owner)?;
            } else {
                let usage = self.native_usage_meter(&owner)?;
                let native = NativeUsage::new(Arc::clone(&usage), Arc::clone(&self.run_receipts))?;
                self.run_receipts.meter(usage);
                self.native_usage.publish(native);
            }
        }
        if let Some(raw) = self.llm.take() {
            self.llm = Some(raw.with_native_allocation(self.native_runs()));
        }
        Ok(self)
    }

    /// Publishes a first live binding only after the original delivery commits.
    /// Existing runs retain the backend they captured before this selection.
    pub(crate) fn install_native_allocation(
        &self,
        allocation: oneiron::llm::run_admission::Allocation,
        terms: oneiron::llm::run_admission::AllocationTerms,
    ) -> Result<
        oneiron::llm::run_admission::AllocationCommit<()>,
        oneiron::llm::run_admission::AllocationStoreError,
    > {
        let _installation = self.native_usage.installation();
        if let Some(native) = self.native_usage.current() {
            Self::check_native_owner(&native, &terms.usage_owner)?;
            return native.ledger.install_backed(allocation, terms);
        }
        let usage = self.native_usage_meter(&terms.usage_owner)?;
        let native = NativeUsage::new(Arc::clone(&usage), Arc::clone(&self.run_receipts))?;
        let commit = native.ledger.install_backed(allocation, terms)?;
        self.run_receipts.meter(usage);
        self.native_usage.publish(native);
        Ok(commit)
    }

    fn check_native_owner(
        native: &NativeUsage,
        owner: &str,
    ) -> Result<(), oneiron::llm::run_admission::AllocationStoreError> {
        if native.producer.owner() == owner {
            return Ok(());
        }
        Err(oneiron::llm::run_admission::AllocationStoreError::Producer(
            Box::new(crate::usage::UsageError::InvalidField {
                field: "usageOwner",
                message: "allocation names another usage producer",
            }),
        ))
    }

    fn native_usage_meter(
        &self,
        owner: &str,
    ) -> Result<Arc<crate::runtime::VaultUsage>, oneiron::llm::run_admission::AllocationStoreError>
    {
        let usage = match self.vault_usage() {
            Some(usage) if usage.owner() == owner => Ok(usage),
            Some(_) => Err(crate::usage::UsageError::InvalidField {
                field: "usageOwner",
                message: "allocation names another usage producer",
            }),
            None => self.new_usage_meter(owner.to_owned()),
        };
        usage.map_err(|error| {
            oneiron::llm::run_admission::AllocationStoreError::Producer(Box::new(error))
        })
    }

    /// The selected authoritative ledger, for original trusted-host grants,
    /// status and retirement. Construction does not replay an old full grant.
    #[must_use]
    pub fn persistent_allocation_ledger(
        &self,
    ) -> Option<Arc<oneiron::llm::run_admission::VaultAllocationLedger>> {
        self.native_usage
            .current()
            .map(|native| Arc::clone(&native.ledger))
    }

    pub(crate) fn native_runs(&self) -> crate::models::NativeUsageBinding {
        self.native_usage.clone()
    }

    /// An undeclared run using the explicitly selected native backend, or
    /// the unchanged ordinary runtime when no native backend was selected.
    #[must_use]
    pub fn undeclared_run(
        &self,
        run: impl Into<String>,
        meter: oneiron::BudgetGuard,
    ) -> oneiron::llm::run_admission::RunAdmission {
        let run = run.into();
        match self.native_usage.current() {
            Some(native) => native.undeclared_run(run, meter),
            None => self.ai.model_runtime().undeclared_run(run, meter),
        }
    }

    pub(crate) fn record_service_cost(
        &self,
        permit: &oneiron::llm::run_admission::RunPermit,
        cost: crate::usage::UsageServiceCost,
    ) -> Result<(), crate::usage::UsageError> {
        if let Some(backend) = permit.persistent_allocation() {
            let native = self
                .native_usage
                .current()
                .filter(|native| Arc::ptr_eq(&native.backend, &backend))
                .ok_or(crate::usage::UsageError::InvalidField {
                    field: "nativeUsageAdmission",
                    message: "the call belongs to another native backend",
                })?;
            return native.producer.record_service_cost(
                permit.instance(),
                permit.lease().id(),
                cost,
            );
        }
        if let Some(usage) = self.vault_usage() {
            usage.record_service_cost(permit.instance(), permit.lease().id(), cost);
        }
        Ok(())
    }

    /// Enables durable usage facts for the owner the trusted host resolved.
    /// The vault id comes from the authority log, never an HTTP payload.
    /// Bind before starting work so every admission has attribution. Each
    /// admitted model call is priced from this vault's model registry as it
    /// reads at admission.
    pub fn with_usage_metering(
        self,
        owner: impl Into<String>,
    ) -> Result<Self, crate::usage::UsageError> {
        let usage = self.new_usage_meter(owner.into())?;
        self.run_receipts.meter(usage);
        Ok(self)
    }

    fn new_usage_meter(
        &self,
        owner: String,
    ) -> Result<Arc<crate::runtime::VaultUsage>, crate::usage::UsageError> {
        let vault_id = self.vault.authority_fold()?.vault_id.ok_or(
            crate::usage::UsageError::InvalidField {
                field: "vaultId",
                message: "usage metering requires an authority-log genesis",
            },
        )?;
        let vault_id = vault_id.iter().map(|byte| format!("{byte:02x}")).collect();
        crate::runtime::VaultUsage::new(
            self.usage_ledger.clone(),
            owner,
            vault_id,
            Arc::clone(&self.vault),
            Arc::clone(&self.retained),
            Arc::clone(self.wire_telemetry.limit_questions()),
        )
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

    /// Flushes retrieval meters and retries the taken memory-only settlement
    /// snapshot before serve closes the vault. Each buffer's drop is the
    /// backstop for paths that stop elsewhere (FIX 11011, FIX 737).
    pub(crate) fn flush_retrieval_meters(&self) {
        self.flush_usage_meters(true);
    }

    fn flush_usage_meters(&self, stopping: bool) {
        self.retrieval_buffer.flush();
        if let Some(native) = self.native_usage.current()
            && let Err(error) = native.backend.retry_settlements()
        {
            tracing::warn!(%error, stopping, "original native terminals remain in memory for retry");
        }
        if let Some(usage) = self.vault_usage() {
            usage.flush_settlements(stopping);
        }
    }

    /// Starts the existing meter worker once. Each tick flushes retrieval rows
    /// and one bounded settlement retry pass. Started where window receipts
    /// start; failed writes keep their payloads for the next tick.
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
                let _ = tokio::task::spawn_blocking(move || server.flush_usage_meters(false)).await;
            }
        });
    }
}
