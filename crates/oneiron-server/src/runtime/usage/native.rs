//! Original admitted usage custody for the explicitly selected native backend.
//! Billing follows the existing usage path, independently of optional evidence
//! capture and its NoRecord checks. No prompt, response or credential is stored.
use std::sync::Arc;

use crate::usage::{UsageError, UsageLedger, UsageServiceCost};
use oneiron::EntityId;
use oneiron::agent_dispatch::budget_doors::UsageEventOrigin;
use oneiron::llm::run_admission::{AllocationProducer, AllocationStoreError, RunEvent, RunReceipt};

use super::{AdmittedCall, VaultUsage, settlement::settlement_event};

/// This is the native allocation producer, not a RunReceiptSink. The selected
/// run's observer must not independently bill the same call through VaultUsage.
pub(crate) struct NativeUsageProducer {
    usage: Arc<VaultUsage>,
    vault: Arc<oneiron::Vault>,
}

impl VaultUsage {
    /// Binds the actual original usage ledger and its vault, not a new owner,
    /// later catalog snapshot or separately supplied writer.
    pub(crate) fn allocation_producer(self: &Arc<Self>) -> Arc<NativeUsageProducer> {
        Arc::new(NativeUsageProducer {
            vault: self.ledger.vault(),
            usage: Arc::clone(self),
        })
    }
}

fn key(instance: EntityId, lease: &str) -> String {
    format!(
        "usage:admission:{}:{}",
        instance.to_hex(),
        blake3::hash(lease.as_bytes()).to_hex()
    )
}

fn invalid(message: &'static str) -> UsageError {
    UsageError::InvalidField {
        field: "nativeUsageAdmission",
        message,
    }
}

fn producer_error(error: UsageError) -> AllocationStoreError {
    AllocationStoreError::Producer(Box::new(error))
}

impl NativeUsageProducer {
    fn read(&self, txn: &heed::RwTxn<'_>, key: &str) -> Result<AdmittedCall, UsageError> {
        let raw = self
            .vault
            .sync_state_get_in_write_txn(txn, key)?
            .ok_or_else(|| invalid("the original admitted call is absent"))?;
        Ok(rmp_serde::from_slice(&raw)?)
    }

    fn write(
        &self,
        txn: &mut heed::RwTxn<'_>,
        key: &str,
        call: &AdmittedCall,
    ) -> Result<(), UsageError> {
        let raw = rmp_serde::to_vec_named(call)?;
        let raw = self
            .vault
            .usage_admission_with_live_attribution_in_write_txn(txn, &raw)?;
        self.vault.sync_state_put_in_write_txn(txn, key, &raw)?;
        Ok(())
    }

    /// The actual paid-service consumer must use this typed native update
    /// before terminal settlement. An error keeps the original row and is not
    /// a zero price or permission to fall back to another money producer.
    pub(crate) fn record_service_cost(
        &self,
        instance: EntityId,
        lease: &str,
        cost: UsageServiceCost,
    ) -> Result<(), UsageError> {
        let key = key(instance, lease);
        self.vault.try_with_write_txn_grouped(|txn| {
            let mut call = self.read(txn, &key)?;
            if call.facts.lease != lease {
                return Err(invalid("the original lease differs"));
            }
            if call.facts.model.is_none() {
                call.service_cost = Some(cost);
                self.write(txn, &key, &call)?;
            }
            Ok(())
        })
    }

    fn freeze(&self, txn: &mut heed::RwTxn<'_>, admitted: &RunReceipt) -> Result<(), UsageError> {
        let RunEvent::Admitted(facts) = &admitted.event else {
            return Err(invalid("freeze requires the original admission"));
        };
        let key = key(admitted.instance, &facts.lease);
        if self.vault.sync_state_get_in_write_txn(txn, &key)?.is_some() {
            return Err(UsageError::IdempotencyConflict);
        }
        let call = self.usage.admitted_call(facts);
        self.write(txn, &key, &call)
    }

    fn settle(&self, txn: &mut heed::RwTxn<'_>, terminal: &RunReceipt) -> Result<(), UsageError> {
        let RunEvent::Settled { lease, .. } = &terminal.event else {
            return Err(invalid("settlement requires the original terminal"));
        };
        let key = key(terminal.instance, lease);
        let call = self.read(txn, &key)?;
        if call.facts.lease != *lease {
            return Err(invalid("the original lease differs"));
        }
        if let Some((event, source, source_rows)) =
            settlement_event(&self.usage.vault_id, terminal, call)
        {
            let raw = UsageLedger::prepare_settlement(
                event,
                source,
                UsageEventOrigin::Engine,
                source_rows,
            )?;
            self.usage.ledger.stage_settlement_in_write_txn(txn, &raw)?;
        }
        // Undispatched terminals also end this admission's retention, without
        // creating a served usage event or changing the durable hold's charge.
        self.vault.sync_state_delete_in_write_txn(txn, &key)?;
        Ok(())
    }
}

impl AllocationProducer for NativeUsageProducer {
    fn freeze_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        admitted: &RunReceipt,
    ) -> Result<(), AllocationStoreError> {
        self.freeze(txn, admitted).map_err(producer_error)
    }

    fn settle_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        terminal: &RunReceipt,
    ) -> Result<(), AllocationStoreError> {
        self.settle(txn, terminal).map_err(producer_error)
    }
}
