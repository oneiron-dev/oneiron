//! Trusted-host attribution of served run settlements to one vault.
//! No wallet, billing price, account balance or tax policy lives here.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use oneiron::EntityId;
use oneiron::llm::run_admission::{Payer, PermitFacts, RunEvent, RunReceipt};

use crate::usage::{
    UsageAllocation, UsageCostInput, UsageCostRates, UsageError, UsageEvent, UsageEventType,
    UsageLedger, UsageMode, UsageRun, UsageTokenCounts,
};

/// One host-resolved owner and authority-log vault id. Runs cannot supply or
/// replace either. Settlements go straight to the durable idempotent ledger,
/// before any downstream consumer batches them.
pub struct VaultUsage {
    ledger: UsageLedger,
    owner: String,
    vault_id: String,
    provider_rates: RwLock<BTreeMap<String, UsageCostRates>>,
    calls: Mutex<BTreeMap<(EntityId, String), AdmittedCall>>,
}

struct AdmittedCall {
    facts: PermitFacts,
    rates: Option<UsageCostRates>,
}

impl VaultUsage {
    pub(crate) fn new(
        ledger: UsageLedger,
        owner: String,
        vault_id: String,
    ) -> Result<Arc<Self>, UsageError> {
        // Validate the scope and read any existing rollup before binding it.
        ledger.vault_rollup(&owner, &vault_id)?;
        Ok(Arc::new(Self {
            ledger,
            owner,
            vault_id,
            provider_rates: RwLock::default(),
            calls: Mutex::default(),
        }))
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[must_use]
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// Provider list-price facts for an offer, never the host's selling
    /// price. Already-admitted calls keep their snapshot. Without a table,
    /// quantities are still recorded and no money amount is invented.
    pub fn set_cost_rates(
        &self,
        offer: impl Into<String>,
        rates: Option<UsageCostRates>,
    ) -> Result<(), UsageError> {
        if let Some(rates) = &rates {
            UsageCostInput {
                token_counts: UsageTokenCounts::default(),
                cost_rates: rates.clone(),
                service_amount: 0,
            }
            .calculate()?;
        }
        let mut tables = self
            .provider_rates
            .write()
            .expect("usage rates lock poisoned");
        let offer = offer.into();
        match rates {
            Some(rates) => {
                tables.insert(offer, rates);
            }
            None => {
                tables.remove(&offer);
            }
        }
        Ok(())
    }

    pub(crate) fn record(&self, receipt: &RunReceipt) {
        match &receipt.event {
            RunEvent::Admitted(facts) => {
                let rates = self
                    .provider_rates
                    .read()
                    .expect("usage rates lock poisoned")
                    .get(&facts.offer)
                    .cloned();
                self.calls
                    .lock()
                    .expect("usage calls lock poisoned")
                    .insert(
                        (receipt.instance, facts.lease.clone()),
                        AdmittedCall {
                            facts: *facts.clone(),
                            rates,
                        },
                    );
            }
            RunEvent::Settled {
                lease,
                dispatched,
                usage,
                service_quantity,
                units,
                unit,
                allocation_units,
                error,
                allocation_error,
            } => {
                let facts = self
                    .calls
                    .lock()
                    .expect("usage calls lock poisoned")
                    .remove(&(receipt.instance, lease.clone()));
                let Some(AdmittedCall { facts, rates }) = facts.filter(|_| *dispatched) else {
                    return;
                };
                let source = match facts.payer {
                    Payer::Host => UsageMode::OneironCloud,
                    Payer::Local => UsageMode::Local,
                    Payer::CustomerKey | Payer::CustomerAccount | Payer::CustomerSeat => {
                        UsageMode::Byo
                    }
                };
                let model = facts.model.as_ref().map(|model| model.as_str().to_owned());
                let allocation = facts
                    .allocation
                    .as_ref()
                    .zip(facts.allocation_unit.as_ref())
                    .map(|(allocation, unit)| UsageAllocation {
                        id: allocation.id.clone(),
                        generation: allocation.generation,
                        reserved_units: facts.allocation_reserved_units.unwrap_or(0),
                        settled_units: allocation_units.unwrap_or(0),
                        unit: unit.as_str().to_owned(),
                        settlement_refused: allocation_error.is_some(),
                    });
                let token_counts = usage
                    .as_ref()
                    .map_or_else(UsageTokenCounts::default, |usage| UsageTokenCounts {
                        input_tokens: usage
                            .input
                            .total
                            .saturating_sub(usage.input.cache_read)
                            .saturating_sub(usage.input.cache_write),
                        output_tokens: usage.output.total,
                        cache_read_tokens: usage.input.cache_read,
                        cache_write_tokens: usage.input.cache_write,
                    });
                let usage_reported = usage.as_ref().is_some_and(|usage| {
                    usage.input.total != 0
                        || usage.output.total != 0
                        || usage.input.cache_read != 0
                        || usage.input.cache_write != 0
                }) || service_quantity.is_some();
                let event = UsageEvent {
                    owner: self.owner.clone(),
                    vault_id: self.vault_id.clone(),
                    idempotency_key: format!(
                        "run:{}:{}",
                        receipt.instance.to_hex(),
                        blake3::hash(lease.as_bytes()).to_hex(),
                    ),
                    source: Some(source),
                    event_type: if model.is_some() {
                        UsageEventType::Inference
                    } else {
                        UsageEventType::Service
                    },
                    role: None,
                    occurred_at: Some(receipt.occurred_at),
                    agent_id: None,
                    service: model.is_none().then(|| facts.subject.clone()),
                    model,
                    token_counts,
                    // A reservation is not measured provider usage.
                    cost_rates: if usage_reported && usage.is_some() {
                        rates
                    } else {
                        None
                    },
                    service_amount: 0,
                    run: Some(UsageRun {
                        instance: receipt.instance.to_hex(),
                        run: receipt.run.clone(),
                        revision: receipt.revision,
                        lease: lease.clone(),
                        offer: facts.offer,
                        route: facts.route,
                        catalog_revision: facts.catalog_revision,
                        payer: facts.payer,
                        reserved_units: facts.reserved_units,
                        settled_units: *units,
                        unit: unit.as_str().to_owned(),
                        usage_reported,
                        service_quantity: *service_quantity,
                        allocation,
                        settlement_refused: error.is_some(),
                    }),
                };
                if self.ledger.record_event(event, source).is_err() {
                    tracing::error!("served run usage could not be persisted");
                }
            }
            _ => {}
        }
    }
}
