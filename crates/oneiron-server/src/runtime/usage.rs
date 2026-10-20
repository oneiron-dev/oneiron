//! Trusted-host attribution of served run settlements to one vault.
//! No wallet, billing price, account balance or tax policy lives here. A
//! room-paid call is billed to the account its run bound at admission
//! (OF-531), never re-read at settlement. Each call keeps the label it was
//! admitted with, and a free-time item's call the agent, cycle, item and
//! spend scope the engine stamped on its run before it began (FIX 4453);
//! every other call stays unbound. A model call carries the vault catalog's
//! list price as it read when the call was admitted (FIX 2629).
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use oneiron::EntityId;
use oneiron::agent_dispatch::budget_doors::UsageEventOrigin;
use oneiron::llm::run_admission::{Payer, PayerAccount, PermitFacts, RunEvent, RunReceipt};

use self::pricing::CatalogPrices;
use crate::usage::{
    UnpricedReason, UsageAllocation, UsageCostInput, UsageCostRates, UsageError, UsageEvent,
    UsageEventType, UsageLedger, UsageMode, UsageRun, UsageTokenCounts,
};

mod pricing;

/// One host-resolved owner and authority-log vault id. Runs cannot supply or
/// replace either. Settlements go straight to the durable idempotent ledger,
/// before any downstream consumer batches them.
pub struct VaultUsage {
    ledger: UsageLedger,
    owner: String,
    vault_id: String,
    /// The registry each admitted model call's list price is read from.
    catalog: CatalogPrices,
    /// The trusted host's explicit overrides, keyed by the exact offer.
    provider_rates: RwLock<BTreeMap<String, UsageCostRates>>,
    calls: Mutex<BTreeMap<(EntityId, String), AdmittedCall>>,
}

struct AdmittedCall {
    facts: PermitFacts,
    rates: Option<UsageCostRates>,
    /// The rows `rates` was read from: the catalog row's, none for the
    /// host's override (FIX 5760).
    price_sources: Option<Vec<EntityId>>,
    /// The billing owner the call's usage lands on, fixed at admission.
    owner: String,
}

impl VaultUsage {
    /// `catalog` is the vault whose model registry prices each admitted call.
    pub(crate) fn new(
        ledger: UsageLedger,
        owner: String,
        vault_id: String,
        catalog: Arc<oneiron::Vault>,
    ) -> Result<Arc<Self>, UsageError> {
        // Validate the scope and read any existing rollup before binding it.
        ledger.vault_rollup(&owner, &vault_id)?;
        Ok(Arc::new(Self {
            ledger,
            owner,
            vault_id,
            catalog: CatalogPrices::new(catalog),
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
    /// price: an explicit override of the catalog's price for calls admitted
    /// on exactly `offer`, `None` to drop it. Already-admitted calls keep
    /// their snapshot. Without a price, quantities are still recorded and no
    /// money amount is invented.
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
                // The host's override for this exact offer, else the
                // catalog's list price for the admitted model as it reads
                // now; either is frozen on the call.
                let overridden = self
                    .provider_rates
                    .read()
                    .expect("usage rates lock poisoned")
                    .get(&facts.offer)
                    .cloned();
                // The host's override reads no row; the catalog's price, the
                // rows its row was read from (FIX 5760).
                let (rates, price_sources) = match overridden {
                    Some(rates) => (Some(rates), Some(Vec::new())),
                    None => self.catalog.snapshot(facts),
                };
                // A room-paid call bills its payer PERSON's own account, which
                // for a live Owner is the vault's; the vault's too when the
                // owners approved that on its payer-needed ask; a call no
                // room pays for, the vault's.
                let owner = match facts.payer_person.as_ref().map(|payer| &payer.account) {
                    Some(PayerAccount::Person { account }) => account.clone(),
                    Some(PayerAccount::VaultOwner | PayerAccount::VaultApproved { .. }) | None => {
                        self.owner.clone()
                    }
                };
                self.calls
                    .lock()
                    .expect("usage calls lock poisoned")
                    .insert(
                        (receipt.instance, facts.lease.clone()),
                        AdmittedCall {
                            facts: *facts.clone(),
                            rates,
                            price_sources,
                            owner,
                        },
                    );
            }
            RunEvent::Settled {
                lease,
                dispatched,
                usage,
                service_quantity,
                stream: _,
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
                let Some(AdmittedCall {
                    facts,
                    rates,
                    price_sources,
                    owner,
                }) = facts.filter(|_| *dispatched)
                else {
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
                // A reservation is not measured provider usage. A call left
                // without a price is never priced at zero, and its record
                // says why, the first that holds: it measured no tokens; no
                // rates were frozen on it at admission; or they quote no rate
                // for cache dimensions it measured, named.
                let measured = usage_reported && usage.is_some();
                let unpriced = match &rates {
                    Some(rates) if measured && rates.prices(&token_counts) => None,
                    _ if token_counts == UsageTokenCounts::default() => {
                        Some(UnpricedReason::NoUsage)
                    }
                    None => Some(UnpricedReason::UnpricedModel),
                    Some(rates) => Some(UnpricedReason::UnquotedCache {
                        dimensions: rates.unquoted_cache(&token_counts),
                    }),
                };
                let rates = rates.filter(|rates| measured && rates.prices(&token_counts));
                let payer = facts.payer_person.as_ref();
                // The engine's stamp, never the run's name or a prompt.
                let bound = facts.attribution.as_ref();
                // The call's facts read its input's rows and its price's,
                // frozen beside the settlement (FIX 5760).
                let source_rows = oneiron::skill_optimize::union_source_rows([
                    facts.source_rows.as_deref(),
                    price_sources.as_deref(),
                ]);
                let event = UsageEvent {
                    owner,
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
                    role: facts.seat.clone(),
                    occurred_at: Some(receipt.occurred_at),
                    agent_id: bound.map(|bound| bound.agent.to_hex()),
                    service: model.is_none().then(|| facts.subject.clone()),
                    model,
                    token_counts,
                    cost_rates: rates,
                    unpriced,
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
                        payer_person: payer.map(|payer| payer.person.to_hex()),
                        payer_scope: payer.map(|payer| payer.root_scope.to_string()),
                        payer_ask: payer.and_then(|payer| match payer.account {
                            PayerAccount::VaultApproved { ask } => Some(ask),
                            PayerAccount::Person { .. } | PayerAccount::VaultOwner => None,
                        }),
                        purpose: facts.call_purpose.clone(),
                        cycle: bound.map(|bound| bound.cycle.to_hex()),
                        item: bound.map(|bound| bound.item.to_hex()),
                        spend_scope: bound.map(|bound| bound.spend_scope.clone()),
                        reserved_units: facts.reserved_units,
                        settled_units: *units,
                        unit: unit.as_str().to_owned(),
                        usage_reported,
                        service_quantity: *service_quantity,
                        allocation,
                        settlement_refused: error.is_some(),
                    }),
                };
                if self
                    .ledger
                    .record_event_sourced(event, source, UsageEventOrigin::Engine, source_rows)
                    .is_err()
                {
                    tracing::error!("served run usage could not be persisted");
                }
            }
            _ => {}
        }
    }
}
