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
mod settlement;

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
        // Validate the scope before binding it. The derived rollup is warmed
        // here, and one that cannot be read never keeps the meter from
        // binding: a recorded call does not wait on it (FIX 6407).
        UsageLedger::validate_scope(&owner, &vault_id)?;
        if let Err(error) = ledger.vault_rollup(&owner, &vault_id) {
            tracing::warn!(
                vault_id = %vault_id,
                ?error,
                "the vault usage rollup could not be read; calls are still metered"
            );
        }
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
}
