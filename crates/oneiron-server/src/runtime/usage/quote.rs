//! One native monetary quote supplier for admission and current stock evidence.

use oneiron::EntityId;
use oneiron::llm::ModelRegistryRow;
use oneiron::llm::run_admission::{OfferBinding, PermitFacts};

use super::VaultUsage;
use super::pricing::{CatalogPrices, QuoteIdentity, custom_endpoint};
use crate::usage::UsageCostRates;

pub(crate) struct NativeQuote {
    pub rates: Option<UsageCostRates>,
    pub price_sources: Option<Vec<EntityId>>,
    pub custom_endpoint: bool,
}

impl VaultUsage {
    fn resolve_quote(
        &self,
        facts: QuoteIdentity<'_>,
        catalog: impl FnOnce() -> (Option<UsageCostRates>, Option<Vec<EntityId>>),
    ) -> NativeQuote {
        let custom_endpoint = custom_endpoint(facts);
        let overridden = self
            .provider_rates
            .read()
            .expect("usage rates lock poisoned")
            .get(facts.offer)
            .cloned();
        // The host's override reads no row; the catalog's price keeps the
        // rows its row was read from (FIX 5760).
        let (rates, price_sources) = match overridden {
            _ if custom_endpoint => (None, Some(Vec::new())),
            Some(rates) => (Some(rates), Some(Vec::new())),
            None => catalog(),
        };
        NativeQuote {
            rates,
            price_sources,
            custom_endpoint,
        }
    }

    pub(super) fn quote_for_facts(&self, facts: &PermitFacts) -> NativeQuote {
        let identity = QuoteIdentity {
            offer: &facts.offer,
            model: facts.model.as_ref(),
            route: &facts.route,
            payer: facts.payer,
            catalog_revision: facts.catalog_revision.as_deref(),
        };
        self.resolve_quote(identity, || self.catalog.snapshot(identity))
    }

    /// Quotes a current constructed binding using the actual registry row read
    /// by the committing writer. The quote grants no permission and freezes no
    /// call: admission will use this same resolver again when a call is made.
    pub(crate) fn quote_for_binding(
        &self,
        binding: &OfferBinding,
        row: &ModelRegistryRow,
    ) -> Option<NativeQuote> {
        if row.catalog.model != binding.model {
            return None;
        }
        let route = format!("{}@{}", binding.route.adapter(), binding.route.origin());
        let identity = QuoteIdentity {
            offer: &binding.offer,
            model: Some(&binding.model),
            route: &route,
            payer: binding.payer,
            catalog_revision: binding.catalog_revision.as_deref(),
        };
        Some(self.resolve_quote(identity, || CatalogPrices::snapshot_row(identity, row)))
    }
}
