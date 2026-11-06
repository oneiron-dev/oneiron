//! One native monetary quote supplier for admission and current stock evidence.

use std::collections::BTreeMap;

use oneiron::EntityId;
use oneiron::llm::registry::ModelRegistryRow;
use oneiron::llm::run_admission::{OfferBinding, PermitFacts};

use super::VaultUsage;
use super::pricing::{CatalogPrices, QuoteIdentity, custom_endpoint};
use crate::usage::UsageCostRates;

pub(crate) struct NativeQuote {
    pub rates: Option<UsageCostRates>,
    pub price_sources: Option<Vec<EntityId>>,
    pub custom_endpoint: bool,
}

/// An immutable view of the meter's ONE override map, not another rate table.
/// The trusted host holds its read guard through the stock decision's commit.
pub(crate) struct QuoteSnapshot<'a> {
    overrides: &'a BTreeMap<String, UsageCostRates>,
}

fn resolve_quote(
    facts: QuoteIdentity<'_>,
    overridden: Option<UsageCostRates>,
    catalog: impl FnOnce() -> (Option<UsageCostRates>, Option<Vec<EntityId>>),
) -> NativeQuote {
    let custom_endpoint = custom_endpoint(facts);
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

impl VaultUsage {
    pub(super) fn quote_for_facts(&self, facts: &PermitFacts) -> NativeQuote {
        let identity = QuoteIdentity {
            offer: &facts.offer,
            model: facts.model.as_ref(),
            route: &facts.route,
            payer: facts.payer,
            catalog_revision: facts.catalog_revision.as_deref(),
        };
        // Preserve admission's original lock boundary: drop it BEFORE any
        // registry read. Already admitted calls keep the resulting quote.
        let overridden = self
            .provider_rates
            .read()
            .expect("usage rates lock poisoned")
            .get(identity.offer)
            .cloned();
        resolve_quote(identity, overridden, || self.catalog.snapshot(identity))
    }

    pub(crate) fn with_quote_snapshot<T>(&self, decide: impl FnOnce(&QuoteSnapshot<'_>) -> T) -> T {
        let overrides = self
            .provider_rates
            .read()
            .expect("usage rates lock poisoned");
        decide(&QuoteSnapshot {
            overrides: &overrides,
        })
    }
}

impl QuoteSnapshot<'_> {
    /// The actual registry row comes from the committing core writer. This
    /// pure projection opens no reader while the override snapshot is held.
    pub(crate) fn for_binding(
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
        Some(resolve_quote(
            identity,
            self.overrides.get(identity.offer).cloned(),
            || CatalogPrices::snapshot_row(identity, row),
        ))
    }
}
