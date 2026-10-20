//! The list price an admitted model call is metered at (FIX 2629): the
//! vault's priced catalog row for that exact model, read once when the call
//! is admitted and frozen on it. A settlement is never repriced, and a catalog
//! edit reaches the next admitted call. The price is the catalog's top-level
//! model list price, the one the training offer drafts from; never a backend
//! pin's price, a selling price, tax or an exchange rate.
use std::sync::Arc;

use oneiron::llm::LlmCatalogCost;
use oneiron::llm::run_admission::PermitFacts;
use oneiron::{EntityId, ModelId};

use crate::usage::{UsageCostRates, catalog_cost_rates};

/// The catalog's per-million list prices carry no currency; they are read as
/// this one, as the training offer and the launch quote read them. No
/// currency is inferred from a provider or a payer.
const CATALOG_CURRENCY: &str = "USD";
/// Domain tag of the price-table snapshot digest.
const SNAPSHOT_DOMAIN: &[u8] = b"oneiron.usage.catalog-list-price.v1";

/// The vault registry whose list prices meter its admitted model calls.
pub(super) struct CatalogPrices {
    vault: Arc<oneiron::Vault>,
}

impl CatalogPrices {
    pub(super) fn new(vault: Arc<oneiron::Vault>) -> Self {
        Self { vault }
    }

    /// The admitted model's list price as the registry reads now, stamped
    /// for `facts`' exact offer, route and catalog revision, beside the rows
    /// that price was read from (FIX 5760). The price is `None` for a paid
    /// connector, a model with no readable registry row, or a quoted rate
    /// that does not convert: the call keeps its quantities and no money is
    /// invented. A failed read never fails the admission.
    pub(super) fn snapshot(
        &self,
        facts: &PermitFacts,
    ) -> (Option<UsageCostRates>, Option<Vec<EntityId>>) {
        // A paid connector reads no catalog row.
        let Some(model) = facts.model.as_ref() else {
            return (None, Some(Vec::new()));
        };
        let row = match self.vault.model_registry_row(model) {
            Ok(Some(row)) => row,
            // No row: the absence is the installed pack's, when one is.
            Ok(None) => {
                let pack = self.vault.model_catalog_source();
                return (None, pack.ok().map(|pack| pack.into_iter().collect()));
            }
            Err(_) => {
                tracing::debug!("an admitted model's list price could not be read");
                return (None, None);
            }
        };
        let rates = row.catalog.cost.as_ref().and_then(|cost| {
            catalog_cost_rates(cost, CATALOG_CURRENCY, snapshot_id(facts, model, cost))
        });
        (rates, row.source_rows)
    }
}

/// The price-table snapshot id: a BLAKE3 digest over the admitted offer,
/// model, route and catalog revision, the four rates as the catalog spells
/// them (an unquoted one included) and the currency they are read in. Each
/// field is length-prefixed, an absent one marked, so a price-only catalog
/// edit changes the id.
fn snapshot_id(facts: &PermitFacts, model: &ModelId, cost: &LlmCatalogCost) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAPSHOT_DOMAIN);
    for field in [
        Some(facts.offer.as_str()),
        Some(model.as_str()),
        Some(facts.route.as_str()),
        facts.catalog_revision.as_deref(),
        Some(cost.input_per_million.as_str()),
        Some(cost.output_per_million.as_str()),
        cost.cache_read_per_million.as_deref(),
        cost.cache_write_per_million.as_deref(),
        Some(CATALOG_CURRENCY),
    ] {
        match field {
            Some(text) => {
                hasher.update(&[1]);
                hasher.update(&(text.len() as u64).to_le_bytes());
                hasher.update(text.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    hasher.finalize().to_hex().to_string()
}
