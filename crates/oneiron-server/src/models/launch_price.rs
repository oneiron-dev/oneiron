//! The launch statement's USD quote (OF-532).
//!
//! A local agent's run is a generative-role call (`ai_host/step.rs`), so its
//! native tokens are priced at the model that role binds: the manifest's pin
//! at the slot's route, else the role's seat. An AGENT_DEF names no model or
//! route of its own: its tier is recorded on the call and never picks another
//! model. The rate is the model's highest catalog rate per token, so the
//! dollar figure is an upper bound. Catalog prices carry no currency and are
//! read as USD. A peer consult, a unit other than tokens, a model with no
//! registry row and any rate that does not parse quote nothing.
use oneiron::agent_dispatch::{LaunchUsdPrices, UsdPriceTarget, UsdUnitPrice};
use oneiron::llm::LlmCatalogCost;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::LeaseUnit;
use oneiron::{ModelId, Vault};

/// The per-vault quote the AI host installs. It holds the seat's model id,
/// never the vault.
pub(crate) struct LaunchUsdQuote {
    seat: ModelId,
}

impl LaunchUsdQuote {
    /// `seat` is the generative role's seat model: the binding when no
    /// manifest pins the role.
    pub(crate) fn new(seat: ModelId) -> Self {
        Self { seat }
    }
}

impl LaunchUsdPrices for LaunchUsdQuote {
    fn quote(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        target: UsdPriceTarget,
        unit: &LeaseUnit,
    ) -> oneiron::Result<Option<UsdUnitPrice>> {
        let UsdPriceTarget::Agent(_) = target else {
            return Ok(None);
        };
        if *unit != LeaseUnit::tokens() {
            return Ok(None);
        }
        // A price never blocks a statement: a binding or row that does not
        // read quotes nothing.
        let Ok(model) =
            vault.price_model_for_role_in_txn(txn, ModelRole::GenerativeReasoner, &self.seat)
        else {
            return Ok(None);
        };
        let Ok(Some(row)) = vault.model_registry_row_in_txn(txn, &model) else {
            return Ok(None);
        };
        Ok(row.catalog.cost.as_ref().and_then(max_rate))
    }
}

/// The highest of a catalog cost's per-million rates (input, output, cache
/// read, cache write), rounded up. `None` when any rate does not parse.
fn max_rate(cost: &LlmCatalogCost) -> Option<UsdUnitPrice> {
    let mut max_rate = 0.0_f64;
    for text in [&cost.input_per_million, &cost.output_per_million]
        .into_iter()
        .chain(cost.cache_read_per_million.iter())
        .chain(cost.cache_write_per_million.iter())
    {
        let rate = text.parse::<f64>().ok()?;
        if !rate.is_finite() || rate < 0.0 {
            return None;
        }
        max_rate = max_rate.max(rate);
    }
    // $p per million tokens is p * 10^6 microdollars per million tokens.
    let numerator = (max_rate * 1_000_000.0).ceil();
    if !numerator.is_finite() || numerator >= u64::MAX as f64 {
        return None;
    }
    Some(UsdUnitPrice {
        usd_micros: numerator as u64,
        per_units: 1_000_000,
    })
}
