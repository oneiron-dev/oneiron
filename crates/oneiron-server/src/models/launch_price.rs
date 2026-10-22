//! The launch statement's USD quote (OF-532).
//!
//! A local agent's run is a generative-role call (`ai_host/step.rs`), so its
//! native tokens are priced at the model its launch plan resolved, a pinned
//! model included, when the launch carries one (FIX 3043); else at the model
//! that role binds: the manifest's pin at the slot's route, else the role's
//! seat. A plan's model with no registry row quotes nothing; it never falls
//! back to the role's price. An AGENT_DEF names no model or route of its
//! own: its tier is recorded on the call and never picks another model. The
//! rate is the model's highest catalog rate per token, so the dollar figure
//! is an upper bound. Only a catalog price quoted in USD makes the quote; one
//! in another currency, or in none its provider named, quotes nothing and is
//! never read as dollars (FIX 9534).
//! A unit other than tokens is priced from that same model's token rate
//! through the one rate the exact offer serving it supplies for the unit
//! (FIX 3041); a unit's name is never read as money. A peer consult, a model
//! with no registry row, a unit no such offer rates and any rate that does
//! not parse or fit quote nothing.
use std::sync::Weak;

use oneiron::agent_dispatch::{LaunchUsdPrices, UsdPriceTarget, UsdUnitPrice};
use oneiron::llm::LlmCatalogCost;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::LeaseUnit;
use oneiron::{ModelId, Vault};

use super::ModelRuntime;

/// The one currency the launch statement quotes in.
const QUOTE_CURRENCY: &str = "USD";

/// The per-vault quote the AI host installs. It holds the seat's model id
/// and a weak handle on the host's model runtime, never the vault.
pub(crate) struct LaunchUsdQuote {
    seat: ModelId,
    /// Where a unit other than tokens finds its offer's rate. Weak: the
    /// runtime holds vault-linked services.
    runtime: Weak<ModelRuntime>,
}

impl LaunchUsdQuote {
    /// `seat` is the generative role's seat model: the binding when no
    /// manifest pins the role.
    pub(crate) fn new(seat: ModelId, runtime: Weak<ModelRuntime>) -> Self {
        Self { seat, runtime }
    }

    /// `per_token`, `U` microdollars per `D` tokens, in `unit`: with the
    /// rate of the exact offer serving `model`, `c` units per `p` tokens,
    /// that is `U*p` microdollars per `D*c` units, kept exact and reduced, so
    /// a spend of `N` units rounds up once, as `ceil(N*U*p/(D*c))`. `None`
    /// when the runtime is gone, no picked offer serves exactly `model`, its
    /// rate for `unit` is missing, zero or ambiguous, or the rate does not
    /// fit.
    fn per_unit(
        &self,
        model: &ModelId,
        unit: &LeaseUnit,
        per_token: UsdUnitPrice,
    ) -> Option<UsdUnitPrice> {
        let runtime = self.runtime.upgrade()?;
        let (_, ladder) = runtime.router()?.served(model)?;
        let rate = ladder.exact_rate(model, unit)?;
        let usd_micros = u128::from(per_token.usd_micros).checked_mul(u128::from(rate.per))?;
        let per_units = u128::from(per_token.per_units).checked_mul(u128::from(rate.cost))?;
        if per_units == 0 {
            return None;
        }
        let common = gcd(usd_micros, per_units);
        Some(UsdUnitPrice {
            usd_micros: u64::try_from(usd_micros / common).ok()?,
            per_units: u64::try_from(per_units / common).ok()?,
        })
    }
}

impl LaunchUsdPrices for LaunchUsdQuote {
    fn quote(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        target: UsdPriceTarget<'_>,
        unit: &LeaseUnit,
    ) -> oneiron::Result<Option<UsdUnitPrice>> {
        let UsdPriceTarget::Agent { model: planned, .. } = target else {
            return Ok(None);
        };
        // A price never blocks a statement: a binding or row that does not
        // read quotes nothing.
        let model = match planned {
            Some(model) => model.clone(),
            None => match vault.price_model_for_role_in_txn(
                txn,
                ModelRole::GenerativeReasoner,
                &self.seat,
            ) {
                Ok(model) => model,
                Err(_) => return Ok(None),
            },
        };
        let Ok(Some(row)) = vault.model_registry_row_in_txn(txn, &model) else {
            return Ok(None);
        };
        let per_token = row.catalog.cost.as_ref().and_then(max_rate);
        if *unit == LeaseUnit::tokens() {
            return Ok(per_token);
        }
        Ok(per_token.and_then(|per_token| self.per_unit(&model, unit, per_token)))
    }
}

/// The highest of a catalog cost's per-million rates (input, output, cache
/// read, cache write), rounded up. `None` when the cost is not quoted in USD
/// or any rate does not parse.
fn max_rate(cost: &LlmCatalogCost) -> Option<UsdUnitPrice> {
    if cost.currency.as_deref() != Some(QUOTE_CURRENCY) {
        return None;
    }
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

/// The greatest common divisor of `a` and `b`: positive when `b` is.
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
