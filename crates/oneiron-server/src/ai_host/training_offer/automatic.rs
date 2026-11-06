//! Fixed-code native evidence for saved-policy stock switches.

use oneiron::llm::registry::ModelRegistryRow;
use oneiron::llm::run_admission::OfferBinding;
use oneiron::skill_optimize::{
    EvalMeasurement, EvalMonetaryRates, EvalServingOffer, HeldOutReplayNotes, OfferCandidate,
    TrainingOffer, pending_training_offers, seat_model_role,
};
use oneiron::{Error, ModelId};

use crate::config::models::role_key;
use crate::server::SyncServer;
use crate::usage::{SeatUsage, UsageCostInput, UsageCostRates, UsageTokenCounts};

pub(super) fn pending(server: &SyncServer, now: u64) {
    let vault = server.vault();
    let offers = match pending_training_offers(vault) {
        Ok(offers) => offers,
        Err(error) => {
            tracing::warn!(%error, "pending stock policies could not be read");
            return;
        }
    };
    for offer in offers {
        apply(server, &offer, now);
    }
}

/// Failure never replaces the original manual offer or ends the Coach's pass.
pub(super) fn apply(server: &SyncServer, offer: &TrainingOffer, now: u64) {
    if let Err(error) = attempt(server, offer, now) {
        tracing::warn!(%error, offer = %offer.id.to_hex(), "the stock offer stayed manual");
    }
}

fn attempt(server: &SyncServer, offer: &TrainingOffer, now: u64) -> oneiron::Result<()> {
    let vault = server.vault();
    if !vault.stock_autoapprove_policy()?.enabled {
        return Ok(());
    }
    let OfferCandidate::Stock { model, licence, .. } = &offer.candidate else {
        return Ok(());
    };
    let Some(judge) = crate::replay_judge::registered() else {
        return Ok(());
    };
    let Some(meter) = server.vault_usage() else {
        return Ok(());
    };
    let Some(role) = seat_model_role(&offer.seat) else {
        return Ok(());
    };
    let runtime = server.ai.model_runtime();
    let Some(router) = runtime.router() else {
        return Ok(());
    };
    let Ok(incumbent_id) = ModelId::new(offer.incumbent.model.clone()) else {
        return Ok(());
    };
    let Ok(candidate_id) = ModelId::new(model.model.clone()) else {
        return Ok(());
    };
    let Some((_, incumbent_ladder)) = router.served(&incumbent_id) else {
        return Ok(());
    };
    let Some((_, candidate_ladder)) = router.served(&candidate_id) else {
        return Ok(());
    };
    let Some(incumbent_binding) = incumbent_ladder.exact_offer_binding() else {
        return Ok(());
    };
    let Some(candidate_binding) = candidate_ladder.exact_offer_binding() else {
        return Ok(());
    };
    // Read quantities once for the SAME frozen window, before opening the core
    // writer. Invoice amounts and historical catalog bills never price either arm.
    let usage = server
        .usage_ledger
        .seat_usage(
            meter.owner(),
            meter.vault_id(),
            &role_key(role),
            None,
            offer.workload.from,
            offer.workload.until,
        )
        .map_err(|_| Error::InvalidConfig("the stock workload could not be read".into()))?;
    if !same_workload(offer, &usage) {
        return Ok(());
    }
    meter.with_quote_snapshot(|quotes| {
        vault.try_autoapprove_stock_offer(
            &offer.id,
            &offer.digest,
            judge.judge_revision(),
            now,
            |txn, current, measured, incumbent_row, candidate_row| {
                let Some((incumbent, candidate)) = measured.serving_offers() else {
                    return Ok(false);
                };
                if !incumbent.matches(incumbent_binding)
                    || !candidate.matches(candidate_binding)
                    || measured.request.requested_offers
                        != Some([
                            EvalServingOffer::from_binding(incumbent_binding),
                            EvalServingOffer::from_binding(candidate_binding),
                        ])
                {
                    return Ok(false);
                }
                let Some(incumbent_quote) = quotes.for_binding(incumbent_binding, incumbent_row)
                else {
                    return Ok(false);
                };
                let Some(candidate_quote) = quotes.for_binding(candidate_binding, candidate_row)
                else {
                    return Ok(false);
                };
                let (Some(before), Some(after)) = (&incumbent_quote.rates, &candidate_quote.rates)
                else {
                    return Ok(false);
                };
                if incumbent_quote.custom_endpoint
                    || candidate_quote.custom_endpoint
                    || !measured_prices_match(
                        measured,
                        incumbent_binding,
                        candidate_binding,
                        before,
                        after,
                    )
                    || !not_pricier(current, &usage, incumbent_row, candidate_row, before, after)
                {
                    return Ok(false);
                }
                // Both observations use the same runtime's captured managed worker.
                // A live registry or backend alone is never a positive file claim.
                let Some(card) = runtime.stock_download_card(&model.model) else {
                    return Ok(false);
                };
                if card.model != model.model || card.licence != *licence {
                    return Ok(false);
                }
                let present = runtime.stock_weights(&model.model).is_some_and(|files| {
                    files.get("model").and_then(serde_json::Value::as_str)
                        == Some(card.model.as_str())
                        && files
                            .get("manifest_sha256")
                            .and_then(serde_json::Value::as_str)
                            == Some(card.manifest_sha256.as_str())
                });
                Ok(present || vault.stock_download_card_seen_in_snapshot(txn, &card)?)
            },
        )
    })?;
    Ok(())
}

fn same_workload(offer: &TrainingOffer, usage: &SeatUsage) -> bool {
    let workload = &offer.workload;
    workload.complete
        && workload.from < workload.until
        && usage.metered_since.is_some_and(|at| at <= workload.from)
        && usage.calls != 0
        && workload.calls == Some(usage.calls)
        && workload.input_tokens == Some(usage.input_tokens)
        && workload.output_tokens == Some(usage.output_tokens)
        && workload.receipt_refs == usage.refs
        && usage.no_usage == 0
        && usage.undecodable == 0
        && usage.unclassified == 0
        && usage.counted_out == 0
        && usage.models.len() == 1
        && usage.models.contains_key(&offer.incumbent.model)
}

fn rates_match(current: &UsageCostRates, measured: &EvalMonetaryRates) -> bool {
    current.currency == measured.currency
        && current.price_table_snapshot == measured.price_table_snapshot
        && current.input_per_million == measured.input_per_million
        && current.output_per_million == measured.output_per_million
        && current.cache_read_per_million == measured.cache_read_per_million
        && current.cache_write_per_million == measured.cache_write_per_million
}

fn measured_prices_match(
    measured: &EvalMeasurement,
    incumbent: &OfferBinding,
    candidate: &OfferBinding,
    before: &UsageCostRates,
    after: &UsageCostRates,
) -> bool {
    let incumbent = incumbent.fingerprint();
    let candidate = candidate.fingerprint();
    measured.cases.iter().all(|case| {
        [
            (&case.incumbent, &incumbent, before),
            (&case.candidate, &candidate, after),
            (&case.retest, &incumbent, before),
        ]
        .into_iter()
        .all(|(leg, fingerprint, rates)| {
            leg.call_price.as_ref().is_some_and(|price| {
                price.binding_fingerprint == *fingerprint && rates_match(rates, &price.rates)
            })
        })
    })
}

/// Counts, not money, are projected by the host's measured tokenizer ratio.
/// Round upward throughout. Equal tokenizer ratios keep exact native counts.
fn scale(count: u64, incumbent: f64, candidate: f64) -> Option<u64> {
    if !incumbent.is_finite() || incumbent <= 0.0 || !candidate.is_finite() || candidate <= 0.0 {
        return None;
    }
    if count == 0 || incumbent == candidate {
        return Some(count);
    }
    let ratio = (candidate / incumbent).next_up();
    let projected = ((count as f64).next_up() * ratio).next_up().ceil();
    (projected.is_finite() && projected < u64::MAX as f64).then_some(projected as u64)
}

fn amount(rates: &UsageCostRates, counts: UsageTokenCounts) -> Option<u64> {
    if !rates.priced() || !rates.prices(&counts) {
        return None;
    }
    if rates.currency.is_none() && rates.free_in_any_currency() {
        return Some(0);
    }
    UsageCostInput {
        token_counts: counts,
        cost_rates: rates.clone(),
        service_amount: 0,
    }
    .calculate()
    .ok()
    .map(|money| money.amount)
}

fn not_pricier(
    offer: &TrainingOffer,
    usage: &SeatUsage,
    incumbent: &ModelRegistryRow,
    candidate: &ModelRegistryRow,
    before: &UsageCostRates,
    after: &UsageCostRates,
) -> bool {
    let compare = || -> Option<bool> {
        let incumbent_ratio = incumbent.tokens_per_o200k?;
        let candidate_ratio = candidate.tokens_per_o200k?;
        let input = usage
            .input_tokens
            .checked_sub(usage.cache_read_tokens)?
            .checked_sub(usage.cache_write_tokens)?;
        let baseline = UsageTokenCounts {
            input_tokens: input,
            output_tokens: usage.output_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            cache_write_tokens: usage.cache_write_tokens,
        };
        let candidate = UsageTokenCounts {
            input_tokens: scale(input, incumbent_ratio, candidate_ratio)?,
            output_tokens: scale(usage.output_tokens, incumbent_ratio, candidate_ratio)?,
            cache_read_tokens: scale(usage.cache_read_tokens, incumbent_ratio, candidate_ratio)?,
            cache_write_tokens: scale(usage.cache_write_tokens, incumbent_ratio, candidate_ratio)?,
        };
        // No FX or assumed currency. Native explicit all-zero prices are free
        // in any currency; every nonfree comparison names the same currency.
        if before.currency != after.currency
            && !before.free_in_any_currency()
            && !after.free_in_any_currency()
        {
            return None;
        }
        if !same_workload(offer, usage) {
            return None;
        }
        Some(amount(after, candidate)? <= amount(before, baseline)?)
    };
    compare().unwrap_or(false)
}
