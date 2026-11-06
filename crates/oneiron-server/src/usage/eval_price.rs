//! A measured leg's snapshot of its existing native usage preparation.

use oneiron::llm::run_admission::OfferBinding;
use oneiron::skill_optimize::{EvalCallPrice, EvalMonetaryRates};

use super::{UsageError, UsageLedger, codec::decode_entry};

impl UsageLedger {
    /// Reads only a native captured settlement for this exact offer. Missing
    /// quotes, unpriced counts and a different billed route stay unknown.
    pub(crate) fn eval_call_price(
        raw: &[u8],
        binding: &OfferBinding,
        instance: &str,
        lease: &str,
    ) -> Result<Option<EvalCallPrice>, UsageError> {
        let stored = decode_entry(raw)?;
        let event = &stored.event;
        let Some(call) = &event.run else {
            return Ok(None);
        };
        if call.instance != instance
            || call.lease != lease
            || event.unpriced.is_some()
            || event.model.as_deref() != Some(binding.model.as_str())
            || call.offer != binding.offer
            || call.route != format!("{}@{}", binding.route.adapter(), binding.route.origin())
            || call.catalog_revision != binding.catalog_revision
            || call.payer != binding.payer
            || !call.usage_reported
            || event.service_amount != 0
        {
            return Ok(None);
        }
        let Some(rates) = &event.cost_rates else {
            return Ok(None);
        };
        let amount = match &stored.cost {
            Some(cost) => cost.amount,
            None if rates.currency.is_none() && rates.free_in_any_currency() => 0,
            None => return Ok(None),
        };
        let counts = &event.token_counts;
        Ok(Some(EvalCallPrice {
            binding_fingerprint: binding.fingerprint(),
            instance: call.instance.clone(),
            lease: call.lease.clone(),
            rates: EvalMonetaryRates {
                currency: rates.currency.clone(),
                price_table_snapshot: rates.price_table_snapshot.clone(),
                input_per_million: rates.input_per_million,
                output_per_million: rates.output_per_million,
                cache_read_per_million: rates.cache_read_per_million,
                cache_write_per_million: rates.cache_write_per_million,
            },
            input_tokens: counts.input_tokens,
            output_tokens: counts.output_tokens,
            cache_read_tokens: counts.cache_read_tokens,
            cache_write_tokens: counts.cache_write_tokens,
            amount,
            source_rows: stored.source_rows,
        }))
    }
}
