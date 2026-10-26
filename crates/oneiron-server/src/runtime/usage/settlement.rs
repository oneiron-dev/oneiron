//! Attribution and durable recording of served run receipts.
//! Admission freezes rates and payer; settlement consumes that same call record.
//! Usage state, configuration, and the catalog pricing child stay in the parent.

use super::{
    AdmittedCall, Payer, PayerAccount, RunEvent, RunReceipt, UnpricedReason, UsageAllocation,
    UsageEvent, UsageEventOrigin, UsageEventType, UsageMode, UsageRun, UsageTokenCounts,
    VaultUsage,
};

impl VaultUsage {
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
                inference_calls: _,
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
                // rates were frozen on it at admission; they name no currency
                // and are not free in any (FIX 9534); or they quote no rate
                // for cache dimensions it measured, named.
                let measured = usage_reported && usage.is_some();
                let unpriced = match &rates {
                    Some(rates) if measured && rates.prices(&token_counts) && rates.priced() => {
                        None
                    }
                    _ if token_counts == UsageTokenCounts::default() => {
                        Some(UnpricedReason::NoUsage)
                    }
                    None => Some(UnpricedReason::UnpricedModel),
                    Some(rates) if !rates.priced() => Some(UnpricedReason::UnknownCurrency),
                    Some(rates) => Some(UnpricedReason::UnquotedCache {
                        dimensions: rates.unquoted_cache(&token_counts),
                    }),
                };
                // A priced call keeps the rates it is priced at; one unpriced
                // for their unknown currency keeps them too, their snapshot
                // and digest with them.
                let rates = rates
                    .filter(|_| matches!(unpriced, None | Some(UnpricedReason::UnknownCurrency)));
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
                // The call's identity, for its log line once the event moves
                // into the ledger.
                let idempotency_key = event.idempotency_key.clone();
                match self.ledger.record_event_sourced(
                    event,
                    source,
                    UsageEventOrigin::Engine,
                    source_rows,
                ) {
                    // Recorded with its counts and frozen rates, and no price:
                    // its price at them does not fit in an amount (FIX 6407).
                    Ok(recorded) if recorded.unpriced == Some(UnpricedReason::PriceOverflow) => {
                        tracing::warn!(
                            vault_id = %self.vault_id,
                            %idempotency_key,
                            replayed = recorded.replayed,
                            reason = "price_overflow",
                            "a settled call was recorded without a representable price"
                        );
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::error!(
                            vault_id = %self.vault_id,
                            %idempotency_key,
                            ?error,
                            "served run usage could not be persisted"
                        );
                    }
                }
            }
            _ => {}
        }
    }
}
