//! Usage telemetry events and per-token-type spans.
use super::allowance::ConsumerAllowanceWarning;
use super::ledger::UsageTelemetryOutcome;
use super::model::{UsageCost, UsageEvent, UsageMode, normalize_money, per_million_cost};

pub(super) fn emit_usage_telemetry(
    event: &UsageEvent,
    source: UsageMode,
    cost: &UsageCost,
    warning: &ConsumerAllowanceWarning,
    outcome: UsageTelemetryOutcome,
) {
    let role = event.role.as_deref().unwrap_or("unknown");
    let agent_id = event.agent_id.as_deref().unwrap_or("unknown");
    let model = event.model.as_deref().unwrap_or("unknown");
    let service = event.service.as_deref().unwrap_or("unknown");
    let warning_used_ratio = warning.used_ratio.unwrap_or(0.0);

    tracing::info!(
        target: "oneiron_server::usage",
        tenant_id = %event.tenant_id,
        account_id = %event.tenant_id,
        vault_id = %event.vault_id,
        role = %role,
        agent_id = %agent_id,
        model = %model,
        service = %service,
        provider_mode = %source.as_str(),
        event_type = %event.event_type.as_str(),
        prompt_tokens = event.token_counts.input_tokens,
        completion_tokens = event.token_counts.output_tokens,
        input_tokens = event.token_counts.input_tokens,
        output_tokens = event.token_counts.output_tokens,
        cache_read_tokens = event.token_counts.cache_read_tokens,
        cache_write_tokens = event.token_counts.cache_write_tokens,
        token_cost_usd = cost.token_cost_usd,
        cache_cost_usd = cost.cache_cost_usd,
        service_cost_usd = cost.service_cost_usd,
        cost_usd = cost.cost_usd,
        credit_units = cost.credit_units,
        allowance_warning_level = %warning.level.as_str(),
        allowance_warning_triggered = warning.triggered,
        allowance_warning_threshold_ratio = warning.threshold_ratio,
        allowance_warning_used_ratio = warning_used_ratio,
        recorded = outcome.recorded,
        replayed = outcome.replayed,
        debited = outcome.debited,
        "usage telemetry recorded"
    );

    emit_usage_token_span(
        event,
        source,
        role,
        "prompt",
        event.token_counts.input_tokens,
        per_million_cost(
            event.token_counts.input_tokens,
            event.cost_rates.input_token_usd_per_million,
        ),
    );
    emit_usage_token_span(
        event,
        source,
        role,
        "completion",
        event.token_counts.output_tokens,
        per_million_cost(
            event.token_counts.output_tokens,
            event.cost_rates.output_token_usd_per_million,
        ),
    );
    emit_usage_token_span(
        event,
        source,
        role,
        "cache_read",
        event.token_counts.cache_read_tokens,
        per_million_cost(
            event.token_counts.cache_read_tokens,
            event.cost_rates.cache_read_token_usd_per_million,
        ),
    );
    emit_usage_token_span(
        event,
        source,
        role,
        "cache_write",
        event.token_counts.cache_write_tokens,
        per_million_cost(
            event.token_counts.cache_write_tokens,
            event.cost_rates.cache_write_token_usd_per_million,
        ),
    );
}

fn emit_usage_token_span(
    event: &UsageEvent,
    source: UsageMode,
    role: &str,
    token_type: &'static str,
    tokens: u64,
    cost_usd: f64,
) {
    let span = tracing::info_span!(
        target: "oneiron_server::usage",
        "usage_token_type",
        tenant_id = %event.tenant_id,
        account_id = %event.tenant_id,
        role = %role,
        provider_mode = %source.as_str(),
        token_type = %token_type,
        tokens = tokens,
        cost_usd = normalize_money(cost_usd),
    );
    let _entered = span.enter();
    tracing::info!(
        target: "oneiron_server::usage",
        token_type = token_type,
        tokens = tokens,
        "usage token type recorded"
    );
}
