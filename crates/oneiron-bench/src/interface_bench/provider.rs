//! Paid-call admission and settlement on the engine ledger, with deadline-bound 429 waits.
use super::config_types::{
    CallAccounting, ChatResponse, OPENROUTER_CHAT_COMPLETIONS, RunSettings, WALL_CLOCK_CAP_S,
};
use super::wire_and_scoring::{openrouter_request_body, pinned_transmit_attestation};
use rand::Rng;
use serde_json::Value;
use std::time::{Duration, Instant};

pub(super) fn call_openrouter(
    api_key: &str,
    messages: &[Value],
    max_tokens: u32,
    request_user: &str,
    settings: &RunSettings,
) -> Result<ChatResponse, String> {
    if api_key.is_empty() || api_key.contains(['\r', '\n']) {
        return Err("provider_credential_missing_or_invalid".into());
    }
    let request = openrouter_request_body(messages, max_tokens, request_user, settings);
    pinned_transmit_attestation(settings, &request)?;
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    // Tokenizer estimate plus the pinned output bound, not measured provider usage.
    let reserve = (oneiron::count_context_pack_tokens(&request.to_string()) as u64)
        .saturating_add(u64::from(max_tokens));
    let lease = settings
        .campaign_budget
        .admit_reserve(reserve)
        .map_err(|_| "campaign_token_lease_unavailable".to_owned())?
        .lease;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(u64::from(WALL_CLOCK_CAP_S));
    let (mut wait_s, mut rate_count, mut backoff) = (0.0, 0_u64, 1.0_f64);
    let mut body = Value::Null;
    let failure = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Some("provider_deadline_exceeded".to_owned());
        }
        let response = client
            .post(OPENROUTER_CHAT_COMPLETIONS)
            .bearer_auth(api_key)
            .json(&request)
            .timeout(remaining)
            .send();
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                break Some(
                    if error.is_timeout() {
                        "provider_deadline_exceeded"
                    } else {
                        "provider_transport_failure"
                    }
                    .to_owned(),
                );
            }
        };
        let status = response.status();
        if status.as_u16() == 429 {
            rate_count = rate_count.saturating_add(1);
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<f64>().ok())
                .filter(|v| v.is_finite() && *v >= 0.0)
                .unwrap_or(0.0);
            let seconds = (backoff + rand::thread_rng().gen_range(0.0..1.0_f64)).max(retry_after);
            // A ceiling on the backoff interval is not a retry or work-count cap.
            backoff = (backoff * 2.0).min(60.0);
            let remaining = deadline.saturating_duration_since(Instant::now());
            let pause = Duration::from_secs_f64(seconds.min(remaining.as_secs_f64()));
            drop(response);
            let waiting = Instant::now();
            std::thread::sleep(pause);
            wait_s += waiting.elapsed().as_secs_f64();
            continue;
        }
        body = match response.json::<Value>() {
            Ok(value) => value,
            Err(error) => {
                break Some(
                    if error.is_timeout() {
                        "provider_deadline_exceeded"
                    } else {
                        "provider_invalid_json"
                    }
                    .to_owned(),
                );
            }
        };
        break (!status.is_success()).then(|| format!("provider_http_{}", status.as_u16()));
    };
    let provider_tokens = valid_usage(&body);
    let usage_reason = provider_tokens.is_none().then(|| {
        if body.get("usage").is_none() {
            "provider_usage_missing"
        } else {
            "provider_usage_invalid"
        }
        .to_owned()
    });
    // Settle before the caller can admit another answer or judge. Missing terminal
    // usage charges the reservation, but that charge never becomes measured usage.
    let charged_tokens = provider_tokens.map_or(reserve, u64::from);
    if let Some(tokens) = provider_tokens {
        settings
            .campaign_budget
            .settle_usage(&lease, u64::from(tokens))
    } else {
        settings.campaign_budget.settle_reserved(&lease)
    }
    .map_err(|_| "campaign_token_settlement_failed".to_owned())?;
    let content = body["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_owned);
    let failure = failure.or_else(|| content.is_none().then(|| "provider_missing_content".into()));
    Ok(ChatResponse {
        content: content.unwrap_or_default(),
        generation_id: body["id"].as_str().map(str::to_owned),
        accounting: CallAccounting {
            provider_tokens,
            usage_reason,
            reserved_tokens: reserve,
            charged_tokens,
            rate_limit_wait_s: wait_s,
            rate_limit_count: rate_count,
            failure_cause: failure,
        },
    })
}

fn valid_usage(body: &Value) -> Option<u32> {
    let usage = body.get("usage")?;
    let total = usage.get("total_tokens")?.as_u64().filter(|n| *n > 0)?;
    // If either component is supplied, both must be well-formed and consistent.
    if usage.get("prompt_tokens").is_some() || usage.get("completion_tokens").is_some() {
        let input = usage.get("prompt_tokens")?.as_u64()?;
        let output = usage.get("completion_tokens")?.as_u64()?;
        if input.checked_add(output)? != total {
            return None;
        }
    }
    u32::try_from(total).ok()
}
