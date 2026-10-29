//! Tavily: basic search and basic extraction, the launch default on the
//! deploy's backend key (CONN-1 A). Both ask for `usage`, so the cost a row
//! records is the credits Tavily reports, at the PAYG price per credit.
use oneiron::web_connector::{WebFetchInput, WebSearchInput};
use reqwest::blocking::Client;
use serde_json::{Value, json};

use super::{Auth, ProviderAnswer, ProviderBody, ProviderError, hit, post_json, text, text_opt};

const SEARCH_URL: &str = "https://api.tavily.com/search";
const EXTRACT_URL: &str = "https://api.tavily.com/extract";
/// PAYG price of one credit: $0.008.
const MICRO_USD_PER_CREDIT: f64 = 8_000.0;

pub(super) fn search(
    client: &Client,
    key: &str,
    input: &WebSearchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let body = json!({
        "query": input.query,
        "search_depth": "basic",
        "max_results": input.result_count(),
        "include_answer": false,
        "include_raw_content": false,
        "include_usage": true,
    });
    let reply = post_json(client, SEARCH_URL, Auth::Bearer, key, &body)?;
    let hits = reply
        .get("results")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| hit(text(row, "title"), text(row, "url"), text(row, "content")))
                .collect()
        })
        .unwrap_or_default();
    Ok(ProviderAnswer {
        body: ProviderBody::Hits(hits),
        cost_micro_usd: credits_cost(&reply),
        request_id: text_opt(&reply, "request_id"),
    })
}

pub(super) fn fetch(
    client: &Client,
    key: &str,
    input: &WebFetchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let body = json!({
        "urls": [input.url],
        "extract_depth": "basic",
        "format": "markdown",
        "include_usage": true,
    });
    let reply = post_json(client, EXTRACT_URL, Auth::Bearer, key, &body)?;
    let Some(page) = reply
        .get("results")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
    else {
        let reason = reply
            .pointer("/failed_results/0/error")
            .and_then(Value::as_str)
            .unwrap_or("the page was not read");
        return Err(ProviderError::message(reason));
    };
    Ok(ProviderAnswer {
        body: ProviderBody::Page {
            url: text_opt(page, "url").unwrap_or_else(|| input.url.clone()),
            title: text_opt(page, "title"),
            content: text(page, "raw_content").to_owned(),
        },
        cost_micro_usd: credits_cost(&reply),
        request_id: text_opt(&reply, "request_id"),
    })
}

/// The reply's `usage.credits` at the PAYG price, when it carries them.
fn credits_cost(reply: &Value) -> Option<u64> {
    super::usd_micro(
        reply
            .pointer("/usage/credits")
            .and_then(Value::as_f64)
            .map(|credits| credits * MICRO_USD_PER_CREDIT / 1_000_000.0),
    )
}
