//! Octen: web search with highlights and standard extraction.
//! octen.ai runs only on the user's own key or the hub (§4.3).
//! octen.ai results may be cached 24 h at most and never stored (§4.6); this adapter keeps nothing.
use oneiron::web_connector::{WebFetchInput, WebSearchInput};
use reqwest::blocking::Client;
use serde_json::{Value, json};

use super::{Auth, ProviderAnswer, ProviderBody, ProviderError, hit, post_json, text, text_opt};

const SEARCH_URL: &str = "https://api.octen.ai/search";
const EXTRACT_URL: &str = "https://api.octen.ai/extract";

pub(super) fn search(
    client: &Client,
    key: &str,
    input: &WebSearchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let body = json!({
        "query": input.query,
        "count": input.result_count(),
        "format": "text",
    });
    let reply = post_json(client, SEARCH_URL, Auth::Header("x-api-key"), key, &body)?;
    if let Some(error) = envelope_error(&reply) {
        return Err(error);
    }
    let hits = reply
        .pointer("/data/results")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    let snippet = match row.get("highlight") {
                        Some(Value::String(highlight)) => highlight.clone(),
                        Some(Value::Array(parts)) => parts
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" "),
                        _ => String::new(),
                    };
                    hit(text(row, "title"), text(row, "url"), &snippet)
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(ProviderAnswer {
        body: ProviderBody::Hits(hits),
        cost_micro_usd: None,
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
        "mode": "standard",
        "format": "markdown",
    });
    let reply = post_json(client, EXTRACT_URL, Auth::Header("x-api-key"), key, &body)?;
    if let Some(error) = envelope_error(&reply) {
        return Err(error);
    }
    let page = reply
        .pointer("/data/results")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first());
    let failed = page
        .and_then(|row| row.get("status"))
        .and_then(Value::as_str)
        == Some("failed");
    if failed || page.is_none() {
        let reason = reply
            .pointer("/data/results/0/error_message")
            .and_then(Value::as_str)
            .filter(|reason| !reason.trim().is_empty())
            .unwrap_or("the page was not read");
        return Err(ProviderError::message(reason));
    }
    let Some(page) = page else {
        return Err(ProviderError::message("the page was not read"));
    };
    Ok(ProviderAnswer {
        body: ProviderBody::Page {
            url: text_opt(page, "url").unwrap_or_else(|| input.url.clone()),
            title: text_opt(page, "title"),
            content: text(page, "full_content").to_owned(),
        },
        cost_micro_usd: None,
        request_id: text_opt(&reply, "request_id"),
    })
}

/// The envelope's `code`/`msg` as an error, when `code` is present and not 0.
fn envelope_error(reply: &Value) -> Option<ProviderError> {
    let code = reply.get("code")?.as_u64()?;
    if code == 0 {
        return None;
    }
    let msg = reply
        .get("msg")
        .and_then(Value::as_str)
        .filter(|msg| !msg.trim().is_empty())
        .unwrap_or("the provider refused the call");
    let mut error = ProviderError::message(msg);
    if let Ok(status) = u16::try_from(code) {
        error.status = Some(status);
    }
    Some(error)
}
