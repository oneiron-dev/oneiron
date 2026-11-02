//! context.dev: web search and scrape, one credit a call, on the user's own
//! key or the hub. The declared price estimates the cost; the reply carries
//! credits only.
use oneiron::web_connector::{WebFetchInput, WebSearchInput};
use reqwest::blocking::Client;
use serde_json::{Value, json};

use super::{Auth, ProviderAnswer, ProviderBody, ProviderError, hit, post_json, text, text_opt};

const SEARCH_URL: &str = "https://api.context.dev/v1/web/search";
const SCRAPE_URL: &str = "https://api.context.dev/v1/web/scrape";

pub(super) fn search(
    client: &Client,
    key: &str,
    input: &WebSearchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let body = json!({
        "query": input.query,
        "numResults": input.result_count(),
    });
    let reply = post_json(client, SEARCH_URL, Auth::Bearer, key, &body)?;
    let hits = reply
        .get("results")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    hit(
                        text(row, "title"),
                        text(row, "url"),
                        text(row, "description"),
                    )
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
        "url": input.url,
        "formats": {"markdown": true},
    });
    let reply = post_json(client, SCRAPE_URL, Auth::Bearer, key, &body)?;
    if reply.pointer("/markdown/success").and_then(Value::as_bool) != Some(true) {
        let reason = reply
            .get("message")
            .and_then(Value::as_str)
            .filter(|reason| !reason.trim().is_empty())
            .unwrap_or("the page was not read");
        return Err(ProviderError::message(reason));
    }
    Ok(ProviderAnswer {
        body: ProviderBody::Page {
            url: input.url.clone(),
            title: reply
                .pointer("/metadata/title")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|title| !title.is_empty())
                .map(str::to_owned),
            content: reply
                .pointer("/markdown/data")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        },
        cost_micro_usd: None,
        request_id: text_opt(&reply, "request_id"),
    })
}
