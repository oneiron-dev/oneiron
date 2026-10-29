//! Tinyfish: TinySearch and TinyFetch, free within their daily allowances, on
//! the user's own key or the hub (internal-use terms).
use oneiron::web_connector::{WebFetchInput, WebSearchInput};
use reqwest::blocking::Client;
use serde_json::{Value, json};

use super::{
    Auth, ProviderAnswer, ProviderBody, ProviderError, get_json, hit, post_json, text, text_opt,
};

const SEARCH_URL: &str = "https://api.search.tinyfish.ai";
const FETCH_URL: &str = "https://api.fetch.tinyfish.ai";

pub(super) fn search(
    client: &Client,
    key: &str,
    input: &WebSearchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let reply = get_json(
        client,
        SEARCH_URL,
        Auth::Header("x-api-key"),
        key,
        &[("query", input.query.clone())],
    )?;
    let limit = input.result_count() as usize;
    let hits = reply
        .get("results")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .take(limit)
                .map(|row| hit(text(row, "title"), text(row, "url"), text(row, "snippet")))
                .collect()
        })
        .unwrap_or_default();
    Ok(ProviderAnswer {
        body: ProviderBody::Hits(hits),
        cost_micro_usd: None,
        request_id: None,
    })
}

pub(super) fn fetch(
    client: &Client,
    key: &str,
    input: &WebFetchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let body = json!({
        "urls": [input.url],
        "format": "markdown",
    });
    let reply = post_json(client, FETCH_URL, Auth::Header("x-api-key"), key, &body)?;
    let Some(page) = reply
        .get("results")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
    else {
        let reason = reply
            .pointer("/errors/0/error")
            .and_then(Value::as_str)
            .filter(|reason| !reason.trim().is_empty())
            .unwrap_or("the page was not read");
        return Err(ProviderError::message(reason));
    };
    Ok(ProviderAnswer {
        body: ProviderBody::Page {
            url: text_opt(page, "final_url")
                .or_else(|| text_opt(page, "url"))
                .unwrap_or_else(|| input.url.clone()),
            title: text_opt(page, "title"),
            content: text(page, "text").to_owned(),
        },
        cost_micro_usd: None,
        request_id: None,
    })
}
