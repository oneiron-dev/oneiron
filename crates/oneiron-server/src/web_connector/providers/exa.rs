//! Exa: auto search with highlights and contents text, on the user's own key
//! or the hub (Exa §4.2). The cost a row records is the `costDollars.total`
//! the reply reports.
use oneiron::web_connector::{FETCH_CONTENT_MAX_CHARS, WebFetchInput, WebSearchInput};
use reqwest::blocking::Client;
use serde_json::{Value, json};

use super::{
    Auth, ProviderAnswer, ProviderBody, ProviderError, hit, post_json, text, text_opt, usd_micro,
};

const SEARCH_URL: &str = "https://api.exa.ai/search";
const CONTENTS_URL: &str = "https://api.exa.ai/contents";

pub(super) fn search(
    client: &Client,
    key: &str,
    input: &WebSearchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let body = json!({
        "query": input.query,
        "numResults": input.result_count(),
        "type": "auto",
        "contents": {"highlights": true},
    });
    let reply = post_json(client, SEARCH_URL, Auth::Header("x-api-key"), key, &body)?;
    let hits = reply
        .get("results")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    let snippet = row
                        .get("highlights")
                        .and_then(Value::as_array)
                        .map(|highlights| {
                            highlights
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .filter(|joined| !joined.trim().is_empty())
                        .unwrap_or_else(|| text(row, "text").to_owned());
                    hit(text(row, "title"), text(row, "url"), &snippet)
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(ProviderAnswer {
        body: ProviderBody::Hits(hits),
        cost_micro_usd: usd_micro(reply.pointer("/costDollars/total").and_then(Value::as_f64)),
        request_id: text_opt(&reply, "requestId"),
    })
}

pub(super) fn fetch(
    client: &Client,
    key: &str,
    input: &WebFetchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let body = json!({
        "urls": [input.url],
        "text": {"maxCharacters": FETCH_CONTENT_MAX_CHARS},
    });
    let reply = post_json(client, CONTENTS_URL, Auth::Header("x-api-key"), key, &body)?;
    let failed = reply
        .pointer("/statuses/0/status")
        .and_then(Value::as_str)
        .is_some_and(|status| status != "success");
    let Some(page) = reply
        .get("results")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
    else {
        return Err(ProviderError::message(fetch_failure(&reply)));
    };
    if failed {
        return Err(ProviderError::message(fetch_failure(&reply)));
    }
    Ok(ProviderAnswer {
        body: ProviderBody::Page {
            url: text_opt(page, "url").unwrap_or_else(|| input.url.clone()),
            title: text_opt(page, "title"),
            content: text(page, "text").to_owned(),
        },
        cost_micro_usd: usd_micro(reply.pointer("/costDollars/total").and_then(Value::as_f64)),
        request_id: text_opt(&reply, "requestId"),
    })
}

/// The first status row's `error` or `source`, when it names one.
fn fetch_failure(reply: &Value) -> &str {
    reply
        .pointer("/statuses/0/error")
        .and_then(Value::as_str)
        .or_else(|| reply.pointer("/statuses/0/source").and_then(Value::as_str))
        .filter(|reason| !reason.trim().is_empty())
        .unwrap_or("the page was not read")
}
