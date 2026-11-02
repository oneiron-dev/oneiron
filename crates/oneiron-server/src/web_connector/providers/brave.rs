//! Brave: Search-plan web search on the user's own key or the hub.
//! Brave's results are transient under its standard grant; this adapter keeps nothing.
use oneiron::web_connector::WebSearchInput;
use reqwest::blocking::Client;
use serde_json::Value;

use super::{Auth, ProviderAnswer, ProviderBody, ProviderError, get_json, hit, text};

const SEARCH_URL: &str = "https://api.search.brave.com/res/v1/web/search";

pub(super) fn search(
    client: &Client,
    key: &str,
    input: &WebSearchInput,
) -> Result<ProviderAnswer, ProviderError> {
    let reply = get_json(
        client,
        SEARCH_URL,
        Auth::Header("x-subscription-token"),
        key,
        &[
            ("q", input.query.clone()),
            ("count", input.result_count().to_string()),
        ],
    )?;
    let hits = reply
        .pointer("/web/results")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    let snippet = strip_tags(text(row, "description"));
                    hit(text(row, "title"), text(row, "url"), &snippet)
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(ProviderAnswer {
        body: ProviderBody::Hits(hits),
        cost_micro_usd: None,
        request_id: None,
    })
}

/// `html` with every `<...>` run removed, as Brave wraps matches in `<strong>`.
fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            if in_tag {
                in_tag = false;
            } else {
                out.push(ch);
            }
        } else if !in_tag {
            out.push(ch);
        }
    }
    out
}
