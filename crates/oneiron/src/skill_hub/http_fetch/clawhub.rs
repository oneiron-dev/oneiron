//! Public ClawHub-compatible search. Results are locators, never pinned packages.
use super::{HttpEndpointSkillHubAdapter, INDEX_LIMIT};
use crate::error::Result;
use crate::skill_hub::package_codec::invalid;
use serde::{Deserialize, Serialize};
use std::io::Read;

/// Public provider metadata. Missing fields do not become package identity.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClawHubSearchHit {
    pub score: Option<f64>,
    pub slug: Option<String>,
    pub display_name: Option<String>,
    pub summary: Option<String>,
    pub version: Option<String>,
    pub updated_at: Option<f64>,
    pub owner_handle: Option<String>,
    pub owner: Option<ClawHubSearchOwner>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClawHubSearchOwner {
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub image: Option<String>,
}

/// Provider failures remain distinct from a successful search with no hits.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ClawHubSearchReply {
    Results {
        /// None means the provider omitted its list, not a confirmed empty list.
        results: Option<Vec<ClawHubSearchHit>>,
    },
    ProviderError {
        status: u16,
        retry_after: Option<String>,
        body: String,
    },
}

#[derive(Deserialize)]
struct SearchResponse {
    results: Option<Vec<ClawHubSearchHit>>,
}

impl HttpEndpointSkillHubAdapter {
    /// Queries `/api/v1/search` on this configured origin, without fetching or
    /// admitting a package. Optional filters are sent only when requested.
    /// The response budget defaults to the existing HTTP index budget and is
    /// caller-overridable; it is not an upstream query parameter.
    pub fn search_clawhub(
        &self,
        q: &str,
        limit: Option<i64>,
        highlighted_only: Option<bool>,
        non_suspicious_only: Option<bool>,
        response_limit_bytes: Option<usize>,
    ) -> Result<ClawHubSearchReply> {
        let mut url = self
            .endpoint
            .join("/api/v1/search")
            .map_err(|_| invalid("invalid ClawHub search URL"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("q", q);
            if let Some(limit) = limit {
                query.append_pair("limit", &limit.to_string());
            }
            if let Some(highlighted_only) = highlighted_only {
                query.append_pair(
                    "highlightedOnly",
                    if highlighted_only { "true" } else { "false" },
                );
            }
            if let Some(non_suspicious_only) = non_suspicious_only {
                query.append_pair(
                    "nonSuspiciousOnly",
                    if non_suspicious_only { "true" } else { "false" },
                );
            }
        }
        let mut response = self
            .client
            .get(url)
            .send()
            .map_err(|_| invalid("ClawHub search transport failed"))?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        let budget = response_limit_bytes.unwrap_or(INDEX_LIMIT);
        if response.content_length().is_some_and(|n| n > budget as u64) {
            return Err(invalid(
                "ClawHub search response exceeds requested byte budget",
            ));
        }
        let mut body = Vec::new();
        response
            .by_ref()
            .take((budget as u64).saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|_| invalid("ClawHub search response read failed"))?;
        if body.len() > budget {
            return Err(invalid(
                "ClawHub search response exceeds requested byte budget",
            ));
        }
        if !status.is_success() {
            return Ok(ClawHubSearchReply::ProviderError {
                status: status.as_u16(),
                retry_after,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        let response: SearchResponse = serde_json::from_slice(&body)
            .map_err(|_| invalid("invalid ClawHub search response"))?;
        Ok(ClawHubSearchReply::Results {
            results: response.results,
        })
    }
}
