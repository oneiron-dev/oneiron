//! Local-service and HTTPS crossencoder adapters, with a nonblocking prepared pipeline rung.
//! Models and endpoints are host configuration. No model weights ship in the engine.
use super::{RerankCandidate, Reranker};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::BudgetLease;
use crate::retrieval_depth::{BackendSpend, DeepSearchBackend, RetrievalError, RetrievalResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_REQUEST_BYTES: usize = 1_048_576;
const MAX_RESPONSE_BYTES: u64 = 1_048_576;
const MAX_CANDIDATES: usize = 50;

/// A host-selected local loopback service or remote HTTPS model.
/// The service implements the indexed `/rerank` response contract.
/// Use `prepare` outside engine transactions, then attach its returned rung to a pipeline.
pub struct CrossEncoder {
    timeout: Duration,
    endpoint: reqwest::Url,
    model: String,
    identity: String,
    bearer: Option<Zeroizing<String>>,
    documents: BTreeMap<EntityId, String>,
}

#[derive(Serialize)]
struct ScoreRequest<'a> {
    model: &'a str,
    query: &'a str,
    documents: &'a [String],
    top_n: usize,
    return_documents: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_budget: Option<u64>,
}
#[derive(Deserialize)]
struct ScoreResponse {
    results: Vec<IndexedScore>,
    usage: Usage,
}
#[derive(Deserialize)]
struct IndexedScore {
    index: usize,
    relevance_score: f32,
}
#[derive(Deserialize)]
struct Usage {
    total_tokens: u64,
}

impl CrossEncoder {
    /// Local inference service: literal loopback address only, no proxy or redirects.
    pub fn local(endpoint: &str, model: &str, timeout: Duration) -> Result<Self> {
        Self::build(endpoint, model, timeout, None, true)
    }
    /// Explicit remote inference opt-in. HTTPS and a nonempty credential are required.
    /// Endpoint/model/credential come from trusted host configuration, never query text.
    pub fn remote(endpoint: &str, model: &str, bearer: String, timeout: Duration) -> Result<Self> {
        if bearer.is_empty() {
            return Err(invalid("remote crossencoder requires credentials"));
        }
        Self::build(endpoint, model, timeout, Some(bearer), false)
    }
    fn build(
        endpoint: &str,
        model: &str,
        timeout: Duration,
        bearer: Option<String>,
        local: bool,
    ) -> Result<Self> {
        let endpoint =
            reqwest::Url::parse(endpoint).map_err(|_| invalid("invalid crossencoder endpoint"))?;
        let loopback = endpoint
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        if model.trim().is_empty()
            || timeout.is_zero()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
            || endpoint.query().is_some()
            || (local && (!loopback || !matches!(endpoint.scheme(), "http" | "https")))
            || (!local && endpoint.scheme() != "https")
        {
            return Err(invalid("invalid crossencoder host configuration"));
        }
        let mut hash = Sha256::new();
        hash.update(endpoint.as_str());
        hash.update([0]);
        hash.update(model);
        let identity = format!("crossencoder:{:x}", hash.finalize());
        Ok(Self {
            timeout,
            endpoint,
            model: model.to_owned(),
            identity,
            bearer: bearer.map(Zeroizing::new),
            documents: BTreeMap::new(),
        })
    }
    /// Supplies text for non-claim candidates. Only admitted candidate ids are sent.
    pub fn with_documents(mut self, documents: BTreeMap<EntityId, String>) -> Self {
        self.documents = documents;
        self
    }
    fn score(
        &self,
        query: &str,
        candidates: &[RerankCandidate<'_>],
        token_budget: Option<u64>,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        if candidates.is_empty() {
            return Ok(BackendSpend::free(Vec::new()));
        }
        if query.trim().is_empty() || candidates.len() > MAX_CANDIDATES || token_budget == Some(0) {
            return Err(invalid("invalid crossencoder batch").into());
        }
        let documents = candidates
            .iter()
            .map(|candidate| {
                if let Some(claim) = candidate.claim {
                    // The admitted claim body, not an unscoped second database read.
                    let value = crate::companion::companion_value_to_json(&claim.value);
                    Ok(format!("{}: {}", claim.predicate, value))
                } else {
                    self.documents
                        .get(&candidate.id)
                        .cloned()
                        .ok_or_else(|| invalid("crossencoder candidate text missing"))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let body = serde_json::to_vec(&ScoreRequest {
            model: &self.model,
            query,
            documents: &documents,
            top_n: candidates.len(),
            return_documents: false,
            token_budget,
        })
        .map_err(|_| invalid("cannot encode crossencoder request"))?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(invalid("crossencoder request too large").into());
        }
        // Blocking reqwest owns a runtime. Create/use/drop it on a dedicated
        // worker, never on an async caller's executor thread or under LMDB.
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.send_batch(body, candidates.len(), token_budget))
                .join()
                .map_err(|_| {
                    RetrievalError::from(invalid("crossencoder transport worker failed"))
                })?
        })
    }

    fn send_batch(
        &self,
        body: Vec<u8>,
        count: usize,
        token_budget: Option<u64>,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout)
            .build()
            .map_err(|_| invalid("crossencoder HTTP client unavailable"))?;
        let mut request = client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(bearer) = &self.bearer {
            request = request.bearer_auth(bearer.as_str());
        }
        let response = request
            .send()
            .map_err(|_| invalid("crossencoder transport failed"))?;
        if !response.status().is_success() {
            return Err(invalid("crossencoder refused request").into());
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid("crossencoder response read failed"))?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(invalid("crossencoder response too large").into());
        }
        let response: ScoreResponse =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid crossencoder response"))?;
        validate_response(response, count, token_budget)
    }
    /// Performs inference outside the pipeline read transaction. The returned rung is immutable.
    /// The caller owns and settles the supplied lease using the returned actual usage.
    pub fn prepare(
        &self,
        query: &str,
        candidates: &[RerankCandidate<'_>],
        token_budget: Option<u64>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<PreparedCrossEncoder>> {
        let scored = self.score(query, candidates, token_budget)?;
        let fingerprint = fingerprint(query, candidates)?;
        // Prepared lookup contents are part of the fork identity, including
        // non-claim text which the pipeline's candidate DTO does not carry.
        let mut identity = Sha256::new();
        identity.update(&self.identity);
        identity.update(fingerprint);
        for candidate in candidates {
            if candidate.claim.is_none() {
                let document = self
                    .documents
                    .get(&candidate.id)
                    .ok_or_else(|| invalid("crossencoder candidate text missing"))?;
                identity.update((document.len() as u64).to_le_bytes());
                identity.update(document);
            }
        }
        for score in &scored.value {
            identity.update(score.to_bits().to_le_bytes());
        }
        Ok(BackendSpend {
            tokens_used: scored.tokens_used,
            value: PreparedCrossEncoder {
                identity: format!("{}:prepared:{:x}", self.identity, identity.finalize()),
                fingerprint,
                scores: scored.value,
            },
        })
    }
}

/// A completed batch. `rerank` performs no network, inference, locks or lazy initialization.
pub struct PreparedCrossEncoder {
    identity: String,
    fingerprint: [u8; 32],
    scores: Vec<f32>,
}
impl Reranker for PreparedCrossEncoder {
    fn id(&self) -> &str {
        &self.identity
    }
    fn rerank(&self, query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        if fingerprint(query, candidates)? != self.fingerprint {
            return Err(invalid("prepared crossencoder candidate snapshot changed"));
        }
        Ok(self.scores.clone())
    }
}
impl DeepSearchBackend for CrossEncoder {
    fn decompose(
        &self,
        _query: &str,
        _already_run: &[String],
        _max_queries: usize,
        _token_budget: Option<u64>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        // A crossencoder scores pairs; it is not a generative decomposer.
        Ok(BackendSpend::free(Vec::new()))
    }
    fn rerank(
        &self,
        query: &str,
        candidates: &[RerankCandidate<'_>],
        token_budget: Option<u64>,
        _lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        self.score(query, candidates, token_budget)
    }
}
fn validate_response(
    response: ScoreResponse,
    count: usize,
    budget: Option<u64>,
) -> RetrievalResult<BackendSpend<Vec<f32>>> {
    let used = response.usage.total_tokens;
    let failure = || RetrievalError {
        error: invalid("crossencoder score coverage or value invalid"),
        tokens_used: used,
    };
    if response.results.len() != count {
        return Err(failure());
    }
    let mut scores = vec![None; count];
    for row in response.results {
        if row.index >= count || !row.relevance_score.is_finite() || scores[row.index].is_some() {
            return Err(failure());
        }
        scores[row.index] = Some(row.relevance_score);
    }
    let value = scores
        .into_iter()
        .map(|score| score.ok_or_else(&failure))
        .collect::<RetrievalResult<Vec<_>>>()?;
    BackendSpend {
        value,
        tokens_used: used,
    }
    .enforce_token_budget(budget)
}
fn fingerprint(query: &str, candidates: &[RerankCandidate<'_>]) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update((query.len() as u64).to_le_bytes());
    hash.update(query);
    for candidate in candidates {
        hash.update(candidate.id.as_bytes());
        hash.update(candidate.score.to_bits().to_le_bytes());
        hash.update(candidate.rank.to_le_bytes());
        let claim = match candidate.claim {
            Some(body) => crate::claim::encode_claim_body(body)?,
            None => Vec::new(),
        };
        hash.update((claim.len() as u64).to_le_bytes());
        hash.update(claim);
    }
    Ok(hash.finalize().into())
}
fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

#[cfg(test)]
mod tests;
