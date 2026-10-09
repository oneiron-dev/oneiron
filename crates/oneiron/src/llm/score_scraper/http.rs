//! Bounded HTTPS JSON transport for configured score sources.
use super::{ScoreFetch, ScoreSourceConfig};
use crate::error::{Error, Result};
use std::{io::Read, time::Duration};

const MAX_SCORE_DOCUMENT_BYTES: u64 = 2 * 1024 * 1024;
const SCORE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Host-neutral, credential-free HTTPS GET adapter. The host owns source URLs
/// and any upstream proxy; redirects are refused to keep the configured target
/// from silently changing. Responses must be JSON within the byte ceiling.
pub struct HttpScoreFetch {
    client: reqwest::blocking::Client,
}

impl HttpScoreFetch {
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(SCORE_REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| transport_error("could not build benchmark HTTP client"))?;
        Ok(Self { client })
    }
}

fn transport_error(message: &str) -> Error {
    Error::Io(std::io::Error::other(message))
}

fn fetch_json(
    client: &reqwest::blocking::Client,
    url: &str,
    deadline: Duration,
) -> Result<serde_json::Value> {
    // Never include URL or peer-provided error bodies in errors: configured
    // URLs may carry secrets in query strings.
    let response = client
        .get(url)
        // The client timeout resets per blocking read in reqwest 0.12. A
        // request timeout also covers body completion while bytes trickle in.
        .timeout(deadline)
        .send()
        .map_err(|_| transport_error("benchmark GET failed"))?;
    if !response.status().is_success() {
        return Err(transport_error("benchmark GET returned non-success status"));
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_SCORE_DOCUMENT_BYTES)
    {
        return Err(transport_error("benchmark response exceeds byte limit"));
    }
    let mut body = Vec::new();
    response
        .take(MAX_SCORE_DOCUMENT_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| transport_error("could not read benchmark response"))?;
    if body.len() as u64 > MAX_SCORE_DOCUMENT_BYTES {
        return Err(transport_error("benchmark response exceeds byte limit"));
    }
    serde_json::from_slice(&body)
        .map_err(|_| transport_error("benchmark response is not valid JSON"))
}

impl ScoreFetch for HttpScoreFetch {
    fn fetch(&mut self, source: &ScoreSourceConfig) -> Result<serde_json::Value> {
        let url = reqwest::Url::parse(&source.url)
            .map_err(|_| transport_error("invalid benchmark HTTPS URL"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(transport_error("invalid benchmark HTTPS URL"));
        }
        fetch_json(&self.client, url.as_str(), SCORE_REQUEST_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_fetch_refuses_insecure_source() {
        let mut fetcher = HttpScoreFetch::new().unwrap();
        let source = ScoreSourceConfig {
            id: "bench".into(),
            url: "http://127.0.0.1/scores".into(),
            rows_pointer: "/data".into(),
            model_pointer: "/model".into(),
            score_pointer: "/score".into(),
            benchmark: "quality".into(),
            model_bindings: Default::default(),
        };
        assert!(fetcher.fetch(&source).is_err());
    }
}
