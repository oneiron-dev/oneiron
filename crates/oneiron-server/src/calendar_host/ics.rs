//! Conditional ICS GET at the secret-custody door. No resolved URL leaves it.
use std::io::Read;
use std::sync::Arc;

use oneiron::Vault;
use oneiron::calendar::ingest::{IcsFeedPollConfig, IcsHttpResponse, IcsHttpTransport};
use oneiron::consent::AuthenticatedOwner;

const MAX_FEED_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) struct HttpIcsFeed {
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    config: IcsFeedPollConfig,
    client: reqwest::blocking::Client,
}

impl HttpIcsFeed {
    pub(crate) fn new(
        vault: Arc<Vault>,
        owner: AuthenticatedOwner,
        config: IcsFeedPollConfig,
    ) -> Result<Self, String> {
        Ok(Self {
            vault,
            owner,
            config,
            client: super::client().map_err(|_| "ICS HTTP client unavailable".to_owned())?,
        })
    }
}

impl IcsHttpTransport for HttpIcsFeed {
    fn get(&self, url: &str, if_none_match: Option<&str>) -> Result<IcsHttpResponse, String> {
        let url = reqwest::Url::parse(url).map_err(|_| "ICS feed URL is invalid")?;
        let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]" | "::1"));
        if !(url.scheme() == "https" || url.scheme() == "http" && local)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err("ICS feed requires HTTPS or loopback HTTP without embedded credentials or fragment".into());
        }
        oneiron::calendar::ingest::feed_door::check_installed_feed(
            &self.vault, &self.owner, &self.config,
        ).map_err(|_| "ICS feed owner or installation no longer admits this poll")?;
        let mut request = self.client.get(url);
        if let Some(etag) = if_none_match {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let response = request.send().map_err(|_| "ICS feed request failed")?;
        let status = response.status().as_u16();
        let etag = response.headers().get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok()).map(str::to_owned);
        let mut body = Vec::new();
        if status == 200 {
            let expected = response.content_length();
            response.take(MAX_FEED_BYTES + 1).read_to_end(&mut body)
                .map_err(|_| "ICS feed response is incomplete")?;
            if body.len() as u64 > MAX_FEED_BYTES {
                return Err("ICS feed response is too large".into());
            }
            if expected.is_some_and(|length| length != body.len() as u64) {
                return Err("ICS feed response is incomplete".into());
            }
        } else if (200..300).contains(&status) {
            return Err("ICS feed response is not a complete HTTP 200".into());
        }
        Ok(IcsHttpResponse { status, etag, body })
    }
}
