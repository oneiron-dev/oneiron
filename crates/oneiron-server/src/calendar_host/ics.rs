//! Conditional ICS GET at the secret-custody door. No resolved URL leaves it.
//!
//! The feed goes out through the one shared network boundary (ARCH-0046,
//! ARCH-0060): on a managed node the hosted egress guard refuses a feed URL
//! whose address is private or the node's own, by its literal here and by its
//! name's answers in the client's resolver. A self-hosted node fetches as before.
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;

use oneiron::Vault;
use oneiron::calendar::ingest::{IcsFeedPollConfig, IcsHttpResponse, IcsHttpTransport};
use oneiron::consent::AuthenticatedOwner;
use oneiron::web_fetch::HostedEgressGuard;

const MAX_FEED_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) struct HttpIcsFeed {
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    config: IcsFeedPollConfig,
    client: reqwest::blocking::Client,
    egress: Option<Arc<HostedEgressGuard>>,
}

impl HttpIcsFeed {
    /// `egress` is the node's hosted egress guard
    /// (`SyncServer::hosted_egress_guard`): `Some` on a managed node, `None`
    /// on a self-hosted one.
    pub(crate) fn new(
        vault: Arc<Vault>,
        owner: AuthenticatedOwner,
        config: IcsFeedPollConfig,
        egress: Option<Arc<HostedEgressGuard>>,
    ) -> Result<Self, String> {
        Ok(Self {
            vault,
            owner,
            config,
            client: super::feed_client(egress.clone())
                .map_err(|_| "ICS HTTP client unavailable".to_owned())?,
            egress,
        })
    }
}

/// Parses a feed URL and admits it at the shared network boundary: HTTPS, or
/// loopback HTTP, with no embedded credentials or fragment; and on a managed
/// node (`Some(egress)`) no address literal the guard refuses and no listed
/// private name at an origin the operator did not list. A name's own answers
/// are checked by the feed client's resolver as it connects.
pub(crate) fn admit_feed_url(
    url: &str,
    egress: Option<&HostedEgressGuard>,
) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(url).map_err(|_| "ICS feed URL is invalid")?;
    let local = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if !(url.scheme() == "https" || url.scheme() == "http" && local)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "ICS feed requires HTTPS or loopback HTTP without embedded credentials or fragment"
                .into(),
        );
    }
    if let Some(guard) = egress {
        let literal = url
            .host_str()
            .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
            .and_then(|host| host.parse::<IpAddr>().ok());
        let refused = match literal {
            Some(ip) => guard.refuses(ip),
            None => guard.refuses_origin(&url),
        };
        if refused.is_some() {
            return Err(
                "ICS feed URL names a private or node address, which a hosted node does not fetch"
                    .into(),
            );
        }
    }
    Ok(url)
}

impl IcsHttpTransport for HttpIcsFeed {
    fn get(&self, url: &str, if_none_match: Option<&str>) -> Result<IcsHttpResponse, String> {
        let url = admit_feed_url(url, self.egress.as_deref())?;
        oneiron::calendar::ingest::feed_door::check_installed_feed(
            &self.vault,
            &self.owner,
            &self.config,
        )
        .map_err(|_| "ICS feed owner or installation no longer admits this poll")?;
        get_admitted(&self.client, url, if_none_match)
    }
}

/// One conditional GET of an admitted feed URL ([`admit_feed_url`]) on the
/// feed client ([`super::feed_client`]): a complete 200 body of at most 16 MiB,
/// a 304, or the provider's status.
pub(crate) fn get_admitted(
    client: &reqwest::blocking::Client,
    url: reqwest::Url,
    if_none_match: Option<&str>,
) -> Result<IcsHttpResponse, String> {
    let mut request = client.get(url);
    if let Some(etag) = if_none_match {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag);
    }
    let response = request.send().map_err(|_| "ICS feed request failed")?;
    let status = response.status().as_u16();
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut body = Vec::new();
    if status == 200 {
        let expected = response.content_length();
        response
            .take(MAX_FEED_BYTES + 1)
            .read_to_end(&mut body)
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
