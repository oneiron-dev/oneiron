//! The client an authorize request names: a registered one from the clients table, or one whose
//! https `client_id` names its client ID metadata document (CIMD), fetched here when the stored
//! copy is older than `OAUTH_CIMD_TTL_SECS`.
//!
//! The fetch is one bounded GET: https only, no redirect, no proxy, five seconds, 64 KiB, a JSON
//! body. On a managed node it goes through the hosted egress guard the web fetcher uses (FIX
//! 6101, 7657), so a client ID cannot point the vault at the node or a private network: an
//! address literal is checked before the request, and a name at connect time, by every address
//! it resolves to. A self-hosted node fetches as its other fetchers do. A failed fetch serves no
//! stale copy: the request is refused.

use std::io::Read as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use oneiron::authority::{OAuthClientRecord, oauth_client_id_is_metadata_url};
use oneiron::web_fetch::{HostedEgressGuard, hosted_dns_resolver};

use crate::server::SyncServer;

/// The most a metadata document's body may hold (CALLS, FIX 4902: an engine call).
const CLIENT_DOCUMENT_MAX_BYTES: u64 = 64 * 1024;
/// How long one metadata document fetch may take, connection included (CALLS, FIX 4902: an
/// engine call).
const CLIENT_DOCUMENT_TIMEOUT: Duration = Duration::from_secs(5);

/// The client `client_id` names at `now`, fetching its metadata document when it has one and
/// the stored copy is stale; `None` for a client this vault does not know or cannot read.
pub(super) async fn resolve_client(
    server: &Arc<SyncServer>,
    client_id: &str,
    now: u64,
) -> Option<OAuthClientRecord> {
    let stored = match server.vault().oauth_client(client_id) {
        Ok(stored) => stored,
        Err(error) => {
            tracing::warn!(%error, "reading an OAuth client failed");
            return None;
        }
    };
    if !oauth_client_id_is_metadata_url(client_id) {
        return stored.filter(|client| client.is_fresh_at(now));
    }
    if let Some(client) = stored.filter(|client| client.is_fresh_at(now)) {
        return Some(client);
    }
    let url = client_id.to_owned();
    let guard = Some(server.untrusted_url_egress_guard());
    // reqwest's blocking client runs a runtime of its own, which panics inside an async one: the
    // fetch runs on a thread of its own, off the request worker (FIX 9529).
    let document = tokio::task::spawn_blocking(move || {
        std::thread::scope(|scope| scope.spawn(|| fetch_client_document(&url, guard)).join())
            .ok()
            .flatten()
    })
    .await
    .ok()
    .flatten()?;
    match server
        .vault()
        .store_oauth_metadata_client(client_id, &document, now)
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "storing an OAuth client metadata document failed");
            None
        }
    }
}

/// One bounded GET of a metadata document, on the calling thread, which must be outside any
/// async runtime. `None` for any refusal or failure.
fn fetch_client_document(url: &str, guard: Option<Arc<HostedEgressGuard>>) -> Option<Vec<u8>> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CLIENT_DOCUMENT_TIMEOUT);
    // A managed node's client resolves every name through the guard, as the web fetcher's does.
    let builder = match guard {
        Some(guard) => {
            let literal = parsed
                .host_str()
                .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
                .and_then(|host| host.parse::<IpAddr>().ok());
            let refused = match literal {
                Some(address) => guard.refuses(address),
                None => guard.refuses_origin(&parsed),
            };
            if refused.is_some() {
                return None;
            }
            builder.dns_resolver(hosted_dns_resolver(guard))
        }
        None => builder,
    };
    let client = builder.build().ok()?;
    let response = client
        .get(parsed)
        .header(reqwest::header::ACCEPT, "application/json")
        .timeout(CLIENT_DOCUMENT_TIMEOUT)
        .send()
        .ok()?;
    let json = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("json"));
    if !response.status().is_success()
        || !json
        || response
            .content_length()
            .is_some_and(|length| length > CLIENT_DOCUMENT_MAX_BYTES)
    {
        return None;
    }
    let mut body = Vec::new();
    response
        .take(CLIENT_DOCUMENT_MAX_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    let within = u64::try_from(body.len()).is_ok_and(|length| length <= CLIENT_DOCUMENT_MAX_BYTES);
    within.then_some(body)
}
