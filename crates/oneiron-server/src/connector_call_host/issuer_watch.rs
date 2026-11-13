//! L5-11 (ARCH-0072 #drift; ARCH-0054 #auth "PRM 401 bootstrap"): automatic
//! issuer change detection at a connector's refusal. A send the connector
//! refused with HTTP 401 and a `Bearer` challenge reads the connector's own
//! protected-resource metadata (RFC 9728) at the well-known URL derived
//! from the installed endpoint, never the URL the challenge names, so the
//! read stays on the connector's origin. It sends no credential and follows
//! no redirect. When the metadata names the endpoint as its resource and no
//! longer lists the issuer a binding answers for, the core door records the
//! change and holds every dependent row until the owner accepts it. Nothing
//! here changes the refused send's answer.

use std::io::Read;

use oneiron::connector_key::{ConnectorCredentialBinding, ConnectorIssuerDetection};
use oneiron::{EntityId, Vault};
use reqwest::header::{ACCEPT, HeaderMap, WWW_AUTHENTICATE};
use reqwest::{StatusCode, Url};
use serde::Deserialize;

use super::HANDSHAKE_TIMEOUT;

/// The RFC 9728 §3.1 well-known path the metadata is read at.
const RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";
/// The most of a metadata reply read; a longer one is not read at all.
const RESOURCE_METADATA_MAX_BYTES: u64 = 64 * 1024;

/// The protected-resource metadata keys the watch reads.
#[derive(Deserialize)]
struct ResourceMetadata {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
}

/// The RFC 9728 §3.1 metadata URL of `endpoint`: the well-known path goes
/// between its host and its path, its query kept, a lone `/` path dropped.
/// `None` for an endpoint that is not an http(s) URL with a host, or that
/// carries a fragment.
pub(crate) fn resource_metadata_url(endpoint: &str) -> Option<Url> {
    let mut url = Url::parse(endpoint).ok()?;
    if !matches!(url.scheme(), "http" | "https") || !url.has_host() || url.fragment().is_some() {
        return None;
    }
    let path = match url.path() {
        "/" => String::new(),
        path => path.to_owned(),
    };
    url.set_path(&format!("{RESOURCE_METADATA_PATH}{path}"));
    Some(url)
}

/// Whether a `WWW-Authenticate` value of the refusal opens a `Bearer`
/// challenge.
fn bearer_challenge(headers: &HeaderMap) -> bool {
    headers.get_all(WWW_AUTHENTICATE).iter().any(|value| {
        value
            .to_str()
            .ok()
            .and_then(|text| text.split_whitespace().next())
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer"))
    })
}

/// The issuers `endpoint`'s metadata lists, read once with no credential:
/// `None` unless it answers 200 with JSON within the size bound, naming
/// exactly `endpoint` as its resource (RFC 9728 §3.3).
fn listed_issuers(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    metadata_url: &Url,
) -> Option<Vec<String>> {
    let response = client
        .get(metadata_url.clone())
        .header(ACCEPT, "application/json")
        .timeout(HANDSHAKE_TIMEOUT)
        .send()
        .ok()?;
    if response.status() != StatusCode::OK {
        return None;
    }
    let mut body = Vec::new();
    response
        .take(RESOURCE_METADATA_MAX_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    if u64::try_from(body.len()).ok()? > RESOURCE_METADATA_MAX_BYTES {
        return None;
    }
    let metadata: ResourceMetadata = serde_json::from_slice(&body).ok()?;
    (metadata.resource == endpoint).then_some(metadata.authorization_servers)
}

/// Reads a refusal of a send under connector key `key_ref` to `endpoint`
/// for an issuer change. Only a 401 with a `Bearer` challenge reads the
/// metadata; any other refusal, an unreadable or mismatched metadata reply,
/// or one with no issuer records nothing. Answers each binding the core
/// door found drifted.
///
/// # Errors
/// The core door's: a malformed detection or a failed write.
pub(crate) fn detect_at_refusal(
    vault: &Vault,
    client: &reqwest::blocking::Client,
    endpoint: &str,
    key_ref: &EntityId,
    status: StatusCode,
    headers: &HeaderMap,
) -> oneiron::Result<Vec<ConnectorCredentialBinding>> {
    if status != StatusCode::UNAUTHORIZED || !bearer_challenge(headers) {
        return Ok(Vec::new());
    }
    let Some(metadata_url) = resource_metadata_url(endpoint) else {
        return Ok(Vec::new());
    };
    let Some(authorization_servers) = listed_issuers(client, endpoint, &metadata_url) else {
        return Ok(Vec::new());
    };
    if authorization_servers.is_empty() {
        return Ok(Vec::new());
    }
    let witness = format!(
        "protected-resource metadata at {}{} lists {authorization_servers:?} after a 401",
        metadata_url.origin().ascii_serialization(),
        metadata_url.path(),
    );
    vault.detect_connector_credential_issuer(&ConnectorIssuerDetection {
        key_ref: *key_ref,
        authorization_servers,
        witness,
    })
}
