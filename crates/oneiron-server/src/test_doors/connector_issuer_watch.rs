//! Door for `tests/connector_issuer_prm_refusal.rs` (L5-11): the issuer
//! watch a connector send runs at a refusal, on the send's own HTTP client,
//! as the three refusal sites of one send call it.

use oneiron::connector_key::ConnectorCredentialBinding;
use oneiron::{EntityId, Vault};
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};

use crate::connector_call_host::{connector_client, issuer_watch};

/// The RFC 9728 metadata URL the watch reads for `endpoint`.
#[must_use]
pub fn resource_metadata_url(endpoint: &str) -> Option<String> {
    issuer_watch::resource_metadata_url(endpoint).map(String::from)
}

/// A refusal with HTTP `status` of a send under `key_ref` to `endpoint`,
/// carrying `www_authenticate` when one is given, read as a send reads it.
/// Answers each binding the watch found drifted.
///
/// # Errors
/// The client build, a header that is not one, and the core door's.
pub fn watch_refusal(
    vault: &Vault,
    endpoint: &str,
    key_ref: &EntityId,
    status: u16,
    www_authenticate: Option<&str>,
) -> oneiron::Result<Vec<ConnectorCredentialBinding>> {
    let client = connector_client()?;
    let status = StatusCode::from_u16(status)
        .map_err(|_| oneiron::Error::InvalidConfig("not an HTTP status".to_owned()))?;
    let mut headers = HeaderMap::new();
    if let Some(challenge) = www_authenticate {
        let value = HeaderValue::from_str(challenge)
            .map_err(|_| oneiron::Error::InvalidConfig("not a header value".to_owned()))?;
        headers.insert(WWW_AUTHENTICATE, value);
    }
    issuer_watch::detect_at_refusal(vault, &client, endpoint, key_ref, status, &headers)
}
