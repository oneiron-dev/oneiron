//! L5-11 seam: the issuer watch a connector send runs at a refusal. It
//! reads nothing yet.

use oneiron::connector_key::ConnectorCredentialBinding;
use oneiron::{EntityId, Vault};
use reqwest::header::HeaderMap;
use reqwest::{StatusCode, Url};

/// The RFC 9728 §3.1 metadata URL of `endpoint` (seam: none yet).
pub(crate) fn resource_metadata_url(endpoint: &str) -> Option<Url> {
    let _ = endpoint;
    None
}

/// Reads a refusal for an issuer change (seam: records nothing yet).
///
/// # Errors
/// None yet.
pub(crate) fn detect_at_refusal(
    vault: &Vault,
    client: &reqwest::blocking::Client,
    endpoint: &str,
    key_ref: &EntityId,
    status: StatusCode,
    headers: &HeaderMap,
) -> oneiron::Result<Vec<ConnectorCredentialBinding>> {
    let _ = (vault, client, endpoint, key_ref, status, headers);
    Ok(Vec::new())
}
