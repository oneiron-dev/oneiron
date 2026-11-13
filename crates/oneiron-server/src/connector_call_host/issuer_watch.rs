//! L5-11 (ARCH-0072 #drift; ARCH-0054 #auth "PRM 401 bootstrap"): automatic
//! issuer change detection at a connector's refusal. A send the connector
//! refused with HTTP 401 and a `Bearer` challenge reads the connector's own
//! protected-resource metadata (RFC 9728) at the well-known URL derived
//! from the installed endpoint, never the URL the challenge names, so the
//! read stays on the connector's origin. It sends no credential and follows
//! no redirect. When the metadata names the endpoint as its resource and no
//! longer lists the issuer a binding answers for, the core door records the
//! change and holds every dependent row until the owner accepts it. Nothing
//! here changes the refused send's answer. The baseline it compares with
//! comes from the owner's admission of the connector, which reads the same
//! metadata (Engine ruling L5-11-BASELINE = C).

use std::io::Read;

use oneiron::connector_key::{
    ConnectorBindingDependent, ConnectorCredentialBinding, ConnectorIssuerDetection,
    ConnectorIssuerObservation,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::{EntityId, Vault};
use reqwest::header::{ACCEPT, HeaderMap, WWW_AUTHENTICATE};
use reqwest::{StatusCode, Url};
use serde::Deserialize;

use super::{HANDSHAKE_TIMEOUT, connector_client};

/// The credential slot a catalog connector's route presents from.
const ROUTE_SLOT: &str = "route";

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

/// Whether a `WWW-Authenticate` field of the refusal opens a `Bearer`
/// challenge anywhere in its challenge list: one field may carry several
/// challenges (RFC 9110 §11.6.1), and the fields may repeat.
fn bearer_challenge(headers: &HeaderMap) -> bool {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(challenge_schemes)
        .any(|scheme| scheme.eq_ignore_ascii_case("bearer"))
}

/// The auth schemes one `WWW-Authenticate` value names, in order. A list
/// element whose first token is not followed by `=` opens a challenge; any
/// other element is a parameter of the challenge before it. A comma inside
/// a quoted string separates nothing.
fn challenge_schemes(value: &str) -> Vec<&str> {
    let mut schemes = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let ends = value.bytes().chain(std::iter::once(b','));
    for (at, byte) in ends.enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        if byte == b'"' {
            quoted = true;
        } else if byte == b',' {
            let element = value[start..at].trim_start_matches([' ', '\t']);
            let word_end = element.find(['=', ' ', '\t']).unwrap_or(element.len());
            let (word, rest) = element.split_at(word_end);
            if !word.is_empty() && !rest.trim_start_matches([' ', '\t']).starts_with('=') {
                schemes.push(word);
            }
            start = at + 1;
        }
    }
    schemes
}

/// The issuers `endpoint`'s metadata lists, read once with no credential,
/// and the witness of that read: `None` unless it answers 200 with JSON
/// within the size bound, naming exactly `endpoint` as its resource (RFC
/// 9728 §3.3) and at least one issuer.
fn read_listed_issuers(
    client: &reqwest::blocking::Client,
    endpoint: &str,
) -> Option<(Vec<String>, String)> {
    let metadata_url = resource_metadata_url(endpoint)?;
    let issuers = listed_issuers(client, endpoint, &metadata_url)?;
    if issuers.is_empty() {
        return None;
    }
    let witness = format!(
        "protected-resource metadata at {}{} lists {issuers:?}",
        metadata_url.origin().ascii_serialization(),
        metadata_url.path(),
    );
    Some((issuers, witness))
}

/// The issuers the metadata at `metadata_url` lists for `endpoint`.
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
    let Some((authorization_servers, read)) = read_listed_issuers(client, endpoint) else {
        return Ok(Vec::new());
    };
    vault.detect_connector_credential_issuer(&ConnectorIssuerDetection {
        key_ref: *key_ref,
        authorization_servers,
        witness: format!("{read} after a 401"),
    })
}

/// The baseline of catalog connector `connector` (key `catalog_key`),
/// recorded inside the owner's admission of it (Engine ruling
/// L5-11-BASELINE = C; closes FIX 9302): its route's slot answers for the
/// first issuer its metadata lists, and every row of the key depends on it.
/// A route with no credential has no issuer to bind, and a connector whose
/// metadata is missing, mismatched or lists no issuer gets no binding. A
/// slot the owner already bound keeps its binding (the observation at
/// generation 0 meets it). Answers the binding recorded now, if any.
///
/// # Errors
/// The client build and the observe door's, past a binding that exists.
pub(crate) fn baseline_at_admission(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    connector: &str,
    catalog_key: &EntityId,
    endpoint: &str,
    credential_ref: Option<&str>,
) -> oneiron::Result<Option<ConnectorCredentialBinding>> {
    let Some(credential_ref) = credential_ref else {
        return Ok(None);
    };
    let Some((issuers, read)) = read_listed_issuers(&connector_client()?, endpoint) else {
        return Ok(None);
    };
    let observed = vault.observe_connector_credential_issuer(
        owner,
        &ConnectorIssuerObservation {
            connector: connector.to_owned(),
            slot: ROUTE_SLOT.to_owned(),
            issuer: issuers[0].clone(),
            credential_ref: credential_ref.to_owned(),
            expected_generation: 0,
            dependents: vec![ConnectorBindingDependent {
                key_ref: *catalog_key,
                tool: None,
            }],
            witness: format!("{read} at the owner's admission"),
        },
    );
    match observed {
        Ok(binding) => Ok(Some(binding)),
        Err(oneiron::Error::ConcurrentWrite(_)) => Ok(None),
        Err(error) => Err(error),
    }
}
