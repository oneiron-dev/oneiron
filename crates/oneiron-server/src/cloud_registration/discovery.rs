//! Discovery as a locator alone (LC cloud #97 §1; L14 agreement 08:3x):
//! `I/auth.md`'s `agent_auth` names where the issuer's metadata is; its
//! issuer must equal the pinned `I`, its client must be the fixed one and it
//! must list the device grant, and every other key is ignored. The metadata
//! then names the endpoints, each checked to be an https URL on the pinned
//! issuer's own origin; the protected-resource metadata must name the pinned
//! audience and issuer. Nothing discovered adds trust: the `jwks_uri` is
//! never fetched, and the keys stay the pins'.

use reqwest::Url;
use serde::Deserialize;

use super::http::Http;
use super::pins::Pins;
use super::wire::{
    AUTH_MD_PATH, CLIENT_ID, DEVICE_GRANT, Failure, REFRESH_GRANT, RESOURCE_METADATA_PATH, SCOPE,
};

/// The issuer's endpoints, as its metadata named them and the pins checked.
#[derive(Clone, Debug)]
pub(crate) struct Endpoints {
    pub(crate) device_authorization: Url,
    pub(crate) token: Url,
    pub(crate) revocation: Url,
    /// The pinned audience `A`, the one place an access token goes.
    pub(crate) audience: Url,
}

/// `auth.md`'s fenced JSON: `agent_auth` alone is read.
#[derive(Deserialize)]
struct AuthMd {
    agent_auth: AgentAuth,
}

#[derive(Deserialize)]
struct AgentAuth {
    issuer: String,
    authorization_server_metadata: String,
    client_id: String,
    grant_types_supported: Vec<String>,
}

/// The authorization server metadata keys the client reads.
#[derive(Deserialize)]
struct ServerMetadata {
    issuer: String,
    device_authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    revocation_endpoint_auth_methods_supported: Vec<String>,
    scopes_supported: Vec<String>,
}

/// The protected-resource metadata keys the client reads.
#[derive(Deserialize)]
struct ResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    bearer_methods_supported: Vec<String>,
}

/// Finds the issuer's endpoints under `pins`: three GETs, no redirect
/// followed, every answer checked against the pins.
pub(crate) fn discover(http: &Http, pins: &Pins) -> Result<Endpoints, Failure> {
    let auth_md = http.get(&on_issuer(pins, AUTH_MD_PATH)?, None)?;
    if auth_md.status != 200 {
        return Err(auth_md.failure("auth.md"));
    }
    if auth_md.media_type != "text/markdown" {
        return Err(off_wire("auth.md is not text/markdown"));
    }
    let text = std::str::from_utf8(&auth_md.body).map_err(|_| off_wire("auth.md is not UTF-8"))?;
    let locator: AuthMd = serde_json::from_str(fenced_json(text)?)
        .map_err(|_| off_wire("auth.md's agent_auth is not the agreed shape"))?;
    let agent = locator.agent_auth;
    if agent.issuer != pins.issuer {
        return Err(off_wire("auth.md names another issuer than the pinned one"));
    }
    if agent.client_id != CLIENT_ID || !listed(&agent.grant_types_supported, DEVICE_GRANT) {
        return Err(off_wire(
            "auth.md does not offer this client the device grant",
        ));
    }
    let metadata_url = same_origin(pins, &agent.authorization_server_metadata)?;
    let reply = http.get(&metadata_url, None)?;
    if reply.status != 200 {
        return Err(reply.failure("authorization server metadata"));
    }
    let metadata: ServerMetadata = reply.json("authorization server metadata")?;
    if metadata.issuer != pins.issuer
        || !listed(&metadata.grant_types_supported, DEVICE_GRANT)
        || !listed(&metadata.grant_types_supported, REFRESH_GRANT)
        || !listed(&metadata.token_endpoint_auth_methods_supported, "none")
        || !listed(&metadata.revocation_endpoint_auth_methods_supported, "none")
        || !listed(&metadata.scopes_supported, SCOPE)
    {
        return Err(off_wire(
            "the issuer's metadata does not match the pins and the wire",
        ));
    }
    let endpoints = Endpoints {
        device_authorization: same_origin(pins, &metadata.device_authorization_endpoint)?,
        token: same_origin(pins, &metadata.token_endpoint)?,
        revocation: same_origin(pins, &metadata.revocation_endpoint)?,
        audience: same_origin(pins, &pins.audience)?,
    };
    let reply = http.get(&on_issuer(pins, RESOURCE_METADATA_PATH)?, None)?;
    if reply.status != 200 {
        return Err(reply.failure("protected-resource metadata"));
    }
    let resource: ResourceMetadata = reply.json("protected-resource metadata")?;
    if resource.resource != pins.audience
        || !listed(&resource.authorization_servers, &pins.issuer)
        || !listed(&resource.scopes_supported, SCOPE)
        || !listed(&resource.bearer_methods_supported, "header")
    {
        return Err(off_wire(
            "the protected-resource metadata does not name the pinned audience and issuer",
        ));
    }
    Ok(endpoints)
}

fn off_wire(reason: &str) -> Failure {
    Failure::OffWire(reason.to_owned())
}

fn listed(values: &[String], wanted: &str) -> bool {
    values.iter().any(|value| value == wanted)
}

/// `path` under the pinned issuer.
fn on_issuer(pins: &Pins, path: &str) -> Result<Url, Failure> {
    pins.issuer_url
        .join(path)
        .map_err(|_| off_wire("an issuer path does not join"))
}

/// `url` when it is an https URL on the pinned issuer's own origin, with no
/// user, query or fragment.
fn same_origin(pins: &Pins, url: &str) -> Result<Url, Failure> {
    let parsed = Url::parse(url).map_err(|_| off_wire("a discovered endpoint is not a URL"))?;
    if parsed.scheme() != "https"
        || parsed.origin() != pins.issuer_url.origin()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(off_wire(
            "a discovered endpoint is not on the pinned issuer's origin",
        ));
    }
    Ok(parsed)
}

/// The one fenced JSON block of `auth.md`.
fn fenced_json(text: &str) -> Result<&str, Failure> {
    let missing = || off_wire("auth.md holds no fenced JSON block");
    let open = text.find("```").ok_or_else(missing)?;
    let after = &text[open + 3..];
    let body = after.split_once('\n').ok_or_else(missing)?.1;
    let close = body.find("```").ok_or_else(missing)?;
    Ok(&body[..close])
}
