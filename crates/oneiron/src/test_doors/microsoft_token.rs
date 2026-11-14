//! Door for `tests/microsoft365_oauth.rs` ([MICROSOFT365-OAUTH-EXCHANGE]):
//! Microsoft's code exchange and refresh against a test's own token
//! endpoints, and the `microsoft365.me` check's and the mail wires' token
//! steps run through a test's own proxy, so the test sees which host each
//! step reaches.

use crate::connector_key::{
    MicrosoftAuthorizationCode, ProviderConnectionChecks, exchange_microsoft_code_at,
    refresh_stored_microsoft_grant_at,
};
use crate::error::{Error, Result};
use crate::mail_pack::GrantIssuer;

/// What a Microsoft code exchange stored: the grant's bytes, and whether
/// Microsoft issued a refresh token.
pub struct ExchangedMicrosoftGrant {
    pub grant: Vec<u8>,
    pub refreshable: bool,
}

/// Microsoft's code exchange against the token endpoints under `origin`
/// (`http://127.0.0.1:<port>`): the client, tenant and sign-in values as
/// the owner's two credentials hold them.
///
/// # Errors
///
/// The exchange's own: a tenant outside the alphabet (nothing sent), the
/// endpoint unreachable, or its refusal.
pub fn exchange_code_at(
    origin: &str,
    client_id: &str,
    client_secret: Option<&str>,
    tenant: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
) -> Result<ExchangedMicrosoftGrant> {
    let grant = exchange_microsoft_code_at(
        &plain_client()?,
        origin,
        &MicrosoftAuthorizationCode {
            client_id,
            client_secret,
            tenant,
            code,
            redirect_uri,
            code_verifier,
        },
    )?;
    Ok(ExchangedMicrosoftGrant {
        grant: grant.as_bytes().to_vec(),
        refreshable: grant.has_refresh_token(),
    })
}

/// The fresh access token a refresh of the stored grant `grant` returns
/// from the token endpoints under `origin`; `None` when the grant is not a
/// refreshable Microsoft grant.
///
/// # Errors
///
/// The refresh's own: a tenant outside the alphabet, the endpoint
/// unreachable, or its refusal.
pub fn refresh_grant_at(origin: &str, grant: &[u8]) -> Result<Option<String>> {
    refresh_stored_microsoft_grant_at(&plain_client()?, origin, grant)
        .map(|fresh| fresh.map(|token| token.as_str().to_owned()))
}

/// The HTTP status of the `microsoft365.me` check's provider call with
/// `grant` as the stored grant, every request sent through the proxy at
/// `proxy` (`http://127.0.0.1:<port>`).
///
/// # Errors
///
/// The check's own, as a proxy that refuses each `CONNECT` makes it fail.
pub fn microsoft365_me_status_via(proxy: &str, grant: &[u8]) -> Result<u16> {
    ProviderConnectionChecks::on_client(proxied_client(proxy)?).microsoft365_me_status(grant)
}

/// The fresh access token the mail pack's wires present for the stored
/// grant `grant` under the issuer `issuer` (`google`, `microsoft`), every
/// request sent through the proxy at `proxy`; `None` when the issuer does
/// not refresh the grant.
///
/// # Errors
///
/// No such issuer, or the refresh's reason code
/// (`<issuer>_credential_refresh_failed`).
pub fn mail_wire_refresh_via(issuer: &str, grant: &[u8], proxy: &str) -> Result<Option<String>> {
    let issuer = match issuer {
        "google" => GrantIssuer::Google,
        "microsoft" => GrantIssuer::Microsoft,
        other => return Err(Error::InvalidConfig(format!("no grant issuer {other}"))),
    };
    issuer
        .refresh(&proxied_client(proxy)?, grant)
        .map(|fresh| fresh.map(|token| token.as_str().to_owned()))
}

/// A client with no proxy, no redirects and a 10 s timeout, for a test's
/// plain-HTTP token endpoint.
fn plain_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| Error::InvalidConfig("test client did not build".to_owned()))
}

/// A client whose every request goes through the proxy at `proxy`.
pub(crate) fn proxied_client(proxy: &str) -> Result<reqwest::blocking::Client> {
    let proxy = reqwest::Proxy::all(proxy)
        .map_err(|_| Error::InvalidConfig("test proxy did not build".to_owned()))?;
    reqwest::blocking::Client::builder()
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| Error::InvalidConfig("proxied test client did not build".to_owned()))
}
