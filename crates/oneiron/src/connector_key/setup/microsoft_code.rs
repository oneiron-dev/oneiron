//! Microsoft's code exchange and refresh ([MICROSOFT365-OAUTH-EXCHANGE]),
//! called with values held inside admitted credential doors.
//!
//! Both post to the tenant's token endpoint on Microsoft's fixed sign-in
//! origin, `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
//! The tenant is the client's word at the exchange and the stored grant's
//! after it, held to the alphabet of Microsoft's tenant names, so no stored
//! value names another host or path. A stored Microsoft grant names its
//! tenant, and a grant that names none is never sent here: it is not one.
//!
//! Microsoft answers each refresh with a newer refresh token as well. The
//! refresh rewrites the stored grant around it ([`GrantAccess::successor`]),
//! and the caller hands that to the custody write-back once its door has
//! returned (RULING MICROSOFT365-REFRESH-WRITEBACK, B).

use std::io::Read as _;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{
    AuthorizationCodeGrant, GrantAccess, MAX_CHECK_REPLY_BYTES, ProviderConnectionChecks, bounded,
    invalid, present,
};
use crate::error::{Error, Result};

/// Microsoft's sign-in origin: every Microsoft token endpoint is under it.
const MICROSOFT_LOGIN_ORIGIN: &str = "https://login.microsoftonline.com";
/// The longest tenant name Microsoft takes: a domain name's length.
const MAX_TENANT_BYTES: usize = 253;

/// A host's completed Microsoft sign-in, borrowed only for its token
/// exchange. The host must validate its sign-in state before admitting the
/// code.
pub struct MicrosoftAuthorizationCode<'a> {
    pub client_id: &'a str,
    /// The client's secret: a web application's; `None` for a public client.
    pub client_secret: Option<&'a str>,
    /// The directory the sign-in ran against: `common`, `organizations`,
    /// `consumers`, a directory id, or one of the directory's domains.
    pub tenant: &'a str,
    pub code: &'a str,
    /// Exactly the redirect URI used to obtain this code.
    pub redirect_uri: &'a str,
    /// The verifier used by the host's sign-in, when it used PKCE.
    pub code_verifier: Option<&'a str>,
}

impl ProviderConnectionChecks {
    /// Exchanges a Microsoft sign-in's code at its tenant's token endpoint.
    /// Call only inside the credential doors that admitted its values. No
    /// credential is logged or persisted by this method.
    ///
    /// # Errors
    ///
    /// A tenant outside the tenant alphabet (nothing is sent), Microsoft
    /// unreachable, or its refusal, named by its error code.
    pub fn exchange_microsoft_authorization_code(
        &self,
        code: MicrosoftAuthorizationCode<'_>,
    ) -> Result<AuthorizationCodeGrant> {
        exchange_microsoft_code_at(&self.client, MICROSOFT_LOGIN_ORIGIN, &code)
    }

    /// A fresh access token for a stored Microsoft grant: one that carries
    /// a refresh token, its OAuth client and its tenant, with the grant
    /// rewritten around Microsoft's newer refresh token. `None` for any
    /// other credential. Called only inside an admitted credential door;
    /// nothing is persisted here.
    pub(crate) fn refresh_stored_microsoft_grant(
        client: &reqwest::blocking::Client,
        value: &[u8],
    ) -> Result<Option<GrantAccess>> {
        refresh_stored_microsoft_grant_at(client, MICROSOFT_LOGIN_ORIGIN, value)
    }
}

/// [`ProviderConnectionChecks::exchange_microsoft_authorization_code`],
/// against the token endpoints under `origin`.
pub(crate) fn exchange_microsoft_code_at(
    client: &reqwest::blocking::Client,
    origin: &str,
    code: &MicrosoftAuthorizationCode<'_>,
) -> Result<AuthorizationCodeGrant> {
    let tenant = tenant_name(code.tenant)?;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("client_id", code.client_id),
        ("code", code.code),
        ("redirect_uri", code.redirect_uri),
    ];
    if let Some(secret) = code.client_secret {
        form.push(("client_secret", secret));
    }
    if let Some(verifier) = code.code_verifier {
        form.push(("code_verifier", verifier));
    }
    let reply = post_token_form(client, origin, tenant, &form, "the authorization code")?;
    let access_token = present(&reply.access_token)
        .ok_or_else(|| invalid("Microsoft returned no access token"))?;
    let refresh_token = present(&reply.refresh_token);
    let grant = StoredMicrosoftGrantOut {
        access_token,
        refresh_token,
        client_id: code.client_id,
        client_secret: code.client_secret,
        tenant,
        scope: present(&reply.scope),
    };
    let bytes = serde_json::to_vec(&grant)
        .map_err(|_| invalid("the Microsoft grant could not be encoded"))?;
    Ok(AuthorizationCodeGrant {
        bytes: Zeroizing::new(bytes),
        refreshable: refresh_token.is_some(),
    })
}

/// [`ProviderConnectionChecks::refresh_stored_microsoft_grant`], against the
/// token endpoints under `origin`. The scopes the sign-in was granted are
/// asked for again; a grant that stored none asks for what it was granted.
/// The successor keeps the grant's client, tenant and scope.
pub(crate) fn refresh_stored_microsoft_grant_at(
    client: &reqwest::blocking::Client,
    origin: &str,
    value: &[u8],
) -> Result<Option<GrantAccess>> {
    let text = std::str::from_utf8(value)
        .map_err(|_| invalid("the stored credential is not text"))?
        .trim();
    if !text.starts_with('{') {
        return Ok(None);
    }
    let grant: StoredMicrosoftGrant = serde_json::from_str(text)
        .map_err(|_| invalid("the stored Microsoft grant is not JSON"))?;
    let (Some(refresh_token), Some(client_id), Some(tenant)) = (
        present(&grant.refresh_token),
        present(&grant.client_id),
        present(&grant.tenant),
    ) else {
        return Ok(None);
    };
    let tenant = tenant_name(tenant)?;
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];
    if let Some(secret) = present(&grant.client_secret) {
        form.push(("client_secret", secret));
    }
    if let Some(scope) = present(&grant.scope) {
        form.push(("scope", scope));
    }
    let mut reply = post_token_form(client, origin, tenant, &form, "the stored refresh token")?;
    let token = reply
        .access_token
        .take()
        .map(Zeroizing::new)
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| invalid("Microsoft's refresh returned no access token"))?;
    let successor = match present(&reply.refresh_token) {
        Some(refresh_token) => {
            let rotated = StoredMicrosoftGrantOut {
                access_token: &token,
                refresh_token: Some(refresh_token),
                client_id,
                client_secret: present(&grant.client_secret),
                tenant,
                scope: present(&grant.scope),
            };
            Some(Zeroizing::new(serde_json::to_vec(&rotated).map_err(
                |_| invalid("the refreshed Microsoft grant could not be encoded"),
            )?))
        }
        None => None,
    };
    Ok(Some(GrantAccess {
        access_token: token,
        successor,
    }))
}

/// `tenant` as a path segment of a token endpoint: letters, digits, `-` and
/// `.`, as a directory id, a domain and Microsoft's three shared names
/// (`common`, `organizations`, `consumers`) are spelled; no other character.
fn tenant_name(tenant: &str) -> Result<&str> {
    let tenant = tenant.trim();
    let spelled = (1..=MAX_TENANT_BYTES).contains(&tenant.len())
        && tenant
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        && !tenant.starts_with(['-', '.'])
        && !tenant.ends_with(['-', '.'])
        && !tenant.contains("..");
    if spelled {
        Ok(tenant)
    } else {
        Err(invalid(
            "the Microsoft tenant is not a directory id, a domain, common, organizations or consumers",
        ))
    }
}

/// One POST of `form` to `tenant`'s token endpoint under `origin`, its reply
/// read within the bound. A refusal names Microsoft's error code (such as
/// `invalid_grant`), never its description or body.
fn post_token_form(
    client: &reqwest::blocking::Client,
    origin: &str,
    tenant: &str,
    form: &[(&str, &str)],
    what: &str,
) -> Result<MicrosoftTokenReply> {
    let url = format!("{origin}/{tenant}/oauth2/v2.0/token");
    let response = client.post(url).form(&form).send().map_err(|error| {
        Error::InvalidConfig(format!(
            "pack setup: Microsoft's token endpoint could not be reached: {}",
            error.without_url()
        ))
    })?;
    let status = response.status().as_u16();
    let mut body = Zeroizing::new(Vec::new());
    response
        .take(MAX_CHECK_REPLY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| invalid("Microsoft's token reply is unreadable"))?;
    if body.len() as u64 > MAX_CHECK_REPLY_BYTES {
        return Err(invalid("Microsoft's token reply exceeds its bound"));
    }
    let reply = serde_json::from_slice::<MicrosoftTokenReply>(&body);
    if !(200..300).contains(&status) {
        let code = reply.as_ref().ok().and_then(|reply| present(&reply.error));
        return Err(Error::InvalidConfig(format!(
            "pack setup: Microsoft refused {what} (HTTP {status}): {}",
            bounded(code.unwrap_or("no reason given"))
        )));
    }
    reply.map_err(|_| invalid("Microsoft's token reply is not JSON"))
}

/// Microsoft's token reply: the tokens, wiped on drop, the space-separated
/// scopes they hold, and the error code of a refusal.
#[derive(Deserialize)]
struct MicrosoftTokenReply {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

impl Drop for MicrosoftTokenReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// A stored Microsoft grant, read inside the credential door and wiped on
/// drop.
#[derive(Deserialize)]
struct StoredMicrosoftGrant {
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

impl Drop for StoredMicrosoftGrant {
    fn drop(&mut self) {
        self.refresh_token.zeroize();
        self.client_secret.zeroize();
    }
}

/// The grant the exchange stores: what the Microsoft 365 connection, its
/// check and the Graph mail wires read.
#[derive(Serialize)]
struct StoredMicrosoftGrantOut<'a> {
    access_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    tenant: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}
