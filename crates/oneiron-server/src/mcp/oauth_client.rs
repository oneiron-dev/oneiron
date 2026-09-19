//! Issuer-bound OAuth client state and pinned client metadata (ARCH-0028).
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Every lookup binds vault, actor and issuer to one connector registration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenCacheKey {
    pub vault_id: String,
    pub actor_ref: String,
    pub issuer: String,
    pub connector_ref: String,
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthClientError {
    #[error("OAuth issuer identity changed; re-consent is required")]
    IssuerDrift,
    #[error("OAuth authorization response issuer does not match")]
    IssuerMismatch,
    #[error("OAuth authorization response state does not match")]
    StateMismatch,
    #[error("OAuth client metadata or token response is invalid")]
    InvalidResponse,
}

struct CachedToken {
    value: String,
    expires_at: u64,
}
/// Process-local host object, never a process-global cache or a vault evidence row.
#[derive(Default)]
pub struct OAuthTokenCache {
    tokens: BTreeMap<TokenCacheKey, CachedToken>,
    issuers: BTreeMap<(String, String, String), String>,
    drifted: BTreeSet<(String, String, String)>,
}
impl std::fmt::Debug for OAuthTokenCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthTokenCache").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationResponse {
    pub iss: String,
    pub state: String,
    pub code: String,
}

impl OAuthTokenCache {
    /// Called only after connector consent commits. Issuer drift invalidates
    /// cached credentials; ordinary redemption cannot silently rebind it.
    pub fn register_issuer(&mut self, key: &TokenCacheKey) -> Result<(), OAuthClientError> {
        validate_key(key)?;
        let pair = (
            key.vault_id.clone(),
            key.actor_ref.clone(),
            key.connector_ref.clone(),
        );
        if self.drifted.contains(&pair) {
            return Err(OAuthClientError::IssuerDrift);
        }
        if self
            .issuers
            .get(&pair)
            .is_some_and(|old| old != &key.issuer)
        {
            self.tokens.retain(|k, _| {
                k.vault_id != key.vault_id
                    || k.actor_ref != key.actor_ref
                    || k.connector_ref != key.connector_ref
            });
            self.drifted.insert(pair);
            return Err(OAuthClientError::IssuerDrift);
        }
        self.issuers.insert(pair, key.issuer.clone());
        Ok(())
    }
    /// A re-consent callback must explicitly retire the old registration first.
    pub fn revoke(&mut self, vault_id: &str, actor_ref: &str, connector_ref: &str) {
        self.tokens.retain(|k, _| {
            k.vault_id != vault_id || k.actor_ref != actor_ref || k.connector_ref != connector_ref
        });
        self.issuers
            .remove(&(vault_id.into(), actor_ref.into(), connector_ref.into()));
        self.drifted
            .remove(&(vault_id.into(), actor_ref.into(), connector_ref.into()));
    }
    pub fn get(&self, key: &TokenCacheKey, now: u64) -> Option<&str> {
        if self.drifted.contains(&(
            key.vault_id.clone(),
            key.actor_ref.clone(),
            key.connector_ref.clone(),
        )) {
            return None;
        }
        if self.issuers.get(&(
            key.vault_id.clone(),
            key.actor_ref.clone(),
            key.connector_ref.clone(),
        )) != Some(&key.issuer)
        {
            return None;
        }
        self.tokens
            .get(key)
            .filter(|token| token.expires_at > now)
            .map(|token| token.value.as_str())
    }
    /// RFC 9207 issuer and state checks run BEFORE the redemption callback.
    /// The callback is the host's PKCE-bound token exchange, not a policy door.
    pub fn redeem(
        &mut self,
        key: &TokenCacheKey,
        expected_state: &str,
        response: &AuthorizationResponse,
        now: u64,
        exchange: impl FnOnce(&str) -> Result<(String, u64), OAuthClientError>,
    ) -> Result<(), OAuthClientError> {
        validate_key(key)?;
        if self.drifted.contains(&(
            key.vault_id.clone(),
            key.actor_ref.clone(),
            key.connector_ref.clone(),
        )) {
            return Err(OAuthClientError::IssuerDrift);
        }
        if self.issuers.get(&(
            key.vault_id.clone(),
            key.actor_ref.clone(),
            key.connector_ref.clone(),
        )) != Some(&key.issuer)
        {
            return Err(OAuthClientError::IssuerDrift);
        }
        if response.iss != key.issuer {
            return Err(OAuthClientError::IssuerMismatch);
        }
        if expected_state.is_empty() || response.state != expected_state {
            return Err(OAuthClientError::StateMismatch);
        }
        if response.code.is_empty() {
            return Err(OAuthClientError::InvalidResponse);
        }
        let (token, expires_at) = exchange(&response.code)?;
        if token.is_empty() || expires_at <= now {
            return Err(OAuthClientError::InvalidResponse);
        }
        self.tokens.insert(
            key.clone(),
            CachedToken {
                value: token,
                expires_at,
            },
        );
        Ok(())
    }
}
fn validate_key(key: &TokenCacheKey) -> Result<(), OAuthClientError> {
    let url = reqwest::Url::parse(&key.issuer).map_err(|_| OAuthClientError::InvalidResponse)?;
    if key.vault_id.is_empty()
        || key.actor_ref.is_empty()
        || key.connector_ref.is_empty()
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OAuthClientError::InvalidResponse);
    }
    Ok(())
}

/// Explicit implementation pin; updating it is a reviewed protocol change.
pub const CIMD_DRAFT: &str = "draft-ietf-oauth-client-id-metadata-document-00";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientApplication {
    Native,
    Web,
}

pub fn client_metadata(
    base: &str,
    application: ClientApplication,
) -> Result<Value, OAuthClientError> {
    let base = reqwest::Url::parse(base).map_err(|_| OAuthClientError::InvalidResponse)?;
    if base.scheme() != "https"
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err(OAuthClientError::InvalidResponse);
    }
    let (kind, path) = match application {
        ClientApplication::Native => ("native", "/oauth/client/native.json"),
        ClientApplication::Web => ("web", "/oauth/client/web.json"),
    };
    let client_id = base
        .join(path)
        .map_err(|_| OAuthClientError::InvalidResponse)?;
    let redirect = match application {
        ClientApplication::Native => "oneiron://oauth/callback".to_owned(),
        ClientApplication::Web => base
            .join("/oauth/callback")
            .map_err(|_| OAuthClientError::InvalidResponse)?
            .to_string(),
    };
    Ok(
        json!({"client_id":client_id.as_str(),"client_name":"Oneiron","application_type":kind,
        "redirect_uris":[redirect],"grant_types":["authorization_code"],"response_types":["code"],
        "token_endpoint_auth_method":"none","cimd_draft":CIMD_DRAFT}),
    )
}

#[cfg(test)]
mod tests;
