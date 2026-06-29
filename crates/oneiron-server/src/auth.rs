//! HTTP authentication helpers for legacy and `/v1/core` routes.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode, request::Parts};
use subtle::ConstantTimeEq;

use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::server::SyncServer;

const LEGACY_SECRET_HEADER: &str = "x-oneiron-secret";

/// Canonical scopes for the `/v1/core/*` route shell.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CoreScope {
    Read,
    Write,
    Auth,
}

impl CoreScope {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "core:read",
            Self::Write => "core:write",
            Self::Auth => "core:auth",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "core:read" => Some(Self::Read),
            "core:write" => Some(Self::Write),
            "core:auth" => Some(Self::Auth),
            _ => None,
        }
    }

    fn all() -> BTreeSet<Self> {
        [Self::Read, Self::Write, Self::Auth].into_iter().collect()
    }
}

/// Authenticated `/v1/core` caller plus extracted scopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoreAuth {
    principal: String,
    scopes: BTreeSet<CoreScope>,
}

impl CoreAuth {
    pub(crate) fn from_headers(
        headers: &HeaderMap,
        config: &SyncServerConfig,
    ) -> Result<Self, ApiError> {
        if headers.contains_key(LEGACY_SECRET_HEADER) && check_auth(headers, config).is_ok() {
            return Ok(Self {
                principal: "legacy-shared-secret".to_owned(),
                scopes: CoreScope::all(),
            });
        }

        if let Some(token) = bearer_token(headers)? {
            return bearer_auth(token, config);
        }

        check_auth(headers, config).map_err(|_| ApiError::unauthorized())?;
        Ok(Self {
            principal: "legacy-shared-secret".to_owned(),
            scopes: CoreScope::all(),
        })
    }

    pub(crate) fn require(&self, scope: CoreScope) -> Result<(), ApiError> {
        if self.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(ApiError::forbidden_scope(scope.as_str()))
        }
    }

    pub(crate) fn principal(&self) -> &str {
        &self.principal
    }
}

impl FromRequestParts<Arc<SyncServer>> for CoreAuth {
    type Rejection = crate::error::EnvelopedApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        server: &Arc<SyncServer>,
    ) -> Result<Self, Self::Rejection> {
        Self::from_headers(&parts.headers, &server.config).map_err(Into::into)
    }
}

/// Validates the legacy shared secret from request headers.
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
/// Shared by the HTTP API routes and the `/ws` upgrade handler.
pub(crate) fn check_auth(headers: &HeaderMap, config: &SyncServerConfig) -> Result<(), StatusCode> {
    let Some(expected) = config.auth_secret.as_ref() else {
        return if config.allow_unauthenticated {
            Ok(())
        } else {
            Err(StatusCode::UNAUTHORIZED)
        };
    };
    if expected.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let provided = headers
        .get(LEGACY_SECRET_HEADER)
        .and_then(|v| v.to_str().ok());

    match provided {
        Some(s) if constant_time_eq(s, expected) => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ApiError::unauthorized())?;
    let Some((scheme, token)) = value.split_once(char::is_whitespace) else {
        return Err(ApiError::unauthorized());
    };
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(ApiError::unauthorized());
    }
    Ok(Some(token))
}

fn bearer_auth(token: &str, config: &SyncServerConfig) -> Result<CoreAuth, ApiError> {
    let Some(expected) = config.auth_secret.as_ref() else {
        if config.allow_unauthenticated {
            return Ok(CoreAuth {
                principal: "dev-bearer".to_owned(),
                scopes: parse_bearer_scopes(token)?.unwrap_or_else(CoreScope::all),
            });
        }
        return Err(ApiError::unauthorized());
    };
    if expected.is_empty() {
        return Err(ApiError::unauthorized());
    }

    let (credential, claims) = token.split_once(';').unwrap_or((token, ""));
    if !constant_time_eq(credential, expected) {
        return Err(ApiError::unauthorized());
    }

    Ok(CoreAuth {
        principal: "bearer".to_owned(),
        scopes: parse_bearer_scopes(claims)?.unwrap_or_else(CoreScope::all),
    })
}

fn parse_bearer_scopes(token_claims: &str) -> Result<Option<BTreeSet<CoreScope>>, ApiError> {
    let mut scopes = None;
    for claim in token_claims.split(';').filter(|claim| !claim.is_empty()) {
        let Some((key, value)) = claim.split_once('=') else {
            return Err(ApiError::unauthorized());
        };
        match key {
            "scope" | "scopes" => scopes = Some(parse_scope_list(value)?),
            _ => return Err(ApiError::unauthorized()),
        }
    }
    Ok(scopes)
}

fn parse_scope_list(value: &str) -> Result<BTreeSet<CoreScope>, ApiError> {
    let mut scopes = BTreeSet::new();
    for item in value.split([',', ' ']).filter(|item| !item.is_empty()) {
        let Some(scope) = CoreScope::parse(item) else {
            return Err(ApiError::unauthorized());
        };
        scopes.insert(scope);
    }
    Ok(scopes)
}

fn constant_time_eq(provided: &str, expected: &str) -> bool {
    provided.len() == expected.len() && provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SyncServerConfig {
        SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn legacy_secret_grants_all_core_scopes() {
        let mut headers = HeaderMap::new();
        headers.insert(LEGACY_SECRET_HEADER, "secret".parse().unwrap());
        let auth = CoreAuth::from_headers(&headers, &config()).unwrap();

        assert_eq!(auth.principal(), "legacy-shared-secret");
        assert!(auth.require(CoreScope::Read).is_ok());
        assert!(auth.require(CoreScope::Write).is_ok());
        assert!(auth.require(CoreScope::Auth).is_ok());
    }

    #[test]
    fn legacy_secret_still_authenticates_with_unrelated_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(LEGACY_SECRET_HEADER, "secret".parse().unwrap());
        headers.insert(AUTHORIZATION, "Basic unrelated".parse().unwrap());
        let auth = CoreAuth::from_headers(&headers, &config()).unwrap();

        assert_eq!(auth.principal(), "legacy-shared-secret");
        assert!(auth.require(CoreScope::Write).is_ok());
    }

    #[test]
    fn bearer_token_extracts_scopes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer secret;scope=core:read,core:auth".parse().unwrap(),
        );
        let auth = CoreAuth::from_headers(&headers, &config()).unwrap();

        assert_eq!(auth.principal(), "bearer");
        assert!(auth.require(CoreScope::Read).is_ok());
        assert!(auth.require(CoreScope::Auth).is_ok());
        assert!(auth.require(CoreScope::Write).is_err());
    }

    #[test]
    fn bare_bearer_secret_bridges_to_all_core_scopes() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer secret".parse().unwrap());
        let auth = CoreAuth::from_headers(&headers, &config()).unwrap();

        assert!(auth.require(CoreScope::Read).is_ok());
        assert!(auth.require(CoreScope::Write).is_ok());
        assert!(auth.require(CoreScope::Auth).is_ok());
    }
}
