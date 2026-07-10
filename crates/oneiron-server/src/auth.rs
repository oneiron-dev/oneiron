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
const IMPLICIT_ALL_IDEMPOTENCY_SCOPES: &str = "__implicit_all_scopes__";

/// Canonical scopes for the `/v1/core/*` route shell.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CoreScope {
    Read,
    Write,
    Auth,
    CompanionProfileRead,
    CompanionAccessGrantWrite,
    CompanionRegisterRead,
    CompanionRegisterWrite,
}

impl CoreScope {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "core:read",
            Self::Write => "core:write",
            Self::Auth => "core:auth",
            Self::CompanionProfileRead => "companion:profile:read",
            Self::CompanionAccessGrantWrite => "companion:access-grant:write",
            Self::CompanionRegisterRead => "companion:register:read",
            Self::CompanionRegisterWrite => "companion:register:write",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "core:read" => Some(Self::Read),
            "core:write" => Some(Self::Write),
            "core:auth" => Some(Self::Auth),
            "companion:profile:read" => Some(Self::CompanionProfileRead),
            "companion:access-grant:write" => Some(Self::CompanionAccessGrantWrite),
            "companion:register:read" => Some(Self::CompanionRegisterRead),
            "companion:register:write" => Some(Self::CompanionRegisterWrite),
            _ => None,
        }
    }

    fn all() -> BTreeSet<Self> {
        [
            Self::Read,
            Self::Write,
            Self::Auth,
            Self::CompanionProfileRead,
            Self::CompanionAccessGrantWrite,
            Self::CompanionRegisterRead,
            Self::CompanionRegisterWrite,
        ]
        .into_iter()
        .collect()
    }
}

/// Authenticated `/v1/core` caller plus extracted scopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoreAuth {
    principal: String,
    principal_ref: Option<String>,
    scopes: BTreeSet<CoreScope>,
    implicit_all_scopes: bool,
}

impl CoreAuth {
    pub(crate) fn from_headers(
        headers: &HeaderMap,
        config: &SyncServerConfig,
    ) -> Result<Self, ApiError> {
        if headers.contains_key(LEGACY_SECRET_HEADER) && check_auth(headers, config).is_ok() {
            return Ok(Self {
                principal: "legacy-shared-secret".to_owned(),
                principal_ref: None,
                scopes: CoreScope::all(),
                implicit_all_scopes: true,
            });
        }

        if let Some(token) = bearer_token(headers)? {
            return bearer_auth(token, config);
        }

        check_auth(headers, config).map_err(|_| ApiError::unauthorized())?;
        Ok(Self {
            principal: "legacy-shared-secret".to_owned(),
            principal_ref: None,
            scopes: CoreScope::all(),
            implicit_all_scopes: true,
        })
    }

    pub(crate) fn require(&self, scope: CoreScope) -> Result<(), ApiError> {
        if self.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(ApiError::forbidden_scope(scope.as_str()))
        }
    }

    pub(crate) fn has_scope(&self, scope: CoreScope) -> bool {
        self.scopes.contains(&scope)
    }

    pub(crate) fn principal(&self) -> &str {
        &self.principal
    }

    pub(crate) fn principal_ref(&self) -> Option<&str> {
        self.principal_ref.as_deref()
    }

    /// Returns whether this auth is an un-narrowed owner-grade session.
    ///
    /// `principal_ref` is the third-party narrowing key: a bearer carrying it
    /// is scoped to that principal and is never owner-grade (OF-365 ILD-1).
    pub(crate) fn is_owner_session(&self) -> bool {
        self.principal_ref.is_none()
    }

    pub(crate) fn idempotency_principal(&self) -> String {
        let scopes = if self.implicit_all_scopes {
            IMPLICIT_ALL_IDEMPOTENCY_SCOPES.to_owned()
        } else {
            self.scopes
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>()
                .join(",")
        };
        let principal_ref = self
            .principal_ref
            .as_deref()
            .map(|principal_ref| format!(":principal_ref={principal_ref}"))
            .unwrap_or_default();
        format!("core:{}{principal_ref}:scopes={scopes}", self.principal)
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
    let Ok(value) = value.to_str() else {
        return Ok(None);
    };
    let value = value.trim_start();
    let Some((scheme, token)) = value.split_once(char::is_whitespace) else {
        if value.eq_ignore_ascii_case("bearer") {
            return Err(ApiError::unauthorized());
        }
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Ok(None);
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(ApiError::unauthorized());
    };
    Ok(Some(token))
}

fn bearer_auth(token: &str, config: &SyncServerConfig) -> Result<CoreAuth, ApiError> {
    let Some(expected) = config.auth_secret.as_ref() else {
        if config.allow_unauthenticated {
            let claims = parse_bearer_claims(token)?;
            let implicit_all_scopes = claims.scopes.is_none();
            return Ok(CoreAuth {
                principal: "dev-bearer".to_owned(),
                principal_ref: claims.principal_ref,
                scopes: claims.scopes.unwrap_or_else(CoreScope::all),
                implicit_all_scopes,
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

    let claims = parse_bearer_claims(claims)?;
    let implicit_all_scopes = claims.scopes.is_none();
    Ok(CoreAuth {
        principal: "bearer".to_owned(),
        principal_ref: claims.principal_ref,
        scopes: claims.scopes.unwrap_or_else(CoreScope::all),
        implicit_all_scopes,
    })
}

#[derive(Default)]
struct BearerClaims {
    scopes: Option<BTreeSet<CoreScope>>,
    principal_ref: Option<String>,
}

fn parse_bearer_claims(token_claims: &str) -> Result<BearerClaims, ApiError> {
    let mut claims = BearerClaims::default();
    let mut saw_claim = false;
    for claim in token_claims.split(';').filter(|claim| !claim.is_empty()) {
        saw_claim = true;
        let Some((key, value)) = claim.split_once('=') else {
            return Err(ApiError::unauthorized());
        };
        match key {
            "scope" | "scopes" => claims.scopes = Some(parse_scope_list(value)?),
            "principal_ref" => claims.principal_ref = Some(parse_principal_ref(value)?),
            _ => return Err(ApiError::unauthorized()),
        }
    }
    if saw_claim && claims.scopes.is_none() {
        return Err(ApiError::unauthorized());
    }
    Ok(claims)
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

fn parse_principal_ref(value: &str) -> Result<String, ApiError> {
    oneiron::EntityId::from_hex(value)
        .map(|id| id.to_hex())
        .map_err(|_| ApiError::unauthorized())
}

fn constant_time_eq(provided: &str, expected: &str) -> bool {
    provided.len() == expected.len() && provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
mod tests;
