//! HTTP authentication helpers for legacy and `/v1/core` routes.
//!
//! One credential travels: `Authorization: Bearer`. It carries either the
//! configured trust-root secret (owner-grade) or a minted
//! `v2.<claims>.<mac-hex>` token whose claims are authenticated by a keyed
//! BLAKE3 MAC. The secret is never inside a token, so a delegated token
//! discloses no trust root and its narrowing cannot be edited off.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, request::Parts};
use subtle::ConstantTimeEq;

use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::server::SyncServer;

const IMPLICIT_ALL_IDEMPOTENCY_SCOPES: &str = "__implicit_all_scopes__";

/// Framing prefix of a v2 core token (`v2.<claims>.<mac-hex>`).
const CORE_TOKEN_V2_PREFIX: &str = "v2.";

/// `blake3::derive_key` context for the v2 token MAC key.
///
/// Byte-exact and load-bearing: it separates this key from every other
/// BLAKE3 use of `auth_secret` (notably the MCP connector-registry hash key)
/// and normalizes an arbitrary-length secret to a uniform 32-byte MAC key.
/// Changing it invalidates every minted token.
const CORE_TOKEN_V2_KDF_CONTEXT: &str = "oneiron-server 2026-07 core-token-v2 mac";

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
        if let Some(token) = bearer_token(headers)? {
            return bearer_auth(token, config);
        }

        // No credential presented: only the explicit unauthenticated-dev
        // escape hatch admits the request, and only when no secret is set.
        if config.auth_secret.is_some() || !config.allow_unauthenticated {
            return Err(ApiError::unauthorized());
        }
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

    /// Returns whether this auth is an un-narrowed owner-grade credential.
    ///
    /// BOTH narrowing axes must be absent. `principal_ref` is the third-party
    /// narrowing key: a bearer carrying it is scoped to that principal
    /// (OF-365 ILD-1). A scope list is the capability narrowing key: a bearer
    /// carrying one is a delegated instrument, and delegation of a subset of
    /// the owner's capabilities is not evidence that the owner is the one
    /// holding it. Reading only `principal_ref` classified an unbound
    /// `scope=core:read` token as owner-grade, which suppressed the
    /// disclosure absence-clamp for exactly the credentials most likely to
    /// be handed to a third party.
    ///
    /// Deliberately NOT named `owner_session`: that is the engine-side ILD
    /// flag for "the owner is in the room", asserted per assembly. This is a
    /// property of the credential. The consent gates derive the former from
    /// the latter and must never conflate them.
    pub(crate) fn is_owner_grade(&self) -> bool {
        self.implicit_all_scopes && self.principal_ref.is_none()
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

/// Authenticates an owner-grade caller.
///
/// Owner-grade means a bearer that resolves to the un-narrowed
/// implicit-all-scopes session: the bare trust-root secret, an empty-claims
/// v2 token, or the unauthenticated-dev fallthrough. Scoped delegation
/// tokens do NOT pass — the full-vault surfaces (`/ws` sync, legacy
/// `/api/*`, the non-core idempotency fallback) keep the boundary where only
/// trust-root holders reach them; scoped tokens stay `/v1`-plane instruments.
pub(crate) fn require_owner_auth(
    headers: &HeaderMap,
    config: &SyncServerConfig,
) -> Result<CoreAuth, ApiError> {
    let auth = CoreAuth::from_headers(headers, config)?;
    if auth.is_owner_grade() {
        Ok(auth)
    } else {
        Err(ApiError::unauthorized())
    }
}

/// Derives the v2 token MAC over a claims string.
///
/// The auth secret is MAC key material only — it appears in no token. Keyed
/// BLAKE3 is a PRF by construction, so this is a MAC and not an ad-hoc
/// `H(k ‖ m)`; domain separation comes from the `derive_key` context.
pub(crate) fn core_token_mac(auth_secret: &str, claims: &str) -> [u8; 32] {
    let key = blake3::derive_key(CORE_TOKEN_V2_KDF_CONTEXT, auth_secret.as_bytes());
    *blake3::keyed_hash(&key, claims.as_bytes()).as_bytes()
}

/// Mints a v2 core token: `v2.<claims>.<mac-hex>`.
///
/// Claims use the existing grammar (`scope=…[;principal_ref=…]`) and may be
/// empty, which mints an owner-grade token.
pub(crate) fn mint_core_token_v2(auth_secret: &str, claims: &str) -> String {
    let mac = blake3::Hash::from(core_token_mac(auth_secret, claims));
    format!("{CORE_TOKEN_V2_PREFIX}{claims}.{}", mac.to_hex())
}

/// Checks a claims string against the grammar the server will enforce, so a
/// mint surface can reject before emitting a token that would only ever 401.
pub(crate) fn validate_bearer_claims(claims: &str) -> Result<(), ApiError> {
    parse_bearer_claims(claims).map(drop)
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

/// Splits a v2 token into its claims and hex-MAC segments.
///
/// Right-splits the last dot so the framing stays stable if a claim value
/// ever carries one. The MAC's shape is not validated here: it is compared
/// against canonical lowercase hex below, which rejects wrong lengths, wrong
/// case, and non-hex alike through one uniform 401.
fn split_core_token_v2(token: &str) -> Option<(&str, &str)> {
    token.strip_prefix(CORE_TOKEN_V2_PREFIX)?.rsplit_once('.')
}

fn bearer_auth(token: &str, config: &SyncServerConfig) -> Result<CoreAuth, ApiError> {
    let Some(expected) = config.auth_secret.as_ref() else {
        if config.allow_unauthenticated {
            // No secret exists to verify against, so the MAC segment is
            // accepted unverified — but the v2 framing is still required, so
            // dev and production speak one token shape.
            let (claims, _mac_hex) =
                split_core_token_v2(token).ok_or_else(ApiError::unauthorized)?;
            let claims = parse_bearer_claims(claims)?;
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

    // The `v2.` prefix is reserved framing: anything wearing it is judged as
    // a token and never falls through to the bare-secret comparison.
    if let Some((claims, mac_hex)) = split_core_token_v2(token) {
        // Verify the literal bytes that are then parsed — no canonicalization
        // gap between what the MAC covers and what the grammar reads.
        let expected_mac = blake3::Hash::from(core_token_mac(expected, claims));
        if !constant_time_eq(mac_hex, expected_mac.to_hex().as_str()) {
            return Err(ApiError::unauthorized());
        }
        let claims = parse_bearer_claims(claims)?;
        let implicit_all_scopes = claims.scopes.is_none();
        return Ok(CoreAuth {
            principal: "bearer".to_owned(),
            principal_ref: claims.principal_ref,
            scopes: claims.scopes.unwrap_or_else(CoreScope::all),
            implicit_all_scopes,
        });
    }

    // Bare trust-root secret presented over the standard header. The v1
    // `secret;scope=…` grammar fails this comparison and is dead outright.
    if !constant_time_eq(token, expected) {
        return Err(ApiError::unauthorized());
    }
    Ok(CoreAuth {
        principal: "bearer".to_owned(),
        principal_ref: None,
        scopes: CoreScope::all(),
        implicit_all_scopes: true,
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
