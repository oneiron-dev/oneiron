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

/// Length of a `jti` claim: 32 lowercase hex characters.
const CORE_TOKEN_JTI_LEN: usize = 32;

/// `sync_state` key prefix for the individual-token revocation registry.
///
/// One key per revoked `jti`; the key IS the fact, so the value is empty.
const REVOKED_TOKEN_JTI_PREFIX: &str = "auth:revoked-token-jti:";

/// The revoked-token registry the verify path consults.
///
/// Revocation is its own explicit act: a `jti` lands here only because an
/// operator named it, never as a side effect of rotation (rotation rewraps
/// the MAC key and invalidates every token at once — a different lever).
///
/// A trait rather than a bare `&Vault` so the crypto/grammar layer stays
/// unit-testable against an in-memory set, and — load-bearing — so that
/// EVERY caller must name a registry. There is deliberately no default and
/// no empty variant: a call site cannot silently skip the consult.
pub(crate) trait RevokedTokenJtis {
    /// Returns whether `jti` has been revoked.
    ///
    /// `Err` means the registry could not be read. Callers fail closed: a
    /// token whose liveness cannot be established is not authenticated.
    fn is_revoked(&self, jti: &str) -> Result<bool, ()>;
}

/// The server-local persistent registry: one `sync_state` row per revoked
/// `jti`, where the key IS the fact and the value is empty.
impl RevokedTokenJtis for oneiron::Vault {
    fn is_revoked(&self, jti: &str) -> Result<bool, ()> {
        self.sync_state_get(&revoked_token_jti_key(jti))
            .map(|row| row.is_some())
            .map_err(drop)
    }
}

/// Registry key for one revoked token identifier.
pub(crate) fn revoked_token_jti_key(jti: &str) -> String {
    format!("{REVOKED_TOKEN_JTI_PREFIX}{jti}")
}

/// Records `jti` as revoked. Returns whether this call was the revocation
/// (`false` means it was already revoked — the op is idempotent).
///
/// Rejects a malformed `jti` rather than writing a row that no token could
/// ever match, so a typo fails loudly at the CLI instead of silently
/// appearing to revoke something.
pub(crate) fn revoke_token_jti(vault: &oneiron::Vault, jti: &str) -> anyhow::Result<bool> {
    if parse_jti(jti).is_err() {
        anyhow::bail!("token id must be exactly {CORE_TOKEN_JTI_LEN} lowercase hex characters");
    }
    let key = revoked_token_jti_key(jti);
    if vault.sync_state_get(&key)?.is_some() {
        return Ok(false);
    }
    vault.sync_state_put(&key, &[])?;
    Ok(true)
}

/// Mints a fresh token identifier.
///
/// UUIDv7 hex: this needs UNIQUENESS, not unpredictability. A `jti` is
/// public — it travels in the token's visible claims and an operator types
/// it into `token revoke` — and guessing one buys nothing, because forging
/// the token carrying it still requires the MAC key.
pub(crate) fn mint_token_jti() -> String {
    oneiron::EntityId::now().to_hex()
}

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
    /// Revocable identity of the credential this auth came from, when it has
    /// one. Retained so a long-lived session can re-consult the registry.
    jti: Option<String>,
    /// D13 actor class the slip binds write identity to (`human`/`agent`/
    /// `system`), when it carries the claim (ONE-1441).
    ///
    /// Additive and optional. Only `/v1/core/facade` handlers read it, and
    /// they REQUIRE it; every route that existed before this field is
    /// unchanged by its absence, which is what an owner-grade secret and a
    /// scoped non-facade slip both present.
    actor_class: Option<String>,
}

impl CoreAuth {
    pub(crate) fn from_headers(
        headers: &HeaderMap,
        config: &SyncServerConfig,
        revoked: &dyn RevokedTokenJtis,
    ) -> Result<Self, ApiError> {
        if let Some(token) = bearer_token(headers)? {
            return bearer_auth(token, config, revoked);
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
            jti: None,
            actor_class: None,
        })
    }

    pub(crate) fn from_oauth_relay(subject: String) -> Self {
        Self {
            principal: format!("oauth-relay:{subject}"),
            principal_ref: None,
            scopes: BTreeSet::from([CoreScope::Read]),
            implicit_all_scopes: false,
            jti: None,
            actor_class: None,
        }
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

    /// The D13 actor class the slip binds, when it carries one (ONE-1441).
    ///
    /// Read only by `/v1/core/facade` handlers, which refuse without it. The
    /// value is already grammar-checked by `parse_actor_class`: reaching a
    /// handler at all means it is one of `human`/`agent`/`system`, so no
    /// handler re-validates the string. It is still not AUTHORITY — the engine
    /// decides whether the named principal's stored entity type admits the
    /// asserted class, per write.
    pub(crate) fn actor_class(&self) -> Option<&str> {
        self.actor_class.as_deref()
    }

    /// Requires that this credential resolves to a REGISTERED principal.
    ///
    /// Additive read over the extractor above; it changes no existing
    /// behaviour and the dev escape hatch is untouched. It exists because
    /// "authenticated" and "a registered actor" are different facts, and the
    /// origin's receive-pack door (ONE-1908, RC4) needs the second one: a
    /// bare trust-root secret and the unauthenticated-dev fallthrough are both
    /// authenticated and neither carries a `principal_ref`, so neither may
    /// push — on loopback exactly as much as anywhere else.
    pub(crate) fn require_registered_principal(&self) -> Result<&str, ApiError> {
        self.principal_ref
            .as_deref()
            .ok_or_else(|| ApiError::forbidden_scope("core:write+principal_ref"))
    }

    /// The credential's revocable identity, when it carries one.
    ///
    /// A bare trust-root secret and the dev fallthrough have none: neither is
    /// individually revocable, and rotation is the lever that retires them.
    pub(crate) fn jti(&self) -> Option<&str> {
        self.jti.as_deref()
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
        Self::from_headers(&parts.headers, &server.config, server.vault().as_ref())
            .map_err(Into::into)
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
    revoked: &dyn RevokedTokenJtis,
) -> Result<CoreAuth, ApiError> {
    let auth = CoreAuth::from_headers(headers, config, revoked)?;
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
/// Claims use the existing grammar (`scope=…[;principal_ref=…][;jti=…]`) and
/// may be empty, which mints an owner-grade token. This is the raw wire
/// helper: it MACs exactly the claims it is handed and adds nothing. Ops
/// mints go through [`mint_identified_core_token_v2`], which attaches the
/// identity that makes the token individually revocable.
pub(crate) fn mint_core_token_v2(auth_secret: &str, claims: &str) -> String {
    let mac = blake3::Hash::from(core_token_mac(auth_secret, claims));
    format!("{CORE_TOKEN_V2_PREFIX}{claims}.{}", mac.to_hex())
}

/// Mints a v2 token carrying a freshly generated `jti`, and returns both.
///
/// Every issued token gets an identity, so every issued token can be revoked
/// individually. A side effect: minting is no longer a pure function of
/// claims and secret — two mints of identical claims produce two distinct
/// tokens, and revoking one leaves its sibling live.
pub(crate) fn mint_identified_core_token_v2(auth_secret: &str, claims: &str) -> (String, String) {
    let jti = mint_token_jti();
    let identified = if claims.is_empty() {
        format!("jti={jti}")
    } else {
        format!("{claims};jti={jti}")
    };
    (mint_core_token_v2(auth_secret, &identified), jti)
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

fn bearer_auth(
    token: &str,
    config: &SyncServerConfig,
    revoked: &dyn RevokedTokenJtis,
) -> Result<CoreAuth, ApiError> {
    let relay_configured = config.oauth_issuer.is_some()
        && config.oauth_jwks_uri.is_some()
        && config.oauth_resource_indicator.is_some();
    let Some(expected) = config.auth_secret.as_ref() else {
        if relay_configured && !token.starts_with(CORE_TOKEN_V2_PREFIX) {
            return crate::oauth_relay::verify_oauth_relay_token(token, config);
        }
        if config.allow_unauthenticated {
            // No secret exists to verify against, so the MAC segment is
            // accepted unverified — but the v2 framing is still required, so
            // dev and production speak one token shape.
            let (claims, _mac_hex) =
                split_core_token_v2(token).ok_or_else(ApiError::unauthorized)?;
            let claims = parse_bearer_claims(claims)?;
            // Revocation is checked in dev too: the registry is real state,
            // and an operator who revoked a jti must not find it live merely
            // because the MAC went unverified.
            return core_auth_for_live_claims("dev-bearer", claims, revoked);
        }
        return Err(ApiError::unauthorized());
    };
    if expected.is_empty() {
        return Err(ApiError::unauthorized());
    }

    // The configured trust root is matched VERBATIM first, before any token
    // parsing. A secret is an opaque operator-chosen string: one that happens
    // to be shaped like `v2.<x>.<y>` is still the owner credential, and
    // judging it as a token would compare its own tail against a MAC and
    // break owner auth outright.
    if constant_time_eq(token, expected) {
        return Ok(CoreAuth {
            principal: "bearer".to_owned(),
            principal_ref: None,
            scopes: CoreScope::all(),
            implicit_all_scopes: true,
            jti: None,
            // The trust root is not an actor. An owner-grade secret binds no
            // principal and therefore no class; facade routes refuse it for
            // exactly that reason, while every other route is unaffected.
            actor_class: None,
        });
    }

    // Not the root itself: `v2.` framing now marks a minted token.
    let Some((claims, mac_hex)) = split_core_token_v2(token) else {
        if config.oauth_issuer.is_some()
            && config.oauth_jwks_uri.is_some()
            && config.oauth_resource_indicator.is_some()
        {
            return crate::oauth_relay::verify_oauth_relay_token(token, config);
        }
        // Neither the root nor a token. The v1 `secret;scope=…` grammar
        // lands here and is dead outright.
        return Err(ApiError::unauthorized());
    };
    // Verify the literal bytes that are then parsed — no canonicalization
    // gap between what the MAC covers and what the grammar reads.
    let expected_mac = blake3::Hash::from(core_token_mac(expected, claims));
    if !constant_time_eq(mac_hex, expected_mac.to_hex().as_str()) {
        return Err(ApiError::unauthorized());
    }
    let claims = parse_bearer_claims(claims)?;
    core_auth_for_live_claims("bearer", claims, revoked)
}

/// Builds the `CoreAuth` for authenticated claims, after confirming the
/// token's identity has not been revoked.
///
/// Fails closed on an unreadable registry: an authentic MAC proves the token
/// was minted, not that it is still live, and "we could not check" must not
/// resolve to "still live".
fn core_auth_for_live_claims(
    principal: &str,
    claims: BearerClaims,
    revoked: &dyn RevokedTokenJtis,
) -> Result<CoreAuth, ApiError> {
    if let Some(jti) = claims.jti.as_deref()
        && is_revoked_or_unreadable(jti, revoked)
    {
        return Err(ApiError::unauthorized());
    }
    let implicit_all_scopes = claims.scopes.is_none();
    Ok(CoreAuth {
        principal: principal.to_owned(),
        principal_ref: claims.principal_ref,
        scopes: claims.scopes.unwrap_or_else(CoreScope::all),
        implicit_all_scopes,
        jti: claims.jti,
        actor_class: claims.actor_class,
    })
}

/// Whether `jti` must be refused: revoked, or a registry that cannot be read.
///
/// The unreadable case collapses into "refuse" deliberately — an authentic
/// MAC proves the token was minted, not that it is still live, and "we could
/// not check" must not resolve to "still live". Shared by the handshake and
/// the live-session re-consult so both fail closed identically.
pub(crate) fn is_revoked_or_unreadable(jti: &str, revoked: &dyn RevokedTokenJtis) -> bool {
    match revoked.is_revoked(jti) {
        Ok(revoked) => revoked,
        Err(()) => {
            tracing::error!("revoked-token registry unreadable; refusing the credential");
            true
        }
    }
}

#[derive(Default)]
struct BearerClaims {
    scopes: Option<BTreeSet<CoreScope>>,
    principal_ref: Option<String>,
    jti: Option<String>,
    actor_class: Option<String>,
}

fn parse_bearer_claims(token_claims: &str) -> Result<BearerClaims, ApiError> {
    let mut claims = BearerClaims::default();
    let mut saw_narrowing_claim = false;
    for claim in token_claims.split(';').filter(|claim| !claim.is_empty()) {
        let Some((key, value)) = claim.split_once('=') else {
            return Err(ApiError::unauthorized());
        };
        match key {
            "scope" | "scopes" => {
                saw_narrowing_claim = true;
                claims.scopes = Some(parse_scope_list(value)?);
            }
            "principal_ref" => {
                saw_narrowing_claim = true;
                claims.principal_ref = Some(parse_principal_ref(value)?);
            }
            // ONE-1441. Narrowing like `principal_ref` beside it: the pair
            // names WHICH actor and WHICH class a facade write is attributed
            // to, so a slip carrying a class but no scope list is refused for
            // the same reason a bare `principal_ref` is.
            //
            // Reached only AFTER the MAC check in `bearer_auth`, so this arm
            // reads bytes the trust root already authenticated and can never
            // weaken the verbatim/MAC gate above it.
            "actor_class" => {
                saw_narrowing_claim = true;
                claims.actor_class = Some(parse_actor_class(value)?);
            }
            // Identity, not narrowing: a `jti` alone leaves the token
            // owner-grade, so it must not trip the scope requirement below.
            "jti" => claims.jti = Some(parse_jti(value)?),
            _ => return Err(ApiError::unauthorized()),
        }
    }
    if saw_narrowing_claim && claims.scopes.is_none() {
        return Err(ApiError::unauthorized());
    }
    Ok(claims)
}

/// Parses a `jti` claim: exactly 32 lowercase hex characters.
///
/// Strict on shape so the registry has one canonical spelling per token —
/// case or length variants would revoke a key no token presents.
fn parse_jti(value: &str) -> Result<String, ApiError> {
    if value.len() != CORE_TOKEN_JTI_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::unauthorized());
    }
    Ok(value.to_owned())
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

/// Parses an `actor_class` claim: the closed D13 vocabulary, exactly.
///
/// A value outside the enum is a MALFORMED credential, not an authorization
/// question, so it 401s here with every other grammar failure rather than
/// reaching a handler and becoming a 403. The distinction is load-bearing for
/// the facade contract: a well-formed slip merely MISSING the claim does reach
/// the handler and fails typed `FORBIDDEN` there.
fn parse_actor_class(value: &str) -> Result<String, ApiError> {
    match value {
        "human" | "agent" | "system" => Ok(value.to_owned()),
        _ => Err(ApiError::unauthorized()),
    }
}

fn constant_time_eq(provided: &str, expected: &str) -> bool {
    provided.len() == expected.len() && provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
mod tests;
