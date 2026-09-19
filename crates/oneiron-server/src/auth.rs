//! HTTP authentication for log-backed version-two capability slips.
//!
//! Authorization carries the serialized slip. `x-oneiron-binding` carries
//! the holder's short-lived Ed25519 proof. The configured retained host
//! secret authenticates through its genuine logged root slip. Legacy
//! string-claim MAC tokens never establish production authority.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, request::Parts};
use subtle::ConstantTimeEq;

use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::server::SyncServer;

mod binding_admission;
mod slips;
pub(crate) use binding_admission::admit_http_binding;
pub(crate) use slips::BindingProof;

const IMPLICIT_ALL_IDEMPOTENCY_SCOPES: &str = "__implicit_all_scopes__";

/// Framing prefix of a v2 core token (`v2.<claims>.<mac-hex>`).
const CORE_TOKEN_V2_PREFIX: &str = "v2.";

/// `blake3::derive_key` context for the v2 token MAC key.
///
/// Byte-exact and load-bearing: it separates this key from every other
/// BLAKE3 use of `auth_secret` (notably the MCP connector-registry hash key)
/// and normalizes an arbitrary-length secret to a uniform 32-byte MAC key.
/// Changing it invalidates every minted token.
#[cfg(test)]
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
    fn host_root(&self, _secret: &str) -> Result<oneiron::authority::VerifiedSlip, ()> {
        Err(())
    }
    fn verify_slip(
        &self,
        _secret: &str,
        _slip: &oneiron::authority::CapabilitySlip,
        _challenge: &[u8],
        _signature: &[u8],
    ) -> Result<oneiron::authority::VerifiedSlip, ()> {
        Err(())
    }
}

/// The server-local persistent registry: one `sync_state` row per revoked
/// `jti`, where the key IS the fact and the value is empty.
impl RevokedTokenJtis for oneiron::Vault {
    fn host_root(&self, secret: &str) -> Result<oneiron::authority::VerifiedSlip, ()> {
        let issuer =
            oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes()).map_err(drop)?;
        self.verified_host_root_slip(&issuer).map_err(drop)
    }
    fn verify_slip(
        &self,
        secret: &str,
        slip: &oneiron::authority::CapabilitySlip,
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<oneiron::authority::VerifiedSlip, ()> {
        let issuer =
            oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes()).map_err(drop)?;
        self.verify_capability_slip(&issuer, slip, challenge, signature)
            .map_err(drop)
    }

    fn is_revoked(&self, jti: &str) -> Result<bool, ()> {
        if jti.len() == 64 {
            let id = slips::parse_slip_id(jti).map_err(drop)?;
            return self
                .capability_slip_id_is_live(&id)
                .map(|live| !live)
                .map_err(drop);
        }
        self.sync_state_get(&revoked_token_jti_key(jti))
            .map(|row| row.is_some())
            .map_err(drop)
    }
}

/// Registry key for one revoked token identifier.
pub(crate) fn revoked_token_jti_key(jti: &str) -> String {
    format!("{REVOKED_TOKEN_JTI_PREFIX}{jti}")
}

/// Retires a legacy 32-hex token identifier. Capability-slip ids instead need
/// a signed `Vault::revoke_capability_slip` operation (the CLI's 64-hex branch).
/// Returns whether this call was the revocation
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
#[cfg(test)]
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
    OrgAdmin(oneiron::federation::OrgAdminPower),
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
            Self::OrgAdmin(power) => power.as_str(),
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
            value => oneiron::federation::OrgAdminPower::parse(value).map(Self::OrgAdmin),
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
            Self::OrgAdmin(oneiron::federation::OrgAdminPower::AddMember),
            Self::OrgAdmin(oneiron::federation::OrgAdminPower::RemoveMember),
            Self::OrgAdmin(oneiron::federation::OrgAdminPower::AssignRole),
            Self::OrgAdmin(oneiron::federation::OrgAdminPower::ResetSharedProjectAccess),
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
    org_ref: Option<String>,
    verified_slip: Option<oneiron::authority::VerifiedSlip>,
    /// Exact authenticated instrument, independent of the verifier's remaining TTL.
    instrument: Option<[u8; 32]>,
}

impl CoreAuth {
    /// Refuses an in-band token without its mandatory holder binding proof.
    /// Neither the trust root (even a v2-shaped root) nor dev-mode unverified
    /// credentials may establish app-tier authority. Claim grammar is unchanged.
    #[cfg(test)]
    pub(crate) fn from_bind_token(
        token: &str,
        config: &SyncServerConfig,
        revoked: &dyn RevokedTokenJtis,
    ) -> Result<Self, ApiError> {
        let _ = (token, config, revoked);
        // A token alone cannot bind a session: possession of the connection
        // private key is mandatory, even for an otherwise valid v2 MAC.
        Err(ApiError::unauthorized())
    }

    pub(crate) fn for_server(headers: &HeaderMap, server: &SyncServer) -> Result<Self, ApiError> {
        if let Some(issuer) = server.managed_issuer.as_ref() {
            let proof = server
                .vault()
                .verified_host_root_slip(issuer)
                .map_err(|_| ApiError::unauthorized())?;
            let mut auth = Self::from_verified(proof, true)?;
            auth.principal = "managed-supervisor".to_owned();
            return Ok(auth);
        }
        Self::from_headers(headers, &server.config, server.vault().as_ref())
    }

    pub(crate) fn from_headers(
        headers: &HeaderMap,
        config: &SyncServerConfig,
        revoked: &dyn RevokedTokenJtis,
    ) -> Result<Self, ApiError> {
        if let Some(token) = bearer_token(headers)? {
            // Secrets are opaque, including one that resembles slip framing.
            if config
                .auth_secret
                .as_deref()
                .is_some_and(|secret| constant_time_eq(token, secret))
            {
                return bearer_auth(token, config, revoked);
            }
            if token.starts_with("v2.slip.") {
                return Self::from_slip_token(
                    token,
                    &BindingProof::from_headers(headers)?,
                    config,
                    revoked,
                );
            }
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
            org_ref: None,
            verified_slip: None,
            instrument: None,
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
            org_ref: None,
            verified_slip: None,
            instrument: None,
        }
    }

    pub(crate) fn require(&self, scope: CoreScope) -> Result<(), ApiError> {
        if scope != CoreScope::Read {
            self.require_unrestricted_record_scope()?;
        }
        if self.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(ApiError::forbidden_scope(scope.as_str()))
        }
    }

    pub(crate) fn has_scope(&self, scope: CoreScope) -> bool {
        self.scopes.contains(&scope)
    }

    pub(crate) fn verified_slip(&self) -> Option<&oneiron::authority::VerifiedSlip> {
        self.verified_slip.as_ref()
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
    pub(crate) fn org_ref(&self) -> Option<&str> {
        self.org_ref.as_deref()
    }

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
    /// The bare secret carries the logged host-root slip id too. Only the
    /// unauthenticated development fallthrough has no credential to revoke.
    pub(crate) fn jti(&self) -> Option<&str> {
        self.jti.as_deref()
    }

    /// Exact, verified, unattenuated top-scope slips are owner-grade even when
    /// bound to an identified holder. Identity is not a capability restriction.
    /// Org-bound, caveated, record/channel-bound and single-use slips are not.
    /// The explicit development hatch keeps its separate legacy predicate.
    pub(crate) fn is_owner_grade(&self) -> bool {
        self.implicit_all_scopes && (self.verified_slip.is_some() || self.principal_ref.is_none())
    }

    /// Reconnect matches the exact verified instrument and projected principal.
    /// Holder proofs have fresh nonces; verification-time remaining TTL can change.
    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        self.instrument.is_some()
            && self.instrument == other.instrument
            && self.principal == other.principal
            && self.principal_ref == other.principal_ref
            && self.actor_class == other.actor_class
            && self.org_ref == other.org_ref
            && self.scopes == other.scopes
            && self.implicit_all_scopes == other.implicit_all_scopes
            && self.jti == other.jti
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
        let org_ref = self
            .org_ref
            .as_deref()
            .map(|org| format!(":org_ref={org}"))
            .unwrap_or_default();
        // The exact verified instrument partitions every caveat. Remaining TTL
        // is a verifier observation, not a new cache or reconnect identity.
        let authority = self
            .instrument
            .map(|fingerprint| format!(":authority={}", blake3::Hash::from(fingerprint).to_hex()))
            .unwrap_or_default();
        format!(
            "core:{}{principal_ref}{org_ref}:scopes={scopes}{authority}",
            self.principal
        )
    }
}

impl FromRequestParts<Arc<SyncServer>> for CoreAuth {
    type Rejection = crate::error::EnvelopedApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        server: &Arc<SyncServer>,
    ) -> Result<Self, Self::Rejection> {
        Self::for_server(&parts.headers, server).map_err(Into::into)
    }
}

/// Authenticates an owner-grade caller.
///
/// The logged host root or an exact verified top-scope instrument reaches
/// full-vault routes. Scoped/org credentials remain `/v1`-plane instruments.
/// The explicit unauthenticated development hatch is unchanged.
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
#[cfg(test)]
pub(crate) fn core_token_mac(auth_secret: &str, claims: &str) -> [u8; 32] {
    let key = blake3::derive_key(CORE_TOKEN_V2_KDF_CONTEXT, auth_secret.as_bytes());
    *blake3::keyed_hash(&key, claims.as_bytes()).as_bytes()
}

/// Mints a v2 core token: `v2.<claims>.<mac-hex>`.
///
/// Claims use the existing grammar (`scope=…[;principal_ref=…][;jti=…]`) and
/// may be empty, which mints an owner-grade token. This is the raw wire
/// helper: it MACs exactly the claims it is handed and adds nothing. Ops
/// mints go through `mint_identified_core_token_v2`, which attaches the
/// identity that makes the token individually revocable.
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
        let verified = revoked
            .host_root(expected)
            .map_err(|_| ApiError::unauthorized())?;
        let mut auth = CoreAuth::from_verified(verified, true)?;
        if !auth.is_owner_grade() {
            return Err(ApiError::unauthorized());
        }
        auth.principal = "bearer".to_owned();
        return Ok(auth);
    }

    if config.oauth_issuer.is_some()
        && config.oauth_jwks_uri.is_some()
        && config.oauth_resource_indicator.is_some()
        && !token.starts_with(CORE_TOKEN_V2_PREFIX)
    {
        return crate::oauth_relay::verify_oauth_relay_token(token, config);
    }
    // String-claim tokens have neither a log mint nor a binding-key proof.
    Err(ApiError::unauthorized())
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
        org_ref: claims.org_ref,
        verified_slip: None,
        instrument: None,
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
    org_ref: Option<String>,
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
            "org_ref" => {
                saw_narrowing_claim = true;
                claims.org_ref = Some(parse_principal_ref(value)?);
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
    if let Some(scopes) = &claims.scopes {
        let has_admin = scopes
            .iter()
            .any(|scope| matches!(scope, CoreScope::OrgAdmin(_)));
        if has_admin
            && (claims.org_ref.is_none()
                || claims.principal_ref.is_none()
                || scopes
                    .iter()
                    .any(|scope| !matches!(scope, CoreScope::OrgAdmin(_))))
        {
            return Err(ApiError::unauthorized());
        }
        if !has_admin && claims.org_ref.is_some() {
            return Err(ApiError::unauthorized());
        }
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
