//! Codes into tokens, tokens into new tokens, revocation, and the bearer's resolution at the
//! `/mcp` ingress.
//!
//! One code's redemption mints one token family: an access token and a refresh token. A refresh
//! spends its refresh token and mints the family's next pair; a spent refresh token presented
//! again, or a code redeemed twice, revokes the whole family (OAuth 2.1 §4.3.1, RFC 6749
//! §4.1.2). A revoked family, or one whose owner agent grant no longer stands, holds no token
//! that resolves, so the owner's one-tap revoke of the grant ends every token of it.

use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::rows::{AuthorizedGrant, CODES, FAMILIES, IssuedToken, TOKENS, TokenFamily, TokenKind};
use super::{
    OAUTH_ACCESS_TOKEN_PREFIX, OAUTH_ACCESS_TTL_SECS, OAUTH_CODE_PREFIX,
    OAUTH_REFRESH_TOKEN_PREFIX, OAUTH_REFRESH_TTL_SECS, mint_secret, oauth_requested_tier,
    secret_row_key,
};
use crate::authority::{AgentTier, HostSlipIssuer, grant_known_withdrawn_in_txn};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::federation::decode_federation_grant_body;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::side_table::HexId;
use crate::store::agent_record::AgentCeiling;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// A code redemption the token endpoint read (`grant_type=authorization_code`).
#[derive(Clone, Copy)]
pub struct OAuthCodeExchange<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
    /// The RFC 8707 resource, when the client sent one.
    pub resource: Option<&'a str>,
}

/// A refresh the token endpoint read (`grant_type=refresh_token`).
#[derive(Clone, Copy)]
pub struct OAuthRefresh<'a> {
    pub refresh_token: &'a str,
    pub client_id: &'a str,
    /// The RFC 8707 resource, when the client sent one.
    pub resource: Option<&'a str>,
    /// The scope it asks for, when it sent one: never wider than the family's tier.
    pub scope: Option<&'a str>,
}

/// A token response's secrets and terms (RFC 6749 §5.1). Not `Debug`: it holds two tokens.
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    /// The access token's lifetime in seconds.
    pub expires_in: u64,
    /// The tier the tokens carry, as its scope value.
    pub scope: &'static str,
}

/// Why the token endpoint refuses a code or a refresh token (RFC 6749 §5.2, RFC 8707 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthTokenRefusal {
    /// Unknown, lapsed, spent or revoked; issued to another client or redirect URI; a PKCE
    /// verifier that does not match; or a grant that no longer stands.
    InvalidGrant,
    /// A resource other than the one the code or family is bound to.
    InvalidTarget,
    /// A scope wider than the family's tier, or one that names no tier.
    InvalidScope,
}

impl OAuthTokenRefusal {
    /// Its RFC 6749 §5.2 or RFC 8707 error code.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidScope => "invalid_scope",
        }
    }
}

/// What an access token lets its bearer do, for the `/mcp` ingress (FIX 4902 slice C): it acts
/// as `agent`, of class `actor_class`, with `scopes` under `ceiling`, bound to `world` when one
/// is named, while `grant_ref` stands and until `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthAccess {
    /// The client's agent principal.
    pub agent: EntityId,
    /// Always [`EdgeActorClass::Agent`].
    pub actor_class: EdgeActorClass,
    /// The tier the owner gave.
    pub tier: AgentTier,
    /// The credential scopes the bearer carries ([`AgentTier::core_scopes`]).
    pub scopes: &'static [&'static str],
    /// The agent's ceiling at its tier ([`AgentTier::ceiling`]).
    pub ceiling: AgentCeiling,
    /// The one world the grant is bound to; `None`: every world the owner reads.
    pub world: Option<EntityId>,
    /// The owner agent grant the token stands on.
    pub grant_ref: EntityId,
    /// The token family the access token is of: every token one code's redemption and its
    /// refreshes minted. The `/mcp` caller's instrument names it, and a long call judges that
    /// caller again by it ([`crate::Vault::oauth_access_is_live`]).
    pub family: EntityId,
    /// The client the token was issued to.
    pub client_id: String,
    /// When the access token lapses (Unix seconds).
    pub expires_at: u64,
}

/// Whether `challenge` has an S256 PKCE challenge's shape (CALLS, FIX 4902: an engine call): the
/// 43 base64url characters of a SHA-256 digest's unpadded encoding (RFC 7636 §4.2).
#[must_use]
pub fn oauth_code_challenge_admitted(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Whether `verifier` is an RFC 7636 §4.1 verifier (43 to 128 unreserved characters) whose S256
/// challenge is `challenge`.
fn pkce_s256_matches(verifier: &str, challenge: &str) -> bool {
    let shaped = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'));
    shaped
        && base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()))
            == challenge
}

/// A fresh access and refresh token, with the keys their rows go under.
struct MintedPair {
    access: String,
    access_key: String,
    refresh: String,
    refresh_key: String,
}

impl MintedPair {
    fn new(issuer: &HostSlipIssuer) -> Result<Self> {
        let access = mint_secret(OAUTH_ACCESS_TOKEN_PREFIX)?;
        let refresh = mint_secret(OAUTH_REFRESH_TOKEN_PREFIX)?;
        Ok(Self {
            access_key: secret_row_key(issuer, &access),
            refresh_key: secret_row_key(issuer, &refresh),
            access,
            refresh,
        })
    }

    /// Puts both rows for `family` at `now` and answers the response; the refresh token lapses
    /// at `refresh_expires_at`.
    fn issue_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        family: EntityId,
        tier: AgentTier,
        now: u64,
        refresh_expires_at: u64,
    ) -> Result<OAuthTokens> {
        TOKENS.put(
            &vault.store,
            txn,
            &self.access_key,
            &IssuedToken {
                kind: TokenKind::Access,
                family,
                expires_at: now.saturating_add(OAUTH_ACCESS_TTL_SECS),
                spent: false,
            },
        )?;
        TOKENS.put(
            &vault.store,
            txn,
            &self.refresh_key,
            &IssuedToken {
                kind: TokenKind::Refresh,
                family,
                expires_at: refresh_expires_at,
                spent: false,
            },
        )?;
        Ok(OAuthTokens {
            access_token: self.access,
            refresh_token: self.refresh,
            expires_in: OAUTH_ACCESS_TTL_SECS,
            scope: tier.wire_name(),
        })
    }
}

/// Revokes `family` in the caller's writer; a family already gone stays gone.
fn revoke_family_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, family: EntityId) -> Result<()> {
    let key = HexId(family);
    if let Some(mut row) = FAMILIES.get(&vault.store, txn, &key)? {
        row.revoked = true;
        FAMILIES.put(&vault.store, txn, &key, &row)?;
    }
    Ok(())
}

impl Vault {
    /// Whether the owner agent grant a sign-in stands on still stands at `now`: a live
    /// FEDERATION_GRANT the owner minted his agent, naming `grant.agent`, that confers now, is
    /// not known withdrawn, and whose pact membership, on a shared vault, still stands.
    fn oauth_grant_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: &AuthorizedGrant,
        now: u64,
    ) -> Result<bool> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &grant.grant_ref)?
        else {
            return Ok(false);
        };
        let Ok(row) = decode_federation_grant_body(&body) else {
            return Ok(false);
        };
        Ok(row.owner_agent
            && row.member_ref == grant.agent
            && row.confers_at(now)
            && !grant_known_withdrawn_in_txn(&self.store, txn, grant.grant_ref)
            && !crate::authority::principal_standing::grant_pact_standing_lapsed_in_txn(
                self,
                txn,
                grant.grant_ref,
                row.scope,
                row.member_ref,
            ))
    }

    /// Redeems an authorization code once: its client, its redirect URI and the PKCE S256 of
    /// the verifier must match, a resource the client sends must be the code's, and its grant
    /// must still stand. Answers a new token family's first pair. A code redeemed before
    /// revokes the family it minted.
    ///
    /// # Errors
    /// A store failure.
    pub fn exchange_oauth_code(
        &self,
        issuer: &HostSlipIssuer,
        exchange: &OAuthCodeExchange<'_>,
        now: u64,
    ) -> Result<std::result::Result<OAuthTokens, OAuthTokenRefusal>> {
        if !exchange.code.starts_with(OAUTH_CODE_PREFIX) {
            return Ok(Err(OAuthTokenRefusal::InvalidGrant));
        }
        let key = secret_row_key(issuer, exchange.code);
        let pair = MintedPair::new(issuer)?;
        self.with_write_txn_grouped(|txn| {
            let Some(mut code) = CODES.get(&self.store, txn, &key)? else {
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            };
            if now >= code.expires_at {
                CODES.delete(&self.store, txn, &key)?;
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            }
            if let Some(family) = code.redeemed_family {
                revoke_family_in_txn(self, txn, family)?;
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            }
            if code.client_id != exchange.client_id
                || code.redirect_uri != exchange.redirect_uri
                || !pkce_s256_matches(exchange.code_verifier, &code.code_challenge)
            {
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            }
            if exchange
                .resource
                .is_some_and(|resource| resource != code.resource)
            {
                return Ok(Err(OAuthTokenRefusal::InvalidTarget));
            }
            if !self.oauth_grant_stands_in_txn(txn, &code.grant, now)? {
                CODES.delete(&self.store, txn, &key)?;
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            }
            let family = EntityId::now();
            let refresh_expires_at = now.saturating_add(OAUTH_REFRESH_TTL_SECS);
            FAMILIES.put(
                &self.store,
                txn,
                &HexId(family),
                &TokenFamily {
                    client_id: code.client_id.clone(),
                    resource: code.resource.clone(),
                    grant: code.grant,
                    expires_at: refresh_expires_at,
                    revoked: false,
                },
            )?;
            code.redeemed_family = Some(family);
            CODES.put(&self.store, txn, &key, &code)?;
            pair.issue_in_txn(self, txn, family, code.grant.tier, now, refresh_expires_at)
                .map(Ok)
        })
    }

    /// Trades a refresh token for its family's next pair, spending it: its client must be the
    /// family's, a resource the client sends must be the family's, a scope it sends must be no
    /// wider than the family's tier, and the grant must still stand. A spent refresh token
    /// presented again revokes its family.
    ///
    /// # Errors
    /// A store failure.
    pub fn refresh_oauth_token(
        &self,
        issuer: &HostSlipIssuer,
        refresh: &OAuthRefresh<'_>,
        now: u64,
    ) -> Result<std::result::Result<OAuthTokens, OAuthTokenRefusal>> {
        if !refresh
            .refresh_token
            .starts_with(OAUTH_REFRESH_TOKEN_PREFIX)
        {
            return Ok(Err(OAuthTokenRefusal::InvalidGrant));
        }
        let asked = match refresh.scope.filter(|scope| !scope.trim().is_empty()) {
            None => None,
            Some(scope) => match oauth_requested_tier(Some(scope)) {
                Some(tier) => Some(tier),
                None => return Ok(Err(OAuthTokenRefusal::InvalidScope)),
            },
        };
        let key = secret_row_key(issuer, refresh.refresh_token);
        let pair = MintedPair::new(issuer)?;
        self.with_write_txn_grouped(|txn| {
            let Some(mut token) = TOKENS
                .get(&self.store, txn, &key)?
                .filter(|token| token.kind == TokenKind::Refresh)
            else {
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            };
            if now >= token.expires_at {
                TOKENS.delete(&self.store, txn, &key)?;
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            }
            let family_key = HexId(token.family);
            let Some(family) = FAMILIES.get(&self.store, txn, &family_key)? else {
                TOKENS.delete(&self.store, txn, &key)?;
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            };
            if family.revoked || now >= family.expires_at {
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            }
            if token.spent {
                revoke_family_in_txn(self, txn, token.family)?;
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            }
            if family.client_id != refresh.client_id {
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            }
            if refresh
                .resource
                .is_some_and(|resource| resource != family.resource)
            {
                return Ok(Err(OAuthTokenRefusal::InvalidTarget));
            }
            if asked.is_some_and(|tier| tier > family.grant.tier) {
                return Ok(Err(OAuthTokenRefusal::InvalidScope));
            }
            if !self.oauth_grant_stands_in_txn(txn, &family.grant, now)? {
                revoke_family_in_txn(self, txn, token.family)?;
                return Ok(Err(OAuthTokenRefusal::InvalidGrant));
            }
            token.spent = true;
            TOKENS.put(&self.store, txn, &key, &token)?;
            let refresh_expires_at = now.saturating_add(OAUTH_REFRESH_TTL_SECS);
            let tier = family.grant.tier;
            FAMILIES.put(
                &self.store,
                txn,
                &family_key,
                &TokenFamily {
                    expires_at: refresh_expires_at,
                    ..family
                },
            )?;
            pair.issue_in_txn(self, txn, token.family, tier, now, refresh_expires_at)
                .map(Ok)
        })
    }

    /// Revokes the family of the token presented (RFC 7009): an access or a refresh token,
    /// issued to `client_id` when the client names itself. An unknown, lapsed or other client's
    /// token changes nothing, and nothing here says which it was.
    ///
    /// # Errors
    /// A store failure.
    pub fn revoke_oauth_token(
        &self,
        issuer: &HostSlipIssuer,
        token: &str,
        client_id: Option<&str>,
        now: u64,
    ) -> Result<()> {
        if !(token.starts_with(OAUTH_ACCESS_TOKEN_PREFIX)
            || token.starts_with(OAUTH_REFRESH_TOKEN_PREFIX))
        {
            return Ok(());
        }
        let key = secret_row_key(issuer, token);
        self.with_write_txn_grouped(|txn| {
            let Some(row) = TOKENS.get(&self.store, txn, &key)? else {
                return Ok(());
            };
            if now >= row.expires_at {
                TOKENS.delete(&self.store, txn, &key)?;
                return Ok(());
            }
            let family_key = HexId(row.family);
            let Some(mut family) = FAMILIES.get(&self.store, txn, &family_key)? else {
                return Ok(());
            };
            if client_id.is_some_and(|client_id| client_id != family.client_id) {
                return Ok(());
            }
            family.revoked = true;
            FAMILIES.put(&self.store, txn, &family_key, &family)?;
            TOKENS.delete(&self.store, txn, &key)?;
            Ok(())
        })
    }

    /// FIX 4902 slice C's seam: what the access token `token` lets its bearer do on `resource`
    /// at `now`. `None` for a token that is unknown, lapsed, revoked (its family), issued for
    /// another resource, or whose owner agent grant no longer stands (revoked, expired,
    /// withdrawn, or its pact membership lapsed). A read: it drops nothing.
    ///
    /// `issuer` is the host issuer whose secret keys the token rows (`SyncServer::host_issuer`);
    /// `resource` is the `/mcp` URL the request reached (`{origin}/mcp`).
    ///
    /// # Errors
    /// A store failure.
    pub fn resolve_oauth_access_token(
        &self,
        issuer: &HostSlipIssuer,
        token: &str,
        resource: &str,
        now: u64,
    ) -> Result<Option<OAuthAccess>> {
        if !token.starts_with(OAUTH_ACCESS_TOKEN_PREFIX) {
            return Ok(None);
        }
        let key = secret_row_key(issuer, token);
        let txn = self.store.env.read_txn()?;
        let Some(row) = TOKENS
            .get(&self.store, &txn, &key)?
            .filter(|row| row.kind == TokenKind::Access && now < row.expires_at)
        else {
            return Ok(None);
        };
        let Some(family) = self.oauth_family_standing_in_txn(&txn, row.family, resource, now)?
        else {
            return Ok(None);
        };
        let tier = family.grant.tier;
        Ok(Some(OAuthAccess {
            agent: family.grant.agent,
            actor_class: EdgeActorClass::Agent,
            tier,
            scopes: tier.core_scopes(),
            ceiling: tier.ceiling(),
            world: family.grant.world,
            grant_ref: family.grant.grant_ref,
            family: row.family,
            client_id: family.client_id,
            expires_at: row.expires_at,
        }))
    }

    /// Whether the `/mcp` caller an access token of `family` resolved to still stands at `now`
    /// (FIX 4902 slice C): exactly while [`Self::resolve_oauth_access_token`] would still resolve
    /// that token to `family` on `resource`. The token lapses at `expires_at`, and its row goes
    /// only past that or with its family's revocation, so the lapse and the family's standing
    /// decide it: not revoked, bound to `resource`, on an owner agent grant that still stands.
    /// A long call or a waiter judges its caller again by this, without the token.
    ///
    /// # Errors
    /// A store failure.
    pub fn oauth_access_is_live(
        &self,
        family: EntityId,
        resource: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.oauth_access_is_live_in_txn(&txn, family, resource, expires_at, now)
    }

    /// [`Self::oauth_access_is_live`], read in the caller's transaction: a writer judges its
    /// caller in the snapshot it commits in.
    ///
    /// # Errors
    /// A store failure.
    pub fn oauth_access_is_live_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        family: EntityId,
        resource: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<bool> {
        if now >= expires_at {
            return Ok(false);
        }
        Ok(self
            .oauth_family_standing_in_txn(txn, family, resource, now)?
            .is_some())
    }

    /// The row of `family` while its tokens still stand on `resource` at `now`: not revoked,
    /// bound to that resource, and on an owner agent grant that still stands. `None` otherwise.
    fn oauth_family_standing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        family: EntityId,
        resource: &str,
        now: u64,
    ) -> Result<Option<TokenFamily>> {
        let Some(row) = FAMILIES.get(&self.store, txn, &HexId(family))? else {
            return Ok(None);
        };
        if row.revoked
            || row.resource != resource
            || !self.oauth_grant_stands_in_txn(txn, &row.grant, now)?
        {
            return Ok(None);
        }
        Ok(Some(row))
    }
}
