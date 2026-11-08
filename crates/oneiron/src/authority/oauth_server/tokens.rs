//! Codes into tokens, tokens into new tokens, revocation, and the bearer's resolution at the
//! `/mcp` ingress.
//!
//! One code's redemption mints one token family: an access token and a refresh token. A refresh
//! spends its refresh token and mints the family's next pair; a spent refresh token presented
//! again, or a code redeemed twice, revokes the whole family (OAuth 2.1 §4.3.1, RFC 6749
//! §4.1.2). A revoked family, or one whose owner agent grant no longer stands, holds no token
//! that resolves, so the owner's one-tap revoke of the grant ends every token of it.
//!
//! Each access token is handed out only once the native slip the server holds for it has landed
//! on its row (`access_slips`, FIX 4902 slice C); a refresh retires the family's previous access
//! token and its slip, and a family's revocation revokes its slip. A new family whose first slip
//! does not stand ends its sign-in: the code is spent, no token was handed out, and the writer
//! that revokes the family takes the grant back (FIX 22193). When that writer fails, the
//! `oauth_expiry` sweep's next pass ends the sign-in in the same one write (FIX 22226).

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use super::access_slips::take_live_access_in_txn;
use super::rows::{
    AuthorizedGrant, CODES, FAMILIES, FamilyOpening, IssuedToken, TOKENS, TokenFamily, TokenKind,
};
use super::{
    OAUTH_ACCESS_TOKEN_PREFIX, OAUTH_ACCESS_TTL_SECS, OAUTH_CODE_PREFIX,
    OAUTH_REFRESH_TOKEN_PREFIX, OAUTH_REFRESH_TTL_SECS, access_holder_key, mint_secret,
    oauth_requested_tier, secret_row_key,
};
use crate::authority::{AgentTier, CapabilitySlip, HostSlipIssuer, grant_known_withdrawn_in_txn};
use crate::error::Result;
use crate::federation::decode_federation_grant_body;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::side_table::HexId;
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

/// What an access token stands for at the `/mcp` ingress (FIX 4902 slice C): the native
/// capability slip the server holds for it, of the family's client agent with its tier's core
/// scopes in the grant's world bound, and that slip's holder key, which the host issuer's secret
/// derives and no row holds. The ingress presents the slip in the token's place with a fresh
/// [`Self::holder_proof`] per request, so the request is that connector's. Not `Debug` or
/// `Clone`: the key signs as the slip's holder.
pub struct OAuthAccess {
    /// The token family the access token is of: every token one code's redemption and its
    /// refreshes minted.
    pub family: EntityId,
    /// The slip the ingress presents in the token's place.
    pub slip: CapabilitySlip,
    holder_key: SigningKey,
}

impl OAuthAccess {
    /// A fresh holder proof of [`Self::slip`] signed at `timestamp`, as the binding header
    /// carries it (`crate::authority::holder_proof`): one per request, never reused.
    ///
    /// # Errors
    /// The slip's binding transcript could not be built.
    pub fn holder_proof(&self, timestamp: u64) -> Result<serde_json::Value> {
        crate::authority::holder_proof(&self.slip, &self.holder_key, timestamp)
    }
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

/// What a token-endpoint writer decided: a pair to hand out once its access token's slip lands,
/// or a refusal; and the slip of a family it revoked or rotated, as the family and the slip's
/// id, revoked once the writer commits, since the authority log takes its own writer.
struct Decided {
    outcome: std::result::Result<Issued, OAuthTokenRefusal>,
    retired: Option<(EntityId, [u8; 32])>,
}

/// A pair a writer put, the family it is of and the grant its slip is minted under.
struct Issued {
    tokens: OAuthTokens,
    family: EntityId,
    grant: AuthorizedGrant,
    /// The pair is the first of its family, which a code's exchange just opened: no token of it
    /// was handed out before.
    opens_family: bool,
}

impl Decided {
    /// `refusal`, with nothing revoked.
    fn refused(refusal: OAuthTokenRefusal) -> Self {
        Self {
            outcome: Err(refusal),
            retired: None,
        }
    }

    /// `refusal`, beside `family`'s revocation, which retired `slip` when it held one.
    fn revoked(refusal: OAuthTokenRefusal, family: EntityId, slip: Option<[u8; 32]>) -> Self {
        Self {
            outcome: Err(refusal),
            retired: slip.map(|slip| (family, slip)),
        }
    }
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
                slip: None,
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
                slip: None,
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

/// Revokes `family` in the caller's writer, retiring its live access token, and answers the id
/// of the slip that token held, for the caller to revoke once its writer commits
/// ([`Vault::retire_access_slip`]); a family already gone stays gone.
pub(super) fn revoke_family_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    family: EntityId,
) -> Result<Option<[u8; 32]>> {
    let key = HexId(family);
    let Some(mut row) = FAMILIES.get(&vault.store, txn, &key)? else {
        return Ok(None);
    };
    row.revoked = true;
    let slip = take_live_access_in_txn(vault, txn, &mut row)?;
    FAMILIES.put(&vault.store, txn, &key, &row)?;
    Ok(slip)
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
    /// must still stand. Answers a new token family's first pair once its access token's slip
    /// has landed. A code redeemed before revokes the family it minted; a lapsed code no
    /// exchange redeemed takes its grant back, and so does a code whose grant no longer stands,
    /// which goes too. A code refused for its client, redirect URI, verifier or resource stays:
    /// a matching exchange may still redeem it, and its lapse takes its grant back. A redeemed
    /// code whose new family's first slip does not stand is spent with no token handed out: the
    /// family is revoked and its grant taken back (FIX 22193), or, when that write fails, by the
    /// expiry sweep's next pass (FIX 22226).
    ///
    /// # Errors
    /// A store failure, a fold failure taking a grant back, or a failure minting the access
    /// token's slip, which revokes the new family and takes its grant back.
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
        let access_key = pair.access_key.clone();
        let decided = self.with_write_txn_grouped(|txn| {
            let Some(mut code) = CODES.get(&self.store, txn, &key)? else {
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidGrant));
            };
            if now >= code.expires_at {
                if let Some(grant) = code.unredeemed_grant() {
                    self.withdraw_lapsed_oauth_grant_in_txn(txn, Some(issuer), &grant)?;
                }
                CODES.delete(&self.store, txn, &key)?;
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidGrant));
            }
            if let Some(family) = code.redeemed_family {
                let slip = revoke_family_in_txn(self, txn, family)?;
                return Ok(Decided::revoked(
                    OAuthTokenRefusal::InvalidGrant,
                    family,
                    slip,
                ));
            }
            if code.client_id != exchange.client_id
                || code.redirect_uri != exchange.redirect_uri
                || !pkce_s256_matches(exchange.code_verifier, &code.code_challenge)
            {
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidGrant));
            }
            if exchange
                .resource
                .is_some_and(|resource| resource != code.resource)
            {
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidTarget));
            }
            if !self.oauth_grant_stands_in_txn(txn, &code.grant, now)? {
                // The code goes, so no token will ever stand on its grant: the grant is taken
                // back as a lapse takes it (FIX 22188). One the owner revoked is already gone.
                self.withdraw_lapsed_oauth_grant_in_txn(txn, Some(issuer), &code.grant)?;
                CODES.delete(&self.store, txn, &key)?;
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidGrant));
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
                    live_access: None,
                    opening: FamilyOpening::Pending { opened_at: now },
                },
            )?;
            code.redeemed_family = Some(family);
            CODES.put(&self.store, txn, &key, &code)?;
            let tokens =
                pair.issue_in_txn(self, txn, family, code.grant.tier, now, refresh_expires_at)?;
            Ok(Decided {
                outcome: Ok(Issued {
                    tokens,
                    family,
                    grant: code.grant,
                    opens_family: true,
                }),
                retired: None,
            })
        })?;
        self.settle_token_request(issuer, &access_key, decided)
    }

    /// Trades a refresh token for its family's next pair, spending it: its client must be the
    /// family's, a resource the client sends must be the family's, a scope it sends must be no
    /// wider than the family's tier, and the grant must still stand. The family's previous
    /// access token and its slip retire, and the pair is answered once the new access token's
    /// slip has landed. A spent refresh token presented again revokes its family.
    ///
    /// # Errors
    /// A store failure, or a failure minting the access token's slip, which revokes the family.
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
        let access_key = pair.access_key.clone();
        let decided = self.with_write_txn_grouped(|txn| {
            let Some(mut token) = TOKENS
                .get(&self.store, txn, &key)?
                .filter(|token| token.kind == TokenKind::Refresh)
            else {
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidGrant));
            };
            if now >= token.expires_at {
                TOKENS.delete(&self.store, txn, &key)?;
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidGrant));
            }
            let family_key = HexId(token.family);
            let Some(mut family) = FAMILIES.get(&self.store, txn, &family_key)? else {
                TOKENS.delete(&self.store, txn, &key)?;
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidGrant));
            };
            if family.revoked || now >= family.expires_at {
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidGrant));
            }
            if token.spent {
                let slip = revoke_family_in_txn(self, txn, token.family)?;
                return Ok(Decided::revoked(
                    OAuthTokenRefusal::InvalidGrant,
                    token.family,
                    slip,
                ));
            }
            if family.client_id != refresh.client_id {
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidGrant));
            }
            if refresh
                .resource
                .is_some_and(|resource| resource != family.resource)
            {
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidTarget));
            }
            if asked.is_some_and(|tier| tier > family.grant.tier) {
                return Ok(Decided::refused(OAuthTokenRefusal::InvalidScope));
            }
            if !self.oauth_grant_stands_in_txn(txn, &family.grant, now)? {
                let slip = revoke_family_in_txn(self, txn, token.family)?;
                return Ok(Decided::revoked(
                    OAuthTokenRefusal::InvalidGrant,
                    token.family,
                    slip,
                ));
            }
            token.spent = true;
            TOKENS.put(&self.store, txn, &key, &token)?;
            // One live access token per family: the one this refresh replaces retires with its
            // slip (`take_live_access_in_txn`).
            let retired = take_live_access_in_txn(self, txn, &mut family)?;
            let refresh_expires_at = now.saturating_add(OAUTH_REFRESH_TTL_SECS);
            let grant = family.grant;
            FAMILIES.put(
                &self.store,
                txn,
                &family_key,
                &TokenFamily {
                    expires_at: refresh_expires_at,
                    ..family
                },
            )?;
            let tokens =
                pair.issue_in_txn(self, txn, token.family, grant.tier, now, refresh_expires_at)?;
            Ok(Decided {
                outcome: Ok(Issued {
                    tokens,
                    family: token.family,
                    grant,
                    opens_family: false,
                }),
                retired: retired.map(|slip| (token.family, slip)),
            })
        })?;
        self.settle_token_request(issuer, &access_key, decided)
    }

    /// The token endpoint's answer once `decided`'s writer committed: the slip it retired is
    /// revoked, and a pair it put is answered once its access token's slip, which the row
    /// `access_key` keeps, has landed ([`Self::hold_access_slip`]); `invalid_grant` when the
    /// family was revoked while the slip was minted. A pair that opened its family and is not
    /// answered ends the sign-in, its grant taken back with the family (FIX 22193).
    fn settle_token_request(
        &self,
        issuer: &HostSlipIssuer,
        access_key: &str,
        decided: Decided,
    ) -> Result<std::result::Result<OAuthTokens, OAuthTokenRefusal>> {
        if let Some((family, slip)) = decided.retired {
            self.retire_access_slip(issuer, family, slip);
        }
        let issued = match decided.outcome {
            Ok(issued) => issued,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(
            if self.hold_access_slip(
                issuer,
                issued.family,
                access_key,
                &issued.grant,
                issued.opens_family,
            )? {
                Ok(issued.tokens)
            } else {
                Err(OAuthTokenRefusal::InvalidGrant)
            },
        )
    }

    /// Revokes the family of the token presented (RFC 7009): an access or a refresh token,
    /// issued to `client_id` when the client names itself, and the slip of the family's live
    /// access token. An unknown, lapsed or other client's token changes nothing, and nothing
    /// here says which it was.
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
        let retired = self.with_write_txn_grouped(|txn| {
            let Some(row) = TOKENS.get(&self.store, txn, &key)? else {
                return Ok(None);
            };
            if now >= row.expires_at {
                TOKENS.delete(&self.store, txn, &key)?;
                return Ok(None);
            }
            let Some(family) = FAMILIES.get(&self.store, txn, &HexId(row.family))? else {
                return Ok(None);
            };
            if client_id.is_some_and(|client_id| client_id != family.client_id) {
                return Ok(None);
            }
            let slip = revoke_family_in_txn(self, txn, row.family)?;
            TOKENS.delete(&self.store, txn, &key)?;
            Ok(slip.map(|slip| (row.family, slip)))
        })?;
        if let Some((family, slip)) = retired {
            self.retire_access_slip(issuer, family, slip);
        }
        Ok(())
    }

    /// FIX 4902 slice C's seam: what the access token `token` stands for on `resource` at `now`,
    /// the slip the server holds for it and that slip's holder key ([`OAuthAccess`]). `None`
    /// for a token that is unknown, lapsed, revoked (its family), issued for another resource,
    /// whose slip has not landed or has lapsed, or whose owner agent grant no longer stands
    /// (revoked, expired, withdrawn, or its pact membership lapsed): that last revokes the
    /// family and its slip, so a call that holds the slip stops too.
    ///
    /// `issuer` is the host issuer whose secret keys the token rows and derives the holder key
    /// (`SyncServer::host_issuer`); `resource` is the `/mcp` URL the request reached
    /// (`{origin}/mcp`).
    ///
    /// # Errors
    /// A store failure reading the token's rows.
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
        let lapsed_grant = {
            let txn = self.store.env.read_txn()?;
            let Some(row) = TOKENS
                .get(&self.store, &txn, &key)?
                .filter(|row| row.kind == TokenKind::Access && now < row.expires_at)
            else {
                return Ok(None);
            };
            let Some(family) = FAMILIES
                .get(&self.store, &txn, &HexId(row.family))?
                .filter(|family| !family.revoked && family.resource == resource)
            else {
                return Ok(None);
            };
            if self.oauth_grant_stands_in_txn(&txn, &family.grant, now)? {
                // The slip runs on the authority clock, which a reopened vault resumes from where
                // it stopped, not on the wall time the token row keeps (review #6508).
                let slip_now = self.instant_in_txn(&txn)?.secs();
                return Ok(row
                    .slip
                    .as_deref()
                    .and_then(|slip| held_access(issuer, row.family, &key, slip, slip_now)));
            }
            row.family
        };
        // The family goes with its slip, so a call that holds the slip stops too; the token
        // resolves nothing whether that lands or not.
        if let Err(error) = self.revoke_oauth_family(issuer, lapsed_grant, None) {
            tracing::warn!(
                %error,
                family = %lapsed_grant.to_hex(),
                "revoking an OAuth token family whose grant no longer stands failed"
            );
        }
        Ok(None)
    }
}

/// The slip `slip`, an access token's row of `family` under `access_key` holds, with its holder
/// key, while it stands at `now` on the authority clock (read in the caller's snapshot, the clock
/// its expiry was minted on): `None` for a slip that does not parse, whose binding key is
/// not the key the host issuer's secret derives for that token, or that has lapsed (the vault's
/// credential lifetime ceiling may cut a slip shorter than its token).
fn held_access(
    issuer: &HostSlipIssuer,
    family: EntityId,
    access_key: &str,
    slip: &str,
    now: u64,
) -> Option<OAuthAccess> {
    let slip = CapabilitySlip::from_token(slip).ok()?;
    let holder_key = access_holder_key(issuer, family, access_key);
    if holder_key.verifying_key().to_bytes() != slip.claims.binding_key
        || now >= slip.claims.expires_at
    {
        return None;
    }
    Some(OAuthAccess {
        family,
        slip,
        holder_key,
    })
}
