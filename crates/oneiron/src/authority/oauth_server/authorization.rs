//! One sign-in's authorization request: recorded at `/oauth/authorize` with one inbox ask to the
//! vault owner, answered by him (`vault.oauth.authorization.answer`), and collected by the
//! authorize page's poll, which mints the code on an allow.
//!
//! The owner's allow admits the client as an agent of his: its agent principal (one per client
//! ID), its ceiling (`grant_agent_principal`), and an owner agent grant of the tier's verbs and
//! the optional world bound (`mint_agent_grant`), which `vault.consent.registry` lists with its
//! one-tap revoke. The code is minted only when the page that holds the request's poll secret
//! collects it, so no row ever holds a code that can still be redeemed.
//!
//! The grant is minted before any token stands on it, so a sign-in that ends first takes it back
//! (FIX 22142): an allowed request no page collected, a code no exchange redeemed, a code whose
//! exchange found its grant no longer standing (FIX 22188), or a redeemed code whose new token
//! family's first access slip did not stand (FIX 22193). The write that drops the row or revokes
//! the family, a read's, the token endpoint's or the `oauth_expiry` sweep's, deletes the grant as
//! the owner's revoke deletes it (`withdraw_agent_grant_without_act_in_txn`): the delete marks the
//! grant withdrawn here and reaches peers with the row's erasure (FIX-LIST 5107, 10772). Beside
//! the owner's signed mint, that marker is what the registry lists as revoked, what his later
//! revoke answers unchanged for (FIX 22188), and what the authority audit pairs the mint with
//! (FIX 22193); no owner is at hand to sign a revoke, and nothing is signed as his. When the
//! install holds the vault's live host issuer, the host also signs the withdrawal
//! (`SlipGrantRevoke`), as a membership change does for an owner's grant it withdraws (FIX 7135),
//! which the audit lists as the mint's revoke. A code whose family's first slip landed keeps its
//! grant: its family's tokens stand on it, and only the owner's revoke ends it. The client's
//! agent principal and its ceiling stay, as the owner's revoke leaves them: every sign-in of the
//! client shares them, and no token resolves for the agent without a standing grant.

use std::collections::BTreeSet;

use super::rows::{
    AuthorizationDecision, AuthorizedGrant, CODES, IssuedCode, PendingAuthorization, REQUESTS,
};
use super::{
    OAUTH_AUTHORIZATION_NOTIFICATION_PRODUCER, OAUTH_CODE_PREFIX, OAUTH_CODE_TTL_SECS,
    OAUTH_PENDING_REQUESTS_MAX, OAUTH_REQUEST_TTL_SECS, OAuthClientRecord, draw_match_code,
    mint_secret, oauth_agent_principal_name, random_hex32, secret_hash, secret_key_matches,
    secret_row_key,
};
use crate::authority::slip_vault::require_host;
use crate::authority::{ActSurface, AgentTier, AuthorityOp, HostSlipIssuer};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};
use crate::side_table::HexId;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

const NOT_PENDING: &str = "this sign-in request is no longer waiting for an answer";
const NOT_A_WORLD: &str = "world_ref names no live world of this vault";

/// One authorize request as the server validated it: a known client, one of its redirect URIs,
/// an S256 challenge, the client's state, the `/mcp` resource and the tier asked.
#[derive(Debug, Clone, Copy)]
pub struct OAuthAuthorizationStart<'a> {
    pub client: &'a OAuthClientRecord,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub state: Option<&'a str>,
    pub resource: &'a str,
    pub tier: AgentTier,
}

/// A recorded request, for the page the browser shows. It holds the page's poll token, a
/// secret, so it is not `Debug`.
pub struct OAuthAuthorizationPending {
    pub request_ref: EntityId,
    /// What the page sends on each poll: the request's id, `.`, and a secret only this answer
    /// holds. The vault keeps the secret's keyed hash.
    pub page_token: String,
    /// The code the page and the owner's ask both show.
    pub match_code: String,
    pub tier: AgentTier,
    pub expires_at: u64,
}

/// Where a request stands for the page that holds its poll token. An allow carries the code, a
/// secret, so it is not `Debug`.
pub enum OAuthAuthorizationStatus {
    /// The owner has not answered.
    Pending,
    /// The owner allowed it: redirect the browser with this code, now minted.
    Allowed {
        redirect_uri: String,
        state: Option<String>,
        code: String,
    },
    /// The owner denied it: redirect the browser with `access_denied`.
    Denied {
        redirect_uri: String,
        state: Option<String>,
    },
    /// It lapsed before an answer reached the page.
    Expired,
    /// No request this token proves.
    Unknown,
}

/// What an owner's allow bound: the client's agent, the grant its tokens stand on, the tier and
/// the world bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthAuthorizationAllowed {
    pub agent: EntityId,
    pub grant_ref: EntityId,
    pub tier: AgentTier,
    pub world: Option<EntityId>,
}

/// Whether `request` still waits for the owner at `now`.
fn waiting(request: &PendingAuthorization, now: u64) -> bool {
    now < request.expires_at && request.decision == AuthorizationDecision::Pending
}

fn not_pending() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        NOT_PENDING,
        &["Ask the app to start its sign-in again."],
    )
}

impl Vault {
    /// Records `start` as a request waiting for the owner, with a fresh poll secret and match
    /// code, and sends the vault owner one inbox ask for it, whose taps answer it. `None` while
    /// [`OAUTH_PENDING_REQUESTS_MAX`] requests already wait. Lapsed requests are dropped here,
    /// each allowed one with its grant.
    ///
    /// # Errors
    /// A store failure.
    pub fn begin_oauth_authorization(
        &self,
        issuer: &HostSlipIssuer,
        start: &OAuthAuthorizationStart<'_>,
        now: u64,
    ) -> Result<Option<OAuthAuthorizationPending>> {
        let request_ref = EntityId::now();
        let secret = random_hex32()?;
        let match_code = draw_match_code()?;
        let expires_at = now.saturating_add(OAUTH_REQUEST_TTL_SECS);
        let request = PendingAuthorization {
            client_id: start.client.client_id.clone(),
            redirect_uri: start.redirect_uri.to_owned(),
            code_challenge: start.code_challenge.to_owned(),
            state: start.state.map(str::to_owned),
            resource: start.resource.to_owned(),
            tier: start.tier,
            page_secret_key: secret_row_key(issuer, &secret),
            expires_at,
            decision: AuthorizationDecision::Pending,
        };
        // The owner's inbox shows the client, the tier and the match code from this object; it
        // holds no secret.
        let detail = serde_json::json!({
            "client_id": start.client.client_id,
            "client_name": start.client.display_name(),
            "client_host": start.client.display_host(start.redirect_uri),
            "tier": start.tier.wire_name(),
            "match_code": match_code,
            "expires_at": expires_at,
        })
        .to_string();
        // One Ask per live owner, each its own notification (its event names the owner): a
        // shared vault's owners each see it, and whichever answers first settles the request;
        // the others' taps then find it settled (review #6478).
        let ask_for = |owner: EntityId| NotificationEvent {
            kind: NotificationKind::Ask,
            source: NotificationSource {
                producer: OAUTH_AUTHORIZATION_NOTIFICATION_PRODUCER.to_owned(),
                event: format!("{}:asked:{}", request_ref.to_hex(), owner.to_hex()),
                result: Some(request_ref.to_hex()),
                detail: Some(detail.clone()),
                ..NotificationSource::default()
            },
            subject_refs: Vec::new(),
            recipient: Some(owner),
            created_at: now,
            origin_conversation: None,
        };
        let recorded = self.with_write_txn_grouped(|txn| {
            let mut waiting_now = 0;
            for (key, row) in REQUESTS.scan(&self.store, txn)? {
                if now >= row.expires_at {
                    if let Some(grant) = row.uncollected_grant() {
                        self.withdraw_lapsed_oauth_grant_in_txn(txn, Some(issuer), &grant)?;
                    }
                    REQUESTS.delete(&self.store, txn, &key)?;
                } else if row.decision == AuthorizationDecision::Pending {
                    waiting_now += 1;
                }
            }
            if waiting_now >= OAUTH_PENDING_REQUESTS_MAX {
                return Ok(false);
            }
            REQUESTS.put(&self.store, txn, &HexId(request_ref), &request)?;
            for owner in crate::policy_model::owners_in_txn(self, txn)? {
                self.record_notification_in_txn(txn, &ask_for(owner))?;
            }
            Ok(true)
        })?;
        Ok(recorded.then(|| OAuthAuthorizationPending {
            request_ref,
            page_token: format!("{}.{secret}", request_ref.to_hex()),
            match_code,
            tier: start.tier,
            expires_at,
        }))
    }

    /// The page's poll: where the request its `page_token` proves stands at `now`. A settled
    /// request is collected once: an allow mints its code (bound to the client, the redirect
    /// URI, the challenge, the resource and the grant) and drops the request; a deny or a lapse
    /// drops it too, and a lapsed allow takes its grant back.
    ///
    /// # Errors
    /// A store failure.
    pub fn collect_oauth_authorization(
        &self,
        issuer: &HostSlipIssuer,
        page_token: &str,
        now: u64,
    ) -> Result<OAuthAuthorizationStatus> {
        let Some((request_ref, secret)) = page_token.split_once('.') else {
            return Ok(OAuthAuthorizationStatus::Unknown);
        };
        let Ok(request_ref) = EntityId::from_hex(request_ref) else {
            return Ok(OAuthAuthorizationStatus::Unknown);
        };
        let presented = secret_hash(issuer, secret);
        let code = mint_secret(OAUTH_CODE_PREFIX)?;
        let code_key = secret_row_key(issuer, &code);
        let key = HexId(request_ref);
        self.with_write_txn_grouped(|txn| {
            let Some(request) = REQUESTS.get(&self.store, txn, &key)? else {
                return Ok(OAuthAuthorizationStatus::Unknown);
            };
            if !secret_key_matches(&request.page_secret_key, &presented) {
                return Ok(OAuthAuthorizationStatus::Unknown);
            }
            if now >= request.expires_at {
                if let Some(grant) = request.uncollected_grant() {
                    self.withdraw_lapsed_oauth_grant_in_txn(txn, Some(issuer), &grant)?;
                }
                REQUESTS.delete(&self.store, txn, &key)?;
                return Ok(OAuthAuthorizationStatus::Expired);
            }
            let PendingAuthorization {
                client_id,
                redirect_uri,
                code_challenge,
                state,
                resource,
                decision,
                ..
            } = request;
            match decision {
                AuthorizationDecision::Pending => Ok(OAuthAuthorizationStatus::Pending),
                AuthorizationDecision::Denied => {
                    REQUESTS.delete(&self.store, txn, &key)?;
                    Ok(OAuthAuthorizationStatus::Denied {
                        redirect_uri,
                        state,
                    })
                }
                AuthorizationDecision::Allowed(grant) => {
                    let issued = IssuedCode {
                        client_id,
                        redirect_uri: redirect_uri.clone(),
                        code_challenge,
                        resource,
                        grant,
                        expires_at: now.saturating_add(OAUTH_CODE_TTL_SECS),
                        redeemed_family: None,
                    };
                    CODES.put(&self.store, txn, &code_key, &issued)?;
                    REQUESTS.delete(&self.store, txn, &key)?;
                    Ok(OAuthAuthorizationStatus::Allowed {
                        redirect_uri,
                        state,
                        code,
                    })
                }
            }
        })
    }

    /// The tier a request still waiting at `now` asked for, for its ask's taps; `None` for a
    /// request that settled, lapsed or never was.
    pub(crate) fn oauth_authorization_tap_in(
        &self,
        txn: &heed::RoTxn<'_>,
        request_ref: EntityId,
        now: u64,
    ) -> Result<Option<AgentTier>> {
        Ok(REQUESTS
            .get(&self.store, txn, &HexId(request_ref))?
            .filter(|request| waiting(request, now))
            .map(|request| request.tier))
    }

    /// The owner's answer to a request still waiting at `now`: a deny records the refusal; an
    /// allow admits the client as his agent at `tier` (the tier it asked for when `None`),
    /// bound to `world` when he names one, and records the grant for the page to collect.
    /// `surface` is where his say-so reached this install, for his acts' audit. An allow whose
    /// request settled or lapsed while it was granted takes the grant back.
    ///
    /// # Errors
    /// An owner refusal; `INVALID_STATE` for a request no longer waiting; `BAD_REQUEST` for a
    /// `world` that is no live world; a refusal of the agent's principal, ceiling or grant.
    #[expect(
        clippy::too_many_arguments,
        reason = "one parameter per field of the owner's answer"
    )]
    pub(crate) fn answer_oauth_authorization(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        request_ref: EntityId,
        allow: bool,
        tier: Option<AgentTier>,
        world: Option<EntityId>,
        now: u64,
    ) -> MemoryResult<Option<OAuthAuthorizationAllowed>> {
        let key = HexId(request_ref);
        let request = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            owner.revalidate_in_txn(self, &txn)?;
            if let Some(world) = world
                && !matches!(
                    live_entity_row_in_txn(&self.store, &txn, &world)?,
                    LiveEntityRow::Live {
                        entity_type: crate::registry::ENTITY_TYPE_WORLD,
                        ..
                    }
                )
            {
                return Err(MemoryError::bad_request(NOT_A_WORLD));
            }
            REQUESTS.get(&self.store, &txn, &key)?
        };
        let Some(request) = request.filter(|request| waiting(request, now)) else {
            return Err(not_pending());
        };
        if !allow {
            let denied = self.with_write_txn_grouped(|txn| {
                owner.revalidate_in_txn(self, txn)?;
                let Some(mut current) = REQUESTS
                    .get(&self.store, txn, &key)?
                    .filter(|current| waiting(current, now))
                else {
                    return Ok(false);
                };
                current.decision = AuthorizationDecision::Denied;
                REQUESTS.put(&self.store, txn, &key, &current)?;
                Ok(true)
            })?;
            return if denied { Ok(None) } else { Err(not_pending()) };
        }
        let tier = tier.unwrap_or(request.tier);
        let agent = self.ensure_agent_principal(&oauth_agent_principal_name(&request.client_id))?;
        self.grant_agent_principal(owner, &agent.to_hex(), tier.ceiling())?;
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            tier.grant_verbs()
                .iter()
                .map(|verb| (*verb).to_owned())
                .collect(),
        );
        if let Some(world) = world {
            scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
        }
        // No repo bounds, verb classes or wallet: the tier's exact verbs.
        let minted = self.mint_agent_grant(
            owner,
            surface,
            agent,
            scope,
            None,
            None,
            BTreeSet::new(),
            None,
        )?;
        let grant = AuthorizedGrant {
            agent,
            grant_ref: minted.standing.id,
            tier,
            world,
        };
        let recorded = self.with_write_txn_grouped(|txn| {
            let Some(mut current) = REQUESTS
                .get(&self.store, txn, &key)?
                .filter(|current| waiting(current, now))
            else {
                return Ok(false);
            };
            current.decision = AuthorizationDecision::Allowed(grant);
            REQUESTS.put(&self.store, txn, &key, &current)?;
            Ok(true)
        });
        match recorded {
            Ok(true) => Ok(Some(OAuthAuthorizationAllowed {
                agent,
                grant_ref: grant.grant_ref,
                tier,
                world,
            })),
            unrecorded => {
                // A failure leaves the client with less, never more: the grant no page will
                // collect is taken back.
                if let Err(error) = self.revoke_agent_grant(owner, surface, grant.grant_ref) {
                    tracing::warn!(
                        %error,
                        grant = %grant.grant_ref.to_hex(),
                        "taking back an OAuth sign-in's unrecorded agent grant failed"
                    );
                }
                unrecorded?;
                Err(not_pending())
            }
        }
    }

    /// Takes back `grant`, the owner agent grant of a sign-in that ended before its client held
    /// a token, in the caller's writer `txn`, the one that drops the request or code or revokes
    /// the token family: its row goes as the owner's revoke deletes it, marked withdrawn here, and
    /// the host's signed withdrawal lands beside it when `issuer` is this vault's live host. With
    /// no such issuer the marker alone keeps the withdrawal on the record (FIX 22188). `false`,
    /// with nothing written, for a grant no longer live: the owner revoked it already.
    ///
    /// # Errors
    /// A store or fold failure, or a host withdrawal the fold did not count.
    pub(super) fn withdraw_lapsed_oauth_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: Option<&HostSlipIssuer>,
        grant: &AuthorizedGrant,
    ) -> Result<bool> {
        if !self.withdraw_agent_grant_without_act_in_txn(txn, grant.grant_ref, grant.agent)? {
            return Ok(false);
        }
        let Some(issuer) = issuer else {
            return Ok(true);
        };
        // An issuer that is no live host of this vault signs nothing and refuses nothing, as a
        // membership change's withdrawal does.
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if require_host(&fold, issuer).is_ok() {
            self.append_slip_op_in_txn(
                txn,
                issuer,
                AuthorityOp::SlipGrantRevoke {
                    grant_ref: grant.grant_ref,
                    membership_receipt: None,
                },
            )?;
        }
        Ok(true)
    }
}
