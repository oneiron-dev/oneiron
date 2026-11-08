//! The OAuth server's five side tables and the rows they hold. A code, a token or a page's poll
//! secret is never a field: its row is keyed by the secret's keyed hash, or holds only that hash.

use serde::{Deserialize, Serialize};

use super::OAUTH_ACCESS_TTL_SECS;
use super::clients::OAuthClientRecord;
use crate::EntityId;
use crate::authority::AgentTier;
use crate::side_table::{self, HexId, Named, SideTable};

/// Every client that may sign in, registered or known by its metadata document. Key: hex64, the
/// BLAKE3 hash of its `client_id`.
pub(super) const CLIENTS: SideTable<String, OAuthClientRecord, Named> =
    SideTable::new(&side_table::AUTHORITY_OAUTH_CLIENT);
/// Each authorization request until its page collects the owner's answer, or it lapses. Key:
/// hex32, the request's id.
pub(super) const REQUESTS: SideTable<HexId, PendingAuthorization, Named> =
    SideTable::new(&side_table::AUTHORITY_OAUTH_REQUEST);
/// Each authorization code until it lapses; a redeemed one stays, naming its token family, so a
/// second redemption revokes that family. Key: hex64, the code's keyed hash.
pub(super) const CODES: SideTable<String, IssuedCode, Named> =
    SideTable::new(&side_table::AUTHORITY_OAUTH_CODE);
/// Each access and refresh token until it lapses; a spent refresh token stays, so its reuse
/// revokes its family. Key: hex64, the token's keyed hash.
pub(super) const TOKENS: SideTable<String, IssuedToken, Named> =
    SideTable::new(&side_table::AUTHORITY_OAUTH_TOKEN);
/// Each token family: every token one code's redemption and its refreshes minted. Key: hex32,
/// the family's id.
pub(super) const FAMILIES: SideTable<HexId, TokenFamily, Named> =
    SideTable::new(&side_table::AUTHORITY_OAUTH_FAMILY);

/// What the owner's allow bound a sign-in to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorizedGrant {
    /// The client's agent principal.
    pub(super) agent: EntityId,
    /// The owner agent grant every token of the sign-in stands on.
    pub(super) grant_ref: EntityId,
    /// The tier the owner gave.
    pub(super) tier: AgentTier,
    /// The one world the grant is bound to; `None`: every world the owner reads.
    pub(super) world: Option<EntityId>,
}

/// Where an authorization request stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum AuthorizationDecision {
    /// Waiting for the owner.
    Pending,
    /// The owner allowed it; the page's next poll mints the code.
    Allowed(AuthorizedGrant),
    /// The owner denied it; the page's next poll sends the client `access_denied`.
    Denied,
}

/// One authorization request, as `/oauth/authorize` validated it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingAuthorization {
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    /// The PKCE S256 challenge the code is bound to.
    pub(super) code_challenge: String,
    /// The client's own `state`, echoed on the redirect.
    pub(super) state: Option<String>,
    /// The RFC 8707 resource: this vault's `/mcp`.
    pub(super) resource: String,
    /// The tier the client asked for.
    pub(super) tier: AgentTier,
    /// The keyed hash of the page's poll secret (hex64).
    pub(super) page_secret_key: String,
    pub(super) expires_at: u64,
    pub(super) decision: AuthorizationDecision,
}

impl PendingAuthorization {
    /// The grant the owner's allow minted, while the request still waits for its page to collect
    /// it: no code was minted from it, so no token stands on it.
    pub(super) fn uncollected_grant(&self) -> Option<AuthorizedGrant> {
        match &self.decision {
            AuthorizationDecision::Allowed(grant) => Some(*grant),
            AuthorizationDecision::Pending | AuthorizationDecision::Denied => None,
        }
    }
}

/// One authorization code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IssuedCode {
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) code_challenge: String,
    pub(super) resource: String,
    pub(super) grant: AuthorizedGrant,
    pub(super) expires_at: u64,
    /// The family its redemption minted; `None` until it is redeemed.
    pub(super) redeemed_family: Option<EntityId>,
}

impl IssuedCode {
    /// The grant of a code no exchange redeemed: no token stands on it.
    pub(super) fn unredeemed_grant(&self) -> Option<AuthorizedGrant> {
        self.redeemed_family.is_none().then_some(self.grant)
    }
}

/// Which kind of token a token row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum TokenKind {
    Access,
    Refresh,
}

/// One access or refresh token. Not `Debug`: an access token's row holds its slip.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IssuedToken {
    pub(super) kind: TokenKind,
    pub(super) family: EntityId,
    pub(super) expires_at: u64,
    /// A refresh token already traded for the next one.
    pub(super) spent: bool,
    /// For an access token, the native capability slip the server holds for it and the `/mcp`
    /// ingress swaps in for it (FIX 4902 slice C, `access_slips`), as its token; `None` on a
    /// refresh token, and until the slip lands. It proves nothing alone: its holder key is
    /// derived from the host issuer's secret and never stored.
    pub(super) slip: Option<String>,
}

/// One token family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenFamily {
    pub(super) client_id: String,
    pub(super) resource: String,
    pub(super) grant: AuthorizedGrant,
    /// When its newest refresh token lapses; past it, no token of the family stands.
    pub(super) expires_at: u64,
    /// Revoked: no token of the family stands, whatever its own expiry.
    pub(super) revoked: bool,
    /// The [`TOKENS`] key of the family's one live access token whose slip landed (FIX 4902 slice
    /// C): the next refresh retires that token and its slip, and a revocation revokes the slip.
    /// `None` before the first slip lands, and once the family is revoked.
    pub(super) live_access: Option<String>,
    /// Whether its first access slip stood, so a token of it was handed out (FIX 22193, 22226).
    pub(super) opening: FamilyOpening,
}

impl TokenFamily {
    /// Whether the expiry sweep drops the family at `now`: past its newest refresh token's
    /// lifetime, with no sign-in end due ([`FamilyOpening::end_due_at`]). A family whose sign-in
    /// end failed stays until a pass ends it and takes its grant back.
    pub(super) fn drop_due_at(&self, now: u64) -> bool {
        now >= self.expires_at && !self.opening.end_due_at(now)
    }
}

/// Whether a token family's first access slip stood (FIX 22193, 22226). Only a family whose first
/// slip stood handed a token out, so only its grant outlives the family; the sign-in of one whose
/// first slip never stood is ended, its grant taken back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum FamilyOpening {
    /// A code's exchange at `opened_at` opened the family, and its first access slip has not
    /// stood: no token of it was handed out.
    Pending { opened_at: u64 },
    /// Its first access slip landed and its first pair was handed out. Only a revoke or a lapse
    /// ends the family; its grant stays until the owner revokes it.
    Stood,
    /// Its first access slip did not stand and its sign-in was ended: the family is revoked, and
    /// its grant was taken back unless another family that is not revoked names it.
    Ended,
}

impl FamilyOpening {
    /// Whether the expiry sweep ends the family's sign-in at `now` (FIX 22226): its first access
    /// slip has not stood and the first access token, minted with the exchange, has lapsed, so
    /// no token request still minting that slip is cut short. A slip that lands after the end
    /// finds the family revoked and stands for nothing; one that landed first marked it
    /// [`Self::Stood`], and the end, judged again in its writer, leaves it.
    pub(super) fn end_due_at(self, now: u64) -> bool {
        matches!(
            self,
            Self::Pending { opened_at } if now >= opened_at.saturating_add(OAUTH_ACCESS_TTL_SECS)
        )
    }
}

/// The [`CLIENTS`] key of a client ID.
pub(super) fn client_key(client_id: &str) -> String {
    blake3::hash(client_id.as_bytes()).to_hex().to_string()
}
