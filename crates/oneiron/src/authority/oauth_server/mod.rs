//! The vault as the OAuth 2.1 authorization server for its own `/mcp` (FIX 4902 slice B; owner
//! CLOUD AGENTS CONNECT = A and DEFAULT ROUTE = A, 2026-10-19; ARCH-0028 #cloud-agents-connect).
//!
//! A stock cloud client adds the vault's `/mcp` URL and signs in: it registers (RFC 7591), or is
//! known by its client ID metadata document (CIMD); it asks at `/oauth/authorize` with PKCE S256
//! and the `/mcp` resource (RFC 8707); the vault owner answers one inbox ask; the client trades
//! its code for an access token and a refresh token, refreshes by rotation and revokes. The
//! server's `api::oauth_server` serves the HTTP side; this module holds every row and decision.
//!
//! The owner's allow is an ordinary agent admission: the client's own agent principal (one per
//! client ID), its ceiling, and an owner agent grant of the tier's verbs, which shows in
//! `vault.consent.registry` with its one-tap revoke. Every token stands on that grant:
//! [`crate::Vault::resolve_oauth_access_token`], the seam the `/mcp` ingress calls (slice C),
//! answers nothing for a token whose grant no longer stands. Clients never hold a slip or a key
//! (ARCH-0028:91).
//!
//! Codes, tokens and the authorize page's poll secret are 32 random bytes. No row, log or
//! receipt holds one: each table keys them by a BLAKE3 hash keyed from the host issuer's secret,
//! as pairing codes are (`slip_pairing::pairing_row_key`). A row past its expiry is dropped when
//! a write reads it; nothing sweeps them.
//!
//! Every value canon leaves open is one named constant or one policy fn here, each marked an
//! engine call (CALLS, FIX 4902).

mod authorization;
mod clients;
mod rows;
mod tokens;

pub use authorization::{
    OAuthAuthorizationAllowed, OAuthAuthorizationPending, OAuthAuthorizationStart,
    OAuthAuthorizationStatus,
};
pub use clients::{
    OAuthClientRecord, OAuthClientRegistration, OAuthClientSource, OAuthRegistrationRefusal,
    oauth_client_id_is_metadata_url, oauth_redirect_uri_admitted,
};
pub use tokens::{
    OAuthAccess, OAuthCodeExchange, OAuthRefresh, OAuthTokenRefusal, OAuthTokens,
    oauth_code_challenge_admitted,
};

use super::{AgentTier, HostSlipIssuer};
use crate::error::Result;

/// How long a pending authorization request waits for the owner's answer, and its page polls
/// (CALLS, FIX 4902: an engine call).
pub const OAUTH_REQUEST_TTL_SECS: u64 = 600;
/// How long an authorization code may be redeemed after the page collects it (CALLS, FIX 4902:
/// an engine call).
pub const OAUTH_CODE_TTL_SECS: u64 = 600;
/// How long an access token stands (CALLS, FIX 4902: an engine call).
pub const OAUTH_ACCESS_TTL_SECS: u64 = 3_600;
/// How long a refresh token may be spent; each refresh mints the next one with a fresh lifetime
/// (CALLS, FIX 4902: an engine call).
pub const OAUTH_REFRESH_TTL_SECS: u64 = 30 * 86_400;
/// How long a fetched client ID metadata document stands before the next authorize fetches it
/// again (CALLS, FIX 4902: an engine call).
pub const OAUTH_CIMD_TTL_SECS: u64 = 3_600;
/// The most authorization requests that may wait on the owner at once, so no stranger fills his
/// inbox; one past it is refused `temporarily_unavailable` (CALLS, FIX 4902: an engine call).
pub const OAUTH_PENDING_REQUESTS_MAX: usize = 16;
/// The most clients the clients table holds, registered and metadata-document ones together;
/// a new one past it is refused (CALLS, FIX 4902: an engine call).
pub const OAUTH_CLIENTS_MAX: usize = 1_024;
/// The longest `client_name` a client may give, in characters (CALLS, FIX 4902: an engine call).
pub const OAUTH_CLIENT_NAME_MAX_CHARS: usize = 128;
/// The most redirect URIs one client may list (CALLS, FIX 4902: an engine call).
pub const OAUTH_REDIRECT_URIS_MAX: usize = 16;
/// The longest redirect URI or metadata-document `client_id` this vault reads, in bytes (CALLS,
/// FIX 4902: an engine call).
pub const OAUTH_URI_MAX_BYTES: usize = 2_048;
/// The longest `state` an authorize request may carry, in bytes (CALLS, FIX 4902: an engine
/// call).
pub const OAUTH_STATE_MAX_BYTES: usize = 1_024;
/// The tier an authorize request asks for when it names no scope (CALLS, FIX 4902: an engine
/// call; the brief's default is propose-only).
pub const OAUTH_DEFAULT_TIER: AgentTier = AgentTier::ProposeOnly;
/// How many characters the match code shown on the authorize page and on the owner's ask has
/// (CALLS, FIX 4902: an engine call).
pub const OAUTH_MATCH_CODE_LEN: usize = 6;
/// The characters a match code is drawn from: capitals and digits without the look-alikes `0`,
/// `1`, `I`, `L`, `O` and `U` (CALLS, FIX 4902: an engine call).
const OAUTH_MATCH_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";
/// What an authorization code starts with, so no other credential reads as one (CALLS, FIX
/// 4902: an engine call).
pub const OAUTH_CODE_PREFIX: &str = "v2.oauth-code.";
/// What an access token starts with: the `/mcp` ingress tells it from a slip by it (CALLS, FIX
/// 4902: an engine call).
pub const OAUTH_ACCESS_TOKEN_PREFIX: &str = "v2.oauth-access.";
/// What a refresh token starts with (CALLS, FIX 4902: an engine call).
pub const OAUTH_REFRESH_TOKEN_PREFIX: &str = "v2.oauth-refresh.";
/// The producer of the owner's ask for an authorization request: `source.result` names the
/// request, `source.detail` is a JSON object of the client, the tier asked and the match code.
pub const OAUTH_AUTHORIZATION_NOTIFICATION_PRODUCER: &str = "oauth.authorization";
/// The BLAKE3 context the host issuer's secret derives the secret-row key under.
const SECRET_HASH_CONTEXT: &str = "oneiron/oauth-server/secret-hash/v1";

/// The OAuth `scope` values this vault knows: each tier's wire name (CALLS, FIX 4902: an engine
/// call; canon names no scope values).
#[must_use]
pub fn oauth_scopes_supported() -> [&'static str; 3] {
    AgentTier::ALL.map(AgentTier::wire_name)
}

/// The tier an authorize or refresh `scope` asks for (CALLS, FIX 4902: an engine call): no
/// scope, or one with no value, asks [`OAUTH_DEFAULT_TIER`]; otherwise every space-separated
/// value must be a tier's wire name, and the widest one named is asked. `None` for a value that
/// names no tier.
#[must_use]
pub fn oauth_requested_tier(scope: Option<&str>) -> Option<AgentTier> {
    let mut values = scope
        .unwrap_or_default()
        .split_ascii_whitespace()
        .peekable();
    if values.peek().is_none() {
        return Some(OAUTH_DEFAULT_TIER);
    }
    values.map(AgentTier::from_wire_name).try_fold(
        AgentTier::ReadOnly,
        |widest: AgentTier, tier: Option<AgentTier>| tier.map(|tier| widest.max(tier)),
    )
}

/// The name of the agent principal every sign-in of one client acts as (CALLS, FIX 4902: an
/// engine call): `oauth:` and the first 32 hex of the client ID's BLAKE3 hash. One client is one
/// agent across its sign-ins, and the `:` keeps it apart from every `oneiron token agent` name,
/// which spells only letters, digits, `-`, `_` and `.`.
fn oauth_agent_principal_name(client_id: &str) -> String {
    let hash = blake3::hash(client_id.as_bytes()).to_hex();
    format!("oauth:{}", &hash.as_str()[..32])
}

/// 32 fresh random bytes from the OS, as 64 lower-case hex characters.
fn random_hex32() -> Result<String> {
    let mut bytes = [0_u8; 32];
    crate::world_keys::os_fill(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A fresh secret: `prefix` and 32 random bytes in hex.
fn mint_secret(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}{}", random_hex32()?))
}

/// The keyed hash a secret is stored under: keyed from the host issuer's secret, so a copied
/// vault file alone cannot test a guess.
fn secret_hash(issuer: &HostSlipIssuer, secret: &str) -> blake3::Hash {
    let key = blake3::derive_key(SECRET_HASH_CONTEXT, issuer.secret());
    blake3::keyed_hash(&key, secret.as_bytes())
}

/// [`secret_hash`] as the row key a table spells it: 64 lower-case hex characters.
fn secret_row_key(issuer: &HostSlipIssuer, secret: &str) -> String {
    secret_hash(issuer, secret).to_hex().to_string()
}

/// Whether `presented` is the hash a row stored as `stored`, compared in constant time.
fn secret_key_matches(stored: &str, presented: &blake3::Hash) -> bool {
    blake3::Hash::from_hex(stored).is_ok_and(|stored| stored == *presented)
}

/// A fresh match code: [`OAUTH_MATCH_CODE_LEN`] characters of [`OAUTH_MATCH_CODE_ALPHABET`],
/// each drawn without modulo bias.
fn draw_match_code() -> Result<String> {
    let alphabet = OAUTH_MATCH_CODE_ALPHABET.len();
    let unbiased = 256 / alphabet * alphabet;
    let mut code = String::with_capacity(OAUTH_MATCH_CODE_LEN);
    while code.len() < OAUTH_MATCH_CODE_LEN {
        let mut bytes = [0_u8; 16];
        crate::world_keys::os_fill(&mut bytes)?;
        for byte in bytes.map(usize::from) {
            if code.len() < OAUTH_MATCH_CODE_LEN && byte < unbiased {
                code.push(char::from(OAUTH_MATCH_CODE_ALPHABET[byte % alphabet]));
            }
        }
    }
    Ok(code)
}
