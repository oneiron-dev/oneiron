//! Opaque bearer credentials and session keys: minting, domain-separated
//! digests, and the token/hold row reads that resolve them.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::LifecycleTokenRow;
use super::claim::read_booking_facts;
use super::storage::{
    decode_row, encode_row, hold_key, meta_key, put_meta, read_meta, read_meta_bytes, read_txn,
    refused,
};
use super::types::{BOOKING_TOKEN_META_PREFIX, LifecycleTokenScope, SoftHoldRow};
use crate::booking::BookingError;
use crate::{EntityId, Vault};

/// Raw opaque-token width, and therefore the bearer secret's entropy.
pub(super) const TOKEN_RAW_BYTES: usize = 32;

// Domain separators. Every digest this module persists is domain-tagged, so a
// hold token digest can never be replayed as a lease digest or a session key.
pub(super) const HOLD_KEY_DOMAIN: &[u8] = b"oneiron.booking.hold_key.v1\0";

const SESSION_DIGEST_DOMAIN: &[u8] = b"oneiron.booking.session.v1\0";

const TOKEN_DIGEST_DOMAIN: &[u8] = b"oneiron.booking.token.v1\0";

const LEASE_DIGEST_DOMAIN: &[u8] = b"oneiron.booking.checkout_lease.v1\0";

const SESSION_KEY_DOMAIN: &[u8] = b"oneiron.booking.session_key.v1\0";

const REVISION_TOKEN_DOMAIN: &[u8] = b"oneiron.booking.revision_token.v1\0";

/// An opaque bearer credential. It encodes nothing: not an EVENT id, a UID, an
/// email address, an action, or a timestamp. Only its digest is ever persisted.
///
/// A hold token is 32 CSPRNG bytes. The revision credentials one confirm issues
/// are DERIVED from that hold token (`revision_token`) rather than minted
/// independently, so a confirm retry is answered with the pair it was answered
/// with the first time instead of a second authority over the same booking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueLifecycleToken(pub String);

/// A server-issued, session-bound checkout lease. Same opacity contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueCheckoutLeaseToken(pub String);

/// The derived visitor session key. Deriving it is the server's job; this type
/// is the 32-byte result, and holds are keyed by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    /// Derives a session key from opaque server-side session material.
    ///
    /// Domain-separated, so session material can never collide with a token or
    /// lease digest computed over the same bytes.
    #[must_use]
    pub fn derive(material: &[u8]) -> Self {
        Self(digest_with(SESSION_KEY_DOMAIN, material))
    }
}

/// What a hold's lifetime is grounded in.
///
/// There is deliberately no caller TTL on either arm: `Ordinary` takes the
/// server default, and `CheckoutExtension` is capped by the verified lease AND
/// by [`MAX_CHECKOUT_HOLD_TTL_SECS`](super::MAX_CHECKOUT_HOLD_TTL_SECS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoldLeaseSpec {
    Ordinary,
    CheckoutExtension {
        server_issued_lease: OpaqueCheckoutLeaseToken,
    },
}

/// Mints a fresh bearer credential from the OS CSPRNG.
///
/// `pub(crate)` for the soft-confirm hook: ONE-1821's participant tokens are
/// bearer credentials with the same opacity contract, and a second CSPRNG
/// minter would be a second entropy story to audit.
pub(crate) fn mint_raw_token() -> String {
    let mut raw = [0_u8; TOKEN_RAW_BYTES];
    OsRng.fill_bytes(&mut raw);
    hex_lower(&raw)
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

/// Domain-tagged BLAKE3. `pub(crate)` so ONE-1821's companion digests keep the
/// same discipline instead of re-deriving it: a companion participant hash can
/// never be replayed as a hold token digest, because the domain differs.
pub(crate) fn digest_with(domain: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(material);
    *hasher.finalize().as_bytes()
}

/// The persisted digest of a lifecycle bearer token.
pub(super) fn token_digest(token: &OpaqueLifecycleToken) -> [u8; 32] {
    digest_with(TOKEN_DIGEST_DOMAIN, token.0.as_bytes())
}

/// The persisted digest of a checkout lease.
pub(super) fn lease_digest(lease: &OpaqueCheckoutLeaseToken) -> [u8; 32] {
    digest_with(LEASE_DIGEST_DOMAIN, lease.0.as_bytes())
}

/// The session binding stored on lease and receipt rows, where the session is
/// only ever compared and never re-read.
pub(super) fn session_digest(session_key: &SessionKey) -> [u8; 32] {
    digest_with(SESSION_DIGEST_DOMAIN, &session_key.0)
}

/// Resolves a token to its EVENT, refusing a token whose recorded scope does not
/// permit `expected`. Scope lives on the row, never in the token.
pub(super) fn resolve_token_event(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    token: &OpaqueLifecycleToken,
    expected: LifecycleTokenScope,
) -> Result<EntityId, BookingError> {
    let row = read_token_row(vault, rtxn, token)?
        .ok_or_else(|| refused("token does not resolve to a booking"))?;
    if row.scope != expected {
        return Err(refused("token scope does not permit this action"));
    }
    Ok(row.event_ref)
}

fn read_token_row(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    token: &OpaqueLifecycleToken,
) -> Result<Option<LifecycleTokenRow>, BookingError> {
    read_meta(vault, rtxn, BOOKING_TOKEN_META_PREFIX, &token_digest(token))
}

/// Derives one revision credential from the hold token that bought the booking.
///
/// Deterministic on purpose. A confirm retry has to answer with the SAME pair
/// the first confirm issued: it cannot replay them, because only their digests
/// are persisted, and minting a fresh pair per retry would put two independent
/// cancel authorities on one booking. Deriving them costs no authority — the
/// hold token is already the credential confirm demands — and the token inherits
/// that hold token's 32 CSPRNG bytes, so it stays as unguessable as a minted
/// one and encodes nothing about the booking it belongs to.
pub(super) fn revision_token(
    hold_token: &OpaqueLifecycleToken,
    scope: LifecycleTokenScope,
) -> OpaqueLifecycleToken {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REVISION_TOKEN_DOMAIN);
    hasher.update(scope.tag());
    hasher.update(hold_token.0.as_bytes());
    OpaqueLifecycleToken(hex_lower(hasher.finalize().as_bytes()))
}

/// Records this booking's reschedule and cancel credentials.
pub(super) fn write_revision_tokens(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: EntityId,
    hold_token: &OpaqueLifecycleToken,
) -> Result<(OpaqueLifecycleToken, OpaqueLifecycleToken), BookingError> {
    let reschedule = revision_token(hold_token, LifecycleTokenScope::Reschedule);
    let cancel = revision_token(hold_token, LifecycleTokenScope::Cancel);
    for (token, scope) in [
        (&reschedule, LifecycleTokenScope::Reschedule),
        (&cancel, LifecycleTokenScope::Cancel),
    ] {
        let encoded = encode_row(&LifecycleTokenRow { event_ref, scope })?;
        let key = meta_key(BOOKING_TOKEN_META_PREFIX, &token_digest(token));
        put_meta(vault, wtxn, &key, &encoded)?;
    }
    Ok((reschedule, cancel))
}

/// This session's hold row, from committed state.
pub(super) fn read_hold_row(
    vault: &Vault,
    session_key: &SessionKey,
) -> Result<Option<SoftHoldRow>, BookingError> {
    let rtxn = read_txn(vault)?;
    let Some(raw) = read_meta_bytes(vault, &rtxn, &hold_key(session_key))? else {
        return Ok(None);
    };
    decode_row(&raw).map(Some)
}

/// The page a token's booking came from.
///
/// Read-only and page-shaped: it resolves the token row, then that booking's
/// recorded source page, and reveals nothing else about the booking. The
/// lifecycle builds a reschedule or cancel oracle from it, and a transport that
/// must prove a submitted action token belongs to the page whose route carried
/// it asks THIS function — the one place that knows the token key derivation
/// and the row codec — rather than decoding a token row of its own.
///
/// A token that resolves to no booking, or a booking missing its source-page
/// claim, yields `None` here; the authoritative path produces the typed refusal.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] when committed state cannot be read;
/// [`BookingError::InvalidConstraint`] when the stored token row does not
/// decode.
pub fn token_page_ref(
    vault: &Vault,
    token: &OpaqueLifecycleToken,
) -> Result<Option<EntityId>, BookingError> {
    let rtxn = read_txn(vault)?;
    let Some(row) = read_token_row(vault, &rtxn, token)? else {
        return Ok(None);
    };
    Ok(read_booking_facts(vault, &rtxn, &row.event_ref)
        .ok()
        .map(|facts| facts.page_ref))
}
