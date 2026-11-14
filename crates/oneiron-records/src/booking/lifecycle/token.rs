//! Moved from `crates/oneiron/src/booking/lifecycle/token.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use rand_core::OsRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;

pub const SESSION_KEY_DOMAIN: &[u8] = b"oneiron.booking.session_key.v1\0";

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

/// Domain-tagged BLAKE3. `pub(crate)` so ONE-1821's companion digests keep the
/// same discipline instead of re-deriving it: a companion participant hash can
/// never be replayed as a hold token digest, because the domain differs.
pub fn digest_with(domain: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(material);
    *hasher.finalize().as_bytes()
}
