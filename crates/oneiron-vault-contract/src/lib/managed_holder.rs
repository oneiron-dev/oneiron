//! Host-attested account actions: one managed widen request, and one request
//! the vault owner makes in person ([`ManagedOwnerAction`]).
//!
//! Only the supervisor, after account authentication and its power check,
//! signs these. The vault child has the per-spawn secret but never infers
//! holder authority from its own host-root capability.
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::TokenHex;

const DOMAIN: &str = "oneiron/managed-account-widen/v1";

/// A host assertion tied to one vault, exact body and authenticated holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedWidenAction {
    pub holder_ref: String,
    pub mac: String,
}

impl ManagedWidenAction {
    /// Called by the supervisor ONLY after it authenticates the named human
    /// account and checks that account's `consent:widen` power.
    pub fn sign_after_account_auth(
        spawn_token: &TokenHex,
        vault: &str,
        holder_ref: &str,
        request_body: &[u8],
    ) -> Self {
        Self {
            holder_ref: holder_ref.to_owned(),
            mac: sign(spawn_token, vault, holder_ref, request_body),
        }
    }

    /// Refuse a forwarded/caller-chosen header unless the supervisor signed
    /// these exact bytes for this vault and this holder.
    pub fn verify(&self, spawn_token: &TokenHex, vault: &str, request_body: &[u8]) -> bool {
        if self.holder_ref.len() != 32
            || !self
                .holder_ref
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.mac.len() != 64
            || !self
                .mac
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return false;
        }
        let expected = sign(spawn_token, vault, &self.holder_ref, request_body);
        bool::from(self.mac.as_bytes().ct_eq(expected.as_bytes()))
    }
}

const OWNER_DOMAIN: &str = "oneiron/managed-account-owner/v2";

/// The header a supervisor sends a [`ManagedOwnerAction`] in.
pub const MANAGED_OWNER_ACTION_HEADER: &str = "x-oneiron-managed-owner-action";

/// The request headers a [`ManagedOwnerAction`] binds, in this order: the
/// room turn, the invocation and the session the call runs in. An absent
/// one binds as empty.
pub const MANAGED_OWNER_BOUND_HEADERS: [&str; 3] = [
    "x-oneiron-room-turn",
    "x-oneiron-invocation",
    "x-oneiron-session",
];

/// The derived-id domain of the embedded owner, the person a personal vault
/// holds from its first open. It must stay the same text as the engine's
/// `EMBEDDED_OWNER_ACTOR` (oneiron-contracts `entity_id::derived_domains`):
/// managed boot refuses to start when the two ids disagree.
const EMBEDDED_OWNER_DOMAIN: &str = "oneiron 2026-08 embedded-owner-actor v1";

/// The embedded owner's holder id as 32 lowercase hex characters: the
/// `holder_ref` a supervisor names a personal vault's owner by in a
/// [`ManagedOwnerAction`]. Computed as the engine's derived-id rule computes
/// it: a BLAKE3 key derivation over the owner's domain with no parts, its
/// first 16 bytes, then the id's version and variant bits.
#[must_use]
pub fn embedded_owner_holder_hex() -> String {
    let digest = blake3::Hasher::new_derive_key(EMBEDDED_OWNER_DOMAIN).finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0F) | 0x80;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    super::hex(&bytes)
}

/// The one request a [`ManagedOwnerAction`] covers.
#[derive(Debug, Clone, Copy)]
pub struct ManagedOwnerRequest<'a> {
    /// The HTTP method, as sent (`POST`).
    pub method: &'a str,
    /// The request path, without its query.
    pub path: &'a str,
    /// The request's query, its exact bytes as sent, without the `?`; empty
    /// when absent. Signed raw: never parsed, reordered or re-encoded.
    pub query: &'a str,
    /// The values of [`MANAGED_OWNER_BOUND_HEADERS`], in order; empty when
    /// absent.
    pub headers: [&'a str; 3],
    /// The exact body bytes.
    pub body: &'a [u8],
}

/// The method a managed voice hello's [`ManagedOwnerAction`] signs; no HTTP
/// request is attested under it (FIX 2391).
pub const MANAGED_VOICE_METHOD: &str = "VOICE";

/// The path a managed voice hello's action signs: a namespace, not a route.
pub const MANAGED_VOICE_PATH: &str = "/voice";

/// How far a managed voice hello's `issued_at` may sit from the vault's
/// clock, either way, in seconds. The vault takes each hello's action once.
pub const MANAGED_VOICE_MAX_SKEW_SECS: u64 = 60;

/// The raw bytes of a managed voice hello's `nonce`: fresh random bytes for
/// each hello, so two hellos for the same room and roster in the same second
/// sign apart. The hello carries them as twice as many lowercase hex
/// characters.
pub const MANAGED_VOICE_NONCE_BYTES: usize = 16;

/// The body a managed voice hello's action signs: its `issued_at`, in Unix
/// seconds, as eight big-endian bytes, then its nonce's raw bytes
/// ([`managed_voice_body`]).
pub type ManagedVoiceBody = [u8; 8 + MANAGED_VOICE_NONCE_BYTES];

/// A managed voice hello's `nonce` as its raw bytes: exactly
/// `2 * MANAGED_VOICE_NONCE_BYTES` lowercase hex characters, else `None`.
#[must_use]
pub fn managed_voice_nonce(text: &str) -> Option<[u8; MANAGED_VOICE_NONCE_BYTES]> {
    if text.len() != 2 * MANAGED_VOICE_NONCE_BYTES
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    super::from_hex(text)?.try_into().ok()
}

/// The [`ManagedVoiceBody`] of a hello issued at `issued_at` (Unix seconds)
/// with `nonce`.
#[must_use]
pub fn managed_voice_body(
    issued_at: u64,
    nonce: &[u8; MANAGED_VOICE_NONCE_BYTES],
) -> ManagedVoiceBody {
    let mut body = [0u8; 8 + MANAGED_VOICE_NONCE_BYTES];
    body[..8].copy_from_slice(&issued_at.to_be_bytes());
    body[8..].copy_from_slice(nonce);
    body
}

impl<'a> ManagedOwnerRequest<'a> {
    /// A managed voice hello as its action signs it: the room and the voice
    /// roster the hello names in the first two bound slots (empty when
    /// absent), and its [`ManagedVoiceBody`] (`issued_at`, then the nonce)
    /// as the body.
    #[must_use]
    pub fn voice(room: &'a str, roster: &'a str, body: &'a ManagedVoiceBody) -> Self {
        Self {
            method: MANAGED_VOICE_METHOD,
            path: MANAGED_VOICE_PATH,
            query: "",
            headers: [room, roster, ""],
            body,
        }
    }

    /// Everything this request binds but its body.
    fn head(&self) -> ManagedOwnerHead<'a> {
        ManagedOwnerHead {
            method: self.method,
            path: self.path,
            query: self.query,
            headers: self.headers,
        }
    }
}

/// One request a [`ManagedOwnerAction`] covers, but its body: for a body
/// that arrives in pieces ([`ManagedOwnerTranscript`]).
#[derive(Debug, Clone, Copy)]
pub struct ManagedOwnerHead<'a> {
    /// The HTTP method, as sent.
    pub method: &'a str,
    /// The request path, without its query.
    pub path: &'a str,
    /// The request's query, its exact bytes as sent, without the `?`; empty
    /// when absent.
    pub query: &'a str,
    /// The values of [`MANAGED_OWNER_BOUND_HEADERS`], in order; empty when
    /// absent.
    pub headers: [&'a str; 3],
}

/// The owner action's transcript of one request whose body arrives in
/// pieces: the same keyed hash over the same length-prefixed items that
/// [`ManagedOwnerAction`] signs and verifies over a whole
/// [`ManagedOwnerRequest`], one format. The body's length goes in before
/// its bytes, so it is the length counted once the body is held whole (a
/// body of unknown length is spooled and counted first), never one the
/// request declares; the transcript then takes exactly that many bytes, in
/// order. It is never a hash of the body or of anything decoded from it.
pub struct ManagedOwnerTranscript {
    hasher: blake3::Hasher,
    holder: String,
    /// Body bytes still to take.
    remaining: u64,
    /// Whether more bytes came than the length it began with.
    overrun: bool,
}

impl ManagedOwnerTranscript {
    /// Begins the transcript `holder_ref`'s action covers on `vault`, for a
    /// request with `head` whose body is `body_len` bytes.
    #[must_use]
    pub fn new(
        spawn_token: &TokenHex,
        vault: &str,
        holder_ref: &str,
        head: &ManagedOwnerHead<'_>,
        body_len: u64,
    ) -> Self {
        let mut key = blake3::derive_key(OWNER_DOMAIN, spawn_token.expose().as_bytes());
        let mut hasher = blake3::Hasher::new_keyed(&key);
        key.zeroize();
        let [room_turn, invocation, session] = head.headers;
        for item in [
            vault.as_bytes(),
            holder_ref.as_bytes(),
            head.method.as_bytes(),
            head.path.as_bytes(),
            head.query.as_bytes(),
            room_turn.as_bytes(),
            invocation.as_bytes(),
            session.as_bytes(),
        ] {
            hasher.update(&(item.len() as u64).to_be_bytes());
            hasher.update(item);
        }
        hasher.update(&body_len.to_be_bytes());
        Self {
            hasher,
            holder: holder_ref.to_owned(),
            remaining: body_len,
            overrun: false,
        }
    }

    /// Takes the body's next bytes.
    pub fn update(&mut self, piece: &[u8]) {
        let taken = piece.len() as u64;
        self.overrun |= taken > self.remaining;
        self.remaining = self.remaining.saturating_sub(taken);
        self.hasher.update(piece);
    }

    /// Whether it took exactly the body's length.
    fn complete(&self) -> bool {
        self.remaining == 0 && !self.overrun
    }

    fn mac(self) -> String {
        self.finish().1
    }

    /// Its holder, and the MAC it came to.
    fn finish(self) -> (String, String) {
        (self.holder, self.hasher.finalize().to_hex().to_string())
    }
}

/// A host assertion that one request is the vault owner's own: tied to one
/// vault, the authenticated holder, the method, path and query, the headers
/// that place the call, and the exact body. The vault names the holder as
/// the request's person only on this assertion, and as its owner only while
/// the holder is the vault's live recorded owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOwnerAction {
    pub holder_ref: String,
    pub mac: String,
}

impl ManagedOwnerAction {
    /// Called by the supervisor ONLY after it authenticates the named human
    /// account as the vault's owner, on that person's own direct request
    /// (never an agent's or a delegated key's), and checks its power for the
    /// verb the path names.
    pub fn sign_after_account_auth(
        spawn_token: &TokenHex,
        vault: &str,
        holder_ref: &str,
        request: &ManagedOwnerRequest<'_>,
    ) -> Self {
        Self {
            holder_ref: holder_ref.to_owned(),
            mac: sign_owner(spawn_token, vault, holder_ref, request),
        }
    }

    /// [`Self::sign_after_account_auth`] for a request whose body arrived in
    /// pieces, once `transcript` took all of it; `None` when it took more or
    /// fewer bytes than the length it began with. The same conditions bind
    /// the supervisor: ONLY after it authenticates the named human account
    /// as the vault's owner, on that person's own direct request.
    #[must_use]
    pub fn sign_transcript_after_account_auth(transcript: ManagedOwnerTranscript) -> Option<Self> {
        if !transcript.complete() {
            return None;
        }
        let (holder_ref, mac) = transcript.finish();
        Some(Self { holder_ref, mac })
    }

    /// Refuse a forwarded/caller-chosen header unless the supervisor signed
    /// this exact request for this vault and this holder.
    pub fn verify(
        &self,
        spawn_token: &TokenHex,
        vault: &str,
        request: &ManagedOwnerRequest<'_>,
    ) -> bool {
        if !self.well_formed() {
            return false;
        }
        let expected = sign_owner(spawn_token, vault, &self.holder_ref, request);
        bool::from(self.mac.as_bytes().ct_eq(expected.as_bytes()))
    }

    /// [`Self::verify`] for a request whose body arrived in pieces: true
    /// only when `transcript` is this action's holder's, begun for the
    /// vault and the request head it names, took exactly its body's length,
    /// and comes to the MAC the supervisor signed.
    #[must_use]
    pub fn verify_transcript(&self, transcript: ManagedOwnerTranscript) -> bool {
        if !self.well_formed() || transcript.holder != self.holder_ref || !transcript.complete() {
            return false;
        }
        let expected = transcript.mac();
        bool::from(self.mac.as_bytes().ct_eq(expected.as_bytes()))
    }

    /// Whether the holder is 32 and the MAC 64 lowercase hex characters.
    fn well_formed(&self) -> bool {
        self.holder_ref.len() == 32
            && self
                .holder_ref
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.mac.len() == 64
            && self
                .mac
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

/// The MAC over a whole request: its transcript, fed the body at once.
fn sign_owner(
    token: &TokenHex,
    vault: &str,
    holder: &str,
    request: &ManagedOwnerRequest<'_>,
) -> String {
    let mut transcript = ManagedOwnerTranscript::new(
        token,
        vault,
        holder,
        &request.head(),
        request.body.len() as u64,
    );
    transcript.update(request.body);
    transcript.mac()
}

fn sign(token: &TokenHex, vault: &str, holder: &str, body: &[u8]) -> String {
    let mut key = blake3::derive_key(DOMAIN, token.expose().as_bytes());
    let mut h = blake3::Hasher::new_keyed(&key);
    for item in [vault.as_bytes(), holder.as_bytes(), body] {
        h.update(&(item.len() as u64).to_be_bytes());
        h.update(item);
    }
    let mac = h.finalize().to_hex().to_string();
    key.zeroize();
    mac
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_action_binds_holder_vault_and_exact_body() {
        let token = TokenHex::from_token(&[3; 32]);
        let action = ManagedWidenAction::sign_after_account_auth(
            &token,
            "vault-a",
            &"a".repeat(32),
            b"proposal A",
        );
        assert!(action.verify(&token, "vault-a", b"proposal A"));
        assert!(!action.verify(&token, "vault-a", b"proposal B"));
        assert!(!action.verify(&token, "vault-b", b"proposal A"));
        assert!(!action.verify(&TokenHex::from_token(&[4; 32]), "vault-a", b"proposal A"));
        let mut other = action;
        other.holder_ref = "b".repeat(32);
        assert!(!other.verify(&token, "vault-a", b"proposal A"));
    }
}
