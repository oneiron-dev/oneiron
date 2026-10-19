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

impl<'a> ManagedOwnerRequest<'a> {
    /// A managed voice hello as its action signs it: the room and the voice
    /// roster the hello names in the first two bound slots (empty when
    /// absent), and its `issued_at`, in Unix seconds, as eight big-endian
    /// bytes of body.
    #[must_use]
    pub fn voice(room: &'a str, roster: &'a str, issued_at: &'a [u8; 8]) -> Self {
        Self {
            method: MANAGED_VOICE_METHOD,
            path: MANAGED_VOICE_PATH,
            query: "",
            headers: [room, roster, ""],
            body: issued_at,
        }
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

    /// Refuse a forwarded/caller-chosen header unless the supervisor signed
    /// this exact request for this vault and this holder.
    pub fn verify(
        &self,
        spawn_token: &TokenHex,
        vault: &str,
        request: &ManagedOwnerRequest<'_>,
    ) -> bool {
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
        let expected = sign_owner(spawn_token, vault, &self.holder_ref, request);
        bool::from(self.mac.as_bytes().ct_eq(expected.as_bytes()))
    }
}

fn sign_owner(
    token: &TokenHex,
    vault: &str,
    holder: &str,
    request: &ManagedOwnerRequest<'_>,
) -> String {
    let mut key = blake3::derive_key(OWNER_DOMAIN, token.expose().as_bytes());
    let mut h = blake3::Hasher::new_keyed(&key);
    let [room_turn, invocation, session] = request.headers;
    for item in [
        vault.as_bytes(),
        holder.as_bytes(),
        request.method.as_bytes(),
        request.path.as_bytes(),
        request.query.as_bytes(),
        room_turn.as_bytes(),
        invocation.as_bytes(),
        session.as_bytes(),
        request.body,
    ] {
        h.update(&(item.len() as u64).to_be_bytes());
        h.update(item);
    }
    let mac = h.finalize().to_hex().to_string();
    key.zeroize();
    mac
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
