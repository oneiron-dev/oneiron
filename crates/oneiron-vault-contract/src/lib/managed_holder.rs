//! Host-attested account action for one managed widen request.
//!
//! Only the supervisor, after account authentication and its power check,
//! signs this body. The vault child has the per-spawn secret but never infers
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
