//! The erasable handoff key's envelopes (FIX 8875): content sealed under the
//! key itself, and the key's transit record sealed to a live target session's
//! ephemeral key. Both bind the key's ref; content binds the caller's
//! associated data, transit the target machine and session.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal_with_aad,
};
use zeroize::Zeroizing;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

pub const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
pub const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
pub const CRYPTO_EPOCH: u64 = 1;
pub const CONTENT_RECIPIENT: &[u8] = b"oneiron/erasable-key/content/v1";
const TRANSIT_AAD_LABEL: &[u8] = b"oneiron/erasable-key/transit/v1";

/// Why an erasable-key envelope did not seal, by the crypto error's kind: a
/// fixed reason, never the error's values or a key's bytes.
pub fn seal_refused(error: &oneiron_crypto::Error, what: &str) -> Error {
    use oneiron_crypto::Error as Crypto;
    let reason = match error {
        Crypto::FieldLength {
            field: "plaintext" | "ciphertext",
            ..
        } => "the plaintext is out of range",
        Crypto::Rng => "the random source failed",
        Crypto::KemKeyRejected => "the key encapsulation was refused",
        _ => "the envelope was refused",
    };
    Error::InvalidConfig(format!("sealing {what} failed: {reason}"))
}

/// Why an erasable-key envelope did not open, by the crypto error's kind: only
/// a failed authentication is the wrong key; every other cause names itself. A
/// fixed reason, never the error's values, a key's bytes or the envelope's.
pub fn open_refused(error: &oneiron_crypto::Error, what: &str) -> Error {
    use oneiron_crypto::Error as Crypto;
    let reason = match error {
        Crypto::OpenFailed => "it does not open with this key",
        Crypto::PurposeMismatch { .. }
        | Crypto::VaultMismatch
        | Crypto::RecipientMismatch
        | Crypto::KeyIdMismatch => "the envelope is bound to another place",
        _ => "a field is out of range",
    };
    Error::InvalidConfig(format!("opening {what} failed: {reason}"))
}

/// A transit envelope's extra associated data: one fixed label, then the
/// target machine (16) | session binding (32) | session nonce (32) | key ref
/// (32), all fixed-width, so no other binding opens as this one's.
pub fn transit_aad(
    machine: &[u8; 16],
    binding: &[u8; 32],
    nonce: &[u8; 32],
    key_ref: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TRANSIT_AAD_LABEL.len() + 16 + 32 + 32 + 32);
    aad.extend_from_slice(TRANSIT_AAD_LABEL);
    aad.extend_from_slice(machine);
    aad.extend_from_slice(binding);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(key_ref);
    aad
}
