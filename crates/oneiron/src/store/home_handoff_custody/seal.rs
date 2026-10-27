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

use crate::error::{Error, Result};

use super::{KeyRef, LiveTarget, TransitSeal, VerifiedHolder};

const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
const CRYPTO_EPOCH: u64 = 1;
const CONTENT_RECIPIENT: &[u8] = b"oneiron/erasable-key/content/v1";
const TRANSIT_AAD_LABEL: &[u8] = b"oneiron/erasable-key/transit/v1";

/// Why an erasable-key envelope did not seal, by the crypto error's kind: a
/// fixed reason, never the error's values or a key's bytes.
fn seal_refused(error: &oneiron_crypto::Error, what: &str) -> Error {
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
fn open_refused(error: &oneiron_crypto::Error, what: &str) -> Error {
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
fn transit_aad(
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

/// Seals `plain` under the erasable key `key`, the 32-byte custody secret the
/// key `key_ref` names, binding `aad` (the caller's: vault, incarnation, ref,
/// section, part and order) as extra associated data.
pub(super) fn seal_content(
    key_ref: &KeyRef,
    key: &Zeroizing<[u8; 32]>,
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::ErasableKey,
        epoch: CRYPTO_EPOCH,
        key_id: key_ref.as_bytes(),
        recipient: CONTENT_RECIPIENT,
        vault_id: key_ref.as_bytes(),
    };
    let kek = Kek::from_bytes_ref(key);
    seal_with_aad(
        &params,
        SealKey::SymmetricKek(&kek),
        plain,
        aad,
        &mut SysRng,
    )
    .map(|envelope| envelope.to_bytes())
    .map_err(|error| seal_refused(&error, "erasable key content"))
}

/// Opens what `seal_content` sealed under the same `key_ref`, `key` and
/// `aad`; any failure (wrong key, wrong ref, wrong aad, damage) is an error.
pub(super) fn open_content(
    key_ref: &KeyRef,
    key: &Zeroizing<[u8; 32]>,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let policy = OpenPolicy {
        purpose: Purpose::ErasableKey,
        vault_id: key_ref.as_bytes(),
        recipient: CONTENT_RECIPIENT,
        key_id: key_ref.as_bytes(),
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: CRYPTO_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let kek = Kek::from_bytes_ref(key);
    Envelope::parse(sealed)
        .map_err(|error| open_refused(&error, "erasable key content"))?
        .open_with_aad(OpenKey::SymmetricKek(&kek), &policy, aad)
        .map_err(|error| open_refused(&error, "erasable key content"))
}

/// Seals `plain` (the key's 81-byte transit record: purpose 1 | parent 16 |
/// incarnation 32 | secret 32) to `target.ephemeral`, the live session's
/// ephemeral hybrid public key: never a machine's long-lived key. Binds the
/// target machine, the session binding and nonce, and `key_ref`.
pub(super) fn seal_transit(
    target: &LiveTarget,
    key_ref: &KeyRef,
    plain: &[u8],
) -> Result<TransitSeal> {
    let machine = target.machine.as_bytes();
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::ErasableKey,
        epoch: CRYPTO_EPOCH,
        key_id: key_ref.as_bytes(),
        recipient: machine,
        vault_id: &target.session.binding,
    };
    let aad = transit_aad(
        machine,
        &target.session.binding,
        &target.session.nonce,
        key_ref.as_bytes(),
    );
    seal_with_aad(
        &params,
        SealKey::Hybrid {
            recipient: &target.ephemeral,
            kem_suite: KEM,
        },
        plain,
        &aad,
        &mut SysRng,
    )
    .map(|envelope| TransitSeal::from_bytes(envelope.to_bytes()))
    .map_err(|error| seal_refused(&error, "the key in transit"))
}

/// Opens a transit seal on the target with `session`, the session-ephemeral
/// secret matching `target.ephemeral`, checking the same binding from the
/// receiving side: `holder.target` (this machine), `holder.session.binding`,
/// `holder.session.nonce`, and `key_ref`.
pub(super) fn open_transit(
    session: &oneiron_crypto::HybridSecretKey,
    holder: &VerifiedHolder,
    key_ref: &KeyRef,
    sealed: &TransitSeal,
) -> Result<Zeroizing<Vec<u8>>> {
    let machine = holder.target.as_bytes();
    let policy = OpenPolicy {
        purpose: Purpose::ErasableKey,
        vault_id: &holder.session.binding,
        recipient: machine,
        key_id: key_ref.as_bytes(),
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: CRYPTO_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let aad = transit_aad(
        machine,
        &holder.session.binding,
        &holder.session.nonce,
        key_ref.as_bytes(),
    );
    Envelope::parse(sealed.as_bytes())
        .map_err(|error| open_refused(&error, "the key in transit"))?
        .open_with_aad(OpenKey::Hybrid(session), &policy, &aad)
        .map_err(|error| open_refused(&error, "the key in transit"))
}
