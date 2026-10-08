//! Sealing and opening, and the one key schedule every wrap type shares:
//!
//! - `W` = the 32-byte wrap secret: the KEK, Argon2id(passphrase), the keystore or
//!   passkey KEK, the recovered Shamir secret, or the hybrid combiner output;
//! - `K = HKDF-SHA256(salt = header salt, ikm = W, info = KEY_LABEL || H)`;
//! - `ciphertext = AEAD(K, header nonce, plaintext, aad = H)`,
//!
//! where `H` is the exact canonical header (every metadata field, the nonce and the
//! ciphertext length). The fresh 32-byte salt makes `K` unique per envelope, so even
//! AES-256-GCM's random 96-bit nonce never repeats under one key in practice.

use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::TryCryptoRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{Envelope, Header, Kdf, Purpose, WrapParams, WrapType, hybrid};
use crate::codec::check_len;
use crate::error::{Error, Result};
use crate::keys::{
    Argon2Cost, HybridPublicKey, HybridSecretKey, Kek, Passphrase, RecoverySecret, fill,
};
use crate::suite::{Suite, SuiteId, SuiteKind, name_of};
use crate::{MAX_PLAINTEXT_LEN, TAG_LEN};

const KEY_LABEL: &[u8] = b"oneiron-crypto/v1/aead-key";

/// What the writer states about a new envelope.
#[derive(Clone, Copy, Debug)]
pub struct SealParams<'a> {
    /// The payload AEAD suite.
    pub suite: SuiteId,
    pub purpose: Purpose,
    pub epoch: u64,
    pub key_id: &'a [u8],
    pub recipient: &'a [u8],
    pub vault_id: &'a [u8],
}

/// The key a writer seals under; it fixes the wrap type.
pub enum SealKey<'a> {
    SymmetricKek(&'a Kek),
    Passphrase {
        passphrase: &'a Passphrase,
        cost: Argon2Cost,
    },
    DeviceKeystore(&'a Kek),
    Passkey(&'a Kek),
    ShamirRecovery {
        secret: &'a RecoverySecret,
        threshold: u8,
        shares: u8,
        share_set_id: [u8; 16],
    },
    Hybrid {
        recipient: &'a HybridPublicKey,
        kem_suite: SuiteId,
    },
}

/// The key a reader opens with. It must match the header's wrap type.
pub enum OpenKey<'a> {
    SymmetricKek(&'a Kek),
    Passphrase(&'a Passphrase),
    DeviceKeystore(&'a Kek),
    Passkey(&'a Kek),
    ShamirRecovery(&'a RecoverySecret),
    Hybrid(&'a HybridSecretKey),
}

/// What the reader expects. Every field is required: the header must match each one
/// before any key derivation runs. The envelope's own claims are never the
/// expectation.
#[derive(Clone, Copy, Debug)]
pub struct OpenPolicy<'a> {
    pub purpose: Purpose,
    pub vault_id: &'a [u8],
    pub recipient: &'a [u8],
    pub key_id: &'a [u8],
    /// Wrap types this reader accepts.
    pub wraps: &'a [WrapType],
    /// Payload AEAD suites this reader accepts.
    pub aead_suites: &'a [SuiteId],
    /// KEM suites this reader accepts for hybrid capsules.
    pub kem_suites: &'a [SuiteId],
    /// The reader's minimum accepted epoch (rollback floor).
    pub min_epoch: u64,
}

/// Seals `plaintext` under `key`. Salt and nonce come from `rng`; an RNG failure is
/// an error, never a weaker envelope.
pub fn seal<R: TryCryptoRng + ?Sized>(
    params: &SealParams<'_>,
    key: SealKey<'_>,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Envelope> {
    let suite = Suite::require(params.suite, &[SuiteKind::Aead], params.epoch)?;
    check_len("plaintext", plaintext.len(), 0, MAX_PLAINTEXT_LEN)?;
    let mut salt = [0u8; 32];
    fill(rng, &mut salt)?;
    let mut nonce = vec![0u8; suite.nonce_len()];
    fill(rng, &mut nonce)?;

    let (wrap, kdf, wrap_params, secret) = match key {
        SealKey::SymmetricKek(kek) => (
            WrapType::SymmetricKek,
            hkdf(salt),
            WrapParams::None,
            copy(kek.expose()),
        ),
        SealKey::DeviceKeystore(kek) => (
            WrapType::DeviceKeystore,
            hkdf(salt),
            WrapParams::None,
            copy(kek.expose()),
        ),
        SealKey::Passkey(kek) => (
            WrapType::Passkey,
            hkdf(salt),
            WrapParams::None,
            copy(kek.expose()),
        ),
        SealKey::ShamirRecovery {
            secret,
            threshold,
            shares,
            share_set_id,
        } => (
            WrapType::ShamirRecovery,
            hkdf(salt),
            WrapParams::Shamir {
                threshold,
                shares,
                share_set_id,
            },
            copy(secret.expose()),
        ),
        SealKey::Passphrase { passphrase, cost } => {
            cost.check()?;
            (
                WrapType::Passphrase,
                Kdf::Argon2idHkdfSha256 { cost, salt },
                WrapParams::None,
                argon2id(passphrase, &cost, &salt)?,
            )
        }
        SealKey::Hybrid {
            recipient,
            kem_suite,
        } => {
            Suite::require(kem_suite, &[SuiteKind::Kem], params.epoch)?;
            let capsule = hybrid::encapsulate(recipient, rng)?;
            let wrap_params = WrapParams::Hybrid {
                kem_suite,
                x25519_ephemeral: capsule.x25519_ephemeral,
                mlkem_ciphertext: capsule.mlkem_ciphertext,
            };
            (
                WrapType::HybridCapsule,
                hkdf(salt),
                wrap_params,
                capsule.secret,
            )
        }
    };

    let ciphertext_len =
        u32::try_from(plaintext.len() + TAG_LEN).map_err(|_| Error::Primitive("length"))?;
    let header = Header {
        suite: params.suite,
        wrap,
        purpose: params.purpose,
        epoch: params.epoch,
        key_id: params.key_id.to_vec(),
        recipient: params.recipient.to_vec(),
        vault_id: params.vault_id.to_vec(),
        kdf,
        wrap_params,
        nonce,
        ciphertext_len,
    };
    header.validate()?;
    let header_bytes = header.encode();
    let key = aead_key(&secret, header.kdf.salt(), &header_bytes)?;
    let ciphertext = aead_seal(header.suite, &key, &header.nonce, &header_bytes, plaintext)?;
    if ciphertext.len() != header.ciphertext_len as usize {
        return Err(Error::Primitive("aead output length"));
    }
    Ok(Envelope {
        header,
        header_bytes,
        ciphertext,
    })
}

impl Envelope {
    /// Checks the header against the reader's policy, then derives the key and opens.
    /// Every cryptographic failure is [`Error::OpenFailed`].
    pub fn open(&self, key: OpenKey<'_>, policy: &OpenPolicy<'_>) -> Result<Zeroizing<Vec<u8>>> {
        let h = &self.header;
        if !policy.aead_suites.contains(&h.suite) {
            return Err(Error::SuiteNotAccepted(name_of(h.suite)));
        }
        if !policy.wraps.contains(&h.wrap) {
            return Err(Error::WrapNotAccepted(h.wrap));
        }
        if let WrapParams::Hybrid { kem_suite, .. } = &h.wrap_params
            && !policy.kem_suites.contains(kem_suite)
        {
            return Err(Error::SuiteNotAccepted(name_of(*kem_suite)));
        }
        if h.epoch < policy.min_epoch {
            return Err(Error::EpochBelowPolicyMinimum {
                epoch: h.epoch,
                min: policy.min_epoch,
            });
        }
        if h.purpose != policy.purpose {
            return Err(Error::PurposeMismatch {
                expected: policy.purpose,
                found: h.purpose,
            });
        }
        if h.vault_id != policy.vault_id {
            return Err(Error::VaultMismatch);
        }
        if h.recipient != policy.recipient {
            return Err(Error::RecipientMismatch);
        }
        if h.key_id != policy.key_id {
            return Err(Error::KeyIdMismatch);
        }

        let secret = match (key, &h.kdf, &h.wrap_params) {
            (OpenKey::SymmetricKek(kek), _, _) if h.wrap == WrapType::SymmetricKek => {
                copy(kek.expose())
            }
            (OpenKey::DeviceKeystore(kek), _, _) if h.wrap == WrapType::DeviceKeystore => {
                copy(kek.expose())
            }
            (OpenKey::Passkey(kek), _, _) if h.wrap == WrapType::Passkey => copy(kek.expose()),
            (OpenKey::ShamirRecovery(secret), _, _) if h.wrap == WrapType::ShamirRecovery => {
                copy(secret.expose())
            }
            (OpenKey::Passphrase(passphrase), Kdf::Argon2idHkdfSha256 { cost, salt }, _) => {
                argon2id(passphrase, cost, salt)?
            }
            (
                OpenKey::Hybrid(secret_key),
                _,
                WrapParams::Hybrid {
                    x25519_ephemeral,
                    mlkem_ciphertext,
                    ..
                },
            ) => hybrid::decapsulate(secret_key, x25519_ephemeral, mlkem_ciphertext)?,
            _ => return Err(Error::WrongKeyForWrap { wrap: h.wrap }),
        };
        let key = aead_key(&secret, h.kdf.salt(), &self.header_bytes)?;
        aead_open(
            h.suite,
            &key,
            &h.nonce,
            &self.header_bytes,
            &self.ciphertext,
        )
    }
}

fn hkdf(salt: [u8; 32]) -> Kdf {
    Kdf::HkdfSha256 { salt }
}

fn copy(bytes: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(*bytes)
}

/// Argon2id v0x13, 32-byte output. The caller has bounded `cost`.
fn argon2id(
    passphrase: &Passphrase,
    cost: &Argon2Cost,
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(cost.m_kib, cost.t, u32::from(cost.p), Some(32))
        .map_err(|_| Error::Primitive("argon2id parameters"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.expose(), salt, &mut *out)
        .map_err(|_| Error::Primitive("argon2id"))?;
    Ok(out)
}

fn aead_key(
    secret: &[u8; 32],
    salt: &[u8; 32],
    header_bytes: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand_multi_info(&[KEY_LABEL, header_bytes], &mut *key)
        .map_err(|_| Error::Primitive("hkdf"))?;
    Ok(key)
}

fn aead_seal(
    suite: SuiteId,
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let out = match suite {
        SuiteId::XCHACHA20POLY1305_V1 => {
            let nonce = XNonce::try_from(nonce).map_err(|_| Error::Primitive("nonce"))?;
            XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::Primitive("key"))?
                .encrypt(&nonce, payload)
        }
        SuiteId::AES256GCM_V1 => {
            let nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(nonce)
                .map_err(|_| Error::Primitive("nonce"))?;
            Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::Primitive("key"))?
                .encrypt(&nonce, payload)
        }
        _ => return Err(Error::Primitive("aead suite")),
    };
    out.map_err(|_| Error::Primitive("aead seal"))
}

fn aead_open(
    suite: SuiteId,
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let out = match suite {
        SuiteId::XCHACHA20POLY1305_V1 => {
            let nonce = XNonce::try_from(nonce).map_err(|_| Error::OpenFailed)?;
            XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::OpenFailed)?
                .decrypt(&nonce, payload)
        }
        SuiteId::AES256GCM_V1 => {
            let nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(nonce)
                .map_err(|_| Error::OpenFailed)?;
            Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::OpenFailed)?
                .decrypt(&nonce, payload)
        }
        _ => return Err(Error::OpenFailed),
    };
    out.map(Zeroizing::new).map_err(|_| Error::OpenFailed)
}
