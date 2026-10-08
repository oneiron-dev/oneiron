//! Signing and verifying records. The signed message for every component is
//! `LABEL || transcript || subject`, where the transcript is the whole record minus
//! the signature bytes. Ed25519 is RFC 8032 pure Ed25519 verified with
//! `verify_strict`; SLH-DSA is FIPS 205 pure SLH-DSA-SHA2-256s with an empty context
//! and hedged signing (a fresh randomizer per signature).

use core::fmt;

use ed25519_dalek::Signer as _;
use rand_core::TryCryptoRng;
use slh_dsa::Sha2_256s;
use zeroize::Zeroizing;

use super::{RecordBody, SigPurpose, SignatureEntry, SignatureRecord, check_roster, roster};
use crate::error::{Error, Result};
use crate::keys::fill;
use crate::suite::{Suite, SuiteId, SuiteKind, name_of};

const LABEL: &[u8] = b"oneiron-crypto/v1/sig";
const SLHDSA_N: usize = 32;
// The wipe sizes come from stack painting (`sign::tests`, x86_64 Linux, rustc 1.96,
// 2026-10-09), one per build: `debug_assertions` stands in for an unoptimized build, as
// Cargo's dev and test profiles pair them. A profile that turns both off gets the release
// size and only a partial wipe; the test's reach check fails when run under it.

/// Stack bytes wiped after an Ed25519 signature: the signer reached 62,248 bytes below its
/// caller in a release build and 152,728 in a dev build (this crate at opt-level 0), most
/// of it [`SigningKey::sign_message_inner`]'s own frame; so about 2.1x and 1.7x that.
const ED25519_STACK_WIPE: usize = if cfg!(debug_assertions) {
    256 * 1024
} else {
    128 * 1024
};
/// Stack bytes wiped after an SLH-DSA signature: 188,056 bytes in a release build and
/// 464,504 in a dev build, so about 1.7x and 1.4x that.
const SLHDSA_STACK_WIPE: usize = if cfg!(debug_assertions) {
    640 * 1024
} else {
    320 * 1024
};

/// A signing key of one signature suite. Zeroizes on drop.
pub enum SigningKey {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    SlhDsaSha2_256s(Box<slh_dsa::SigningKey<Sha2_256s>>),
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({}, redacted)", name_of(self.suite()))
    }
}

impl SigningKey {
    /// A fresh Ed25519 key.
    pub fn generate_ed25519<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        fill(rng, &mut *seed)?;
        Ok(Self::Ed25519(Box::new(
            ed25519_dalek::SigningKey::from_bytes(&seed),
        )))
    }

    /// A fresh SLH-DSA-SHA2-256s key: FIPS 205 slh_keygen, with the three seeds drawn
    /// from `rng` (so an RNG failure stays an error).
    pub fn generate_slhdsa_sha2_256s<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut seeds = Zeroizing::new([0u8; 3 * SLHDSA_N]);
        fill(rng, &mut *seeds)?;
        let (sk_seed, rest) = seeds.split_at(SLHDSA_N);
        let (sk_prf, pk_seed) = rest.split_at(SLHDSA_N);
        let key = slh_dsa::SigningKey::<Sha2_256s>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
        Ok(Self::SlhDsaSha2_256s(Box::new(key)))
    }

    pub fn suite(&self) -> SuiteId {
        match self {
            Self::Ed25519(_) => SuiteId::SIG_ED25519_V1,
            Self::SlhDsaSha2_256s(_) => SuiteId::SIG_SLHDSA_SHA2_256S_V1,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::Ed25519(key) => VerifyingKey::Ed25519(key.verifying_key()),
            Self::SlhDsaSha2_256s(key) => {
                let vk: &slh_dsa::VerifyingKey<Sha2_256s> = (**key).as_ref();
                VerifyingKey::SlhDsaSha2_256s(Box::new(vk.clone()))
            }
        }
    }

    /// Signs, then wipes the stack the signer ran on. SLH-DSA-SHA2's PRF_msg is
    /// HMAC-SHA-512 keyed by SK.prf, and `hmac` leaves the padded key block in a plain
    /// stack value; upstream asks callers to erase it (RustCrypto/meta#38). The same wipe
    /// takes whatever else the signers leave there, such as WOTS+/FORS values and the
    /// Ed25519 nonce. Best effort: register copies and spills in this frame are not reached.
    fn sign_message<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let signature = self.sign_message_inner(message, rng);
        match self {
            Self::Ed25519(_) => zeroize::zeroize_stack::<ED25519_STACK_WIPE>(),
            Self::SlhDsaSha2_256s(_) => zeroize::zeroize_stack::<SLHDSA_STACK_WIPE>(),
        }
        signature
    }

    /// Out of line, so its frames sit below [`Self::sign_message`]'s and the wipe after it
    /// covers them.
    #[inline(never)]
    fn sign_message_inner<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Ed25519(key) => Ok(key.sign(message).to_bytes().to_vec()),
            Self::SlhDsaSha2_256s(key) => {
                let mut randomizer = [0u8; SLHDSA_N];
                fill(rng, &mut randomizer)?;
                let signature = key
                    .try_sign_with_context(message, &[], Some(&randomizer))
                    .map_err(|_| Error::Primitive("slh-dsa sign"))?;
                Ok(signature.to_vec())
            }
        }
    }
}

/// A verifying key of one signature suite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    SlhDsaSha2_256s(Box<slh_dsa::VerifyingKey<Sha2_256s>>),
}

impl VerifyingKey {
    pub fn suite(&self) -> SuiteId {
        match self {
            Self::Ed25519(_) => SuiteId::SIG_ED25519_V1,
            Self::SlhDsaSha2_256s(_) => SuiteId::SIG_SLHDSA_SHA2_256S_V1,
        }
    }

    /// Parses a public key of `suite` (Ed25519: 32 bytes; SLH-DSA-SHA2-256s: 64).
    pub fn from_bytes(suite: SuiteId, bytes: &[u8]) -> Result<Self> {
        match suite {
            SuiteId::SIG_ED25519_V1 => {
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::FieldLength {
                    field: "ed25519 public key",
                    len: bytes.len(),
                    min: 32,
                    max: 32,
                })?;
                ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map(Self::Ed25519)
                    .map_err(|_| Error::Primitive("ed25519 public key"))
            }
            SuiteId::SIG_SLHDSA_SHA2_256S_V1 => slh_dsa::VerifyingKey::<Sha2_256s>::try_from(bytes)
                .map(|key| Self::SlhDsaSha2_256s(Box::new(key)))
                .map_err(|_| Error::FieldLength {
                    field: "slh-dsa public key",
                    len: bytes.len(),
                    min: 64,
                    max: 64,
                }),
            other => {
                let suite = Suite::allowed(other)?;
                Err(Error::WrongSuiteKind {
                    suite: suite.name,
                    expected: SuiteKind::Signature,
                    actual: suite.kind,
                })
            }
        }
    }

    fn verify_message(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Ed25519(key) => <[u8; 64]>::try_from(signature).is_ok_and(|sig| {
                key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig))
                    .is_ok()
            }),
            Self::SlhDsaSha2_256s(key) => slh_dsa::Signature::<Sha2_256s>::try_from(signature)
                .is_ok_and(|sig| key.try_verify_with_context(message, &[], &sig).is_ok()),
        }
    }
}

/// What the verifier requires. The record's own suite is never the expectation: a
/// root that must be dual-signed is verified with the dual suite here.
#[derive(Clone, Copy, Debug)]
pub struct VerifyPolicy<'a> {
    /// The exact record suite required (single or dual).
    pub suite: SuiteId,
    pub purpose: SigPurpose,
    pub signer: &'a [u8],
    pub min_epoch: u64,
}

fn message(transcript: &[u8], subject: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LABEL.len() + transcript.len() + subject.len());
    out.extend_from_slice(LABEL);
    out.extend_from_slice(transcript);
    out.extend_from_slice(subject);
    out
}

/// Signs `subject` under `suite`. `keys` pairs each key with its key id and must
/// hold a key for every suite the record's roster requires.
pub fn sign<R: TryCryptoRng + ?Sized>(
    suite: SuiteId,
    purpose: SigPurpose,
    epoch: u64,
    signer: &[u8],
    subject: &[u8],
    keys: &[(&[u8], &SigningKey)],
    rng: &mut R,
) -> Result<SignatureRecord> {
    let record_suite = Suite::require(
        suite,
        &[SuiteKind::Signature, SuiteKind::DualSignature],
        epoch,
    )?;
    let mut chosen = Vec::new();
    let mut entries = Vec::new();
    for component in roster(record_suite) {
        let spec = Suite::require(component, &[SuiteKind::Signature], epoch)?;
        let (key_id, key) = keys
            .iter()
            .find(|(_, key)| key.suite() == component)
            .ok_or(Error::SigningKeyMissing(spec.name))?;
        chosen.push(*key);
        entries.push(SignatureEntry {
            suite: component,
            key_id: key_id.to_vec(),
            signature: vec![0; spec.signature_len],
        });
    }
    let mut record = SignatureRecord {
        suite,
        purpose,
        epoch,
        signer: signer.to_vec(),
        body: RecordBody::Signatures(entries),
    };
    record.validate()?;
    let message = message(&record.transcript(), subject);
    let RecordBody::Signatures(entries) = &mut record.body else {
        return Err(Error::Primitive("record body"));
    };
    for (entry, key) in entries.iter_mut().zip(chosen) {
        entry.signature = key.sign_message(&message, rng)?;
    }
    record.validate()?;
    Ok(record)
}

impl SignatureRecord {
    /// Verifies the record over `subject` against the verifier's policy. Every
    /// component the policy's suite requires must be present and must verify under a
    /// key from `keys` with the entry's suite and key id. A checkpoint reference never
    /// verifies in v1.
    pub fn verify(
        &self,
        subject: &[u8],
        policy: &VerifyPolicy<'_>,
        keys: &[(&[u8], &VerifyingKey)],
    ) -> Result<()> {
        if self.suite != policy.suite {
            return Err(Error::SuiteNotAccepted(name_of(self.suite)));
        }
        if self.purpose != policy.purpose {
            return Err(Error::SigPurposeMismatch {
                expected: policy.purpose,
                found: self.purpose,
            });
        }
        if self.signer != policy.signer {
            return Err(Error::SignerMismatch);
        }
        if self.epoch < policy.min_epoch {
            return Err(Error::EpochBelowPolicyMinimum {
                epoch: self.epoch,
                min: policy.min_epoch,
            });
        }
        let suite = Suite::require(
            self.suite,
            &[SuiteKind::Signature, SuiteKind::DualSignature],
            self.epoch,
        )?;
        let RecordBody::Signatures(entries) = &self.body else {
            return Err(Error::CheckpointRefUnverified);
        };
        check_roster(suite, entries)?;
        let message = message(&self.transcript(), subject);
        for entry in entries {
            let name = name_of(entry.suite);
            let (_, key) = keys
                .iter()
                .find(|(key_id, key)| {
                    *key_id == entry.key_id.as_slice() && key.suite() == entry.suite
                })
                .ok_or(Error::VerifyingKeyMissing(name))?;
            if !key.verify_message(&message, &entry.signature) {
                return Err(Error::SignatureInvalid(name));
            }
        }
        Ok(())
    }
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests;
