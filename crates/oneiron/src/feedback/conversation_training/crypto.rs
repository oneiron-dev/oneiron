//! The publisher training files' crypto (OF-420): the install signature on
//! what the vault writes (C1, D6), the intake's sealing key (CALLS-5) and
//! the intake's receipt key. No key material reaches the outbox: the vault
//! writes ciphertext, signatures and public keys only.
//!
//! Every chunk is sealed with the envelope escrow seals its capsules with
//! (`oneiron_crypto::seal`, a hybrid X25519 + ML-KEM-1024 capsule to the
//! intake's public key); nothing here adds a primitive. The intake's key is
//! its own: never the escrow key, never one the vault mints or shares.

use ed25519_dalek::{Signature, Signer as _, VerifyingKey};
use getrandom::SysRng;
use oneiron_crypto::{HybridPublicKey, Purpose, SealKey, SealParams, SuiteId, seal};
use oneiron_vault_contract::conversation_training::{
    PieceReceiptV1, TRAINING_RECEIPT_TYPE, TRAINING_SEAL_RECIPIENT, TRAINING_SIGNATURE_SUITE,
    TrainingReceiptV2, TrainingSignatureV2, piece_receipt_signed_message, training_signed_message,
};
use serde::Serialize;

use crate::Vault;
use crate::error::{Error, Result};

use super::lifecycle::TrainingUnavailable;

/// The payload AEAD every chunk is sealed under.
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
/// The KEM of the capsule to the intake.
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
/// The crypto epoch every chunk is sealed at.
const SEAL_EPOCH: u64 = 1;
/// The plaintext bytes one chunk carries at most: the envelope codec's own
/// bound. Chunking splits transport; the text goes whole, in as many chunks
/// as it takes.
const CHUNK_BYTES: usize = oneiron_crypto::MAX_PLAINTEXT_LEN;

/// The intake's sealing key, as the outbox's recipient file holds it
/// (CALLS-5).
pub struct IntakeRecipient {
    key: HybridPublicKey,
    /// The BLAKE3 of the file's bytes, which every offer names.
    key_id: [u8; 32],
}

impl IntakeRecipient {
    /// The key a recipient file's bytes hold.
    ///
    /// # Errors
    /// [`TrainingUnavailable::UnusableIntakeKey`] for bytes that are no
    /// hybrid public key.
    pub fn from_key_file(bytes: &[u8]) -> std::result::Result<Self, TrainingUnavailable> {
        let key = HybridPublicKey::from_bytes(bytes)
            .map_err(|_| TrainingUnavailable::UnusableIntakeKey)?;
        Ok(Self {
            key,
            key_id: *blake3::hash(bytes).as_bytes(),
        })
    }

    /// The BLAKE3 of the recipient file's bytes.
    #[must_use]
    pub const fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }
}

impl std::fmt::Debug for IntakeRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntakeRecipient")
            .field("key_id", &oneiron_vault_contract::hex(&self.key_id))
            .finish_non_exhaustive()
    }
}

/// The intake's Ed25519 receipt keys, as the outbox's receipt key file holds
/// them: what authenticates a receipt. The file is a ring (FIX 6156): the
/// current key's 32 raw bytes, then, while a rotation drains, the previous
/// key's 32. A receipt either key signed verifies, so a rotation strands no
/// receipt the old key signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntakeReceiptKey {
    /// The intake's current receipt key.
    current: VerifyingKey,
    /// The key before it, which the intake drops only once every receipt it
    /// signed is delivered.
    previous: Option<VerifyingKey>,
}

impl IntakeReceiptKey {
    /// The ring a receipt key file's bytes hold: 32 bytes for the current
    /// key alone, 64 for the current key then the previous one.
    ///
    /// # Errors
    /// [`TrainingUnavailable::UnusableReceiptKey`] for any other length, or a
    /// member that is no Ed25519 public key: no ring is taken in part.
    pub fn from_key_file(bytes: &[u8]) -> std::result::Result<Self, TrainingUnavailable> {
        match bytes.len() {
            32 => Ok(Self {
                current: receipt_key_member(bytes)?,
                previous: None,
            }),
            64 => {
                let (current, previous) = bytes.split_at(32);
                Ok(Self {
                    current: receipt_key_member(current)?,
                    previous: Some(receipt_key_member(previous)?),
                })
            }
            _ => Err(TrainingUnavailable::UnusableReceiptKey),
        }
    }

    /// Whether `receipt`, an anonymous window's receipt (TL-6), is signed by
    /// either key of the ring over [`piece_receipt_signed_message`] of its
    /// body. Only the ring's keys are tried: a receipt names no key, and none
    /// a reply carries is ever trusted.
    #[must_use]
    pub fn verify_piece_receipt(&self, receipt: &PieceReceiptV1) -> bool {
        let Some(signature) = signature_of(&receipt.signature) else {
            return false;
        };
        let Ok(message) = piece_receipt_signed_message(&receipt.body) else {
            return false;
        };
        self.members()
            .any(|key| key.verify_strict(&message, &signature).is_ok())
    }

    /// The ring's keys, the current one first.
    fn members(&self) -> impl Iterator<Item = &VerifyingKey> {
        std::iter::once(&self.current).chain(self.previous.as_ref())
    }
}

/// One member of a receipt key ring: 32 bytes that are an Ed25519 public
/// key.
fn receipt_key_member(bytes: &[u8]) -> std::result::Result<VerifyingKey, TrainingUnavailable> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TrainingUnavailable::UnusableReceiptKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| TrainingUnavailable::UnusableReceiptKey)
}

/// An Ed25519 signature spelled as 128 hex characters; `None` for any other
/// text.
fn signature_of(hex: &str) -> Option<Signature> {
    oneiron_vault_contract::from_hex(hex)
        .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
        .map(|bytes| Signature::from_bytes(&bytes))
}

/// C1 (D6): signs `body`, for a file of `file_type`, with this install's
/// machine key over the contract's signed message (its own domain, never an
/// authority transcript). The signature is for the intake's authentication
/// of this install only: the intake checks it, then discards it and the key,
/// and keeps no install identity beside the codes (TRAINING-LINK = C). No
/// account rides on it: in managed mode the supervisor binds its own when it
/// ships, and a self-hosted vault ships through the anonymous window (TL-6),
/// which takes none. `None` before this install has a machine identity.
///
/// # Errors
/// Storage faults, a machine identity whose signer is not loaded, and a body
/// that does not encode.
pub(super) fn sign_training_payload<T: Serialize>(
    vault: &Vault,
    file_type: &str,
    body: &T,
) -> Result<Option<TrainingSignatureV2>> {
    let key = {
        let txn = vault.store.env.read_txn()?;
        crate::identity::read_machine_signing_key_in_txn(vault, &txn)?
    };
    let Some(key) = key else {
        return Ok(None);
    };
    let message = training_signed_message(file_type, body)
        .map_err(|_| Error::InvariantViolation("a training file body does not encode"))?;
    let signature = key.sign(&message);
    Ok(Some(TrainingSignatureV2 {
        suite: TRAINING_SIGNATURE_SUITE.to_owned(),
        public_key: oneiron_vault_contract::hex(key.verifying_key().as_bytes()),
        signature: oneiron_vault_contract::hex(&signature.to_bytes()),
    }))
}

/// Whether `receipt` is signed over its body by a key of the intake's
/// receipt key ring: its suite, the key it names and its strict signature
/// all checked against that one key, the current one or the previous.
pub(super) fn receipt_verifies(key: &IntakeReceiptKey, receipt: &TrainingReceiptV2) -> bool {
    let signed = &receipt.signature;
    if signed.suite != TRAINING_SIGNATURE_SUITE {
        return false;
    }
    let Some(signature) = signature_of(&signed.signature) else {
        return false;
    };
    let Ok(message) = training_signed_message(TRAINING_RECEIPT_TYPE, &receipt.body) else {
        return false;
    };
    key.members().any(|member| {
        signed.public_key == oneiron_vault_contract::hex(member.as_bytes())
            && member.verify_strict(&message, &signature).is_ok()
    })
}

/// Seals `text` to the intake, one envelope per chunk, in part order. Each
/// envelope binds the offer's scope (in the envelope's vault id, so its
/// clear header names no vault), the submission and its part, so no chunk
/// opens as another offer's or another part.
///
/// # Errors
/// A sealing failure; nothing is half sealed.
pub(super) fn seal_training_text(
    recipient: &IntakeRecipient,
    scope: &[u8; 32],
    submission: &[u8; 16],
    text: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let mut sealed = Vec::new();
    for (part, plaintext) in text.chunks(CHUNK_BYTES).enumerate() {
        let part = u32::try_from(part)
            .map_err(|_| Error::ArithmeticOverflow("training offer chunk count"))?;
        let mut key_id = [0; 20];
        key_id[..16].copy_from_slice(submission);
        key_id[16..].copy_from_slice(&part.to_be_bytes());
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::PublisherTrainingOffer,
            epoch: SEAL_EPOCH,
            key_id: &key_id,
            recipient: TRAINING_SEAL_RECIPIENT,
            vault_id: scope,
        };
        let key = SealKey::Hybrid {
            recipient: &recipient.key,
            kem_suite: KEM,
        };
        let envelope = seal(&params, key, plaintext, &mut SysRng)
            .map_err(|_| Error::Refused("sealing a training offer chunk failed".to_owned()))?;
        sealed.push(envelope.to_bytes());
    }
    Ok(sealed)
}
