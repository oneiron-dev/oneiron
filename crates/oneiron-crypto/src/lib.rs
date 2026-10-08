//! The oneiron crypto contract: one versioned format for sealed envelopes and
//! signature records, a suite table that fails closed, and a strict parser.
//!
//! This crate depends on nothing in `oneiron`. It builds no vault encryption; the
//! engine lanes that need encryption (DEK custody, the vault at rest, backups,
//! signatures, capsules) call into it. The byte format, the suite table and the
//! key schedule are specified in `README.md` next to this crate.
//!
//! Every refusal is a typed [`Error`]. No error, `Debug` or `Display` output carries
//! key bytes or plaintext; secret types zeroize on drop.

mod codec;
mod envelope;
mod error;
mod keys;
mod nonce;
mod record;
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod stack_probe;
mod suite;

pub use crate::envelope::{
    Envelope, Header, Kdf, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, WrapParams, WrapType,
    seal,
};
pub use crate::error::{Error, Result};
pub use crate::keys::{
    Argon2Cost, HYBRID_PUBLIC_KEY_LEN, HybridPublicKey, HybridSecretKey, Kek,
    MLKEM1024_CIPHERTEXT_LEN, MLKEM1024_ENCAPSULATION_KEY_LEN, Passphrase, RecoverySecret,
};
pub use crate::nonce::NonceLedger;
pub use crate::record::{
    CheckpointRef, RecordBody, SigPurpose, SignatureEntry, SignatureRecord, SigningKey,
    VerifyPolicy, VerifyingKey, sign,
};
pub use crate::suite::{Suite, SuiteId, SuiteKind, SuiteStatus, suite_table};

/// Upper bound on any identifier field (key id, recipient id, vault id, signer id).
pub const MAX_ID_LEN: usize = 64;
/// Upper bound on the plaintext one envelope seals. Larger artifacts are split by
/// their owner into several envelopes.
pub const MAX_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;
/// AEAD tag length of every allowed AEAD suite.
pub const TAG_LEN: usize = 16;
