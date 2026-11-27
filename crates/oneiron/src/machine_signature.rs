//! A machine's own signature on what it states to the owner's other
//! machines over the mesh: the job submit and the job receipt (pass 33),
//! and the organ call receipt (OF-575). One trait holds both halves, so
//! there is one key path: [`MachineSignatures::sign`] signs as this install
//! with its machine key, and [`MachineSignatures::verify`] checks a peer's
//! signature against the machine key its MACHINE row holds in this replica
//! now.
//!
//! The signed bytes are [`machine_signature_transcript`]: a versioned,
//! NUL-terminated domain (the tree's convention, e.g.
//! `oneiron/job-receipt/v1\0`), then the message. The vault's
//! implementation reads the install's machine signing key; a test may
//! implement it with a fixed key.

use crate::EntityId;

/// Why a machine signature could not be made or does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineSignatureError {
    /// This install has no machine signing key: not enrolled, or its
    /// keystore is not attached.
    NoMachineKey,
    /// The statement names another machine as its signer than this
    /// install.
    NotThisMachine { named: EntityId, local: EntityId },
    /// This replica holds no live MACHINE row with a key for `machine`.
    UnknownMachine { machine: EntityId },
    /// The signature is not `machine`'s over these bytes.
    Mismatch { machine: EntityId },
    /// The statement did not encode.
    Encode(String),
    /// The store could not be read.
    Store(String),
}

impl std::fmt::Display for MachineSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMachineKey => write!(f, "this install has no machine signing key"),
            Self::NotThisMachine { named, local } => write!(
                f,
                "the statement names machine {} as its signer, not this install's {}",
                named.to_hex(),
                local.to_hex()
            ),
            Self::UnknownMachine { machine } => {
                write!(f, "no live MACHINE row with a key for {}", machine.to_hex())
            }
            Self::Mismatch { machine } => {
                write!(f, "the signature is not {}'s", machine.to_hex())
            }
            Self::Encode(why) => write!(f, "the signed statement did not encode: {why}"),
            Self::Store(why) => write!(f, "the store could not be read: {why}"),
        }
    }
}

impl std::error::Error for MachineSignatureError {}

/// Signs as this install's machine, and checks the owner's other machines'
/// signatures.
pub trait MachineSignatures: Send + Sync {
    /// This install's machine and its Ed25519 signature over
    /// [`machine_signature_transcript`]`(domain, message)`.
    ///
    /// # Errors
    /// `NoMachineKey`, `Store`.
    fn sign(
        &self,
        domain: &[u8],
        message: &[u8],
    ) -> Result<(EntityId, [u8; 64]), MachineSignatureError>;

    /// `Ok` when `signature` is `machine`'s over
    /// [`machine_signature_transcript`]`(domain, message)`, checked against
    /// the machine key `machine`'s live MACHINE row holds in this replica.
    ///
    /// # Errors
    /// `UnknownMachine`, `Mismatch`, `Store`.
    fn verify(
        &self,
        machine: EntityId,
        domain: &[u8],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), MachineSignatureError>;
}

/// The bytes a machine signature covers: `domain` (versioned and
/// NUL-terminated), then `message`.
#[must_use]
pub fn machine_signature_transcript(domain: &[u8], message: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(domain.len() + message.len());
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(message);
    transcript
}
