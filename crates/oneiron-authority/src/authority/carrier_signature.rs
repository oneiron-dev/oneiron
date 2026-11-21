//! The carrier signature of an act that is stored on its own row, not on the AUTHORITY_LOG
//! (Fable pass 28, DESIGN 3.4).
//!
//! An act of use (a TASK authority fact, for example) records who did it on the row it
//! changes. The machine that ran the door, its carrier, signs that row with its install key.
//! This module holds the one transcript such a signature covers and the one check of it, so
//! no row kind writes its own.
//!
//! The check says only that the key signed these exact bytes. What the key proves (that the
//! machine is one the fold admitted for the act's actor, and that the actor may make the act)
//! is the judge's answer in `oneiron::authority`, not this module's. A log act keeps its own
//! entry transcript and `verify_entry_signatures`; nothing here applies to it.

use crate::entity_id::EntityId;

use super::{AUTHORITY_HASH_LEN, AuthorityVaultId, strong_ed25519_verified_once};

/// The tag every carrier transcript starts with. No other transcript an install key signs
/// starts with it, so a carrier signature never stands for another protocol's signature,
/// whatever domain a row kind picks.
pub const CARRIER_TRANSCRIPT_TAG: &[u8] = b"oneiron/carrier-act/v1";

/// The machine that carried an act stored on a row, and its install key's signature over
/// that row's [`carrier_transcript`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierSignature {
    /// The MACHINE entity that ran the door.
    pub machine: EntityId,
    /// The machine's Ed25519 install key.
    pub key: [u8; 32],
    /// The key's signature over the row's carrier transcript.
    pub signature: [u8; 64],
}

/// The bytes a carrier signs for one row: [`CARRIER_TRANSCRIPT_TAG`], the row kind's
/// `domain`, the vault, the row's id, the carrying machine, and the BLAKE3 digest of the
/// row's canonical body without its [`CarrierSignature`].
///
/// `domain` is a constant per row kind and versions its body, for example
/// `b"oneiron/task-fact/v2"`. Every part after it has a fixed length, so two transcripts
/// are equal only when every part is.
#[must_use]
pub fn carrier_transcript(
    domain: &[u8],
    vault: &AuthorityVaultId,
    row: &EntityId,
    machine: &EntityId,
    body: &[u8],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(
        CARRIER_TRANSCRIPT_TAG.len() + domain.len() + AUTHORITY_HASH_LEN + 16 + 16 + 32,
    );
    transcript.extend_from_slice(CARRIER_TRANSCRIPT_TAG);
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(vault);
    transcript.extend_from_slice(row.as_bytes());
    transcript.extend_from_slice(machine.as_bytes());
    transcript.extend_from_slice(blake3::hash(body).as_bytes());
    transcript
}

/// Whether `signature` is its key's signature over the [`carrier_transcript`] of this row,
/// carried by `signature.machine`. A weak key never verifies. A success on exactly these
/// bytes is remembered, so a reader pays for each row once (FIX 21959).
#[must_use]
pub fn carrier_signature_verifies(
    signature: &CarrierSignature,
    domain: &[u8],
    vault: &AuthorityVaultId,
    row: &EntityId,
    body: &[u8],
) -> bool {
    let transcript = carrier_transcript(domain, vault, row, &signature.machine, body);
    strong_ed25519_verified_once(&signature.key, &transcript, &signature.signature)
}
