//! A sealed backup's checkpoint fact (FIX 7326): its engine vault id, the
//! full BLAKE3 of its canonical image (the checkpoint id a restore compares),
//! its commitment digest, the BLAKE3 of its every byte and its size, signed
//! once the artifact is complete with the keys that signed its commitment. It
//! travels beside the artifact, never in it, so a host that never opens a
//! vault learns the artifact's checkpoint id from its pinned signer.
//!
//! The signed subject is its own domain, so a fact's signature is never a
//! commitment's, nor a commitment's a fact's (a commitment's MessagePack
//! starts with a map byte, a subject with the domain's length, `0x21`):
//!
//! ```text
//! subject  u8 33 ‖ "oneiron/backup-checkpoint-fact/v1" ‖ u16be 1
//!          ‖ engine vault id (32) ‖ checkpoint id (32)
//!          ‖ commitment digest (32) ‖ outer BLAKE3 (32) ‖ u64be size
//! file     "ONCF" ‖ u16be 1 ‖ u32be n ‖ subject (n) ‖ u32be n ‖ signature record (n)
//! ```
//!
//! Both are read strictly: exact domain, version and lengths, nothing after
//! the record.

use super::commitment::{CheckpointSigner, MAX_SIGNED_FRAME, verify_commitment_signature};
use super::inspect::{BackupEvidence, verify_with_pins};
use crate::codec::{Reader, check_len, put_lp8};
use crate::error::{Error, Result};
use crate::record::SignatureRecord;

/// The signed subject's domain.
pub const CHECKPOINT_FACT_DOMAIN: &[u8] = b"oneiron/backup-checkpoint-fact/v1";
/// The signed subject's version.
pub const CHECKPOINT_FACT_VERSION: u16 = 1;
/// The fact file's magic.
pub const CHECKPOINT_FACT_MAGIC: &[u8; 4] = b"ONCF";
/// The fact file's encoding version.
pub const CHECKPOINT_FACT_FILE_VERSION: u16 = 1;
/// The signed subject's length: the domain's length byte and bytes, the
/// version, four 32-byte digests and the size.
pub const CHECKPOINT_FACT_SUBJECT_LEN: usize = 1 + CHECKPOINT_FACT_DOMAIN.len() + 2 + 4 * 32 + 8;

/// What one sealed backup is, as its signer says once it is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointFact {
    /// The engine's vault id.
    pub engine_vault_id: [u8; 32],
    /// BLAKE3 of the canonical image the artifact seals: its checkpoint id.
    pub checkpoint_id: [u8; 32],
    /// BLAKE3 of the artifact's commitment bytes.
    pub commitment_digest: [u8; 32],
    /// BLAKE3 of the artifact's every byte.
    pub outer_blake3: [u8; 32],
    /// The artifact's length in bytes.
    pub size: u64,
}

impl CheckpointFact {
    /// The exact bytes that are signed.
    pub fn subject(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHECKPOINT_FACT_SUBJECT_LEN);
        put_lp8(&mut out, CHECKPOINT_FACT_DOMAIN);
        out.extend_from_slice(&CHECKPOINT_FACT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.engine_vault_id);
        out.extend_from_slice(&self.checkpoint_id);
        out.extend_from_slice(&self.commitment_digest);
        out.extend_from_slice(&self.outer_blake3);
        out.extend_from_slice(&self.size.to_be_bytes());
        out
    }

    /// Reads a signed subject: its domain and version exactly, every field,
    /// nothing after them.
    fn from_subject(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let domain = r.lp8(
            "checkpoint fact domain",
            CHECKPOINT_FACT_DOMAIN.len(),
            CHECKPOINT_FACT_DOMAIN.len(),
        )?;
        if domain != CHECKPOINT_FACT_DOMAIN {
            return Err(Error::BackupMalformed("checkpoint fact domain"));
        }
        let version = r.u16("checkpoint fact version")?;
        if version != CHECKPOINT_FACT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let fact = Self {
            engine_vault_id: r.array("checkpoint fact vault id")?,
            checkpoint_id: r.array("checkpoint fact checkpoint id")?,
            commitment_digest: r.array("checkpoint fact commitment digest")?,
            outer_blake3: r.array("checkpoint fact outer digest")?,
            size: r.u64("checkpoint fact size")?,
        };
        r.finish()?;
        Ok(fact)
    }
}

/// A checkpoint fact and the signature record over its subject, as its file
/// holds them. Nothing in it is trusted until [`verify_checkpoint_fact`]
/// passes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpointFact {
    fact: CheckpointFact,
    signature: Vec<u8>,
}

impl SignedCheckpointFact {
    /// `fact` with `signature`, the signature record's bytes over its
    /// subject. Refused when the record does not parse or is longer than a
    /// reader takes; nothing is verified.
    pub fn new(fact: CheckpointFact, signature: Vec<u8>) -> Result<Self> {
        check_len(
            "checkpoint fact signature",
            signature.len(),
            1,
            MAX_SIGNED_FRAME as usize,
        )?;
        SignatureRecord::parse(&signature)?;
        Ok(Self { fact, signature })
    }

    /// The fact file's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let subject = self.fact.subject();
        let mut out = Vec::with_capacity(
            CHECKPOINT_FACT_MAGIC.len() + 10 + subject.len() + self.signature.len(),
        );
        out.extend_from_slice(CHECKPOINT_FACT_MAGIC);
        out.extend_from_slice(&CHECKPOINT_FACT_FILE_VERSION.to_be_bytes());
        put_lp32(&mut out, &subject);
        put_lp32(&mut out, &self.signature);
        out
    }

    /// Reads a fact file: its magic and version, the subject at its exact
    /// length, a signature record that parses, nothing after it.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take(CHECKPOINT_FACT_MAGIC.len(), "checkpoint fact magic")? != CHECKPOINT_FACT_MAGIC {
            return Err(Error::BadMagic {
                expected: "checkpoint fact",
            });
        }
        let version = r.u16("checkpoint fact file version")?;
        if version != CHECKPOINT_FACT_FILE_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let subject = lp32(
            &mut r,
            "checkpoint fact subject",
            CHECKPOINT_FACT_SUBJECT_LEN,
            CHECKPOINT_FACT_SUBJECT_LEN,
        )?;
        let fact = CheckpointFact::from_subject(subject)?;
        let signature = lp32(
            &mut r,
            "checkpoint fact signature",
            1,
            MAX_SIGNED_FRAME as usize,
        )?;
        r.finish()?;
        Self::new(fact, signature.to_vec())
    }
}

/// Checks `signed` against the artifact `evidence` describes and the signer
/// `pin` trusted from outside both: the artifact is `pin`'s
/// ([`verify_with_pins`] with `pin` alone), the fact's record is `pin`'s over
/// its subject (the dual suite, `BatchCheckpoint`, the signature epoch, its
/// install id and both keys), and the fact names the artifact's vault id,
/// commitment digest, outer BLAKE3 and size. Returns the fact, its checkpoint
/// id now the signer's. The caller read `evidence` from the bytes it holds;
/// nothing here enrolls a signer or reads a key.
pub fn verify_checkpoint_fact(
    signed: &SignedCheckpointFact,
    evidence: &BackupEvidence,
    pin: &CheckpointSigner,
) -> Result<CheckpointFact> {
    verify_with_pins(evidence, std::slice::from_ref(pin))?;
    let fact = signed.fact;
    verify_commitment_signature(&fact.subject(), &signed.signature, pin)?;
    let checks: [(bool, &'static str); 4] = [
        (
            fact.engine_vault_id == evidence.engine_vault_id,
            "fact vault id",
        ),
        (
            fact.commitment_digest == evidence.commitment_digest,
            "fact commitment digest",
        ),
        (
            fact.outer_blake3 == evidence.outer_blake3,
            "fact outer digest",
        ),
        (fact.size == evidence.size, "fact size"),
    ];
    match checks.into_iter().find(|(holds, _)| !holds) {
        Some((_, field)) => Err(Error::BackupCommitmentMismatch(field)),
        None => Ok(fact),
    }
}

/// Appends a `u32be` length prefix and the bytes; both are bounded far below
/// `u32::MAX`.
fn put_lp32(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes[..len as usize]);
}

/// A `u32be` length prefix followed by that many bytes, length in `min..=max`.
fn lp32<'a>(r: &mut Reader<'a>, field: &'static str, min: usize, max: usize) -> Result<&'a [u8]> {
    let len = r.u32(field)? as usize;
    check_len(field, len, min, max)?;
    r.take(len, field)
}
