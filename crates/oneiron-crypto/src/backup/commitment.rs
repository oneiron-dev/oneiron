//! The clear commitment every sealed artifact carries, its digest, and the
//! check of its dual Ed25519 + SLH-DSA-SHA2-256s signature against a signer the
//! reader trusts from outside the artifact (moved from the engine's
//! `recovery::checkpoint::commitment`). Which signers to trust stays the
//! reader's: an artifact never names its own trust.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::record::{SigPurpose, SignatureRecord, VerifyPolicy, VerifyingKey};
use crate::suite::SuiteId;

/// The commitment version the engine writes: the artifact's prelude version,
/// with the registry binding and the public key and custody refs signed.
pub const COMMITMENT_VERSION: u16 = super::ARTIFACT_VERSION_V2;
/// The commitment version written with a version 1 prelude, read only for a
/// host that still holds artifacts written before version 2.
pub const COMMITMENT_VERSION_V1: u16 = super::ARTIFACT_VERSION_V1;
/// The signature suite every commitment is signed with.
pub const CHECKPOINT_SIGNATURE_SUITE: SuiteId = SuiteId::SIG_DUAL_ED25519_SLHDSA_SHA2_256S_V1;
/// The crypto epoch every commitment and its signature are made at.
pub const CHECKPOINT_SIGNATURE_EPOCH: u64 = 1;
/// The Ed25519 component's key id in the signature record.
pub const ED25519_KEY_ID: &[u8] = b"ed25519";
/// The SLH-DSA-SHA2-256s component's key id in the signature record.
pub const SLHDSA_KEY_ID: &[u8] = b"slh-dsa-sha2-256s";
/// Longest commitment or signature record a reader takes.
pub const MAX_SIGNED_FRAME: u64 = 128 * 1024;

/// One install's checkpoint signer for one vault: its install id and both
/// public keys. A host trusts its checkpoints by pinning it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSigner {
    pub install: [u8; 16],
    pub ed25519: [u8; 32],
    /// The SLH-DSA-SHA2-256s public key, 64 bytes.
    pub slhdsa: Vec<u8>,
}

/// Where an artifact's exterior key custody stood when its snapshot was taken:
/// the custody log's vault and namespace, writer epoch, sequence and tip. A
/// position, never a key or an id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyRef {
    pub vault: [u8; 32],
    pub namespace: [u8; 16],
    pub epoch: u64,
    pub seq: u64,
    pub tip: [u8; 32],
}

/// What one artifact's signature covers. Named MessagePack. Version 2 adds
/// the four optional fields at the end, which version 1 never carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub version: u16,
    /// The engine's vault id.
    pub vault_id: [u8; 32],
    /// The [`super::ArtifactKind`] wire byte.
    pub kind: u8,
    pub snapshot: [u8; 32],
    pub sequence: u64,
    pub epoch: u64,
    /// The previous checkpoint's commitment digest; `None` for the first.
    pub predecessor: Option<[u8; 32]>,
    /// BLAKE3 of the sealed manifest's envelope.
    pub manifest: [u8; 32],
    pub created_at: u64,
    pub signer: CheckpointSigner,
    /// The prelude's registry binding, signed (FIX 5826); `None` where the
    /// artifact was written with no registry id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_binding: Option<[u8; 32]>,
    /// The commitment naming the vault data key the artifact is sealed under,
    /// as its key header carries it. Always set in version 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_commitment: Option<[u8; 32]>,
    /// BLAKE3 of the clear key header's exact bytes. Always set in version 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_header_blake3: Option<[u8; 32]>,
    /// Where the vault's exterior key custody stood at the snapshot; `None`
    /// where the vault never published custody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<CustodyRef>,
}

impl Commitment {
    /// The exact bytes that are signed, and whose BLAKE3 is the commitment's
    /// digest ([`commitment_digest`]).
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|_| Error::BackupMalformed("commitment"))
    }

    /// Reads a commitment's bytes, of either version, each with its own
    /// fields only. Nothing in it is trusted until its signature verifies
    /// against a signer the reader pinned.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let commitment: Self =
            rmp_serde::from_slice(bytes).map_err(|_| Error::BackupMalformed("commitment"))?;
        let v2_refs = commitment.key_commitment.is_some() && commitment.key_header_blake3.is_some();
        let v1_shape = commitment.registry_binding.is_none()
            && commitment.key_commitment.is_none()
            && commitment.key_header_blake3.is_none()
            && commitment.custody_ref.is_none();
        match commitment.version {
            COMMITMENT_VERSION if v2_refs => Ok(commitment),
            COMMITMENT_VERSION_V1 if v1_shape => Ok(commitment),
            COMMITMENT_VERSION | COMMITMENT_VERSION_V1 => {
                Err(Error::BackupMalformed("commitment fields"))
            }
            other => Err(Error::UnsupportedVersion(other)),
        }
    }
}

/// The commitment's digest: BLAKE3 of its exact bytes. The next checkpoint names
/// it as its predecessor.
pub fn commitment_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Verifies `record`, the signature record over the commitment `bytes`, as
/// `signer`'s: the dual suite, `BatchCheckpoint`, the signature epoch, the
/// signer's install id, and both component signatures under its two keys. The
/// caller has decided to trust `signer`.
pub fn verify_commitment_signature(
    bytes: &[u8],
    record: &[u8],
    signer: &CheckpointSigner,
) -> Result<()> {
    let ed25519 = VerifyingKey::from_bytes(SuiteId::SIG_ED25519_V1, &signer.ed25519)?;
    let slhdsa = VerifyingKey::from_bytes(SuiteId::SIG_SLHDSA_SHA2_256S_V1, &signer.slhdsa)?;
    SignatureRecord::parse(record)?.verify(
        bytes,
        &VerifyPolicy {
            suite: CHECKPOINT_SIGNATURE_SUITE,
            purpose: SigPurpose::BatchCheckpoint,
            signer: &signer.install,
            min_epoch: CHECKPOINT_SIGNATURE_EPOCH,
        },
        &[(ED25519_KEY_ID, &ed25519), (SLHDSA_KEY_ID, &slhdsa)],
    )
}
