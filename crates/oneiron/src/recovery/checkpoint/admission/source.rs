//! A cold managed restore's source checks, in the contract's order (LC FIX
//! 5384/5385): the artifact read once, whole, from one open file, and
//! checked against the plan before anything opens; the same file then opens
//! for the restore, never its path again.
//!
//! 1. The prelude's engine vault id is the plan's (`source_identity_mismatch`).
//! 2. The key header's data-key commitment is the plan's, which the
//!    delivered key's own is ([`CheckpointKey::from_delivered`]) (`data_key_mismatch`).
//! 3. The kind, then the whole-file BLAKE3 and the snapshot id
//!    (`artifact_kind_mismatch`, `artifact_identity_mismatch`).
//! 4. The signed commitment against the plan's external signer pins alone,
//!    never a signer the artifact names (`signer_untrusted`,
//!    `signature_invalid`).
//! 5. The commitment against the clear parts, then, as the restore opens
//!    it, the manifest, every frame and digest and the image
//!    (`artifact_integrity_invalid`, `codec_invalid`).
//! 6. A registry binding the artifact carries is the plan's registry id's;
//!    one it does not carry passes (`backup_registry_binding_mismatch`).
//!
//! [`CheckpointKey::from_delivered`]: super::super::CheckpointKey::from_delivered

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use oneiron_crypto::backup::{
    ARTIFACT_VERSION_V2, BackupEvidence, RegistryMatch, inspect_backup, verify_with_pins,
};

use super::super::CheckpointSigner;
use super::reason::{Rejected, RestoreAdmissionError, RestoreAdmissionReason as R, RestorePhase};
use super::{SignerTrust, SourceExpectation, VerifiedSource};
use crate::world_keys::refused;
use crate::{Error, Result};

fn codec() -> Error {
    Error::CorruptedIndex("sealed checkpoint artifact")
}

fn check(reason: R, error: Error) -> RestoreAdmissionError {
    Rejected::new(reason, error).at(RestorePhase::SourceCheck)
}

/// The reason a shared-codec failure names.
fn crypto_reason(error: &oneiron_crypto::Error) -> R {
    match error {
        oneiron_crypto::Error::BackupRead(_) => R::StorageIo,
        oneiron_crypto::Error::BackupMalformed(_) => R::CodecInvalid,
        oneiron_crypto::Error::BackupCommitmentMismatch(_) => R::ArtifactIntegrityInvalid,
        oneiron_crypto::Error::SignerMismatch => R::SignerUntrusted,
        _ => R::SignatureInvalid,
    }
}

/// Checks 1 to 5's signed part on the artifact at `path`, read once from
/// the file returned for the restore to open. Its signer is admitted by the
/// plan's pins or, beside them, as one of `delegated`, the signers the
/// vault's mode roots delegated (FIX 968); either way both its signatures
/// are checked the one shared way, against that signer.
pub(super) fn inspect(
    path: &Path,
    expected: &SourceExpectation,
    delegated: &[CheckpointSigner],
) -> std::result::Result<(File, BackupEvidence, SignerTrust), RestoreAdmissionError> {
    let file = File::open(path).map_err(|error| check(R::StorageIo, error.into()))?;
    let evidence = inspect_backup(BufReader::new(&file)).map_err(|error| {
        let reason = crypto_reason(&error);
        check(reason, codec())
    })?;
    // The engine reads version 2 only.
    if evidence.format_version != ARTIFACT_VERSION_V2 {
        return Err(check(R::CodecInvalid, codec()));
    }
    if evidence.engine_vault_id != expected.engine_vault_id {
        return Err(check(
            R::SourceIdentityMismatch,
            refused("the checkpoint is another vault's"),
        ));
    }
    if evidence.key_commitment != expected.data_key_commitment {
        return Err(check(
            R::DataKeyMismatch,
            refused("the checkpoint is sealed under another data key than the plan's"),
        ));
    }
    if evidence.kind != expected.kind {
        return Err(check(
            R::ArtifactKindMismatch,
            refused("the checkpoint is not the kind the plan names"),
        ));
    }
    if evidence.outer_blake3 != expected.artifact_digest || evidence.snapshot != expected.snapshot {
        return Err(check(
            R::ArtifactIdentityMismatch,
            refused("the checkpoint is not the artifact the plan names"),
        ));
    }
    let signer = &evidence.commitment.signer;
    let (pins, trust) = if !expected.signer_pins.contains(signer) && delegated.contains(signer) {
        (std::slice::from_ref(signer), SignerTrust::ModeRootDelegated)
    } else {
        (expected.signer_pins.as_slice(), SignerTrust::Pinned)
    };
    verify_with_pins(&evidence, pins).map_err(|error| {
        let reason = crypto_reason(&error);
        let error = match reason {
            R::SignerUntrusted => refused("the checkpoint's signer is not trusted here"),
            R::SignatureInvalid => refused("the checkpoint's signature does not verify"),
            _ => codec(),
        };
        check(reason, error)
    })?;
    Ok((file, evidence, trust))
}

/// Check 6, once the artifact opened whole.
pub(super) fn registry(
    evidence: &BackupEvidence,
    expected: &SourceExpectation,
) -> std::result::Result<bool, RestoreAdmissionError> {
    match evidence.registry_match(&expected.registry_id) {
        Ok(RegistryMatch::Matches) => Ok(true),
        Ok(RegistryMatch::Absent) => Ok(false),
        Ok(RegistryMatch::Mismatch) => Err(check(
            R::BackupRegistryBindingMismatch,
            refused("the checkpoint is bound to another registry vault than the plan's"),
        )),
        Err(_) => Err(check(R::CodecInvalid, codec())),
    }
}

/// BLAKE3 over the external pin set in canonical order: each signer's
/// install id, Ed25519 key, and length-prefixed SLH-DSA key.
fn pin_set_digest(pins: &[CheckpointSigner]) -> Result<[u8; 32]> {
    let mut sorted: Vec<&CheckpointSigner> = pins.iter().collect();
    sorted
        .sort_by(|a, b| (a.install, a.ed25519, &a.slhdsa).cmp(&(b.install, b.ed25519, &b.slhdsa)));
    sorted.dedup();
    let mut hasher = blake3::Hasher::new_derive_key("oneiron/restore-pin-set/v1");
    for pin in sorted {
        hasher.update(&pin.install);
        hasher.update(&pin.ed25519);
        let len = u32::try_from(pin.slhdsa.len()).map_err(|_| codec())?;
        hasher.update(&len.to_be_bytes());
        hasher.update(&pin.slhdsa);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// What the checks verified, apart from what the plan expected: with what
/// admitted the signer, and the mode-root policy's digest where that was
/// its delegation.
pub(super) fn verified(
    evidence: &BackupEvidence,
    expected: &SourceExpectation,
    checkpoint_id: [u8; 32],
    registry_bound: bool,
    (signer_trust, policy_digest): (SignerTrust, Option<[u8; 32]>),
) -> std::result::Result<VerifiedSource, RestoreAdmissionError> {
    let commitment = &evidence.commitment;
    Ok(VerifiedSource {
        engine_vault_id: evidence.engine_vault_id,
        data_key_commitment: evidence.key_commitment,
        kind: evidence.kind,
        artifact_digest: evidence.outer_blake3,
        artifact_size: evidence.size,
        snapshot: evidence.snapshot,
        checkpoint_id,
        commitment_digest: evidence.commitment_digest,
        sequence: commitment.sequence,
        crypto_epoch: commitment.epoch,
        predecessor: commitment.predecessor,
        created_at: commitment.created_at,
        signer_install: commitment.signer.install,
        pin_set_digest: pin_set_digest(&expected.signer_pins)
            .map_err(|error| check(R::CodecInvalid, error))?,
        signer_trust,
        policy_digest: policy_digest.filter(|_| signer_trust == SignerTrust::ModeRootDelegated),
        registry_bound,
    })
}
