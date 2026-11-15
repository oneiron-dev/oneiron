//! The archive's provenance signature (L2-23, canon ARCH-0027
//! #manifest-provenance-built): the exporting install signs the archive's
//! contents manifest with its machine key, and the vault it is offered to
//! judges that key on its own authority fold.
//!
//! The signature covers [`WholeVaultDocumentManifest`], which binds every
//! member by length and BLAKE3, never the storage manifest alone: a storage
//! manifest names no content, so a signature over it could be lifted onto
//! another archive's rows.
//!
//! Whose archive counts as the owner's own (Engine RULING L2-23-SIGNER = B,
//! sharpened by the lead's HOSTED-CARRIER-FIRST-PIN = D, "the yes must be
//! provably his; a carrier's word is not him saying so"): only a machine this
//! install trusts as the owner's own device signs one, and only while that
//! `Yours` is his own signature: his pinned recovery root's mark, or on a
//! vault that is not hosted an owner-held roster key's revision. A `Yours`
//! that rests on a carrier's act (any linked machine, the signer itself
//! included, carries one) proves no more than an unsigned archive. A live
//! machine of the vault in any other role the owner answered (a hosted node,
//! an execution node, a rented, work or school machine) signs an archive that
//! is not his. An unanswered install's key, like an unprofiled install's,
//! proves nothing.
//!
//! The fold says who signed each revision, but a checkpoint image the host
//! attests supplies its revisions with their signers, and this install never
//! folded them (Sol r2 P1). So the owner's `Yours` proves an archive only by
//! the signed row it names, held here: a host can withhold a row, never sign
//! one as the owner's key.

use ed25519_dalek::Signer;
use oneiron_authority::authority::verify_entry_signatures;
use serde::{Deserialize, Serialize};

use super::WholeVaultDocumentManifest;
use super::export_authority::hex_lower;
use crate::Vault;
use crate::authority::{
    AuthorityFold, AuthorityOp, MachineRevision, authority_entry_hash,
    authority_log_entity_id_from_hash, owner_act_signer_admits,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::identity::InstallSigner;

/// Domain separator of the archive provenance transcript.
pub const ARCHIVE_PROVENANCE_DOMAIN: &[u8] = b"oneiron/archive-provenance/v1\0";

/// Who signed an archive's contents manifest, and with which key. Each field
/// is lowercase hex: the machine id (32 chars), its Ed25519 machine key (64)
/// and the signature over [`archive_provenance_transcript`] (128).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveProvenance {
    pub machine: String,
    pub machine_key: String,
    pub signature: String,
}

/// What an archive's provenance proves to the vault that judges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveSigner {
    /// A machine this install trusts as the owner's own device, by his own
    /// signature, signed it.
    OwnerDevice,
    /// A live machine of this vault signed it, in a role the owner answered
    /// that is not his own device here.
    OtherMachine,
    /// No signature, none this vault can tie to a machine of its own, or one
    /// by a machine whose `Yours` here is a carrier's word or rests on no
    /// owner-signed row this install holds.
    Unproven,
}

/// The bytes an archive's machine key signs: the domain, the vault id, the
/// machine id, the machine key, and BLAKE3 over the manifest as it encodes
/// with no provenance. The digest is taken over the re-encoded parsed
/// manifest, so the archive's own formatting does not matter.
///
/// # Errors
/// [`Error::InvariantViolation`] when the manifest does not encode.
pub fn archive_provenance_transcript(
    vault_id: &[u8; 32],
    machine: EntityId,
    machine_key: &[u8; 32],
    manifest: &WholeVaultDocumentManifest,
) -> Result<Vec<u8>> {
    let unsigned = WholeVaultDocumentManifest {
        provenance: None,
        ..manifest.clone()
    };
    let encoded = serde_json::to_vec(&unsigned)
        .map_err(|_| Error::InvariantViolation("archive manifest serialization failed"))?;
    let mut transcript = Vec::with_capacity(ARCHIVE_PROVENANCE_DOMAIN.len() + 32 + 16 + 32 + 32);
    transcript.extend_from_slice(ARCHIVE_PROVENANCE_DOMAIN);
    transcript.extend_from_slice(vault_id);
    transcript.extend_from_slice(machine.as_bytes());
    transcript.extend_from_slice(machine_key);
    transcript.extend_from_slice(blake3::hash(&encoded).as_bytes());
    Ok(transcript)
}

/// Signs `manifest` with this install's machine key, once its member and
/// file lists are final. An archive whose storage manifest states no vault
/// id has nothing to be verified against and goes out unsigned, as the
/// export never refuses (ARCH-0052 P6).
pub(crate) fn sign_archive_manifest(
    signer: &InstallSigner,
    manifest: &mut WholeVaultDocumentManifest,
) -> Result<()> {
    let Some(authority) = manifest.storage.authority() else {
        return Ok(());
    };
    let vault_id = authority.parse_identity()?.vault_id;
    let machine_key = signer.machine_key.verifying_key().to_bytes();
    let transcript =
        archive_provenance_transcript(&vault_id, signer.machine, &machine_key, manifest)?;
    manifest.provenance = Some(ArchiveProvenance {
        machine: signer.machine.to_hex(),
        machine_key: hex_lower(&machine_key),
        signature: hex_lower(&signer.machine_key.sign(&transcript).to_bytes()),
    });
    Ok(())
}

/// Judges `manifest`'s provenance on `fold`, the read-only fold of `vault`
/// whose vault id is `vault_id`.
///
/// The key must stand as its machine here ([`AuthorityFold::machine_proof_key`]:
/// the trusted identity's key under this install's pin, else a live roster
/// revision's in an answered role) and pass the one carrier rule
/// ([`owner_act_signer_admits`]: a live machine no chain removed, never a
/// roster key), and the signature must verify. Then the machine is the
/// owner's own device exactly when this install trusts it as his explicit
/// `Yours` by his own signature
/// ([`AuthorityFold::trusted_yours_revision`]) and holds the row of that
/// signature ([`owner_signed_row_held`]). A `Yours` carried by a machine's
/// install key is a carrier's word (Sol r1 P1: a hosted node can carry an
/// owner answer for itself), so it reads as unsigned, as does a `Yours`
/// whose row this install does not hold, and anything that does not parse
/// or verify.
///
/// # Errors
/// A store read of the signature's row fails.
pub(crate) fn archive_signer(
    vault: &Vault,
    fold: &AuthorityFold,
    vault_id: &[u8; 32],
    manifest: &WholeVaultDocumentManifest,
) -> Result<ArchiveSigner> {
    let Some(provenance) = manifest.provenance.as_ref() else {
        return Ok(ArchiveSigner::Unproven);
    };
    let (Some(machine), Some(key), Some(signature)) = (
        lower_hex::<16>(&provenance.machine).and_then(|bytes| EntityId::from_bytes(bytes).ok()),
        lower_hex::<32>(&provenance.machine_key),
        lower_hex::<64>(&provenance.signature),
    ) else {
        return Ok(ArchiveSigner::Unproven);
    };
    let stands = fold.machine_proof_key(machine) == Some(key)
        && owner_act_signer_admits(fold.machine(machine), &fold.roster, &key)
        && archive_provenance_transcript(vault_id, machine, &key, manifest).is_ok_and(
            |transcript| {
                oneiron_authority::authority::strong_ed25519_verified_once(
                    &key,
                    &transcript,
                    &signature,
                )
            },
        );
    if !stands {
        return Ok(ArchiveSigner::Unproven);
    }
    let hosted = vault.privacy_posture() == crate::HostingPrivacyPosture::Hosted;
    let Some((revision, owner_signed)) = fold.trusted_yours_revision(machine, hosted) else {
        return Ok(ArchiveSigner::OtherMachine);
    };
    Ok(
        if owner_signed && owner_signed_row_held(vault, revision, machine, &key)? {
            ArchiveSigner::OwnerDevice
        } else {
            ArchiveSigner::Unproven
        },
    )
}

/// Whether `vault` holds the row `revision` stands by as the signature the
/// fold says it is: the AUTHORITY_LOG row at [`MachineRevision::entry`],
/// with that hash, a valid shape and signatures, the revision's signer as
/// its primary signer, and a machine profile equal to the revision's, which
/// names `machine` and `key`. A row this install does not hold, and an entry
/// whose id names a row of another kind, prove nothing (Sol r2 P1: a
/// checkpoint image the host attests can carry a revision no owner key
/// signed, under any entry hash).
///
/// # Errors
/// The store read fails, or a stored row there no longer decodes.
fn owner_signed_row_held(
    vault: &Vault,
    revision: &MachineRevision,
    machine: EntityId,
    key: &[u8; 32],
) -> Result<bool> {
    let Ok(id) = authority_log_entity_id_from_hash(&revision.entry) else {
        return Ok(false);
    };
    let entry = match vault.get_authority_log_entry(&id) {
        Ok(Some(entry)) => entry,
        Ok(None) | Err(Error::InvalidEntityType(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(revision.profile.machine == machine
        && revision.profile.machine_key == *key
        && authority_entry_hash(&entry)? == revision.entry
        && entry.validate_shape().is_ok()
        && verify_entry_signatures(&entry).is_ok()
        && *entry.signer_key() == revision.signer
        && matches!(&entry.op, AuthorityOp::MachineProfile(profile) if *profile == revision.profile))
}

/// `N` bytes of lowercase hex, the one spelling an archive writes.
fn lower_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    crate::deletion::parse_hex::<N>(text)
}
