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
//! install trusts as the owner's own device signs one. A live machine of the
//! vault in any other role the owner answered (a hosted node, an execution
//! node, a rented, work or school machine) signs an archive that is not his.
//! An unanswered install's key, like an unprofiled install's, proves nothing.

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use super::WholeVaultDocumentManifest;
use super::export_authority::hex_lower;
use crate::authority::{AuthorityFold, owner_act_signer_admits};
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
    /// A machine this install trusts as the owner's own device signed it.
    OwnerDevice,
    /// A live machine of this vault signed it, in a role the owner answered
    /// that is not his own device here.
    OtherMachine,
    /// No signature, or none this vault can tie to a machine of its own.
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

/// Judges `manifest`'s provenance on `fold`, this vault's own read-only fold
/// whose vault id is `vault_id`.
///
/// The key must stand as its machine here ([`AuthorityFold::machine_proof_key`]:
/// the trusted identity's key under this install's pin, else a live roster
/// revision's in an answered role) and pass the one carrier rule
/// ([`owner_act_signer_admits`]: a live machine no chain removed, never a
/// roster key), and the signature must verify. Then the machine is the
/// owner's own device exactly when this install trusts it
/// ([`AuthorityFold::trusted_machine`]: live, and his explicit `Yours`).
/// Anything that does not parse or verify reads as unsigned.
pub(crate) fn archive_signer(
    fold: &AuthorityFold,
    vault_id: &[u8; 32],
    manifest: &WholeVaultDocumentManifest,
) -> ArchiveSigner {
    // RED SEAM (not for merge): main's verdict, whatever the signature.
    if manifest.provenance.is_some() {
        return ArchiveSigner::Unproven;
    }
    let Some(provenance) = manifest.provenance.as_ref() else {
        return ArchiveSigner::Unproven;
    };
    let (Some(machine), Some(key), Some(signature)) = (
        lower_hex::<16>(&provenance.machine).and_then(|bytes| EntityId::from_bytes(bytes).ok()),
        lower_hex::<32>(&provenance.machine_key),
        lower_hex::<64>(&provenance.signature),
    ) else {
        return ArchiveSigner::Unproven;
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
        ArchiveSigner::Unproven
    } else if fold.trusted_machine(machine).is_some() {
        ArchiveSigner::OwnerDevice
    } else {
        ArchiveSigner::OtherMachine
    }
}

/// `N` bytes of lowercase hex, the one spelling an archive writes.
fn lower_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    crate::deletion::parse_hex::<N>(text)
}
