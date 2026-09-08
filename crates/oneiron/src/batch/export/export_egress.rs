//! Whole-vault manifest egress doors and the Vault export surface.
use std::path::{Path, PathBuf};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::export_authority::{
    NO_LOCAL_AUTHORITY_ROOT, VaultImportReceipt, authority_manifest_for_vault,
    classify_vault_import_manifest, validate_export_vault_label,
};
use super::export_manifest::{
    ExportManifest, ExportManifestArtifact, ExportSecretsNulledManifest,
    whole_vault_export_manifest_artifact,
};

/// THE WHOLE-VAULT EXPORT EGRESS DOOR (ARCH-0052 P6, owner ruling
/// R-20260807-06).
///
/// One of the two surviving off-record egress doors, and the ONLY off-record
/// question the export path asks. `true` means the row belongs to a live
/// session overlay and is SKIPPED; export itself always runs.
///
/// Export used to REFUSE outright while any session was open, because base
/// carried fenced session rows an artifact could ship. It no longer does:
/// session content lives only in the overlay, so the artifact cannot contain it
/// and a refusal would only punish the user for having a room open. What CAN
/// appear in an enumeration is an id — an overlay member reachable through a
/// composed view — so the door skips ids, never refuses.
///
/// A base write commissioned during a live session (an on-record write after a
/// mode flip, or a P5 promote) is NOT an overlay member, so it exports
/// normally. That asymmetry is the whole point of the predicate: it asks about
/// membership in a room, not about whether a room exists.
///
/// The whole-vault ROW enumerator is OF-222 / ONE-1240 and does not exist yet.
/// When it lands, its sole entity-row loop calls THIS function and nothing
/// else — no second predicate, no fences-present fast path, no scrub.
pub fn whole_vault_export_excludes_entity(vault: &Vault, id: &EntityId) -> Result<bool> {
    vault.store.off_record_sessions.contains_entity(id)
}

/// Whether any artifact in `artifacts` carries secret taint refs.
///
/// STATE-INDEPENDENT on purpose: `TaintedLive` exhaust is nulled exactly as
/// `TaintedStale` exhaust is. An export leaves this vault; the honest
/// question at the egress door is "did a secret go into making this", and
/// the answer does not improve because the secret has not rotated yet.
/// That also keeps the manifest reproducible — a bundle does not change
/// shape merely because someone rotated a key between two exports.
pub fn export_bundle_carries_tainted_exhaust(
    vault: &Vault,
    artifacts: &[EntityId],
) -> Result<bool> {
    for id in artifacts {
        if !vault.artifact_taint_refs(id)?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Narrows a caller's `secrets_nulled` declaration for the bundle it will
/// describe: tainted exhaust in the bundle FORCES the structural
/// placeholder, and touches nothing else.
///
/// One direction only. This can turn the placeholder flag on; it can never
/// turn a caller's flag off, so a redacted export stays redacted.
pub fn secrets_nulled_for_export_bundle(
    vault: &Vault,
    secrets_nulled: ExportSecretsNulledManifest,
    artifacts: &[EntityId],
) -> Result<ExportSecretsNulledManifest> {
    if export_bundle_carries_tainted_exhaust(vault, artifacts)? {
        return Ok(secrets_nulled.with_structural_placeholders());
    }
    Ok(secrets_nulled)
}

/// Builds a whole-vault export manifest for a bundle whose artifacts are
/// known, flipping the manifest through [`ExportManifest::from_secrets_nulled`]
/// when the bundle carries secret-tainted exhaust (SECRET-04, ONE-1922).
///
/// The manifest and the bundle cannot disagree: the same
/// [`secrets_nulled_for_export_bundle`] answer that nulls the exhaust is the
/// one stamped into the manifest that describes it.
pub fn whole_vault_export_manifest_artifact_for_bundle(
    vault: &Vault,
    secrets_nulled: ExportSecretsNulledManifest,
    artifacts: &[EntityId],
) -> Result<ExportManifestArtifact> {
    let secrets_nulled = secrets_nulled_for_export_bundle(vault, secrets_nulled, artifacts)?;
    whole_vault_export_manifest_artifact_for_vault(vault, secrets_nulled)
}

/// Builds a whole-vault export manifest for a vault handle.
///
/// Runs unconditionally: the manifest describes the vault's SHAPE (serializer,
/// ABI, DB manifest), which no session can taint, and per-row exclusion is
/// [`whole_vault_export_excludes_entity`]'s job at the enumeration door.
pub fn whole_vault_export_manifest_artifact_for_vault(
    vault: &Vault,
    secrets_nulled: ExportSecretsNulledManifest,
) -> Result<ExportManifestArtifact> {
    whole_vault_export_manifest_artifact_for_vault_with_label(vault, secrets_nulled, None)
}

/// Builds a whole-vault export manifest carrying an owner-supplied label.
///
/// The label is a hint for the human reading a pile of artifacts later; it is
/// validated here so a malformed one fails at export rather than at the import
/// that needed it.
pub fn whole_vault_export_manifest_artifact_for_vault_with_label(
    vault: &Vault,
    secrets_nulled: ExportSecretsNulledManifest,
    vault_label: Option<&str>,
) -> Result<ExportManifestArtifact> {
    let authority = match authority_manifest_for_vault(vault) {
        Ok(authority) => Some(authority),
        // An unrooted vault still exports: the egress door skips rows, it never
        // refuses. It just ships the authority-less shape, which imports as
        // `MissingAuthorityManifest` rather than as a restore.
        Err(Error::InvariantViolation(NO_LOCAL_AUTHORITY_ROOT)) => None,
        Err(other) => return Err(other),
    };
    if let Some(label) = vault_label {
        validate_export_vault_label(label)?;
    }
    if authority.is_none() && vault_label.is_none() {
        // The vault contributed nothing, so this IS the pure fixture shape —
        // and stays byte-identical to it.
        return whole_vault_export_manifest_artifact(secrets_nulled);
    }

    let mut manifest = ExportManifest::from_secrets_nulled(secrets_nulled);
    manifest.authority = authority;
    manifest.vault_label = vault_label.map(str::to_owned);
    ExportManifestArtifact::from_manifest(&manifest)
}

/// Writes a whole-vault export manifest for a vault handle.
pub fn write_whole_vault_export_manifest_for_vault(
    vault: &Vault,
    export_dir: impl AsRef<Path>,
    secrets_nulled: ExportSecretsNulledManifest,
) -> Result<PathBuf> {
    whole_vault_export_manifest_artifact_for_vault(vault, secrets_nulled)?.write_to_dir(export_dir)
}

/// Writes a whole-vault export manifest carrying an owner-supplied label.
pub fn write_whole_vault_export_manifest_for_vault_with_label(
    vault: &Vault,
    export_dir: impl AsRef<Path>,
    secrets_nulled: ExportSecretsNulledManifest,
    vault_label: Option<&str>,
) -> Result<PathBuf> {
    whole_vault_export_manifest_artifact_for_vault_with_label(vault, secrets_nulled, vault_label)?
        .write_to_dir(export_dir)
}

impl Vault {
    /// Builds the manifest for a whole-vault export. Succeeds while an
    /// off-record session is live.
    pub fn whole_vault_export_manifest_artifact(
        &self,
        secrets_nulled: ExportSecretsNulledManifest,
    ) -> Result<ExportManifestArtifact> {
        whole_vault_export_manifest_artifact_for_vault(self, secrets_nulled)
    }

    /// Builds the manifest for a whole-vault export, carrying an owner-supplied
    /// label.
    pub fn whole_vault_export_manifest_artifact_with_label(
        &self,
        secrets_nulled: ExportSecretsNulledManifest,
        vault_label: Option<&str>,
    ) -> Result<ExportManifestArtifact> {
        whole_vault_export_manifest_artifact_for_vault_with_label(self, secrets_nulled, vault_label)
    }

    /// Writes the manifest for a whole-vault export. Succeeds while an
    /// off-record session is live.
    pub fn write_whole_vault_export_manifest(
        &self,
        export_dir: impl AsRef<Path>,
        secrets_nulled: ExportSecretsNulledManifest,
    ) -> Result<PathBuf> {
        write_whole_vault_export_manifest_for_vault(self, export_dir, secrets_nulled)
    }

    /// Writes the manifest for a whole-vault export, carrying an owner-supplied
    /// label.
    pub fn write_whole_vault_export_manifest_with_label(
        &self,
        export_dir: impl AsRef<Path>,
        secrets_nulled: ExportSecretsNulledManifest,
        vault_label: Option<&str>,
    ) -> Result<PathBuf> {
        write_whole_vault_export_manifest_for_vault_with_label(
            self,
            export_dir,
            secrets_nulled,
            vault_label,
        )
    }

    /// Classifies an export manifest against this vault. Reads the manifest
    /// only — nothing is staged, admitted, or trusted.
    pub fn classify_vault_import_manifest(
        &self,
        manifest_bytes: &[u8],
        expected_label: Option<&str>,
    ) -> Result<VaultImportReceipt> {
        classify_vault_import_manifest(self, manifest_bytes, expected_label)
    }
}
