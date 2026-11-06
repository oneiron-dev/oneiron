//! Core half of `batch::export::export_authority`: its store-layer items live in `oneiron_store::batch::export::export_authority` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::batch::export::export_authority::*;

use super::export_manifest::ExportManifest;
use crate::Vault;
use crate::authority::AuthorityFold;
use crate::error::{Error, Result};
use oneiron_authority::authority::AuthorityVaultId;
use oneiron_contracts::authority::AuthorityEntryHash;
use std::collections::BTreeSet;

/// Classifies an export manifest against the vault it is offered to.
///
/// MANIFEST ONLY. This reads no vault bytes, stages no foreign content, mutates
/// no trust, and admits nothing — it answers one question ("what is this
/// artifact, relative to me?") and hands back a receipt. Acting on the verdict
/// is the caller's business.
///
/// The blueprint pins "performs no writes", so the local identity question is
/// answered through the READONLY authority fold
/// (`local_authority_identity_readonly`): classification persists nothing —
/// no first-seen sidecar backfill, no migration marker, no observation-clock
/// write, and it never takes LMDB's single-writer lock (SOL-ONE-1379-1).
///
/// The order of questions is deliberate. The serializer and data-shape gates run
/// first, because a manifest this build cannot even read has no identity worth
/// comparing. Then the authority chain decides identity, and only then do the
/// label and the secret-nulling flags get a say — a label can never promote a
/// foreign chain, and a matching chain can never excuse nulled content.
///
/// A matching chain is a claim, not a proof: the manifest is unsigned, and its
/// vault id and digest can be copied from any export of this vault. So a
/// same-chain artifact always carries
/// [`VaultImportMismatch::UnauthenticatedProvenance`] and reads
/// [`VaultImportClassification::ReviewRequired`]. Whole-vault import treats the
/// verdict as advisory, so the owner's own export still restores.
pub fn classify_vault_import_manifest(
    vault: &Vault,
    manifest_bytes: &[u8],
    expected_label: Option<&str>,
) -> Result<VaultImportReceipt> {
    let manifest = ExportManifest::from_json_for_import(manifest_bytes)?;
    let manifest_digest = canonical_manifest_digest(&manifest)?;

    let exported_label = manifest.vault_label.clone();
    if let Some(label) = exported_label.as_deref() {
        validate_export_vault_label(label)?;
    }
    if let Some(label) = expected_label {
        validate_export_vault_label(label)?;
    }

    let exported_authority = manifest
        .authority
        .as_ref()
        .map(ExportAuthorityManifest::parse_identity)
        .transpose()?;
    let local_authority = local_authority_identity_readonly(vault)?;

    let mut mismatches = BTreeSet::new();
    if exported_authority.is_none() {
        mismatches.insert(VaultImportMismatch::MissingAuthorityManifest);
    }
    if local_authority.is_none() {
        mismatches.insert(VaultImportMismatch::LocalAuthorityMissing);
    }

    let mut foreign_chain = false;
    if let (Some(exported), Some(local)) = (exported_authority, local_authority) {
        if exported.vault_id == local.vault_id {
            mismatches.insert(VaultImportMismatch::UnauthenticatedProvenance);
            if exported.valid_entries_digest != local.valid_entries_digest {
                mismatches.insert(VaultImportMismatch::AuthorityChainDigest);
            }
        } else {
            foreign_chain = true;
            mismatches.insert(VaultImportMismatch::AuthorityVaultId);
        }
    }

    if let Some(expected) = expected_label
        && exported_label.as_deref() != Some(expected)
    {
        mismatches.insert(VaultImportMismatch::VaultLabel);
    }

    if manifest.secrets_nulled.payloads || manifest.secrets_nulled.structural_placeholders {
        mismatches.insert(VaultImportMismatch::RedactedOrSecretNulled);
    }

    let classification = if foreign_chain {
        VaultImportClassification::ForeignAuthorityChain
    } else if mismatches.is_empty() {
        VaultImportClassification::ByteFaithfulOwnerRestore
    } else {
        VaultImportClassification::ReviewRequired
    };

    Ok(VaultImportReceipt {
        manifest_digest,
        classification,
        mismatches: mismatches.into_iter().collect(),
        exported_vault_id: exported_authority.map(|identity| identity.vault_id),
        local_vault_id: local_authority.map(|identity| identity.vault_id),
        exported_label,
        expected_label: expected_label.map(str::to_owned),
        byte_faithful: classification == VaultImportClassification::ByteFaithfulOwnerRestore,
    })
}

/// The exporting vault's authority stanza.
///
/// Fails with [`NO_LOCAL_AUTHORITY_ROOT`] when the fold derives no vault id —
/// unrooted, or a multi-root log the fold collapsed. Both mean the same thing
/// here: there is no identity to sign this artifact with.
pub(super) fn authority_manifest_for_vault(vault: &Vault) -> Result<ExportAuthorityManifest> {
    let identity = local_authority_identity(vault)?
        .ok_or(Error::InvariantViolation(NO_LOCAL_AUTHORITY_ROOT))?;
    Ok(ExportAuthorityManifest {
        vault_id: hex_lower(&identity.vault_id),
        valid_entries_digest: hex_lower(&identity.valid_entries_digest),
    })
}

/// Folds this vault's authority once and reduces it to the two values the
/// manifest compares on.
///
/// This is the WRITE-side fold: it backfills first-seen sidecars, stamps the
/// one-shot migration marker, and advances the observation clock
/// (`authority.rs`). That is exactly what an export wants — exporting is
/// owner-initiated and already writes the artifact, so recording this vault's
/// first-seen observations here costs nothing extra. The import classifier
/// must NOT take this path; it uses
/// [`local_authority_identity_readonly`].
fn local_authority_identity(vault: &Vault) -> Result<Option<AuthorityChainIdentity>> {
    Ok(authority_identity_of_fold(vault.authority_fold()?))
}

/// The classifier's identity question, answered without a single write.
///
/// [`classify_vault_import_manifest`] is manifest-only by blueprint ("it
/// performs no writes"): offering an artifact for classification must leave
/// the vault untouched, so this folds inside a caller-owned read transaction
/// through [`Vault::authority_fold_readonly_in_txn`], which persists nothing —
/// no sidecar backfill, no migration marker, no observation-clock advance —
/// and opens no transaction of its own (SOL-ONE-1379-1). A corrupt first-seen
/// sidecar, like every other fold error, propagates.
fn local_authority_identity_readonly(vault: &Vault) -> Result<Option<AuthorityChainIdentity>> {
    let rtxn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&rtxn)?;
    Ok(authority_identity_of_fold(fold))
}

/// Reduces a fold — however it was computed — to the two values the manifest
/// compares on. Both identity paths share this tail so the write and readonly
/// folds can never disagree about what the local identity IS.
fn authority_identity_of_fold(fold: AuthorityFold) -> Option<AuthorityChainIdentity> {
    let vault_id = fold.vault_id?;
    Some(AuthorityChainIdentity {
        valid_entries_digest: authority_valid_entries_digest(&vault_id, &fold.valid_entries),
        vault_id,
    })
}

/// Digests the manifest a classification actually accepted.
///
/// Taken over the re-encoded manifest, not over the caller's bytes: the receipt
/// commits to what was PARSED, so whitespace or key-order noise in the artifact
/// cannot make two identical manifests receipt differently.
pub(super) fn canonical_manifest_digest(manifest: &ExportManifest) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EXPORT_MANIFEST_RECEIPT_DOMAIN);
    hasher.update(&manifest.to_json_pretty()?);
    Ok(*hasher.finalize().as_bytes())
}
