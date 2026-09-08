//! Export authority digests, import classification, and label validation.
use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, AuthorityVaultId};
use crate::error::{Error, Result};

use super::export_manifest::ExportManifest;

/// Longest owner-supplied vault label an export manifest may carry.
///
/// The label is a human hint on the artifact ("laptop, before the reinstall"),
/// never an identity: it is compared byte-for-byte and it NEVER overrides the
/// authority chain, so a matching label on a foreign chain still classifies as
/// foreign.
pub const MAX_EXPORT_VAULT_LABEL_BYTES: usize = 128;

/// Domain separator for the exported authority-chain digest.
pub const EXPORT_AUTHORITY_DIGEST_DOMAIN: &[u8] = b"oneiron/export-authority/v1\0";

/// Domain separator for the import-classification receipt digest.
pub const EXPORT_MANIFEST_RECEIPT_DOMAIN: &[u8] = b"oneiron/export-manifest-receipt/v1\0";

/// The single message [`authority_manifest_for_vault`] raises for "this vault
/// has no derived root", matched as a pattern by the export path.
///
/// The export door NEVER refuses (ARCH-0052 P6), so an unrooted vault has to
/// ship the authority-less manifest shape rather than fail. Keeping the
/// distinction in one private sentinel is what lets the strict accessor and the
/// tolerant export path share a single authority fold.
pub(super) const NO_LOCAL_AUTHORITY_ROOT: &str =
    "export authority manifest needs a derived vault id";

/// The exporting vault's authority identity, as carried in the manifest.
///
/// Both fields are 64-char lowercase hex and are parsed fail-closed on import:
/// a manifest that cannot state its chain identity unambiguously does not get
/// to be an owner restore.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportAuthorityManifest {
    vault_id: String,
    valid_entries_digest: String,
}

/// What an import manifest is, relative to the vault it is offered to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultImportClassification {
    /// Same chain, same chain state, nothing nulled: the owner's own artifact
    /// coming home.
    ByteFaithfulOwnerRestore,
    /// A well-formed chain identity that is not this vault's. Never a restore.
    ForeignAuthorityChain,
    /// Identity could not be established, or it matched and something else
    /// drifted. Every reason is listed in [`VaultImportReceipt::mismatches`].
    ReviewRequired,
}

/// One reason a manifest is not a byte-faithful owner restore.
///
/// Ordering is the declaration order and is what the receipt lists in: identity
/// questions first, then chain state, then the softer label and content facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VaultImportMismatch {
    /// The manifest carries no authority stanza at all.
    MissingAuthorityManifest,
    /// This vault cannot state its chain identity: the fold derives no vault
    /// id (unrooted, or a conflicted root), or the readonly fold the
    /// classifier is pinned to refuses because a pending widen's first-seen
    /// time was never locally observed (`AUTHORITY_FIRST_SEEN_INDETERMINATE`).
    /// Both are fail-closed: never byte-faithful, never confidently foreign.
    LocalAuthorityMissing,
    /// Both sides state a root and they differ.
    AuthorityVaultId,
    /// Same root, different set of valid authority entries.
    AuthorityChainDigest,
    /// The manifest's label is not the label the caller expected.
    VaultLabel,
    /// Payloads or structural placeholders were nulled at export, so the
    /// artifact cannot restore the bytes it came from — even on a matching
    /// chain.
    RedactedOrSecretNulled,
}

/// The classification verdict plus everything it was derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultImportReceipt {
    pub manifest_digest: [u8; 32],
    pub classification: VaultImportClassification,
    pub mismatches: Vec<VaultImportMismatch>,
    pub exported_vault_id: Option<[u8; 32]>,
    pub local_vault_id: Option<[u8; 32]>,
    pub exported_label: Option<String>,
    pub expected_label: Option<String>,
    pub byte_faithful: bool,
}

/// One side's authority identity in decoded form — the local fold's, or the one
/// a manifest claims. Comparing the two is the whole classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthorityChainIdentity {
    vault_id: AuthorityVaultId,
    valid_entries_digest: [u8; 32],
}

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
/// owner-initiated and already writes the artifact, and running the migration
/// here is what lets a legacy vault export a determinate identity at all. The
/// import classifier must NOT take this path; it uses
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
/// and opens no transaction of its own (SOL-ONE-1379-1).
///
/// The one divergence from the write fold that matters here is
/// [`crate::authority::AUTHORITY_FIRST_SEEN_INDETERMINATE`]: on a
/// pre-migration vault whose pending widen would rest on a never-observed
/// first-seen time, the readonly fold refuses rather than pick a roster. The
/// classifier answers that the same way it answers an unrooted vault — local
/// identity UNKNOWN, surfacing as `LocalAuthorityMissing` and therefore
/// `ReviewRequired`. That is fail-closed (never byte-faithful, never
/// confidently foreign), it matches the fold's own refusal semantics, and it
/// self-heals: one write-path fold records the observation and the next
/// classification is exact. A corrupt sidecar is not unknown-but-healing, so
/// it and every other error propagate.
fn local_authority_identity_readonly(vault: &Vault) -> Result<Option<AuthorityChainIdentity>> {
    let rtxn = vault.store.env.read_txn()?;
    let fold = match vault.authority_fold_readonly_in_txn(&rtxn) {
        Ok(fold) => fold,
        Err(err) if crate::authority::is_indeterminate_first_seen(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
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

/// Commits an authority chain's whole valid-entry set to one digest.
///
/// The vault id is bound in so the digest cannot be replayed under a different
/// root, and the entries hash in `BTreeSet` order so two devices that folded the
/// same chain agree byte-for-byte regardless of arrival order.
pub(super) fn authority_valid_entries_digest(
    vault_id: &AuthorityVaultId,
    valid_entries: &BTreeSet<AuthorityEntryHash>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EXPORT_AUTHORITY_DIGEST_DOMAIN);
    hasher.update(vault_id);
    for entry in valid_entries {
        hasher.update(entry);
    }
    *hasher.finalize().as_bytes()
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

/// Owner-supplied labels are never trimmed, normalized, or case-folded — the
/// label the owner typed is the label that gets compared, so the only rules are
/// the ones that keep it displayable and bounded.
pub(super) fn validate_export_vault_label(label: &str) -> Result<()> {
    if label.is_empty() {
        return Err(Error::InvalidConfig(
            "export vault label must not be empty".to_owned(),
        ));
    }
    if label.len() > MAX_EXPORT_VAULT_LABEL_BYTES {
        return Err(Error::InvalidConfig(format!(
            "export vault label exceeds {MAX_EXPORT_VAULT_LABEL_BYTES} bytes"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(
            "export vault label must not contain control characters".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parses one 32-byte manifest hex field, fail-closed.
///
/// Lowercase only and exactly 64 chars: uppercase or short forms would let two
/// spellings of one chain identity exist, and a classifier that accepts both is
/// a classifier that can be argued with.
fn parse_manifest_hex32(field: &str, text: &str) -> Result<[u8; 32]> {
    let malformed = || Error::InvalidConfig(format!("malformed export authority {field}"));
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(malformed());
    }
    let mut out = [0_u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| malformed())?;
    }
    Ok(out)
}

impl ExportAuthorityManifest {
    #[must_use]
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    #[must_use]
    pub fn valid_entries_digest(&self) -> &str {
        &self.valid_entries_digest
    }

    fn parse_identity(&self) -> Result<AuthorityChainIdentity> {
        Ok(AuthorityChainIdentity {
            vault_id: parse_manifest_hex32("vault id", &self.vault_id)?,
            valid_entries_digest: parse_manifest_hex32(
                "valid entries digest",
                &self.valid_entries_digest,
            )?,
        })
    }
}
