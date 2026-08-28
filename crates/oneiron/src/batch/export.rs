use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(all(feature = "sync", test))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(all(feature = "sync", test))]
use std::sync::{Arc, Barrier};
#[cfg(feature = "sync")]
use std::sync::{Mutex, OnceLock};

use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, AuthorityVaultId};
use crate::claim::ClaimLifecycleStatus;
use crate::companion::{
    CompanionExportClassification, CompanionExpression, CompanionExpressionRegister,
    CompanionRecord, CompanionRecordKey, CompanionRecordKind, CompanionRegister, CompanionScope,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::serialize::{WHOLE_VAULT_EXPORT_SERIALIZER, WHOLE_VAULT_EXPORT_SERIALIZER_VERSION};
use crate::store::{
    DB_MANIFEST, DB_MANIFEST_VERSION, DbManifestEntry, MAX_DBS, STORAGE_ABI_VERSION,
    STORAGE_SCHEMA_VERSION,
};

pub const EXPORT_MANIFEST_ARTIFACT_NAME: &str = "manifest.json";
pub const EXPORT_MANIFEST_VERSION: u16 = 1;
pub const COMPANION_EXPORT_LAYER_VERSION: u16 = 1;

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
const NO_LOCAL_AUTHORITY_ROOT: &str = "export authority manifest needs a derived vault id";

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionExportLayer {
    layer_version: u16,
    personas: Vec<CompanionExportRecord>,
    relationships: Vec<CompanionExportRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionExportRecord {
    key: CompanionRecordKey,
    record: CompanionRecord,
    expression: Option<CompanionExpression>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportManifestArtifact {
    relative_path: &'static str,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportManifest {
    manifest_version: u16,
    serializer: ExportSerializerManifest,
    secrets_nulled: ExportSecretsNulledManifest,
    data_shape: ExportDataShapeManifest,
    /// Absent on artifacts written before the authority stanza existed, and on
    /// vaults that have no derived root to record. Both are import-visible as
    /// mismatches, never as a silent pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<ExportAuthorityManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault_label: Option<String>,
}

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

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportSerializerManifest {
    name: String,
    version: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportSecretsNulledManifest {
    payloads: bool,
    structural_placeholders: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportDataShapeManifest {
    storage_abi_version: u16,
    storage_schema_version: u16,
    db_manifest_version: u16,
    max_dbs: u32,
    named_databases: Vec<ExportDbManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportDbManifestEntry {
    n: u8,
    name: String,
    group: String,
}

pub fn companion_export_layer(
    records: &CompanionRegister,
    expressions: &CompanionExpressionRegister,
) -> CompanionExportLayer {
    let mut personas = Vec::new();
    let mut relationships = Vec::new();

    for (key, record) in records.iter() {
        if !companion_record_exportable(record) {
            continue;
        }

        let exported = CompanionExportRecord {
            key: key.clone(),
            record: record.clone(),
            expression: expressions.lookup(key),
        };

        match record.kind() {
            CompanionRecordKind::Persona => personas.push(exported),
            CompanionRecordKind::Relationship => relationships.push(exported),
        }
    }

    CompanionExportLayer {
        layer_version: COMPANION_EXPORT_LAYER_VERSION,
        personas,
        relationships,
    }
}

fn companion_record_exportable(record: &CompanionRecord) -> bool {
    record.lifecycle == ClaimLifecycleStatus::Active
        && record.export_classification == CompanionExportClassification::Portable
        && !matches!(&record.scope, CompanionScope::SharedVault { .. })
}

impl CompanionExportLayer {
    #[must_use]
    pub const fn layer_version(&self) -> u16 {
        self.layer_version
    }

    #[must_use]
    pub fn personas(&self) -> &[CompanionExportRecord] {
        &self.personas
    }

    #[must_use]
    pub fn relationships(&self) -> &[CompanionExportRecord] {
        &self.relationships
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.personas.len() + self.relationships.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.personas.is_empty() && self.relationships.is_empty()
    }
}

impl CompanionExportRecord {
    #[must_use]
    pub const fn key(&self) -> &CompanionRecordKey {
        &self.key
    }

    #[must_use]
    pub const fn record(&self) -> &CompanionRecord {
        &self.record
    }

    #[must_use]
    pub const fn expression(&self) -> Option<CompanionExpression> {
        self.expression
    }
}

impl ExportManifestArtifact {
    pub fn current(redacted: bool) -> Result<Self> {
        Self::from_manifest(&ExportManifest::from_redacted(redacted))
    }

    pub fn from_manifest(manifest: &ExportManifest) -> Result<Self> {
        Ok(Self {
            relative_path: EXPORT_MANIFEST_ARTIFACT_NAME,
            bytes: manifest.to_json_pretty()?,
        })
    }

    #[must_use]
    pub const fn relative_path(&self) -> &str {
        self.relative_path
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn write_to_dir(&self, export_dir: impl AsRef<Path>) -> Result<PathBuf> {
        let path = export_dir.as_ref().join(self.relative_path);
        fs::write(&path, &self.bytes)?;
        Ok(path)
    }
}

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

/// Pure manifest construction for internal fixtures/import tooling.
pub(crate) fn whole_vault_export_manifest_artifact(
    secrets_nulled: ExportSecretsNulledManifest,
) -> Result<ExportManifestArtifact> {
    ExportManifestArtifact::from_manifest(&ExportManifest::from_secrets_nulled(secrets_nulled))
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
fn authority_manifest_for_vault(vault: &Vault) -> Result<ExportAuthorityManifest> {
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
fn authority_valid_entries_digest(
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
fn canonical_manifest_digest(manifest: &ExportManifest) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EXPORT_MANIFEST_RECEIPT_DOMAIN);
    hasher.update(&manifest.to_json_pretty()?);
    Ok(*hasher.finalize().as_bytes())
}

/// Owner-supplied labels are never trimmed, normalized, or case-folded — the
/// label the owner typed is the label that gets compared, so the only rules are
/// the ones that keep it displayable and bounded.
fn validate_export_vault_label(label: &str) -> Result<()> {
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

fn hex_lower(bytes: &[u8]) -> String {
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

impl ExportManifest {
    #[must_use]
    pub fn clear() -> Self {
        Self::from_redacted(false)
    }

    #[must_use]
    pub fn from_redacted(redacted: bool) -> Self {
        Self::from_secrets_nulled(ExportSecretsNulledManifest::from_redacted(redacted))
    }

    #[must_use]
    pub fn from_secrets_nulled(secrets_nulled: ExportSecretsNulledManifest) -> Self {
        Self {
            manifest_version: EXPORT_MANIFEST_VERSION,
            serializer: ExportSerializerManifest::current(),
            secrets_nulled,
            data_shape: ExportDataShapeManifest::current(),
            authority: None,
            vault_label: None,
        }
    }

    #[must_use]
    pub const fn redacted(&self) -> bool {
        self.secrets_nulled.payloads
    }

    #[must_use]
    pub const fn structurally_secret_nulled(&self) -> bool {
        self.secrets_nulled.structural_placeholders
    }

    #[must_use]
    pub const fn manifest_version(&self) -> u16 {
        self.manifest_version
    }

    #[must_use]
    pub const fn serializer(&self) -> &ExportSerializerManifest {
        &self.serializer
    }

    #[must_use]
    pub const fn data_shape(&self) -> &ExportDataShapeManifest {
        &self.data_shape
    }

    #[must_use]
    pub const fn authority(&self) -> Option<&ExportAuthorityManifest> {
        self.authority.as_ref()
    }

    #[must_use]
    pub fn vault_label(&self) -> Option<&str> {
        self.vault_label.as_deref()
    }

    pub fn to_json_pretty(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self)
            .map_err(|_| Error::InvariantViolation("export manifest JSON encode failed"))
    }

    pub fn from_json_for_import(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|_| Error::InvalidConfig("invalid export manifest JSON".to_owned()))?;
        manifest.validate_import_supported()?;
        Ok(manifest)
    }

    pub fn validate_import_supported(&self) -> Result<()> {
        if self.manifest_version != EXPORT_MANIFEST_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported export manifest version {}",
                self.manifest_version
            )));
        }
        self.serializer.validate_import_supported()?;
        self.data_shape.validate_import_supported()
    }
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

impl ExportSerializerManifest {
    #[must_use]
    pub fn current() -> Self {
        Self {
            name: WHOLE_VAULT_EXPORT_SERIALIZER.to_owned(),
            version: WHOLE_VAULT_EXPORT_SERIALIZER_VERSION,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    fn validate_import_supported(&self) -> Result<()> {
        if self.name != WHOLE_VAULT_EXPORT_SERIALIZER
            || self.version != WHOLE_VAULT_EXPORT_SERIALIZER_VERSION
        {
            return Err(Error::InvalidConfig(format!(
                "unsupported export serializer {}@{}",
                self.name, self.version
            )));
        }
        Ok(())
    }
}

impl ExportSecretsNulledManifest {
    #[must_use]
    pub const fn from_redacted(redacted: bool) -> Self {
        Self {
            payloads: redacted,
            structural_placeholders: redacted,
        }
    }

    #[must_use]
    pub const fn payloads(&self) -> bool {
        self.payloads
    }

    #[must_use]
    pub const fn structural_placeholders(&self) -> bool {
        self.structural_placeholders
    }
}

impl ExportDataShapeManifest {
    #[must_use]
    pub fn current() -> Self {
        Self {
            storage_abi_version: STORAGE_ABI_VERSION,
            storage_schema_version: STORAGE_SCHEMA_VERSION,
            db_manifest_version: DB_MANIFEST_VERSION,
            max_dbs: MAX_DBS,
            named_databases: DB_MANIFEST
                .iter()
                .copied()
                .map(ExportDbManifestEntry::from)
                .collect(),
        }
    }

    #[must_use]
    pub const fn storage_abi_version(&self) -> u16 {
        self.storage_abi_version
    }

    #[must_use]
    pub const fn storage_schema_version(&self) -> u16 {
        self.storage_schema_version
    }

    #[must_use]
    pub const fn db_manifest_version(&self) -> u16 {
        self.db_manifest_version
    }

    #[must_use]
    pub const fn max_dbs(&self) -> u32 {
        self.max_dbs
    }

    #[must_use]
    pub fn named_databases(&self) -> &[ExportDbManifestEntry] {
        &self.named_databases
    }

    fn validate_import_supported(&self) -> Result<()> {
        if self.storage_abi_version != STORAGE_ABI_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported export storage ABI version {}",
                self.storage_abi_version
            )));
        }
        if self.storage_schema_version != STORAGE_SCHEMA_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported export storage schema version {}",
                self.storage_schema_version
            )));
        }
        if self.db_manifest_version != DB_MANIFEST_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported export DB manifest version {}",
                self.db_manifest_version
            )));
        }
        if self.max_dbs != MAX_DBS {
            return Err(Error::InvalidConfig(format!(
                "unsupported export max DB count {}",
                self.max_dbs
            )));
        }
        if self.named_databases.len() != DB_MANIFEST.len()
            || !self
                .named_databases
                .iter()
                .zip(DB_MANIFEST.iter().copied())
                .all(|(actual, expected)| actual.matches_store_entry(expected))
        {
            return Err(Error::InvalidConfig(
                "unsupported export DB manifest shape".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ExportDbManifestEntry {
    #[must_use]
    pub const fn n(&self) -> u8 {
        self.n
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn group(&self) -> &str {
        &self.group
    }

    fn matches_store_entry(&self, entry: DbManifestEntry) -> bool {
        self.n == entry.n && self.name == entry.name && self.group == entry.group
    }
}

impl From<DbManifestEntry> for ExportDbManifestEntry {
    fn from(value: DbManifestEntry) -> Self {
        Self {
            n: value.n,
            name: value.name.to_owned(),
            group: value.group.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(feature = "sync")]
mod foreign_stage {
    use super::*;
    use crate::sync::selector::{FederationAdmissionRole, admit_federated_window_update};
    use crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
    use crate::sync::types::WindowKey;

    pub const VAULT_IMPORT_RECEIPT_KEY_PREFIX: &str = "vault_import_receipt:v1:";
    // Admission must be unique before helper effects occur within one process.
    static STAGED_IMPORT_ADMISSION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    #[cfg(test)]
    static STAGED_IMPORT_ADMISSION_COUNT: AtomicUsize = AtomicUsize::new(0);
    #[cfg(test)]
    static STAGED_IMPORT_FIRST_STAGE_BARRIER: OnceLock<Mutex<Option<Arc<Barrier>>>> =
        OnceLock::new();

    /// Test-only observation of real selector admissions; retries that reuse a
    /// durable Pending receipt never increment this counter.
    #[cfg(test)]
    pub fn staged_import_admission_count() -> usize {
        STAGED_IMPORT_ADMISSION_COUNT.load(Ordering::SeqCst)
    }
    #[cfg(test)]
    pub fn reset_staged_import_admission_count() {
        STAGED_IMPORT_ADMISSION_COUNT.store(0, Ordering::SeqCst);
    }
    /// Installs a barrier immediately before the process-wide admission lock.
    #[cfg(test)]
    pub fn install_staged_import_first_stage_barrier(barrier: Arc<Barrier>) {
        *STAGED_IMPORT_FIRST_STAGE_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap() = Some(barrier);
    }
    #[cfg(test)]
    pub fn clear_staged_import_first_stage_barrier() {
        *STAGED_IMPORT_FIRST_STAGE_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap() = None;
    }

    #[cfg(test)]
    type PreContentHook = Arc<dyn Fn(&Vault) + Send + Sync>;
    /// One-shot hook fired inside the staged-content read window, i.e. AFTER a
    /// Pending receipt has been observed and BEFORE its content row is read.
    /// Lets a test land a confirmation (and its same-txn GC) in exactly the
    /// interleaving a concurrent confirmer would otherwise hit by chance.
    ///
    /// Keyed by `receipt_id` so a hook armed by one test can never be consumed
    /// by an unrelated staging on another test thread.
    #[cfg(test)]
    type ArmedPreContentHook = OnceLock<Mutex<Option<([u8; 32], PreContentHook)>>>;
    #[cfg(test)]
    static STAGED_IMPORT_PRE_CONTENT_HOOK: ArmedPreContentHook = OnceLock::new();

    #[cfg(test)]
    pub fn install_staged_import_pre_content_hook(receipt_id: [u8; 32], hook: PreContentHook) {
        *STAGED_IMPORT_PRE_CONTENT_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap() = Some((receipt_id, hook));
    }

    #[cfg(test)]
    fn take_staged_import_pre_content_hook(receipt_id: &[u8; 32]) -> Option<PreContentHook> {
        let cell = STAGED_IMPORT_PRE_CONTENT_HOOK.get_or_init(|| Mutex::new(None));
        let mut slot = cell.lock().unwrap();
        if slot.as_ref().is_some_and(|(armed, _)| armed == receipt_id) {
            return slot.take().map(|(_, hook)| hook);
        }
        None
    }
    const VAULT_IMPORT_CONTENT_KEY_PREFIX: &str = "vault_import_content:v1:";
    /// Verdict text `sync::selector::admit_federated_entity_blob` raises when a
    /// REMOTE entity blob is too short to carry its metadata header.
    ///
    /// Matching the verdict text — rather than the bare `CorruptedIndex`
    /// discriminant — is what keeps this scoped to the foreign artifact. Every
    /// LOCAL store fault reachable from `admit_federated_window_update` raises a
    /// DIFFERENT text (`authority_fold` uses "entity header", "type index row
    /// without entity", "type index row kind mismatch", and the first-seen
    /// sidecar constants), so local corruption stays retryable and only the
    /// truncated remote blob becomes terminal.
    const REMOTE_ENTITY_METADATA_CORRUPT: &str = "entity metadata";
    pub const VAULT_IMPORT_RECEIPT_SCHEMA_VERSION: u8 = 1;
    pub const VAULT_IMPORT_RECEIPT_ID_DOMAIN: &[u8] = b"oneiron/vault-import-receipt/v1\0";
    pub const MAX_FOREIGN_PLATFORM_NAME_BYTES: usize = 128;
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ForeignVaultImportSource {
        AnotherPerson { peer_ref: EntityId },
        ForeignPlatform { platform: String },
    }
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VaultImportStageStatus {
        Pending = 1,
        Confirmed = 2,
        Failed = 3,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VaultImportFailure {
        AdmissionRejected = 1,
        ConfirmationMismatch = 2,
        DurableImportFailed = 3,
    }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VaultImportStageReceipt {
        pub receipt_id: [u8; 32],
        pub manifest_digest: [u8; 32],
        pub remote_update_digest: [u8; 32],
        pub admitted_update_digest: Option<[u8; 32]>,
        pub window_key: String,
        pub source: ForeignVaultImportSource,
        pub role: FederationAdmissionRole,
        pub status: VaultImportStageStatus,
        pub confirmed_by: Option<EntityId>,
        pub confirmed_at_secs: Option<u64>,
        pub failure: Option<VaultImportFailure>,
    }
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StagedVaultImport {
        pub(crate) receipt: VaultImportStageReceipt,
        pub(crate) admitted_update: Vec<u8>,
    }
    impl StagedVaultImport {
        pub fn receipt(&self) -> &VaultImportStageReceipt {
            &self.receipt
        }
        pub fn receipt_id(&self) -> [u8; 32] {
            self.receipt.receipt_id
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VaultImportConfirmation {
        pub receipt_id: [u8; 32],
        pub actor: EntityId,
        pub confirmed_at_secs: u64,
    }

    fn source_bytes(s: &ForeignVaultImportSource) -> Result<Vec<u8>> {
        match s {
            ForeignVaultImportSource::AnotherPerson { peer_ref } => {
                let mut x = vec![1];
                x.extend_from_slice(peer_ref.as_bytes());
                Ok(x)
            }
            ForeignVaultImportSource::ForeignPlatform { platform } => {
                if platform.is_empty()
                    || platform != platform.trim()
                    || platform.len() > MAX_FOREIGN_PLATFORM_NAME_BYTES
                    || platform.chars().any(char::is_control)
                {
                    return Err(Error::InvalidConfig("invalid foreign platform".into()));
                }
                let mut x = vec![2];
                x.extend_from_slice(platform.as_bytes());
                Ok(x)
            }
        }
    }
    fn receipt_key(id: &[u8; 32]) -> String {
        format!("{VAULT_IMPORT_RECEIPT_KEY_PREFIX}{}", super::hex_lower(id))
    }
    fn content_key(id: &[u8; 32]) -> String {
        format!("{VAULT_IMPORT_CONTENT_KEY_PREFIX}{}", super::hex_lower(id))
    }
    fn receipt_id(
        manifest: &[u8; 32],
        source: &ForeignVaultImportSource,
        window: &str,
        remote: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let mut h = blake3::Hasher::new();
        h.update(VAULT_IMPORT_RECEIPT_ID_DOMAIN);
        h.update(manifest);
        h.update(&source_bytes(source)?);
        h.update(window.as_bytes());
        h.update(remote);
        Ok(*h.finalize().as_bytes())
    }
    fn optional_digest(v: Option<[u8; 32]>) -> rmpv::Value {
        v.map_or(rmpv::Value::Nil, |x| rmpv::Value::Binary(x.to_vec()))
    }
    pub(crate) fn encode_vault_import_receipt(r: &VaultImportStageReceipt) -> Result<Vec<u8>> {
        // Receipt state is part of the durable protocol, not merely display metadata.
        if WindowKey::try_new(r.window_key.clone()).is_none()
            || r.role != FederationAdmissionRole::Guest
            || r.receipt_id
                != receipt_id(
                    &r.manifest_digest,
                    &r.source,
                    &r.window_key,
                    &r.remote_update_digest,
                )?
        {
            return Err(Error::InvalidConfig("invalid receipt identity".into()));
        }
        match r.status {
            VaultImportStageStatus::Pending => {
                if r.admitted_update_digest.is_none()
                    || r.confirmed_by.is_some()
                    || r.confirmed_at_secs.is_some()
                    || r.failure.is_some()
                {
                    return Err(Error::InvalidConfig("invalid pending receipt".into()));
                }
            }
            VaultImportStageStatus::Confirmed => {
                if r.admitted_update_digest.is_none()
                    || r.confirmed_by.is_none()
                    || r.confirmed_at_secs.unwrap_or(0) == 0
                    || r.failure.is_some()
                {
                    return Err(Error::InvalidConfig("invalid confirmed receipt".into()));
                }
            }
            VaultImportStageStatus::Failed => {
                if r.admitted_update_digest.is_some()
                    || r.confirmed_by.is_some()
                    || r.confirmed_at_secs.is_some()
                    || r.failure.is_none()
                {
                    return Err(Error::InvalidConfig("invalid failed receipt".into()));
                }
            }
        }
        let v = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("v"),
                rmpv::Value::from(VAULT_IMPORT_RECEIPT_SCHEMA_VERSION),
            ),
            (
                rmpv::Value::from("id"),
                rmpv::Value::Binary(r.receipt_id.to_vec()),
            ),
            (
                rmpv::Value::from("manifest"),
                rmpv::Value::Binary(r.manifest_digest.to_vec()),
            ),
            (
                rmpv::Value::from("remote"),
                rmpv::Value::Binary(r.remote_update_digest.to_vec()),
            ),
            (
                rmpv::Value::from("admitted"),
                optional_digest(r.admitted_update_digest),
            ),
            (
                rmpv::Value::from("window"),
                rmpv::Value::from(r.window_key.clone()),
            ),
            (
                rmpv::Value::from("source"),
                rmpv::Value::Binary(source_bytes(&r.source)?),
            ),
            (rmpv::Value::from("role"), rmpv::Value::from(2u8)),
            (
                rmpv::Value::from("status"),
                rmpv::Value::from(r.status as u8),
            ),
            (
                rmpv::Value::from("confirmed_by"),
                r.confirmed_by.map_or(rmpv::Value::Nil, |x| {
                    rmpv::Value::Binary(x.as_bytes().to_vec())
                }),
            ),
            (
                rmpv::Value::from("confirmed_at_secs"),
                r.confirmed_at_secs
                    .map_or(rmpv::Value::Nil, rmpv::Value::from),
            ),
            (
                rmpv::Value::from("failure"),
                r.failure
                    .map_or(rmpv::Value::Nil, |x| rmpv::Value::from(x as u8)),
            ),
        ]);
        let mut b = Vec::new();
        rmpv::encode::write_value(&mut b, &v)
            .map_err(|_| Error::InvariantViolation("receipt encode failed"))?;
        Ok(b)
    }
    pub fn vault_import_stage_receipt(
        vault: &Vault,
        id: &[u8; 32],
    ) -> Result<Option<VaultImportStageReceipt>> {
        let Some(raw) = vault.sync_state_get(&receipt_key(id))? else {
            return Ok(None);
        };
        let mut c = std::io::Cursor::new(&raw);
        let v = rmpv::decode::read_value(&mut c)
            .map_err(|_| Error::InvalidConfig("invalid receipt".into()))?;
        if c.position() != raw.len() as u64 {
            return Err(Error::InvalidConfig("trailing receipt bytes".into()));
        };
        let rmpv::Value::Map(f) = v else {
            return Err(Error::InvalidConfig("receipt is not map".into()));
        };
        let names = [
            "v",
            "id",
            "manifest",
            "remote",
            "admitted",
            "window",
            "source",
            "role",
            "status",
            "confirmed_by",
            "confirmed_at_secs",
            "failure",
        ];
        if f.len() != names.len() {
            return Err(Error::InvalidConfig("receipt shape".into()));
        };
        let mut seen = std::collections::HashSet::new();
        for (k, _) in &f {
            let Some(n) = k.as_str() else {
                return Err(Error::InvalidConfig("receipt key".into()));
            };
            if !names.contains(&n) || !seen.insert(n) {
                return Err(Error::InvalidConfig("receipt keys".into()));
            }
        }
        let get = |n| {
            f.iter()
                .find(|(k, _)| k.as_str() == Some(n))
                .map(|(_, v)| v)
        };
        let bin = |v: Option<&rmpv::Value>, n| -> Result<Vec<u8>> {
            match v {
                Some(rmpv::Value::Binary(b)) if b.len() == n => Ok(b.clone()),
                _ => Err(Error::InvalidConfig("receipt binary".into())),
            }
        };
        if !matches!(get("v"),Some(rmpv::Value::Integer(i)) if i.as_u64()==Some(1)) {
            return Err(Error::InvalidConfig("receipt version".into()));
        };
        let rid: [u8; 32] = bin(get("id"), 32)?
            .try_into()
            .map_err(|_| Error::InvalidConfig("receipt binary".into()))?;
        if &rid != id {
            return Err(Error::InvalidConfig("receipt id mismatch".into()));
        };
        let manifest: [u8; 32] = bin(get("manifest"), 32)?
            .try_into()
            .map_err(|_| Error::InvalidConfig("receipt binary".into()))?;
        let remote: [u8; 32] = bin(get("remote"), 32)?
            .try_into()
            .map_err(|_| Error::InvalidConfig("receipt binary".into()))?;
        let window = match get("window") {
            Some(rmpv::Value::String(x)) => x
                .as_str()
                .ok_or_else(|| Error::InvalidConfig("window utf8".into()))?
                .to_owned(),
            _ => return Err(Error::InvalidConfig("window type".into())),
        };
        if WindowKey::try_new(window.clone()).is_none() {
            return Err(Error::InvalidConfig("window invalid".into()));
        };
        let source_raw = bin(
            get("source"),
            get("source")
                .and_then(|v| {
                    if let rmpv::Value::Binary(b) = v {
                        Some(b.len())
                    } else {
                        None
                    }
                })
                .unwrap_or(0),
        )?;
        let source = match source_raw.first() {
            Some(1) if source_raw.len() == 17 => ForeignVaultImportSource::AnotherPerson {
                peer_ref: EntityId::from_bytes(
                    source_raw[1..]
                        .try_into()
                        .map_err(|_| Error::InvalidConfig("source invalid".into()))?,
                )?,
            },
            Some(2) => ForeignVaultImportSource::ForeignPlatform {
                platform: String::from_utf8(source_raw[1..].to_vec())
                    .map_err(|_| Error::InvalidConfig("source utf8".into()))?,
            },
            _ => return Err(Error::InvalidConfig("source invalid".into())),
        };
        if source_bytes(&source)? != source_raw {
            return Err(Error::InvalidConfig("source noncanonical".into()));
        };
        if rid != receipt_id(&manifest, &source, &window, &remote)? {
            return Err(Error::InvalidConfig("receipt derivation".into()));
        };
        if !matches!(get("role"),Some(rmpv::Value::Integer(i))if i.as_u64()==Some(2)) {
            return Err(Error::InvalidConfig("role".into()));
        };
        let status = match get("status") {
            Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(1) => {
                VaultImportStageStatus::Pending
            }
            Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(2) => {
                VaultImportStageStatus::Confirmed
            }
            Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(3) => {
                VaultImportStageStatus::Failed
            }
            _ => return Err(Error::InvalidConfig("status".into())),
        };
        let admitted = match get("admitted") {
            Some(rmpv::Value::Nil) => None,
            Some(rmpv::Value::Binary(b)) if b.len() == 32 => Some(
                b.clone()
                    .try_into()
                    .map_err(|_| Error::InvalidConfig("admitted".into()))?,
            ),
            _ => return Err(Error::InvalidConfig("admitted".into())),
        };
        let by = match get("confirmed_by") {
            Some(rmpv::Value::Nil) => None,
            Some(rmpv::Value::Binary(b)) if b.len() == 16 => Some(EntityId::from_bytes(
                b.clone()
                    .try_into()
                    .map_err(|_| Error::InvalidConfig("confirmer".into()))?,
            )?),
            _ => return Err(Error::InvalidConfig("confirmer".into())),
        };
        let at = match get("confirmed_at_secs") {
            Some(rmpv::Value::Nil) => None,
            Some(rmpv::Value::Integer(i)) => Some(
                i.as_u64()
                    .ok_or_else(|| Error::InvalidConfig("negative time".into()))?,
            ),
            _ => return Err(Error::InvalidConfig("time".into())),
        };
        let failure = match get("failure") {
            Some(rmpv::Value::Nil) => None,
            Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(1) => {
                Some(VaultImportFailure::AdmissionRejected)
            }
            Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(2) => {
                Some(VaultImportFailure::ConfirmationMismatch)
            }
            Some(rmpv::Value::Integer(i)) if i.as_u64() == Some(3) => {
                Some(VaultImportFailure::DurableImportFailed)
            }
            _ => return Err(Error::InvalidConfig("failure".into())),
        };
        let r = VaultImportStageReceipt {
            receipt_id: rid,
            manifest_digest: manifest,
            remote_update_digest: remote,
            admitted_update_digest: admitted,
            window_key: window,
            source,
            role: FederationAdmissionRole::Guest,
            status,
            confirmed_by: by,
            confirmed_at_secs: at,
            failure,
        };
        if encode_vault_import_receipt(&r)? != raw {
            return Err(Error::InvalidConfig("receipt noncanonical".into()));
        };
        Ok(Some(r))
    }
    pub(crate) fn vault_import_confirm_if_pending(
        vault: &Vault,
        expected: &VaultImportStageReceipt,
        confirmed: &VaultImportStageReceipt,
    ) -> Result<bool> {
        let key = receipt_key(&expected.receipt_id);
        let a = encode_vault_import_receipt(expected)?;
        let b = encode_vault_import_receipt(confirmed)?;
        vault.with_write_txn(|w| {
            let Some(current) = vault.store.sync_state.get(w, &key)? else {
                return Ok(false);
            };
            if current != a {
                return Ok(false);
            }
            vault.store.sync_state.put(w, &key, &b)?;
            // The staged payload exists only to recover a Pending receipt. Once this CAS
            // wins the receipt leaves Pending forever, so drop the content in the same
            // write txn: the terminal receipt and the GC commit or roll back together.
            vault
                .store
                .sync_state
                .delete(w, &content_key(&expected.receipt_id))?;
            Ok(true)
        })
    }
    /// Reads the admitted bytes retained solely to make a Pending receipt recoverable
    /// after the caller loses its in-memory `StagedVaultImport`.
    ///
    /// The row exists only while the receipt is Pending: `vault_import_confirm_if_pending`
    /// deletes it atomically in the same write txn that moves the receipt out of Pending,
    /// so a confirmed (or otherwise terminal) receipt never retains staged content.
    pub fn vault_import_staged_content(vault: &Vault, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        vault.sync_state_get(&content_key(id))
    }

    fn put_stage_if_absent(
        vault: &Vault,
        receipt: &VaultImportStageReceipt,
        admitted: Option<&[u8]>,
    ) -> Result<bool> {
        let receipt_key = receipt_key(&receipt.receipt_id);
        let encoded = encode_vault_import_receipt(receipt)?;
        let content_key = content_key(&receipt.receipt_id);
        vault.with_write_txn(|w| {
            if vault.store.sync_state.get(w, &receipt_key)?.is_some() {
                return Ok(false);
            }
            if let Some(content) = admitted {
                vault.store.sync_state.put(w, &content_key, content)?;
            }
            vault.store.sync_state.put(w, &receipt_key, &encoded)?;
            Ok(true)
        })
    }

    fn staged_from_pending(
        vault: &Vault,
        receipt: VaultImportStageReceipt,
    ) -> Result<StagedVaultImport> {
        #[cfg(test)]
        if let Some(hook) = take_staged_import_pre_content_hook(&receipt.receipt_id) {
            hook(vault);
        }
        // The receipt was read in an EARLIER txn than the content row below, so
        // the two are not observed atomically. `vault_import_confirm_if_pending`
        // moves the receipt out of Pending and deletes the content in ONE write
        // txn, so a confirmation that commits inside this window leaves us
        // holding a Pending receipt whose content is legitimately gone. Treating
        // that as corruption would let a routine confirm race turn an ACCEPTED
        // import into a false "missing admitted content" error, so re-read the
        // receipt before judging and believe the durable state.
        let observed = vault_import_staged_content(vault, &receipt.receipt_id)?;
        let matches_receipt = |admitted: &[u8]| {
            admitted.len() <= MAX_DECODED_PAYLOAD_BYTES
                && receipt.admitted_update_digest == Some(*blake3::hash(admitted).as_bytes())
        };
        let admitted = match observed {
            Some(admitted) if matches_receipt(&admitted) => admitted,
            // Content is missing, oversized, or not the bytes this receipt
            // promises. Revalidate against the durable receipt: if it already
            // left Pending, the content was GC'd by the winning transition and
            // the terminal receipt is the honest answer — the same one a read
            // ordered a moment later would have returned. It carries no staged
            // content, exactly like every other terminal arm in this module.
            observed => {
                if let Some(current) = vault_import_stage_receipt(vault, &receipt.receipt_id)?
                    && !matches!(current.status, VaultImportStageStatus::Pending)
                {
                    return Ok(StagedVaultImport {
                        receipt: current,
                        admitted_update: Vec::new(),
                    });
                }
                // Still Pending (or vanished) with unusable content: this is a
                // real invariant break, not a race. Fail closed.
                return Err(Error::InvariantViolation(if observed.is_none() {
                    "pending receipt missing admitted content"
                } else {
                    "pending receipt admitted content mismatch"
                }));
            }
        };
        Ok(StagedVaultImport {
            receipt,
            admitted_update: admitted,
        })
    }

    pub fn stage_foreign_vault_import(
        vault: &Vault,
        classification: &VaultImportReceipt,
        source: ForeignVaultImportSource,
        key: &WindowKey,
        remote: &[u8],
    ) -> Result<StagedVaultImport> {
        #[cfg(test)]
        if let Some(barrier) = STAGED_IMPORT_FIRST_STAGE_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap()
            .clone()
        {
            barrier.wait();
        }
        let _admission_guard = STAGED_IMPORT_ADMISSION_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| Error::InvariantViolation("staged admission lock poisoned"))?;
        if remote.len() > MAX_DECODED_PAYLOAD_BYTES {
            return Err(Error::InvalidConfig("foreign update too large".into()));
        };
        if classification.byte_faithful
            != matches!(
                classification.classification,
                VaultImportClassification::ByteFaithfulOwnerRestore
            )
            || !matches!(
                classification.classification,
                VaultImportClassification::ForeignAuthorityChain
                    | VaultImportClassification::ReviewRequired
            )
        {
            return Err(Error::InvalidConfig(
                "invalid foreign classification".into(),
            ));
        };
        let source = match source {
            ForeignVaultImportSource::ForeignPlatform { platform } => {
                ForeignVaultImportSource::ForeignPlatform {
                    platform: platform.trim().to_owned(),
                }
            }
            x => x,
        };
        source_bytes(&source)?;
        let remote_digest = *blake3::hash(remote).as_bytes();
        let id = receipt_id(
            &classification.manifest_digest,
            &source,
            key.as_str(),
            &remote_digest,
        )?;
        if let Some(existing) = vault_import_stage_receipt(vault, &id)? {
            return match existing.status {
                VaultImportStageStatus::Pending => staged_from_pending(vault, existing),
                // An already-confirmed matching artifact is idempotently observable, but it
                // cannot be used to import again because it carries no staged content.
                VaultImportStageStatus::Confirmed | VaultImportStageStatus::Failed => {
                    Ok(StagedVaultImport {
                        receipt: existing,
                        admitted_update: Vec::new(),
                    })
                }
            };
        }
        #[cfg(test)]
        STAGED_IMPORT_ADMISSION_COUNT.fetch_add(1, Ordering::SeqCst);
        let admitted = match admit_federated_window_update(
            vault,
            key,
            remote,
            FederationAdmissionRole::Guest,
        ) {
            Ok(a) if a.len() <= MAX_DECODED_PAYLOAD_BYTES => a,
            Ok(_) => {
                let failed = VaultImportStageReceipt {
                    receipt_id: id,
                    manifest_digest: classification.manifest_digest,
                    remote_update_digest: remote_digest,
                    admitted_update_digest: None,
                    window_key: key.as_str().into(),
                    source,
                    role: FederationAdmissionRole::Guest,
                    status: VaultImportStageStatus::Failed,
                    confirmed_by: None,
                    confirmed_at_secs: None,
                    failure: Some(VaultImportFailure::AdmissionRejected),
                };
                if put_stage_if_absent(vault, &failed, None)? {
                    return Ok(StagedVaultImport {
                        receipt: failed,
                        admitted_update: Vec::new(),
                    });
                }
                let winner = vault_import_stage_receipt(vault, &id)?.ok_or_else(|| {
                    Error::InvariantViolation("receipt disappeared during refusal")
                })?;
                return match winner.status {
                    VaultImportStageStatus::Pending => staged_from_pending(vault, winner),
                    VaultImportStageStatus::Confirmed | VaultImportStageStatus::Failed => {
                        Ok(StagedVaultImport {
                            receipt: winner,
                            admitted_update: Vec::new(),
                        })
                    }
                };
            }
            Err(error) => {
                // Only typed protocol refusal is terminal. Storage, corruption,
                // configuration, and engine errors remain retryable.
                //
                // Gate rejections are NEVER terminal here. A Gate refusal encodes
                // local policy/trust state at decision time, not a defect in the
                // foreign artifact, and `receipt_id` deliberately excludes that
                // state. Writing a Failed receipt for one would make an artifact
                // permanently unimportable under its re-derived id even after the
                // operator installs the missing permit, so pending-outcome Gate
                // rejections fall through to the retryable `Err` path below and
                // leave no receipt behind.
                let terminal = matches!(error,
                    Error::SyncProtocolError { .. }
                        | Error::CrdtDecodeError { .. }
                        | Error::InvalidClaimBody(_)
                        | Error::InvalidKey
                        | Error::MaintenanceKindNotWritable(_)
                        | Error::ReservedEdgeKind(_)
                        | Error::AuthorityLogStoreKeyMismatch { .. })
                    // Only this selector-produced local-root fault is retryable.
                    || matches!(&error, Error::InvalidAuthorityLogBody(message) if *message != "missing local authority root")
                    // A remote entity blob too short to carry its metadata
                    // header is a DEFECT IN THE FOREIGN ARTIFACT, exactly like
                    // the invalid key / invalid claim body / unwritable kind
                    // refusals already listed above: re-fetching the same bytes
                    // re-derives the same `receipt_id` and truncates again, so
                    // leaving it retryable spins forever instead of telling the
                    // operator the artifact is unusable. Fail closed with a
                    // terminal Failed receipt. This is verdict-text scoped (see
                    // `REMOTE_ENTITY_METADATA_CORRUPT`) and deliberately does
                    // NOT make `CorruptedIndex` as a whole terminal — a local
                    // index fault during admission still retries.
                    || matches!(&error, Error::CorruptedIndex(verdict) if *verdict == REMOTE_ENTITY_METADATA_CORRUPT);
                if !terminal {
                    return Err(error);
                }
                let failed = VaultImportStageReceipt {
                    receipt_id: id,
                    manifest_digest: classification.manifest_digest,
                    remote_update_digest: remote_digest,
                    admitted_update_digest: None,
                    window_key: key.as_str().into(),
                    source,
                    role: FederationAdmissionRole::Guest,
                    status: VaultImportStageStatus::Failed,
                    confirmed_by: None,
                    confirmed_at_secs: None,
                    failure: Some(VaultImportFailure::AdmissionRejected),
                };
                if put_stage_if_absent(vault, &failed, None)? {
                    return Ok(StagedVaultImport {
                        receipt: failed,
                        admitted_update: Vec::new(),
                    });
                }
                let winner = vault_import_stage_receipt(vault, &id)?.ok_or_else(|| {
                    Error::InvariantViolation("receipt disappeared during refusal")
                })?;
                return match winner.status {
                    VaultImportStageStatus::Pending => staged_from_pending(vault, winner),
                    VaultImportStageStatus::Confirmed | VaultImportStageStatus::Failed => {
                        Ok(StagedVaultImport {
                            receipt: winner,
                            admitted_update: Vec::new(),
                        })
                    }
                };
            }
        };
        let pending = VaultImportStageReceipt {
            receipt_id: id,
            manifest_digest: classification.manifest_digest,
            remote_update_digest: remote_digest,
            admitted_update_digest: Some(*blake3::hash(&admitted).as_bytes()),
            window_key: key.as_str().into(),
            source,
            role: FederationAdmissionRole::Guest,
            status: VaultImportStageStatus::Pending,
            confirmed_by: None,
            confirmed_at_secs: None,
            failure: None,
        };
        if put_stage_if_absent(vault, &pending, Some(&admitted))? {
            return Ok(StagedVaultImport {
                receipt: pending,
                admitted_update: admitted,
            });
        }
        let existing = vault_import_stage_receipt(vault, &id)?
            .ok_or_else(|| Error::InvariantViolation("receipt disappeared during stage"))?;
        match existing.status {
            VaultImportStageStatus::Pending => staged_from_pending(vault, existing),
            VaultImportStageStatus::Confirmed | VaultImportStageStatus::Failed => {
                Ok(StagedVaultImport {
                    receipt: existing,
                    admitted_update: Vec::new(),
                })
            }
        }
    }
}
#[cfg(feature = "sync")]
pub use foreign_stage::*;
