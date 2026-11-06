//! Export authority digests, import classification, and label validation.
use std::collections::BTreeSet;

use oneiron_authority::authority::AuthorityVaultId;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::authority::AuthorityEntryHash;

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
pub const NO_LOCAL_AUTHORITY_ROOT: &str = "export authority manifest needs a derived vault id";

/// The exporting vault's authority identity, as carried in the manifest.
///
/// Both fields are 64-char lowercase hex and are parsed fail-closed on import:
/// a manifest that cannot state its chain identity unambiguously does not get
/// to be an owner restore.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportAuthorityManifest {
    pub vault_id: String,
    pub valid_entries_digest: String,
}

/// What an import manifest is, relative to the vault it is offered to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultImportClassification {
    /// Same chain, same chain state, nothing nulled, and provenance proved: the
    /// owner's own artifact coming home.
    ///
    /// No export is signed yet, so no manifest earns this today: every
    /// same-chain artifact carries [`VaultImportMismatch::UnauthenticatedProvenance`]
    /// and reads [`Self::ReviewRequired`]. It is reserved for a manifest whose
    /// signer this vault can verify.
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
    /// id (unrooted, or a conflicted root). Fail-closed: never byte-faithful,
    /// never confidently foreign.
    LocalAuthorityMissing,
    /// Both sides state a root and they differ.
    AuthorityVaultId,
    /// Both sides state the same root, but nothing proves the manifest came
    /// from this chain: the vault id and the valid-entries digest are public
    /// facts anyone holding one export can copy. Fail-closed until manifests
    /// are signed by a key this vault can verify.
    UnauthenticatedProvenance,
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
pub struct AuthorityChainIdentity {
    pub vault_id: AuthorityVaultId,
    pub valid_entries_digest: [u8; 32],
}

/// Commits an authority chain's whole valid-entry set to one digest.
///
/// The vault id is bound in so the digest cannot be replayed under a different
/// root, and the entries hash in ascending order, each once: every caller
/// passes an ordered set (a `BTreeSet` or the fold's `ValidEntries`), never a
/// list or a hash set's iterator, so two devices that folded the same chain
/// agree byte-for-byte regardless of arrival order.
pub fn authority_valid_entries_digest<'a>(
    vault_id: &'a AuthorityVaultId,
    valid_entries: impl IntoIterator<Item = &'a AuthorityEntryHash>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EXPORT_AUTHORITY_DIGEST_DOMAIN);
    hasher.update(vault_id);
    for entry in valid_entries {
        hasher.update(entry);
    }
    *hasher.finalize().as_bytes()
}

/// Owner-supplied labels are never trimmed, normalized, or case-folded — the
/// label the owner typed is the label that gets compared, so the only rules are
/// the ones that keep it displayable and bounded.
pub fn validate_export_vault_label(label: &str) -> Result<()> {
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

pub fn hex_lower(bytes: &[u8]) -> String {
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

    pub fn parse_identity(&self) -> Result<AuthorityChainIdentity> {
        Ok(AuthorityChainIdentity {
            vault_id: parse_manifest_hex32("vault id", &self.vault_id)?,
            valid_entries_digest: parse_manifest_hex32(
                "valid entries digest",
                &self.valid_entries_digest,
            )?,
        })
    }
}
