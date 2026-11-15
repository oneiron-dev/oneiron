//! Door for `tests/signed_archive_provenance.rs` (L2-23 Sol r2 P1): the
//! archive verdict on this vault's own read-only fold with the trusted
//! revisions of one machine naming another authority entry. That is the
//! shape of a revision a checkpoint image the host attests supplies: the
//! image says who signed it, and this install may hold no row of it, or a
//! row of another kind at the id its entry hash derives.

use crate::authority::AuthorityEntryHash;
use crate::batch::export::{
    VaultImportReceipt, WholeVaultDocumentManifest, classify_vault_archive_manifest_on_fold,
};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// Classifies the archive manifest `archive_manifest_bytes` as
/// [`Vault::classify_vault_archive_manifest`] does with no expected label,
/// on this vault's read-only fold whose trusted revisions of `machine` (its
/// accepted roster revision and each anchor chain's head) name `entry`.
///
/// # Errors
/// The manifest does not parse or validate, the fold fails, `machine` has
/// no folded revision, or the classification fails.
pub fn classify_archive_with_trusted_entry(
    vault: &Vault,
    archive_manifest_bytes: &[u8],
    machine: EntityId,
    entry: AuthorityEntryHash,
) -> Result<VaultImportReceipt> {
    let manifest: WholeVaultDocumentManifest = serde_json::from_slice(archive_manifest_bytes)
        .map_err(|_| Error::InvalidConfig("unsupported whole-vault archive manifest".to_owned()))?;
    manifest.validate()?;
    let mut fold = {
        let rtxn = vault.store.env.read_txn()?;
        vault.authority_fold_readonly_in_txn(&rtxn)?
    };
    let folded = fold
        .machines
        .get_mut(&machine)
        .ok_or(Error::InvariantViolation(
            "the machine has no folded revision",
        ))?;
    for revision in folded
        .roster_trusted
        .iter_mut()
        .chain(folded.anchored.values_mut())
    {
        revision.entry = entry;
    }
    classify_vault_archive_manifest_on_fold(vault, &fold, &manifest, None)
}
