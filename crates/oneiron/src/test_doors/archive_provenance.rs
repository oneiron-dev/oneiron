//! Doors for `tests/signed_archive_provenance.rs`: the archive verdict on
//! this vault's own read-only fold, rewritten into the shape a checkpoint
//! image the host attests can give it.
//!
//! - L2-23 Sol r2 P1: the trusted revisions of one machine name another
//!   authority entry. The image says who signed a revision, and this install
//!   may hold no row of it, or a row of another kind at the id its entry
//!   hash derives.
//! - L2-23 Sol r3 P2: on a hosted vault, the pinned recovery root's anchor
//!   chain of one machine is headed by a `Yours` whose signed row this
//!   install holds. The image says which revision heads that chain, so a
//!   vault that adopted one cannot tell the owner's latest word from an
//!   older one.
//! - L2-23 Astra r2 P2: the fold and the signature's row come from two
//!   committed states, the row's snapshot older than the fold's.

use std::io::Cursor;

use crate::authority::{
    AuthorityEntryHash, AuthorityFold, AuthorityKey, PinnedRoot, RecoveryRootId,
};
use crate::batch::export::{
    ArchiveVerifierState, VaultImportReceipt, WholeVaultDocumentManifest, checked_archive_manifest,
    classify_vault_archive_manifest_on_fold,
};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// Classifies the archive manifest `archive_manifest_bytes` as
/// [`Vault::classify_vault_archive`] does with no expected label, on this
/// vault's read-only fold whose trusted revisions of `machine` (its
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
    let manifest = parsed_manifest(archive_manifest_bytes)?;
    let rtxn = vault.store.env.read_txn()?;
    let mut fold = vault.authority_fold_readonly_in_txn(&rtxn)?;
    let verifier = ArchiveVerifierState::in_txn(vault, &rtxn)?;
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
    classify_vault_archive_manifest_on_fold(vault, &rtxn, &fold, verifier, &manifest, None)
}

/// Classifies the archive manifest `archive_manifest_bytes` as
/// [`Vault::classify_vault_archive`] does with no expected label, as a
/// hosted vault whose pinned recovery root's anchor signed `machine`'s
/// `Yours`, and which adopted a checkpoint image when `adopted_checkpoint`.
/// The fold is this vault's own read-only fold with the pin set to the
/// anchor key that signed `machine`'s accepted roster revision, and that
/// revision moved to the anchor's chain: the row it names is held here and
/// is that key's real signature.
///
/// # Errors
/// The manifest does not parse or validate, the fold fails, `machine` has
/// no accepted roster revision or an Ed25519 key did not sign it, or the
/// classification fails.
pub fn classify_archive_under_pinned_anchor(
    vault: &Vault,
    archive_manifest_bytes: &[u8],
    machine: EntityId,
    adopted_checkpoint: bool,
) -> Result<VaultImportReceipt> {
    let manifest = parsed_manifest(archive_manifest_bytes)?;
    let rtxn = vault.store.env.read_txn()?;
    let mut fold = vault.authority_fold_readonly_in_txn(&rtxn)?;
    let folded = fold
        .machines
        .get_mut(&machine)
        .ok_or(Error::InvariantViolation(
            "the machine has no folded revision",
        ))?;
    let revision = folded
        .roster_trusted
        .take()
        .ok_or(Error::InvariantViolation(
            "the machine has no accepted roster revision",
        ))?;
    let &AuthorityKey::Ed25519(anchor_key) = &revision.signer else {
        return Err(Error::InvariantViolation(
            "an Ed25519 key did not sign the machine's revision",
        ));
    };
    folded.anchored.insert(anchor_key, revision);
    fold.pinned_root = Some(PinnedRoot {
        id: RecoveryRootId(*blake3::hash(&anchor_key).as_bytes()),
        anchor_key,
    });
    let verifier = ArchiveVerifierState {
        hosted: true,
        adopted_checkpoint,
    };
    classify_vault_archive_manifest_on_fold(vault, &rtxn, &fold, verifier, &manifest, None)
}

/// Classifies the archive `export` writes, as [`Vault::classify_vault_archive`]
/// does with no expected label, on this vault's read-only fold once `export`
/// ran, in the snapshot this vault stood in before it ran: there the
/// classification reads the signature's row and the vault's state. `export`
/// runs on a thread of its own while this one holds that snapshot, since the
/// vendored heed has no NOTLS.
///
/// # Errors
/// The snapshot or the fold does not read, `export` fails or panics, the
/// archive fails its member check, or the classification fails.
pub fn classify_archive_in_snapshot_before(
    vault: &Vault,
    export: impl FnOnce() -> Result<Vec<u8>> + Send,
) -> Result<VaultImportReceipt> {
    let rtxn = vault.store.env.read_txn()?;
    let verifier = ArchiveVerifierState::in_txn(vault, &rtxn)?;
    let later = std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<(AuthorityFold, WholeVaultDocumentManifest)> {
                let manifest = checked_archive_manifest(Cursor::new(export()?))?;
                let txn = vault.store.env.read_txn()?;
                Ok((vault.authority_fold_readonly_in_txn(&txn)?, manifest))
            })
            .join()
    });
    let (fold, manifest) =
        later.map_err(|_| Error::InvariantViolation("the export thread panicked"))??;
    classify_vault_archive_manifest_on_fold(vault, &rtxn, &fold, verifier, &manifest, None)
}

fn parsed_manifest(archive_manifest_bytes: &[u8]) -> Result<WholeVaultDocumentManifest> {
    let manifest: WholeVaultDocumentManifest = serde_json::from_slice(archive_manifest_bytes)
        .map_err(|_| Error::InvalidConfig("unsupported whole-vault archive manifest".to_owned()))?;
    manifest.validate()?;
    Ok(manifest)
}
