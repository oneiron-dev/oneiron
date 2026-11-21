//! An image's archive manifests: the virtual content sets that hold covered
//! rows' original signed scaffold, and the machines that hold them (see the
//! parent module's doc).

use super::*;

#[doc(hidden)]
pub(super) use oneiron_records::authority::checkpoint_image::archive::archive_id_of;
#[doc(hidden)]
pub use oneiron_records::authority::checkpoint_image::archive::{
    AuthorityArchiveCustodian, AuthorityArchiveManifest,
};

/// What an archive id commits: one vault's exact signed rows, by hash. Each
/// row hash commits that row's canonical signed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityArchiveContent {
    pub vault_id: AuthorityVaultId,
    /// Ascending, unique and nonempty.
    pub rows: Vec<AuthorityEntryHash>,
}

/// An archive's content id: `BLAKE3-derive_key(AUTHORITY_ARCHIVE_ID_CONTEXT,
/// vault_id ‖ row count (u64 BE) ‖ each row hash, ascending)`. A virtual
/// content-set commitment: not a location, a checkpoint id or a proof that
/// any copy is durable. Rows that are empty, unsorted or repeated refuse.
pub fn authority_archive_id(content: &AuthorityArchiveContent) -> Result<[u8; 32]> {
    archive_id_of(&content.vault_id, &content.rows)
}

/// The one local-custody manifest a builder writes: `held_covered`, the
/// covered rows this vault physically holds in original signed bytes
/// (ascending), with this install's own proved machine as the only
/// custodian. None when it holds none of them or no machine of its own is
/// proved here: an image never names custody it cannot stand behind.
pub(in crate::authority) fn local_archive_manifest(
    vault_id: &AuthorityVaultId,
    held_covered: Vec<AuthorityEntryHash>,
    custodian: Option<AuthorityArchiveCustodian>,
) -> Result<Option<AuthorityArchiveManifest>> {
    let Some(custodian) = custodian.filter(|_| !held_covered.is_empty()) else {
        return Ok(None);
    };
    Ok(Some(AuthorityArchiveManifest {
        archive: archive_id_of(vault_id, &held_covered)?,
        rows: held_covered,
        custodians: vec![custodian],
    }))
}

/// This install's own machine as an archive custodian, when `fold` proves
/// it: the install's machine id, with the signer loaded for it, whose
/// machine key is the one `fold` names for that machine
/// ([`AuthorityFold::machine_proof_key`]). None before the install has a
/// machine, with no signer loaded, or when the fold names another key.
pub(in crate::authority) fn local_archive_custodian_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
) -> Result<Option<AuthorityArchiveCustodian>> {
    let Some(machine) = crate::identity::read_machine_id_in_txn(vault, txn)? else {
        return Ok(None);
    };
    let Some(signer) = vault
        .loaded_install_signer()
        .filter(|signer| signer.machine == machine)
    else {
        return Ok(None);
    };
    let proof_key = signer.machine_key.verifying_key().to_bytes();
    Ok((fold.machine_proof_key(machine) == Some(proof_key))
        .then_some(AuthorityArchiveCustodian { machine, proof_key }))
}
