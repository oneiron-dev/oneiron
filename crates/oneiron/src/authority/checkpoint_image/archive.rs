//! An image's archive manifests: the virtual content sets that hold covered
//! rows' original signed scaffold, and the machines that hold them (see the
//! parent module's doc).

use super::*;

/// One cold archive that holds covered rows' original signed scaffold: a
/// content set and the machines that hold it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityArchiveManifest {
    /// The archive's content id: [`authority_archive_id`] of this vault and
    /// `rows`.
    pub archive: [u8; 32],
    /// The covered rows it holds, ascending.
    pub rows: Vec<AuthorityEntryHash>,
    /// The machines that hold them, ascending, at least one. Advertised
    /// availability: a reader fetches and verifies each row itself.
    pub custodians: Vec<AuthorityArchiveCustodian>,
}

/// A machine of the same vault that holds an archive's rows: its id and the
/// machine key a connection proves it by ([`PeerMachine::Proven`]). A
/// locator only: never a checkpoint root, a quorum key or a permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityArchiveCustodian {
    pub machine: EntityId,
    pub proof_key: [u8; 32],
}

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

pub(super) fn archive_id_of(
    vault_id: &AuthorityVaultId,
    rows: &[AuthorityEntryHash],
) -> Result<[u8; 32]> {
    if rows.is_empty() || !ascending(rows) {
        return Err(refused("authority archive content"));
    }
    let mut hasher = blake3::Hasher::new_derive_key(AUTHORITY_ARCHIVE_ID_CONTEXT);
    hasher.update(vault_id);
    hasher.update(&u64::try_from(rows.len()).unwrap_or(u64::MAX).to_be_bytes());
    for row in rows {
        hasher.update(row);
    }
    Ok(*hasher.finalize().as_bytes())
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
