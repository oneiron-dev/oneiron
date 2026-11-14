//! Moved from `crates/oneiron/src/authority/checkpoint_image/archive.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::checkpoint_image::*;
use crate::authority::*;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Cursor;

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

pub fn archive_id_of(vault_id: &AuthorityVaultId, rows: &[AuthorityEntryHash]) -> Result<[u8; 32]> {
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
