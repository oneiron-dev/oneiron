//! Doors for `tests/git_smart_http.rs` (SMART-HTTP-SECRET-PUSH-EXPECTATIONS):
//! the hits a marked push's intent wrote down, value-free. The door verdict
//! (`DoorWindowVerdict::AdmitMarked`) is opaque by design, and the public
//! `Vault::repo_secret_marks` opens a working tree, which a bare origin has
//! none of.

use crate::Vault;
use crate::error::Result;
use crate::origin::secret_marks::{
    RepoSecretMark, RepoSecretMarkLookup, for_each_repo_secret_mark_in_txn,
};

/// One readable mark, as the door saw its hit: no value, span or excerpt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkedHit {
    /// The exact path, when the door knew it.
    pub path: Option<String>,
    /// The detector's reason code.
    pub detector_kind: String,
    /// The marked blob's Git OID.
    pub blob: String,
}

/// Every readable repo secret mark the vault holds, of every store, in walk
/// order.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub fn marked_hits(vault: &Vault) -> Result<Vec<MarkedHit>> {
    let txn = vault.store.env.read_txn()?;
    let mut hits = Vec::new();
    for_each_repo_secret_mark_in_txn(
        vault,
        &txn,
        RepoSecretMarkLookup::ReadableClaims,
        &mut |mark: RepoSecretMark| {
            hits.push(MarkedHit {
                path: mark.path,
                detector_kind: mark.detector_kind,
                blob: mark.blob_oid.as_str().to_owned(),
            });
            Ok(())
        },
    )?;
    Ok(hits)
}
