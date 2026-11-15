//! Door for `tests/found_key_note_fork_upload.rs` (REVIEW-7904 second commit
//! F2): whether the NOTE's authority would admit a pending fork's own
//! operations as this install now holds the fork. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::{EntityId, Result, Vault};

/// Why the NOTE's authority would refuse the upload of `fork` of `note`, as
/// far as the fork's own operations go: they must edit its text alone and
/// add its own authorship entry alone. `None` when it would admit them.
///
/// # Errors
///
/// A fork that makes no upload from this install, and storage errors.
pub fn fork_upload_refusal(
    vault: &Vault,
    note: EntityId,
    fork: EntityId,
) -> Result<Option<&'static str>> {
    let txn = vault.store.env.read_txn()?;
    crate::note::fork_upload_refusal_in_txn(vault, &txn, note, fork)
}
