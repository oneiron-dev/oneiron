//! Door for `tests/world_key_survives_signer_fork.rs` (Astra anchorsec-seq-floor-s T5):
//! sign a world's key record with this install's machine key.
//!
//! The test copies the mint's record for the standing install's own record and for the
//! removed key's fork on an old parent; only this door reads the signing key. Compiled
//! only under `--cfg oneiron_test_support`; never API.

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityLogEntry, AuthorityOp, WorldKeyWrapsRecord};
use crate::error::Result;

/// Signs `record` with this install's machine key at `seq` on `parents`.
///
/// # Errors
///
/// The fold's, a missing machine key, or the signing refusal.
pub fn sign_world_key_record_as_install(
    vault: &Vault,
    record: WorldKeyWrapsRecord,
    seq: u64,
    parents: BTreeSet<AuthorityEntryHash>,
) -> Result<AuthorityLogEntry> {
    let fold = vault.authority_fold()?;
    let txn = vault.store.env.read_txn()?;
    let signing = crate::identity::read_machine_signing_key_in_txn(vault, &txn)?
        .ok_or_else(crate::authority::invalid_authority)?;
    crate::authority::sign_side_entry(
        &fold,
        &signing,
        seq,
        parents,
        AuthorityOp::WorldKeyWraps(record),
        seq + 1,
    )
}
