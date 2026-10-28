//! The parents a machine's residence result names (FIX 5412, CALLS "FIX 5412
//! result parents"): the fold's main-log heads where they are shown to carry
//! both the rows the signer's standing rests on and the directive's row,
//! else those rows and the directive's row themselves. A vault that adopted
//! a checkpoint image keeps fold states at its frontier and tail rows, so a
//! result on the heads folds past the image without the covered history; on
//! the explicit rows, a covered row off the frontier would need it.

use std::collections::BTreeSet;

use crate::authority::{AuthorityEntryHash, AuthorityFold, KeyFrontier, standing_rows};
use crate::error::Result;
use crate::{EntityId, Vault};

/// What a result names when no main head is shown to carry its evidence
/// (CALLS RESIDENCE_RESULT_COVER_UNKNOWN): the explicit rows, as before.
const RESIDENCE_RESULT_COVER_UNKNOWN_KEEPS_EXPLICIT: bool = true;

/// The parents of `machine`'s result for the directive signed as `directive`,
/// read in `txn` on `fold`: the main heads where every row `machine`'s
/// standing rests on and the directive's row are among them or beneath them
/// ([`KeyFrontier::carries_in_txn`]), never an unrelated main-log head; else
/// those rows and the directive's row.
pub(super) fn residence_result_parents_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    machine: EntityId,
    directive: AuthorityEntryHash,
) -> Result<BTreeSet<AuthorityEntryHash>> {
    let mut named = standing_rows(fold, machine);
    named.insert(directive);
    debug_assert!(RESIDENCE_RESULT_COVER_UNKNOWN_KEEPS_EXPLICIT);
    let Some(mut heads) = KeyFrontier::main_heads(fold) else {
        return Ok(named);
    };
    if heads.carries_in_txn(&vault.store, txn, fold, &named)? {
        return Ok(heads.parents().clone());
    }
    Ok(named)
}
