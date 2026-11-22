//! Door for `tests/doors_read_standing_heads.rs` (FIX
//! [FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES], site O7): whether
//! another machine stands, through the fold reader the tick release uses.
//!
//! The unit under test is `AuthorityFold::profiles_other_machine`, which
//! counted any admitter's unremoved chain, and now reads the heads a machine
//! stands under here and the accepted roster revisions. The door folds with
//! `authority_view_readonly_in_txn`, as `releases_here` does.
//!
//! # Errors
//!
//! Storage and fold errors, as the reader's.

use crate::error::Result;
use crate::{EntityId, Vault};

/// Whether the vault profiles a machine besides `own` that none of those
/// chains removed.
pub fn profiles_other_machine(vault: &Vault, own: Option<EntityId>) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    Ok(fold.profiles_other_machine(own))
}
