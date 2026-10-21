//! The stored subjects one derived read folds together (FIX 7815): an entity
//! and every shell merged into it, read through as ARCH-0055 keeps a merge.

use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// `subject`, then every redirect shell that resolves to exactly it. A shell
/// a split left between heads resolves to more than one and folds into
/// none. Every row keeps its stored subject: a caller folds what it derives
/// from them, never the rows themselves.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn redirect_equivalent_subjects_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<Vec<EntityId>> {
    let shells = crate::identity_redirect::inbound_redirect_shells_in_txn(
        &vault.store,
        rtxn,
        &BTreeSet::from([*subject]),
    )?;
    let mut subjects = vec![*subject];
    for shell in shells {
        if vault.resolve_entity_in_txn(rtxn, &shell)?.as_slice() == [*subject] {
            subjects.push(shell);
        }
    }
    Ok(subjects)
}
