//! The narrower grants an accepted widening replaces (FIX 9740).
//!
//! Filing records each replaced grant's reference, its bound's digest. A
//! same-bound mint overwrites that reference with a new issuance, so every
//! mint takes its reference out of each open proposal's list, in the minting
//! writer: an accept then revokes only issuances that stood at filing.
use super::super::codec::GRANTS;
use super::super::{AuthenticatedOwner, ConsentGrantRow, GrantBound};
use super::WIDEN_PROPOSALS;
use crate::{Result, Vault};

/// Whether `row` is one of `owner`'s ordinary active grants that `bound`
/// strictly widens: an accepted widen replaces it (Engine 11:40).
/// A bypass grant, an equal bound and another owner's grant never are.
fn is_widen_predecessor(row: &ConsentGrantRow, bound: &GrantBound, owner: &str) -> bool {
    row.is_active()
        && row.bypass.is_none()
        && row.owner_stamp.principal_ref == owner
        && bound.contains(row.grant.bound())
        && !row.grant.bound().contains(bound)
}

/// The grants `bound` replaces, as they stand when the widening is filed.
pub(super) fn predecessors_at_filing(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    bound: &GrantBound,
    owner: &str,
) -> Result<Vec<String>> {
    Ok(GRANTS
        .scan(&vault.store, txn)?
        .into_iter()
        .filter(|(_, row)| is_widen_predecessor(row, bound, owner))
        .map(|(_, row)| crate::consent::consent_grant_row_grant_ref(&row))
        .collect())
}

/// Revoke, each with its own receipt and in the accepting writer, every
/// grant recorded at filing that is still one `bound` replaces. Revoking the
/// wider grant then leaves none behind.
pub(super) fn retire_predecessors_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    bound: &GrantBound,
    owner_ref: &str,
    predecessors: &[String],
) -> Result<()> {
    for predecessor in predecessors {
        if let Some(prior) = vault.consent_grant_in_txn(&*wtxn, predecessor)?
            && is_widen_predecessor(&prior, bound, owner_ref)
        {
            vault.revoke_consent_grant_in_txn(wtxn, owner, predecessor)?;
        }
    }
    Ok(())
}

/// A grant minted under `grant_ref` is a new issuance: no open widening
/// filed before it may revoke it. Called by every standing-grant mint.
pub(in crate::consent) fn forget_widen_predecessor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    grant_ref: &str,
) -> Result<()> {
    let mut changed = Vec::new();
    for (reference, mut row) in WIDEN_PROPOSALS.scan(&vault.store, &*wtxn)? {
        let open = matches!(
            crate::consent::ConsentLifecycle::widen(
                Some(super::widen_state(&row)),
                crate::consent::WidenCommand::ForgetPredecessor
            ),
            crate::consent::WidenStep::Write(crate::consent::WidenState::Filed)
        );
        if open && row.predecessors.iter().any(|listed| listed == grant_ref) {
            row.predecessors.retain(|listed| listed != grant_ref);
            changed.push((reference, row));
        }
    }
    for (reference, row) in changed {
        WIDEN_PROPOSALS.put(&vault.store, wtxn, &reference, &row)?;
    }
    Ok(())
}
