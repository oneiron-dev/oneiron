//! The narrower grants an accepted widening replaces (FIX 9740).
use super::super::codec::GRANTS;
use super::super::{AuthenticatedOwner, ConsentGrantRow, GrantBound};
use crate::store::GateDecisionId;
use crate::{Result, Vault};
use serde::{Deserialize, Serialize};

/// One grant a widening replaces, frozen at filing: its reference and the
/// mint that issued it. A same-bound re-mint overwrites the reference with a
/// new issuance, which the accept leaves standing.
#[derive(Serialize, Deserialize)]
pub(super) struct PredecessorIssuance {
    grant_ref: String,
    created_at: u64,
    minted_under: GateDecisionId,
}

impl PredecessorIssuance {
    fn of(row: &ConsentGrantRow) -> Self {
        Self {
            grant_ref: row.grant_ref(),
            created_at: row.created_at,
            minted_under: row.owner_stamp.decision_id,
        }
    }

    /// Whether `row` is still the issuance frozen at filing.
    fn issued(&self, row: &ConsentGrantRow) -> bool {
        row.created_at == self.created_at && row.owner_stamp.decision_id == self.minted_under
    }
}

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
) -> Result<Vec<PredecessorIssuance>> {
    Ok(GRANTS
        .scan(&vault.store, txn)?
        .into_iter()
        .filter(|(_, row)| is_widen_predecessor(row, bound, owner))
        .map(|(_, row)| PredecessorIssuance::of(&row))
        .collect())
}

/// Revoke, each with its own receipt and in the accepting writer, every
/// grant frozen at filing that is still that same issuance and still one
/// `bound` replaces. Revoking the wider grant then leaves none behind; a
/// re-minted or changed grant stays.
pub(super) fn retire_predecessors_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    bound: &GrantBound,
    owner_ref: &str,
    predecessors: &[PredecessorIssuance],
) -> Result<()> {
    for predecessor in predecessors {
        if let Some(prior) = vault.consent_grant_in_txn(&*wtxn, &predecessor.grant_ref)?
            && predecessor.issued(&prior)
            && is_widen_predecessor(&prior, bound, owner_ref)
        {
            vault.revoke_consent_grant_in_txn(wtxn, owner, &predecessor.grant_ref)?;
        }
    }
    Ok(())
}
