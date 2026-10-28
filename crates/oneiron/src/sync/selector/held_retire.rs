//! Retirement of the facet stamps federation admission holds ahead of their
//! rows (Astra-b F2 on #1432): past their wait, and once the grant they were
//! held under no longer confers, each with its typed receipt (FIX 8890).

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::{FederationGrantActivation, federation_grant_activation};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::federation::decode_federation_grant_body;

use super::authorize::live_federation_grant_in;

/// The grants among `grants` that still confer at `now_secs`, judged in
/// `txn`: stored, live, not made inactive by a pact, and not expired. Scope
/// and member checks belong to the selector a peer sends, not to the grant.
fn grants_conferring_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grants: &BTreeSet<EntityId>,
    now_secs: u64,
) -> Result<BTreeSet<EntityId>> {
    let mut conferring = BTreeSet::new();
    if grants.is_empty() {
        return Ok(conferring);
    }
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    for grant_id in grants {
        let raw = match live_federation_grant_in(vault, txn, grant_id) {
            Ok(raw) => raw,
            Err(Error::Sync(SyncError::SyncProtocolError { .. })) => continue,
            Err(local) => return Err(local),
        };
        let Ok(grant) = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]) else {
            continue;
        };
        if grant.confers_at(now_secs)
            && !matches!(
                federation_grant_activation(&fold, grant_id),
                FederationGrantActivation::Inactive(_)
            )
        {
            conferring.insert(*grant_id);
        }
    }
    Ok(conferring)
}

/// Retires the facet stamps past the owner's wait for held stamps (30 days
/// unless he sets another) and those held under a grant that no longer
/// confers, each with its typed receipt (Astra-b F2 on #1432, FIX 8890);
/// returns how many went.
pub(crate) fn retire_held_facet_stamps(vault: &Vault) -> Result<u64> {
    let now = vault.store.clock.now_recorded_at();
    crate::federation::facet_read::retire_held_stamps(vault, now, |txn, grants| {
        grants_conferring_in(vault, txn, grants, now)
    })
}
