//! A rewrap's bindings on a machine that already holds its record (WILL L04
//! row 04, CALLS CUSTODY_BIND_TRAVEL): the owner's bind is a rewrap whose
//! transition carries the record as its holder bound it, at the generation
//! and status every holder already has.

use super::{CustodyApplied, CustodyTransition, TRANSITIONS, WipedRecord};
use crate::Vault;
use crate::authority::{AuthorityFold, CustodyChange, OwnerWorkBody};
use crate::error::Result;
use crate::secret_custody::SecretCustodyRecord;
use crate::side_table::HexId;

/// Takes the bindings of `carried`, the record a rewrap `transition` carries
/// at the generation and status this vault holds, into the record held
/// here. They apply by the request they enact, never by the carrier's
/// arrival or signing time: only while that request is a rewrap among the
/// secret's live custody requests in `fold`, and is not the request of the
/// carrier this vault keeps, so neither a replay nor a carrier its request
/// superseded applies again. The value, generation and status stay as held,
/// and bindings wider than the live floor here leave the record as it is.
pub(super) fn rebind_held_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fold: &AuthorityFold,
    transition: &CustodyTransition,
    carried: &SecretCustodyRecord,
    at: u64,
) -> Result<CustodyApplied> {
    let current = fold
        .custody_heads(transition.id)
        .into_iter()
        .any(|(hash, request)| {
            hash == transition.request
                && matches!(
                    request.work,
                    OwnerWorkBody::Custody {
                        change: CustodyChange::Rewrap,
                        ..
                    }
                )
        });
    let applied = TRANSITIONS
        .get(&vault.store, wtxn, &HexId(transition.id))?
        .and_then(|held| CustodyTransition::decode(&held).ok())
        .is_some_and(|held| held.request == transition.request);
    if !current || applied {
        return Ok(CustodyApplied::Stale);
    }
    let Some(held) = super::super::read_secret_custody_in_txn(&vault.store, wtxn, &transition.id)?
    else {
        return Ok(CustodyApplied::Stale);
    };
    let mut held = WipedRecord(held);
    if held.0.bindings == carried.bindings {
        return Ok(CustodyApplied::Stale);
    }
    held.0.bindings.clone_from(&carried.bindings);
    if super::super::refuse_bindings_wider_than_live_floor(&vault.store, wtxn, &held.0).is_err() {
        return Ok(CustodyApplied::Kept);
    }
    super::super::put_secret_custody_in_txn(vault, wtxn, &transition.id, &held.0, at)?;
    Ok(CustodyApplied::Written)
}
