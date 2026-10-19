//! A rewrap's bindings on a machine that already holds its record (WILL L04
//! row 04, CALLS CUSTODY_BIND_TRAVEL): the owner's bind is a rewrap whose
//! transition carries the record as its holder bound it, at the generation
//! and status every holder already has.
//!
//! A receiver whose live floor refuses those bindings keeps its record and
//! keeps the carrier as its latest, so it still relays it, but does not take
//! the request's bindings: the rebind stays pending, and applies once the
//! floor admits it (CALLS CUSTODY_REBIND_PENDING_FLOOR). What is pending is
//! derived from the kept carrier and the fold alone; the request a receiver
//! took is kept beside the record so a replay never applies again.

use super::{CustodyApplied, CustodyTransition, WipedRecord};
use crate::Vault;
use crate::authority::{AuthorityFold, CustodyChange, OwnerWorkBody};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::SecretCustodyRecord;
use crate::side_table::{self, HexId, Raw, SideTable};

/// How a receiver meets a rebind wider than its live floor (CALLS
/// CUSTODY_REBIND_PENDING_FLOOR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyRebindPendingFloor {
    /// The record stays as held and the carrier stays this vault's latest,
    /// but the request's bindings are not taken. The rebind is pending while
    /// its request is still one of the secret's live custody requests, a
    /// rewrap another install holds for, at the generation and status held
    /// here, and no admitted revoke names the secret. The custody pass after
    /// an authority catch-up and on the served tick judges each pending
    /// rebind again from the kept carrier and the fold, and takes its
    /// bindings, exactly as its holder bound them, once the live floor here
    /// admits them: once, by the request, in the committing transaction,
    /// which keeps the request as taken beside the record. A replay never
    /// takes them again, a later rebind or rotation supersedes it, and a
    /// terminal revoke drops it. No queue is kept: the taken request is
    /// node-local, and a restore rebuilds what is pending from the kept
    /// carriers.
    ApplyWhenFloorAdmits,
}

const CUSTODY_REBIND_PENDING_FLOOR: CustodyRebindPendingFloor =
    CustodyRebindPendingFloor::ApplyWhenFloorAdmits;

/// The rewrap request whose bindings this vault took into each record it
/// holds as a receiver, by record id.
const TAKEN: SideTable<HexId, [u8; 32], Raw> = SideTable::new(&side_table::SECRET_CUSTODY_REBIND);

/// Whether `transition` enacts a rewrap that is still one of its secret's
/// live custody requests in `fold`, done by an install other than `this`:
/// a request a later rebind, rotation or revoke replaced is not, and the
/// holder bound its own record in the commit that signed the carrier.
fn rebind_current(
    fold: &AuthorityFold,
    transition: &CustodyTransition,
    this: Option<EntityId>,
) -> bool {
    fold.custody_heads(transition.id)
        .into_iter()
        .any(|(hash, request)| {
            hash == transition.request
                && Some(request.executor) != this
                && matches!(
                    request.work,
                    OwnerWorkBody::Custody {
                        change: CustodyChange::Rewrap,
                        ..
                    }
                )
        })
}

/// Whether this vault took the bindings of `transition`'s request already.
fn taken_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    transition: &CustodyTransition,
) -> Result<bool> {
    Ok(TAKEN.get(&vault.store, txn, &HexId(transition.id))? == Some(transition.request))
}

/// Takes the bindings of `carried`, the record a rewrap `transition` carries
/// at the generation and status this vault holds, into the record held
/// here. They apply by the request they enact, never by the carrier's
/// arrival or signing time: only while that request is a rewrap among the
/// secret's live custody requests in `fold`, done by another install, and
/// this vault has not taken it, so neither a replay nor a carrier its
/// request superseded applies again. The value, generation and status stay
/// as held. Bindings wider than the live floor here leave the record as it
/// is and the request untaken: the rebind stays pending (CALLS
/// CUSTODY_REBIND_PENDING_FLOOR).
pub(super) fn rebind_held_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fold: &AuthorityFold,
    transition: &CustodyTransition,
    carried: &SecretCustodyRecord,
    at: u64,
) -> Result<CustodyApplied> {
    let this = crate::identity::read_machine_id_in_txn(vault, wtxn)?;
    if !rebind_current(fold, transition, this) || taken_in_txn(vault, wtxn, transition)? {
        return Ok(CustodyApplied::Stale);
    }
    let Some(held) = super::super::read_secret_custody_in_txn(&vault.store, wtxn, &transition.id)?
    else {
        return Ok(CustodyApplied::Stale);
    };
    let mut held = WipedRecord(held);
    let applied = if held.0.bindings == carried.bindings {
        CustodyApplied::Stale
    } else {
        held.0.bindings.clone_from(&carried.bindings);
        match CUSTODY_REBIND_PENDING_FLOOR {
            CustodyRebindPendingFloor::ApplyWhenFloorAdmits => {
                if super::super::refuse_bindings_wider_than_live_floor(&vault.store, wtxn, &held.0)
                    .is_err()
                {
                    return Ok(CustodyApplied::Kept);
                }
            }
        }
        super::super::put_secret_custody_in_txn(vault, wtxn, &transition.id, &held.0, at)?;
        CustodyApplied::Written
    };
    TAKEN.put(
        &vault.store,
        wtxn,
        &HexId(transition.id),
        &transition.request,
    )?;
    Ok(applied)
}

/// Whether `transition`, a carrier this vault keeps as its latest, is a
/// rebind pending here that the live floor now admits: a live rewrap
/// another install holds for, at the generation and status of the record
/// held here, with bindings that record does not hold and this vault has
/// not taken. Reads no value.
#[cfg(feature = "sync")]
fn pending_rebind_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    this: Option<EntityId>,
    transition: &CustodyTransition,
) -> Result<bool> {
    if transition.status == crate::secret_custody::SecretCustodyStatus::Revoked
        || fold.custody_revoked(&transition.id)
        || !rebind_current(fold, transition, this)
        || taken_in_txn(vault, txn, transition)?
    {
        return Ok(false);
    }
    let Some(held) =
        super::super::read_secret_custody_admission_in_txn(&vault.store, txn, &transition.id)?
    else {
        return Ok(false);
    };
    let Ok(carried) = transition.record() else {
        return Ok(false);
    };
    Ok(held.status == transition.status
        && held.rotation_generation == transition.generation
        && held.bindings != carried.bindings
        && super::super::refuse_bindings_wider_than_live_floor(&vault.store, txn, &carried).is_ok())
}

impl Vault {
    /// Takes the bindings of every rebind pending here that the live floor
    /// now admits (CALLS CUSTODY_REBIND_PENDING_FLOOR): each judged from the
    /// carrier this vault keeps and its fold, then again in one writer
    /// transaction through the same path a carrier's arrival takes, its
    /// request kept as taken in that commit. The custody pass after an
    /// authority catch-up and on the served tick runs it. Returns how many
    /// records it rebound.
    #[cfg(feature = "sync")]
    pub(crate) fn apply_pending_rebinds(&self) -> Result<usize> {
        let due: Vec<CustodyTransition> = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let this = crate::identity::read_machine_id_in_txn(self, &txn)?;
            let mut due = Vec::new();
            for (_, carrier) in super::TRANSITIONS.scan(&self.store, &txn)? {
                let Ok(transition) = CustodyTransition::decode(&carrier) else {
                    continue;
                };
                if pending_rebind_in_txn(self, &txn, &fold, this, &transition)? {
                    due.push(transition);
                }
            }
            due
        };
        if due.is_empty() {
            return Ok(0);
        }
        self.with_write_txn(|wtxn| {
            let mut rebound = 0;
            for transition in &due {
                // A rebind carries no value: the record keeps the one held.
                let applied = super::apply_custody_transition_in_txn(
                    self,
                    wtxn,
                    transition,
                    None,
                    transition.signed_at,
                )?;
                if applied == CustodyApplied::Written {
                    rebound += 1;
                }
            }
            Ok(rebound)
        })
    }
}
