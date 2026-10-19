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
//!
//! A carrier that brings the record itself, a register, a rotate or any live
//! carrier above the record held here, waits the same way when the floor
//! refuses its bindings, and applies with its value once the floor admits
//! it (CALLS CUSTODY_CARRIER_PENDING_FLOOR, FIX 5336).

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
    /// terminal revoke drops it. No queue is kept: what is pending is
    /// derived from the kept carriers, and the taken request is canonical
    /// beside the record it was taken into (FIX 5337), so a checkpoint
    /// carries both.
    ApplyWhenFloorAdmits,
}

const CUSTODY_REBIND_PENDING_FLOOR: CustodyRebindPendingFloor =
    CustodyRebindPendingFloor::ApplyWhenFloorAdmits;

/// How a receiver meets a carrier that brings the record itself, wider than
/// its live floor (CALLS CUSTODY_CARRIER_PENDING_FLOOR).
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyCarrierPendingFloor {
    /// A live carrier this vault keeps as its latest, sealed to this
    /// machine, of a record it does not hold or holds at an earlier
    /// generation and status (a register, a rotate, or a rewrap it never
    /// took), whose bindings the live floor here refused, stays pending.
    /// The custody pass after an authority catch-up and on the served tick
    /// finds each one the floor now admits, opens its value outside any
    /// transaction, and applies it through the path a carrier's arrival
    /// takes, which judges signature, request, permits, revoke, local, name
    /// and floor again in the committing transaction. A value this machine
    /// cannot open yet leaves it pending; a later carrier supersedes it; an
    /// admitted revoke drops it. One whose name another record here holds
    /// stays pending too, but its value is not opened while the name is
    /// held: each pass judges the name again first, by the rule the apply
    /// binds it by (FIX 5408). No queue is kept: the kept carriers and the
    /// record held decide what is pending.
    ApplyWhenFloorAdmits,
}

#[cfg(feature = "sync")]
const CUSTODY_CARRIER_PENDING_FLOOR: CustodyCarrierPendingFloor =
    CustodyCarrierPendingFloor::ApplyWhenFloorAdmits;

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

/// Whether `transition`, a carrier this vault keeps as its latest, brings a
/// record pending here that the live floor now admits (CALLS
/// CUSTODY_CARRIER_PENDING_FLOOR): live, standing on `fold`, sealed to
/// `this` machine, of a portable record this vault does not hold or holds
/// live at an earlier generation and status, under a name the apply would
/// bind to it (FIX 5408). Reads no value.
#[cfg(feature = "sync")]
fn pending_carrier_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    this: Option<EntityId>,
    transition: &CustodyTransition,
) -> Result<bool> {
    if transition.status == crate::secret_custody::SecretCustodyStatus::Revoked
        || fold.custody_revoked(&transition.id)
        || !transition
            .permits()
            .any(|permit| Some(permit.machine) == this)
    {
        return Ok(false);
    }
    let held = super::super::read_secret_custody_in_txn(&vault.store, txn, &transition.id)?.map(
        |mut held| {
            zeroize::Zeroize::zeroize(&mut held.value_bytes);
            held
        },
    );
    if held.is_some_and(|held| {
        !super::custody_portable(&held)
            || held.status == crate::secret_custody::SecretCustodyStatus::Revoked
            || transition.order() <= (held.rotation_generation, super::status_rank(held.status))
    }) {
        return Ok(false);
    }
    let Ok(carried) = transition.record() else {
        return Ok(false);
    };
    match CUSTODY_CARRIER_PENDING_FLOOR {
        CustodyCarrierPendingFloor::ApplyWhenFloorAdmits => Ok(
            super::super::refuse_bindings_wider_than_live_floor(&vault.store, txn, &carried)
                .is_ok()
                && transition.verify(fold).is_ok()
                && super::super::doors::can_bind_synced_name_in_txn(
                    &vault.store,
                    txn,
                    &carried.name,
                    &transition.id,
                    transition.generation,
                )?,
        ),
    }
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
    /// now admits (CALLS CUSTODY_REBIND_PENDING_FLOOR), and applies every
    /// carrier that brings a record the floor refused before and now admits
    /// (CALLS CUSTODY_CARRIER_PENDING_FLOOR): each judged from the carrier
    /// this vault keeps and its fold, then again in one writer transaction
    /// through the same path a carrier's arrival takes, a rebind's request
    /// kept as taken in that commit. A carrier's value is opened before that
    /// transaction, and the keystore is read only when one waits on it: a
    /// carrier whose name another record here holds stays pending unopened,
    /// and is judged again on the next pass (FIX 5408). The custody pass
    /// after an authority catch-up and on the served tick runs it. Returns
    /// how many records it wrote.
    #[cfg(feature = "sync")]
    pub(crate) fn apply_pending_rebinds(&self) -> Result<usize> {
        let (rebinds, carriers, vault_id) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let this = crate::identity::read_machine_id_in_txn(self, &txn)?;
            let mut rebinds = Vec::new();
            let mut carriers = Vec::new();
            for (_, carrier) in super::TRANSITIONS.scan(&self.store, &txn)? {
                let Ok(transition) = CustodyTransition::decode(&carrier) else {
                    continue;
                };
                if pending_rebind_in_txn(self, &txn, &fold, this, &transition)? {
                    rebinds.push(transition);
                } else if pending_carrier_in_txn(self, &txn, &fold, this, &transition)? {
                    carriers.push(transition);
                }
            }
            (rebinds, carriers, fold.vault_id)
        };
        // A value this machine cannot open yet leaves its carrier pending.
        let opened: Vec<_> = match (carriers.is_empty(), vault_id) {
            (false, Some(vault_id)) => match self.machine_secret_outside_txn() {
                Ok(secret) => carriers
                    .into_iter()
                    .filter_map(|transition| {
                        let value =
                            transition.open_value(&vault_id, secret.machine, &secret.secret)?;
                        Some((transition, value))
                    })
                    .collect(),
                Err(_) => Vec::new(),
            },
            _ => Vec::new(),
        };
        if rebinds.is_empty() && opened.is_empty() {
            return Ok(0);
        }
        self.with_write_txn(|wtxn| {
            let mut written = 0;
            // A rebind carries no value: the record keeps the one held.
            let due = rebinds.iter().map(|transition| (transition, None)).chain(
                opened
                    .iter()
                    .map(|(transition, value)| (transition, Some(value.as_slice()))),
            );
            for (transition, value) in due {
                let applied = super::apply_custody_transition_in_txn(
                    self,
                    wtxn,
                    transition,
                    value,
                    transition.signed_at,
                )?;
                if applied == CustodyApplied::Written {
                    written += 1;
                }
            }
            Ok(written)
        })
    }

    /// [`Self::apply_pending_rebinds`] at once, after a commit that may have
    /// changed an admitted POLICY_MANIFEST, and so the custody floor (FIX
    /// 5338): a rebind or carrier pending on a narrower floor applies right
    /// after the floor widens, not at the next catch-up or served tick. It is
    /// a second commit, never part of the floor change's: a failure is logged
    /// by its kind only, the floor change stands as committed, and the tick's
    /// pass tries again. Call it outside any write transaction. Without the
    /// `sync` feature no carrier waits here, and it does nothing.
    pub(crate) fn apply_pending_rebinds_after_commit(&self) {
        #[cfg(feature = "sync")]
        if let Err(error) = self.apply_pending_rebinds() {
            tracing::warn!(
                kind = ?error.kind(),
                "pending custody was not judged again after a floor change; the next pass retries"
            );
        }
    }
}

/// Whether the row bytes `blob` a sync writer wrote are a POLICY_MANIFEST,
/// whose body the custody floor merges (FIX 5338): that writer calls
/// [`Vault::apply_pending_rebinds_after_commit`] once its commit lands.
#[cfg(feature = "sync")]
pub(crate) fn moves_custody_floor(blob: &[u8]) -> bool {
    crate::batch::EntityMetadataHeader::parse(blob)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_POLICY_MANIFEST)
}
