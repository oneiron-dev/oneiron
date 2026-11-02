//! A custody transition's value sealed under its own erasable carrier key
//! (KS-6, FIX 7402; CALLS `KS-6 carrier wire`): transition v3, signed only
//! while `CUSTODY_CARRIER_LEAF_WIRE` is on.
//!
//! The executor mints the transition's key in the writer that signs it,
//! before any byte is sealed (CALLS `KS-6 leaf deposit`), seals the value
//! under it once, then seals those bytes to each permit as before; every
//! piece signs the key's reference. A recipient opens its envelope with its
//! machine key, then the value with the carrier key, answered live and held
//! in memory only (`leaf_delivery`). Until the key is here the transition
//! is kept and stays pending, as a carrier waiting on its floor does, and
//! the custody pass after an authority catch-up and on the served tick
//! opens it once the key is here.
//!
//! No machine acknowledges a transition (CALLS
//! CUSTODY_REPLICATION_WITHOUT_ACK), so its key retires when this install
//! no longer keeps the transition as its record's latest: a later one
//! replaces it, or a revoke drops it. An erase retires it with the rest.

use super::super::carrier_custody::{CUSTODY_CARRIER_LEAF_WIRE, CarrierRef};
use super::super::leaf_delivery::LeafNeed;
use super::super::types::{SecretCustodyRecord, SecretCustodyStatus};
use super::{CustodyPieces, TRANSITIONS, status_rank};
use crate::Vault;
use crate::authority::AuthorityFold;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::HexId;
use crate::store::{CredentialLeaf, CustodyKind};

/// The carrier key minted for one transition, with its reference.
pub(crate) struct TransitionLeaf {
    pub(crate) carrier: CarrierRef,
    pub(crate) leaf: CredentialLeaf,
}

/// The carrier key the transition of record `id`, as `record` stands, is
/// sealed under, minted in `wtxn` while the carrier wire is on and the
/// record is live. `None` otherwise: a revoked transition seals no value,
/// and with the wire off every transition travels as on main.
///
/// # Errors
/// The refusals of `Store::mint_carrier_leaf_in_txn`: an archived vault, an
/// erased credential, custody faults.
pub(super) fn mint_transition_leaf_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    record: &SecretCustodyRecord,
) -> Result<Option<TransitionLeaf>> {
    if !CUSTODY_CARRIER_LEAF_WIRE || record.status == SecretCustodyStatus::Revoked {
        return Ok(None);
    }
    let (instance, leaf) =
        vault
            .store
            .mint_carrier_leaf_in_txn(wtxn, CustodyKind::CustodyTransition, &id)?;
    Ok(Some(TransitionLeaf {
        carrier: CarrierRef::transition(id, instance, record.rotation_generation),
        leaf,
    }))
}

/// Retires the carrier key of the transition this vault keeps of record
/// `id`, in `wtxn`, when that transition names one: it is about to be
/// replaced or dropped, so no recipient asks for it again. The key is
/// staged to retire where this install's custody holds it, and any copy it
/// was answered goes from memory. A fault staging it is warned and leaves
/// the key to its credential's erase.
///
/// # Errors
/// Storage faults reading the kept transition.
pub(super) fn retire_held_carrier_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let Some(carrier) = TRANSITIONS
        .get(&vault.store, wtxn, &HexId(id))?
        .and_then(|held| CustodyPieces::decode(&held))
        .and_then(|held| held.lead().carrier)
    else {
        return Ok(());
    };
    vault.custody_leaves().forget(&carrier);
    if let Err(error) = vault.store.stage_carrier_retirement_in_txn(
        wtxn,
        carrier.kind,
        &carrier.credential,
        &carrier.instance,
    ) {
        tracing::warn!(
            kind = ?error.kind(),
            "a replaced custody transition's carrier key stays until its credential's erase"
        );
    }
    Ok(())
}

/// Each transition this vault keeps whole that stands on `fold`, seals a
/// value to `machine` under a carrier key and is not applied here yet: the
/// key this install asks for, live, from the request's executor that signed
/// it. A revoked one, one an admitted revoke ended, a kit push and one whose
/// record this vault holds at its order or later need none.
///
/// # Errors
/// Storage faults.
pub(crate) fn transitions_awaiting_leaf_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    machine: EntityId,
) -> Result<Vec<LeafNeed>> {
    let mut needs = Vec::new();
    if !CUSTODY_CARRIER_LEAF_WIRE {
        return Ok(needs);
    }
    for (_, row) in TRANSITIONS.scan(&vault.store, txn)? {
        let Some(held) = CustodyPieces::decode(&row) else {
            continue;
        };
        let lead = held.lead();
        let Some(carrier) = lead.carrier else {
            continue;
        };
        if lead.status == SecretCustodyStatus::Revoked
            || fold.custody_revoked(&lead.id)
            || !held.permits().any(|permit| permit.machine == machine)
            || held.verify(fold).is_err()
        {
            continue;
        }
        let applied = super::super::read_secret_custody_meta_in_txn(&vault.store, txn, &lead.id)?
            .is_some_and(|record| {
                lead.order() <= (record.rotation_generation, status_rank(record.status))
            });
        let Some(request) = fold.counted_owner_work_request(&lead.request) else {
            continue;
        };
        if applied || request.kit_root().is_some() {
            continue;
        }
        needs.push(LeafNeed {
            carrier,
            work: lead.request,
            holder: request.executor,
        });
    }
    Ok(needs)
}

#[cfg(feature = "sync")]
impl Vault {
    /// The value `pieces` seal to this machine, opened with `secret`
    /// ([`CustodyPieces::open_value`]), then under the transition's carrier
    /// key when it names one: `None` while this install holds no such key,
    /// so the transition stays kept and pending until the key is answered.
    pub(crate) fn open_custody_value(
        &self,
        pieces: &CustodyPieces,
        vault_id: &[u8; 32],
        secret: &crate::world_keys::MachineSecret,
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let opened = pieces.open_value(vault_id, secret.machine, &secret.secret)?;
        let lead = pieces.lead();
        let Some(carrier) = lead.carrier else {
            return Some(opened);
        };
        if !CUSTODY_CARRIER_LEAF_WIRE
            || carrier.kind != CustodyKind::CustodyTransition
            || carrier.credential != lead.id
        {
            return None;
        }
        let leaf = self.carrier_leaf_outside_txn(&carrier)?;
        carrier.open(&leaf, None, &opened).ok()
    }
}
