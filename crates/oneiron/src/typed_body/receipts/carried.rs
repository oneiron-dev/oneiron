//! A typed-body commit receipt on the owner's other machines (FIX 12470).
//!
//! A carried commit's operations reach the owner's other machines on its
//! body's document frame (FIX 2458), but its receipt row stayed where it was
//! written, so a read there found no receipt and a fold of the body's
//! provenance failed. The row now rides the base window beside its body
//! (`sync::typed_body_rows`), exactly as the writing vault holds it, with the
//! birth of the body it was made on.
//!
//! Where it lands, the row is stored as it came. No peer is bound and no
//! MadeBy is recorded, so the reader's checks stand: a commit whose actor
//! binding has not arrived yet reads as unreceipted until it does. An erased
//! copy beats a live one made at the same time and never reads as live
//! again; two copies that differ otherwise conflict, and the row held here
//! stands.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{RECEIPTS, StoredReceipt};
use crate::Vault;
use crate::entity_doc::DocumentMerge;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::typed_body::{HEADS, require_live};

/// One commit's receipt as it rides to the owner's other machines: the row
/// as its vault holds it, under its body and commit peer, and the birth of
/// the body it was made on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarriedReceipt {
    pub(crate) entity: EntityId,
    pub(crate) peer: u64,
    /// The body's birth frontier ([`crate::typed_body::TypedBodyHead::birth`]).
    pub(crate) birth: Vec<u8>,
    receipt: StoredReceipt,
}

impl CarriedReceipt {
    /// Whether the receipt names an actor: a live one names its actor and
    /// its MadeBy's process's actor, an erased one names no one.
    pub(crate) fn names_actor(&self) -> bool {
        matches!(self.receipt, StoredReceipt::Live { .. })
    }

    /// Whether this copy holds all of `other`, a copy of the same receipt:
    /// merging `other` into it changes nothing.
    pub(crate) fn covers(&self, other: &Self) -> bool {
        self.entity == other.entity
            && self.peer == other.peer
            && self.birth == other.birth
            && joined(&self.receipt, &other.receipt).as_ref() == Some(&self.receipt)
    }

    /// This copy as this vault holds a carried one: its erased form, the
    /// commit time alone, where this vault erased the actor it names or the
    /// actor its MadeBy's process names, as the erase leaves a receipt here
    /// (`erase_receipt_actor_in_txn`). Read from this vault's own hard-delete
    /// markers, never from an absent actor.
    pub(crate) fn carried_here(mut self, vault: &Vault, txn: &RoTxn<'_>) -> Result<Self> {
        let erased = match &self.receipt {
            StoredReceipt::Live { actor, made_by, .. } => {
                let gone = vault.carrier_actor_erased_in_txn(txn, actor)?
                    || vault.carrier_actor_erased_in_txn(txn, &made_by.process.actor)?;
                gone.then_some(made_by.at)
            }
            StoredReceipt::Erased { .. } => None,
        };
        if let Some(at) = erased {
            self.receipt = StoredReceipt::Erased { at };
        }
        Ok(self)
    }

    /// This vault's copy of the same receipt, beside this copy's birth: what
    /// a divergence is digested against. `None` when it holds none.
    pub(crate) fn held_here_in_txn(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<Option<Self>> {
        Ok(RECEIPTS
            .get(&vault.store, txn, &(self.entity, self.peer))?
            .map(|receipt| Self {
                entity: self.entity,
                peer: self.peer,
                birth: self.birth.clone(),
                receipt,
            }))
    }
}

/// Every receipt row of `entity`'s body this vault holds, each as it rides
/// to the owner's other machines. Empty when `entity` holds no typed body
/// here or is not live here.
pub(crate) fn carried_receipts_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
) -> Result<Vec<CarriedReceipt>> {
    let Some(head) = HEADS.get(&vault.store, txn, entity)? else {
        return Ok(Vec::new());
    };
    match require_live(&vault.store, txn, entity) {
        Ok(()) => {}
        Err(Error::EntityNotFound) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    Ok(RECEIPTS
        .scan_from(&vault.store, txn, entity.as_bytes())?
        .into_iter()
        .map(|((_, peer), receipt)| CarriedReceipt {
            entity: *entity,
            peer,
            birth: head.birth.clone(),
            receipt,
        })
        .collect())
}

/// Merges `carried`, another machine's copy of a receipt, into this vault's
/// in the caller's writer. It writes the receipt row and nothing else: no
/// peer is bound, no MadeBy is recorded. A receipt whose body is not live
/// here is refused, as a frame for it is, and never brings it back; one
/// whose body has not landed here waits; one of another body birth stands
/// apart. A copy naming an actor this vault erased lands in its erased form.
/// A row this vault lacks is written; an erased copy beats a live one made
/// at the same time and never turns live again; copies that differ
/// otherwise conflict, and the one held here stands.
pub(crate) fn merge_carried_receipt_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    carried: &CarriedReceipt,
) -> Result<DocumentMerge> {
    let entity = carried.entity;
    if crate::ports::removed_in_txn(&vault.store, wtxn, &entity)? {
        return Ok(DocumentMerge::Refused("its body's entity is removed here"));
    }
    match require_live(&vault.store, wtxn, &entity) {
        Ok(()) => {}
        Err(Error::EntityNotFound) => {
            return Ok(DocumentMerge::Refused("its body's entity is not live here"));
        }
        Err(error) => return Err(error),
    }
    let Some(head) = HEADS.get(&vault.store, wtxn, &entity)? else {
        return Ok(DocumentMerge::Waiting);
    };
    if head.birth != carried.birth {
        return Ok(DocumentMerge::Refused("a receipt of another body birth"));
    }
    let carried = carried.clone().carried_here(vault, wtxn)?;
    let key = (entity, carried.peer);
    let merged = match RECEIPTS.get(&vault.store, wtxn, &key)? {
        None => carried.receipt,
        Some(held) => match joined(&held, &carried.receipt) {
            Some(merged) if merged == held => return Ok(DocumentMerge::Held),
            Some(merged) => merged,
            None => {
                tracing::warn!(
                    entity = %entity.to_hex(),
                    peer = carried.peer,
                    "a carried typed body receipt diverges from the one held here"
                );
                return Ok(DocumentMerge::Conflict);
            }
        },
    };
    RECEIPTS.put(&vault.store, wtxn, &key, &merged)?;
    crate::batch::queue_committed_rows(vault, wtxn, BTreeSet::from([entity]));
    Ok(DocumentMerge::Written)
}

/// Two copies of one receipt as one: the copy both hold, or the erased form
/// where one is erased and the other is live and made at the same time.
/// `None` when they conflict.
fn joined(held: &StoredReceipt, carried: &StoredReceipt) -> Option<StoredReceipt> {
    if held == carried {
        return Some(held.clone());
    }
    match (held, carried) {
        (StoredReceipt::Erased { at }, StoredReceipt::Live { made_by, .. })
        | (StoredReceipt::Live { made_by, .. }, StoredReceipt::Erased { at })
            if *at == made_by.at =>
        {
            Some(StoredReceipt::Erased { at: *at })
        }
        _ => None,
    }
}
