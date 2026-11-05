//! Core half of `typed_body::receipts::checkpoint`: its store-layer items live in `oneiron_store::typed_body::receipts::checkpoint` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

pub(crate) use oneiron_store::typed_body::receipts::checkpoint::*;

use heed::RoTxn;
use super::{RECEIPTS, StoredReceipt};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{self, ActorPart, Captured, OwnerRef, RowLocator};

/// Moves both actors out of a live receipt, leaving `entity` in their place.
fn take_actors(receipt: &mut StoredReceipt, entity: EntityId) -> Vec<(String, EntityId)> {
    match receipt {
        StoredReceipt::Live { actor, made_by, .. } => vec![
            (ACTOR.to_owned(), std::mem::replace(actor, entity)),
            (
                PROCESS.to_owned(),
                std::mem::replace(&mut made_by.process.actor, entity),
            ),
        ],
        StoredReceipt::Erased { .. } => Vec::new(),
    }
}

pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    for row in rows::typed_rows(dbs, txn, RECEIPTS, out)? {
        let entity = row.key.0;
        rows::split_actors(out, OwnerRef::entity(&entity), RECEIPTS, row, |receipt| {
            take_actors(receipt, entity)
        })?;
    }
    Ok(())
}

pub(crate) fn owns(at: &RowLocator) -> bool {
    at.in_table(RECEIPTS.decl())
}

pub(crate) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    rows::check_row(RECEIPTS, at, value)
}

/// A live receipt with both actors back, or its erased form when either did
/// not open.
pub(crate) fn join(value: &[u8], parts: &[&ActorPart]) -> Result<Vec<u8>> {
    let mut filled = (false, false);
    let receipt = rows::join_actors(RECEIPTS, value, parts, |receipt, field, id| {
        let StoredReceipt::Live { actor, made_by, .. } = receipt else {
            return Err(rows::bad_part());
        };
        match field {
            ACTOR => {
                *actor = id;
                filled.0 = true;
            }
            PROCESS => {
                made_by.process.actor = id;
                filled.1 = true;
            }
            _ => return Err(rows::bad_part()),
        }
        Ok(())
    })?;
    let receipt = match receipt {
        StoredReceipt::Live { made_by, .. } if filled != (true, true) => {
            StoredReceipt::Erased { at: made_by.at }
        }
        whole => whole,
    };
    RECEIPTS.encode_value(&receipt)
}
