//! The typed-body commit receipts (KS7-2), under their body's entity tree. A
//! live receipt names its actor and, in its MadeBy, the process's actor: the
//! compartment keeps the receipt with both set to its own entity, and each
//! actor is an actor part. A restore writes the live receipt back only when
//! both open; otherwise it writes the erased form, the commit time alone, as
//! the erase does. The typed-body getter reads them.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::RoTxn;

use super::{RECEIPTS, StoredReceipt};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{self, ActorPart, Captured, OwnerRef, RowLocator};

/// The field the receipt's actor fills.
const ACTOR: &str = "actor";

/// The field the MadeBy process's actor fills.
const PROCESS: &str = "made_by.process.actor";

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
