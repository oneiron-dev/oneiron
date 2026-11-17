//! The checkpoint getter of row births (KS7-2): each birth envelope under its
//! born row's entity tree, and each born-from index row under the born row,
//! holding while its trigger does. A birth names its process's actor: the
//! compartment keeps the birth with the born row in that place, and the actor
//! is an actor part. A birth is immutable and has no erased form, so a
//! restore writes it back only when its actor opens; otherwise the row reads
//! as having no stamped birth, never a stand-in. Nothing calls this until
//! KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::birth_record::{BIRTH_BY_TRIGGER, ROW_BIRTH, RowBirth};
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, Check, Join, PlacedTable, Restore,
};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RowLocator, TypedRow,
};

/// The field the MadeBy process's actor fills.
const PROCESS: &str = "made_by.process.actor";

/// Every birth by its born row, its actor split out, and every born-from
/// index row under its born row, holding while its trigger does.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[
        &PlacedTable {
            table: ROW_BIRTH,
            place: place_birth,
        },
        &PlacedTable {
            table: BIRTH_BY_TRIGGER,
            place: place_born_from,
        },
    ],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: None,
    join: Join::Row(join),
    restore: Restore::Parts,
};

/// A birth under its born row, with the born row in its actor's place.
fn place_birth(out: &mut Captured, row: TypedRow<EntityId, RowBirth>) -> Result<()> {
    let born = row.key;
    rows::split_actors(out, OwnerRef::entity(&born), ROW_BIRTH, row, |birth| {
        let actor = std::mem::replace(&mut birth.made_by.process.actor, born);
        vec![(PROCESS.to_owned(), actor)]
    })
}

/// A born-from index row under its born row, holding while its trigger does.
#[allow(
    clippy::unnecessary_wraps,
    reason = "a placement callback: PlacedTable's fn pointer returns Result"
)]
fn place_born_from(out: &mut Captured, row: TypedRow<(EntityId, EntityId), ()>) -> Result<()> {
    let (trigger, born) = row.key;
    let owner = OwnerRef::entity(&born);
    out.depends(owner, &row.at, OwnerRef::entity(&trigger));
    out.exact(owner, row.at, row.bytes);
    Ok(())
}

/// A birth with its actor back; `None` when the actor did not open.
fn join(
    _: &Store,
    _: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if !at.in_table(ROW_BIRTH.decl()) {
        return Err(rows::bad_part());
    }
    if parts.is_empty() {
        return Ok(None);
    }
    let birth = rows::join_actors(ROW_BIRTH, value, parts, |birth, field, actor| {
        if field != PROCESS {
            return Err(rows::bad_part());
        }
        birth.made_by.process.actor = actor;
        Ok(())
    })?;
    ROW_BIRTH.encode_value(&birth).map(Some)
}
