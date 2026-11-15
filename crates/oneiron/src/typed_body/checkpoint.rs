//! The checkpoint getter of typed bodies (KS7-2): each entity's body head,
//! head snapshot, forks, fork snapshots and commit receipts
//! ([`super::receipts::checkpoint`]), under its own entity tree. A body's
//! commit messages name no one (its receipts do), so its snapshots stay
//! exact. A fork's opener and settler are actor parts; an open fork whose
//! opener did not open goes on restore, as the erase deletes it, and its
//! snapshot holds only while its opener's tree opens. Office bodies keep
//! their documents here, not in a second snapshot. Nothing calls this until
//! KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeMap;

use heed::RoTxn;

use super::receipts::checkpoint as receipts;
use super::{BodyActor, DOCS, FORK_DOCS, FORKS, HEADS, TypedBodyFork, TypedForkState};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, CapturedByAdapter, Check, Join, Restore,
};
use crate::store::checkpoint_payload::rows::{self, ActorPart, Captured, OwnerRef, RowLocator};

/// Every typed-body row by entity: heads and snapshots exact, each fork's
/// and receipt's actors split out. The capture is the adapter's own: an
/// open fork's snapshot holds while the opener its fork row names does.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[
        &CapturedByAdapter(HEADS),
        &CapturedByAdapter(DOCS),
        &CapturedByAdapter(FORKS),
        &CapturedByAdapter(FORK_DOCS),
        receipts::TABLE,
    ],
    capture: Capture::Own(capture),
    check: Check::ByTable,
    row_owner: None,
    join: Join::Row(join),
    restore: Restore::Parts,
};

/// The field a fork's opener fills.
const OPENER: &str = "opener";

/// The field the actor who merged or discarded a fork fills.
const SETTLER: &str = "settler";

fn take_actors(fork: &mut TypedBodyFork) -> Vec<(String, EntityId)> {
    let mut actors = Vec::new();
    if let BodyActor::Actor(id) = std::mem::replace(&mut fork.opener, BodyActor::Erased) {
        actors.push((OPENER.to_owned(), id));
    }
    if let TypedForkState::Merged { by, .. } | TypedForkState::Discarded { by, .. } =
        &mut fork.state
        && let BodyActor::Actor(id) = std::mem::replace(by, BodyActor::Erased)
    {
        actors.push((SETTLER.to_owned(), id));
    }
    actors
}

fn fill(slot: &mut BodyActor, actor: EntityId) -> Result<()> {
    if *slot != BodyActor::Erased {
        return Err(rows::bad_part());
    }
    *slot = BodyActor::Actor(actor);
    Ok(())
}

fn put_actor(fork: &mut TypedBodyFork, field: &str, actor: EntityId) -> Result<()> {
    match (field, &mut fork.state) {
        (OPENER, _) => fill(&mut fork.opener, actor),
        (SETTLER, TypedForkState::Merged { by, .. } | TypedForkState::Discarded { by, .. }) => {
            fill(by, actor)
        }
        _ => Err(rows::bad_part()),
    }
}

/// Every typed-body row in `txn`, by entity.
fn capture(store: &Store, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    for row in rows::typed_rows(store, txn, HEADS, out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(store, txn, DOCS, out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    // An open fork's snapshot goes with the fork when its opener is erased.
    let mut openers = BTreeMap::new();
    for row in rows::typed_rows(store, txn, FORKS, out)? {
        if let (TypedForkState::Open, BodyActor::Actor(opener)) =
            (&row.value.state, row.value.opener)
        {
            openers.insert(row.key, opener);
        }
        let owner = OwnerRef::entity(&row.key.0);
        rows::split_actors(out, owner, FORKS, row, take_actors)?;
    }
    for row in rows::typed_rows(store, txn, FORK_DOCS, out)? {
        let owner = OwnerRef::entity(&row.key.0);
        if let Some(opener) = openers.get(&row.key) {
            out.depends(owner, &row.at, OwnerRef::entity(opener));
        }
        out.exact(owner, row.at, row.bytes);
    }
    receipts::capture(store, txn, out)
}

/// A fork or receipt with its opened actors back, as the erase leaves it
/// for each actor that did not open.
fn join(
    _: &Store,
    _: &RoTxn<'_>,
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    if at.in_table(FORKS.decl()) {
        let fork = rows::join_actors(FORKS, value, parts, put_actor)?;
        if fork.opener == BodyActor::Erased && fork.state == TypedForkState::Open {
            return Ok(None);
        }
        return FORKS.encode_value(&fork).map(Some);
    }
    if at.in_table(receipts::TABLE.decl()) {
        return receipts::join(value, parts).map(Some);
    }
    Err(rows::bad_part())
}
