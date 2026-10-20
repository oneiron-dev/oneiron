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

use heed::{RoTxn, RwTxn};

use super::receipts::checkpoint as receipts;
use super::{BodyActor, DOCS, FORK_DOCS, FORKS, HEADS, TypedBodyFork, TypedForkState};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
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
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, HEADS, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, DOCS, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    // An open fork's snapshot goes with the fork when its opener is erased.
    let mut openers = BTreeMap::new();
    for row in rows::typed_rows(dbs, txn, FORKS, &mut out)? {
        if let (TypedForkState::Open, BodyActor::Actor(opener)) =
            (&row.value.state, row.value.opener)
        {
            openers.insert(row.key, opener);
        }
        let owner = OwnerRef::entity(&row.key.0);
        rows::split_actors(&mut out, owner, FORKS, row, take_actors)?;
    }
    for row in rows::typed_rows(dbs, txn, FORK_DOCS, &mut out)? {
        let owner = OwnerRef::entity(&row.key.0);
        if let Some(opener) = openers.get(&row.key) {
            out.depends(owner, &row.at, OwnerRef::entity(opener));
        }
        out.exact(owner, row.at, row.bytes);
    }
    receipts::capture(dbs, txn, &mut out)?;
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    [HEADS.decl(), DOCS.decl(), FORKS.decl(), FORK_DOCS.decl()]
        .into_iter()
        .any(|decl| at.in_table(decl))
        || receipts::owns(at)
}

/// The bundle framing of `rows`' typed-body parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(HEADS.decl()) {
        rows::check_row(HEADS, at, value)
    } else if at.in_table(DOCS.decl()) {
        rows::check_row(DOCS, at, value)
    } else if at.in_table(FORKS.decl()) {
        rows::check_row(FORKS, at, value)
    } else if at.in_table(FORK_DOCS.decl()) {
        rows::check_row(FORK_DOCS, at, value)
    } else if receipts::owns(at) {
        receipts::check(at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// A fork or receipt with its opened actors back, as the erase leaves it
/// for each actor that did not open.
fn join(
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
    if receipts::owns(at) {
        return receipts::join(value, parts).map(Some);
    }
    Err(rows::bad_part())
}

/// Puts `opened`'s typed-body rows back: exact rows as they are, and each
/// fork and receipt with the actors that opened.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, join)
}
