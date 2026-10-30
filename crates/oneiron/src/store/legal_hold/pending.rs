//! An owner erase that waits (OF-470 C2, C4): the owner's confirmed erase a
//! host order keeps, and the owner's plain delete that only secret orders
//! keep (FIX 1465). One row per record, in the one pending-erase family. It
//! keeps the request's kind, its reason and its generation, so what runs
//! once nothing holds the record is the erase the owner asked for, and a
//! newer request replaces an older one instead of being refused. In a shared
//! vault that erases through its veto window, an explicit lift-and-erase
//! names its own `erase` act too (FIX 9781). The row names no hold, so it
//! tells the owner nothing a secret order keeps.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::deletion::DeleteReason;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;

/// An owner erase that waits. Key: id16 (record).
const PENDING_ERASES: SideTable<EntityId, PendingErase, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_PENDING_ERASE);

/// Which owner act a waiting erase carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PendingEraseKind {
    /// The owner's "Lift the hold and erase?" confirm: a hard erase, and an
    /// audience edit erased as a privacy erase leaves it.
    LiftAndErase,
    /// The owner's plain delete, only secret orders keeping it (FIX 1465):
    /// it runs under the reason the owner asked for.
    OwnerDelete,
}

/// One waiting owner erase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingErase {
    pub(crate) confirmed_by: Option<String>,
    pub(crate) confirmed_at: u64,
    pub(crate) kind: PendingEraseKind,
    pub(crate) reason: DeleteReason,
    /// This request's own id. The erase that runs proves it in its writers,
    /// and only the row it ran for is dropped.
    pub(crate) generation: EntityId,
    /// The `erase` act an explicit lift-and-erase waits out in a shared
    /// vault with two or more Owners (FIX 9781).
    pub(crate) veto_act: Option<String>,
}

impl PendingErase {
    /// The same owner act as `other`: a retry of it keeps its generation.
    fn same_request(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.reason == other.reason
            && self.confirmed_by == other.confirmed_by
    }
}

/// Records that the owner's erase of `record` waits. The same request again
/// keeps the row it finds; a different one replaces it, under its own
/// generation. Returns the row as stored.
pub(crate) fn put_pending_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    request: PendingErase,
) -> Result<PendingErase> {
    if let Some(stored) = PENDING_ERASES.get(dbs, txn, record)?
        && stored.same_request(&request)
    {
        return Ok(stored);
    }
    PENDING_ERASES.put(dbs, txn, record, &request)?;
    Ok(request)
}

/// Names the `erase` act the waiting erase of `record` at `generation`
/// waits out (FIX 9781). False when that request no longer waits, or
/// already names an act: the first act named is the one it waits out (FIX
/// 10401).
pub(crate) fn set_pending_veto_act_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    generation: &EntityId,
    act: String,
) -> Result<bool> {
    let Some(mut pending) = PENDING_ERASES.get(dbs, txn, record)? else {
        return Ok(false);
    };
    if pending.generation != *generation || pending.veto_act.is_some() {
        return Ok(false);
    }
    pending.veto_act = Some(act);
    PENDING_ERASES.put(dbs, txn, record, &pending)?;
    Ok(true)
}

/// The explicit lift-and-erase requests that wait with no `erase` act named
/// (FIX 10401): each one whose act never started, as when the confirm's
/// writer committed and its act start did not follow.
pub(crate) fn erases_without_act_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Vec<(EntityId, PendingErase)>> {
    Ok(PENDING_ERASES
        .scan(dbs, txn)?
        .into_iter()
        .filter(|(_, pending)| {
            pending.kind == PendingEraseKind::LiftAndErase && pending.veto_act.is_none()
        })
        .collect())
}

/// The waiting erase of `record`, when one waits.
pub(crate) fn pending_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<PendingErase>> {
    PENDING_ERASES.get(dbs, txn, record)
}

/// The waiting erases whose records nothing holds now, each with its
/// request.
pub(crate) fn due_erases_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Vec<(EntityId, PendingErase)>> {
    let mut due = Vec::new();
    for (record, pending) in PENDING_ERASES.scan(dbs, txn)? {
        if !super::held_in_txn(dbs, txn, record.as_bytes())? {
            due.push((record, pending));
        }
    }
    Ok(due)
}

/// Drops the waiting erase of `record` only while it is still request
/// `generation`: a newer request stays for its own run.
pub(crate) fn drop_pending_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    generation: &EntityId,
) -> Result<()> {
    if PENDING_ERASES
        .get(dbs, txn, record)?
        .is_some_and(|pending| pending.generation == *generation)
    {
        PENDING_ERASES.delete(dbs, txn, record)?;
    }
    Ok(())
}

/// Drops the waiting erase of `record`, whatever its request, as the
/// record's own erase does.
pub(super) fn erase_pending_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
) -> Result<()> {
    PENDING_ERASES.delete(dbs, txn, record)?;
    Ok(())
}

/// A privacy erasure the owner's plain delete queued under secret orders
/// (FIX 1465): where Oneiron hosts the bytes, the record those orders keep
/// serves only their purpose while one stands (C6, FIX 8849), as a refused
/// one's does. Nothing is logged as refused: the owner's act was accepted.
pub(crate) fn use_limit_pending_privacy_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    record: EntityId,
    at: u64,
) -> Result<()> {
    if !super::hosts_bytes(store)
        || super::notice::retaining_holds_in_txn(store, txn, &record)?.is_empty()
    {
        return Ok(());
    }
    super::keep_use_limited_in_txn(store, txn, record, at)
}
