//! An owner-confirmed erase that waits on a shared vault's veto window
//! (OF-470 C4, FIX 9781). One row per record, in the one pending-erase
//! family. It keeps the request's kind, its reason, its generation and the
//! `erase` act it waits out, so what runs once that act clears is the erase
//! the owner asked for, and a newer request replaces an older one instead of
//! being refused. A request the owner withdrew stays as the record of that
//! withdrawal, who and when, and waits no more (FIX 10401): no read here
//! returns it as waiting, and a new request replaces it. A lift-and-erase
//! keeps its confirm's check-in decision, which the `erase` act a legal-hold
//! pass restarts for it records (row CHECK-IN-LEGAL-HOLD-RESTARTED-ACT-NO-DECISION).

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::check_in::CheckInDecision;
use crate::deletion::DeleteReason;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// An owner erase that waits. Key: id16 (record).
const PENDING_ERASES: SideTable<EntityId, PendingErase, Named> =
    SideTable::new(&side_table::LEGAL_HOLD_PENDING_ERASE);

#[doc(hidden)]
pub(crate) use oneiron_records::store::legal_hold::pending::PendingEraseKind;

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
    /// The owner's withdrawal of this request, once made (FIX 10401).
    pub(crate) withdrawn: Option<EraseWithdrawalRecord>,
    /// The check-in decision of the confirm that made or last repeated this
    /// request before its `erase` act started: the act a legal-hold pass
    /// starts for it records this decision (row
    /// CHECK-IN-LEGAL-HOLD-RESTARTED-ACT-NO-DECISION). None on a row stored
    /// before this field, which the pass restarts with no decision, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) check_in: Option<CheckInDecision>,
}

/// Who withdrew a waiting erase, and when (FIX 10401).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EraseWithdrawalRecord {
    pub(crate) by: String,
    pub(crate) at: u64,
}

impl PendingErase {
    /// The same owner act as `other`: a retry of it keeps its generation. A
    /// withdrawn request is never the same: a new one replaces it.
    fn same_request(&self, other: &Self) -> bool {
        self.withdrawn.is_none()
            && self.kind == other.kind
            && self.reason == other.reason
            && self.confirmed_by == other.confirmed_by
    }

    /// The request still waits: the owner has not withdrawn it.
    fn waits(&self) -> bool {
        self.withdrawn.is_none()
    }
}

/// Records that the owner's erase of `record` waits. The same request again
/// keeps the row it finds, with its generation; while that row names no
/// `erase` act it takes the new confirm's check-in decision, the one the act
/// started next records. A different request replaces it, under its own
/// generation. Returns the row as stored.
pub(crate) fn put_pending_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    request: PendingErase,
) -> Result<PendingErase> {
    if let Some(mut stored) = PENDING_ERASES.get(dbs, txn, record)?
        && stored.same_request(&request)
    {
        if stored.veto_act.is_none() && stored.check_in != request.check_in {
            stored.check_in = request.check_in;
            PENDING_ERASES.put(dbs, txn, record, &stored)?;
        }
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
    if pending.generation != *generation || pending.veto_act.is_some() || !pending.waits() {
        return Ok(false);
    }
    pending.veto_act = Some(act);
    PENDING_ERASES.put(dbs, txn, record, &pending)?;
    Ok(true)
}

/// Takes the `erase` act name off the waiting erase of `record`, as a crash
/// between its confirm's writer and its act start leaves the row (FIX
/// 10401). The act it named; `None` when no erase of `record` waits, or it
/// names no act.
#[cfg(oneiron_test_support)]
pub(crate) fn take_pending_veto_act_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
) -> Result<Option<String>> {
    let Some(mut pending) = pending_erase_in_txn(dbs, txn, record)? else {
        return Ok(None);
    };
    let act = pending.veto_act.take();
    if act.is_some() {
        PENDING_ERASES.put(dbs, txn, record, &pending)?;
    }
    Ok(act)
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
            pending.waits()
                && pending.kind == PendingEraseKind::LiftAndErase
                && pending.veto_act.is_none()
        })
        .collect())
}

/// The waiting erase of `record`, when one waits.
pub(crate) fn pending_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<PendingErase>> {
    Ok(PENDING_ERASES
        .get(dbs, txn, record)?
        .filter(PendingErase::waits))
}

/// Records the owner `by`'s withdrawal at `at` of the waiting erase of
/// `record`, while it is still request `generation` (FIX 10401): the row
/// stays as that withdrawal's record and waits no more. False when that
/// request no longer waits.
pub(crate) fn withdraw_pending_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    generation: &EntityId,
    by: String,
    at: u64,
) -> Result<bool> {
    let Some(mut pending) = pending_erase_in_txn(dbs, txn, record)? else {
        return Ok(false);
    };
    if pending.generation != *generation {
        return Ok(false);
    }
    pending.withdrawn = Some(EraseWithdrawalRecord { by, at });
    PENDING_ERASES.put(dbs, txn, record, &pending)?;
    Ok(true)
}

/// The waiting erases whose records nothing holds now, each with its
/// request.
pub(crate) fn due_erases_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Vec<(EntityId, PendingErase)>> {
    let mut due = Vec::new();
    for (record, pending) in PENDING_ERASES.scan(dbs, txn)? {
        if pending.waits() && !super::held_in_txn(dbs, txn, record.as_bytes())? {
            due.push((record, pending));
        }
    }
    Ok(due)
}

/// Drops the waiting erase of `record` only while it is still request
/// `generation`: a newer request stays for its own run, and a withdrawn one
/// stays as its withdrawal's record (FIX 10401).
pub(crate) fn drop_pending_erase_in_txn(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    record: &EntityId,
    generation: &EntityId,
) -> Result<()> {
    if pending_erase_in_txn(dbs, txn, record)?
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

/// The actor sweep's step over the waiting erases: a hard erase of the asker
/// whose approved check-in a lift-and-erase's confirm applied leaves
/// [`ERASED_CALL_IDENTITY`] where the decision its row keeps named them, as
/// the shared-act scrub does on the act itself (P24-SHAPE Q7 = A), so the act
/// a legal-hold pass restarts never names them. The decision, its basis and
/// the spent check-in stay. The table declares no scrub: an actor's erase
/// deletes each retained copy of a table that does, and this table's copies
/// are legal-hold evidence.
pub(crate) fn erase_pending_erase_requester_in_txn(
    vault: &crate::Vault,
    txn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    for (record, mut pending) in PENDING_ERASES.scan(&vault.store, txn)? {
        let Some(requester) = pending
            .check_in
            .as_mut()
            .and_then(|decision| decision.requester.as_mut())
        else {
            continue;
        };
        let names_actor = *requester == actor.to_hex()
            || EntityId::from_hex(requester).is_ok_and(|named| named == *actor);
        if !names_actor {
            continue;
        }
        ERASED_CALL_IDENTITY.clone_into(requester);
        PENDING_ERASES.put(&vault.store, txn, &record, &pending)?;
    }
    Ok(())
}
