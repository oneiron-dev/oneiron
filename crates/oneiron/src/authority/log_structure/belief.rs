//! The belief the fold past an adopted image reads (FIX
//! [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]): the store door's view without a
//! root request's wait, over the stored rows, the rows the fold takes as
//! stored, and, while a pending probe runs, the whole batch it judges.

use std::cell::RefCell;

use super::*;
use crate::store::Store;

thread_local! {
    /// The whole batch a pending probe judges (`pending_history_of`), for
    /// belief only: each probe still folds one row with the batch rows it
    /// rests on. None outside such a probe. Arriving folds are never cached,
    /// and none reads a cached fold, so no cached view sees it.
    static STAGED_BATCH: RefCell<Option<Vec<AuthorityLogEntry>>> =
        const { RefCell::new(None) };
}

/// Holds [`STAGED_BATCH`] while a pending probe runs, and restores the
/// earlier value on drop.
pub(in crate::authority) struct StagedBatchGuard {
    earlier: Option<Vec<AuthorityLogEntry>>,
}

impl Drop for StagedBatchGuard {
    fn drop(&mut self) {
        STAGED_BATCH.with(|staged| *staged.borrow_mut() = self.earlier.take());
    }
}

/// Counts `batch` in the belief [`fold_belief_structure_in_txn`] reads on
/// this thread until the guard drops, so a key a row of the batch enrolls
/// vouches for the batch rows it signs (#9476 review round 2).
pub(in crate::authority) fn stage_batch_for_belief(
    batch: Vec<AuthorityLogEntry>,
) -> StagedBatchGuard {
    let earlier = STAGED_BATCH.with(|staged| staged.borrow_mut().replace(batch));
    StagedBatchGuard { earlier }
}

impl LocalRoots {
    /// [`Self::read_in_txn`] with a wait a root request committed left out,
    /// unresolved: resolving it reads the fold, so the fold past an adopted
    /// image reads its belief this way (FIX
    /// [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]). It believes no fewer rows
    /// than the store gate: an awaited anchor's rows are believed under
    /// neither reading ([`AuthorityStructure::believes`]), and a wait made at
    /// this install's pin door stays.
    fn read_without_request_wait_in_txn(
        store: &Store,
        txn: &heed::RoTxn<'_>,
    ) -> crate::error::Result<Self> {
        let row = crate::authority::pinned_root::read_pin_row_in_txn(store, txn)?;
        let mut local = Self::default();
        if let Some(pin) = row.pin {
            local.anchors.insert(pin.anchor_key);
            local.roots.insert(pin.id);
        }
        if let Some(MachineAdmitter::Anchor(anchor)) = row.earlier {
            local.anchors.insert(anchor);
        }
        local
            .roots
            .extend(row.awaiting.filter(|_| row.awaited_for.is_none()));
        Ok(local)
    }
}

/// The structure the store door's view reads (`log_budget::door_view`), over
/// the same rows, under [`LocalRoots::read_without_request_wait_in_txn`]:
/// the fold past an adopted image reads which tail rows this install
/// believes here, since resolving a root request's wait reads that fold (FIX
/// [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]). The `arriving` rows, which the
/// fold takes as stored though they are not, and a pending probe's staged
/// batch ([`stage_batch_for_belief`]) count as stored rows do: the belief is
/// the one the fold reads once they are stored (#9476 review round 2).
pub(in crate::authority) fn fold_belief_structure_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    arriving: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> crate::error::Result<AuthorityStructure> {
    let evidence = crate::authority::checkpoint_adopt::cached_adopted_evidence_in_txn(store, txn)?;
    let mut entries = Vec::new();
    for (id, body) in authority_log_rows_in_txn(store, txn)? {
        if evidence
            .as_ref()
            .is_some_and(|evidence| evidence.covers_id(&id))
        {
            continue;
        }
        entries.push(open_vault_authority_body_in_txn(store, txn, &body)?);
    }
    entries.extend(arriving.values().cloned());
    STAGED_BATCH.with(|staged| entries.extend(staged.borrow().iter().flatten().cloned()));
    let carried = evidence
        .iter()
        .flat_map(|evidence| evidence.bodies().values());
    Ok(authority_structure_under(
        carried.chain(&entries),
        LocalRoots::read_without_request_wait_in_txn(store, txn)?,
    ))
}
