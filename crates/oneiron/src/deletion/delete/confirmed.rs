//! The pending-confirmed-delete gate of a due owner-confirmed erase (FIX 6337).
//!
//! An erase the owner confirmed while a host order kept its record runs from
//! the legal-hold pass once nothing holds it. Its row may go before then, so
//! the writer that would first publish or tear the record re-proves that the
//! erase still waits, and a hold's refusal there names the owner the row
//! records as confirming it. None waiting cancels the erase: nothing is
//! published or torn. Once its tombstone has published, the erase is decided
//! and finishes, whatever a later writer reads.

use std::cell::{Cell, RefCell};

use crate::Vault;
use crate::deletion::LegalHoldActorKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::legal_hold::{HoldActor, pending_erase_by_in_txn};

use super::DeleteEntityOutcome;

/// What a due owner-confirmed erase came to (FIX 6337).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfirmedEraseOutcome {
    /// The erase ran as its rail runs it.
    Completed(DeleteEntityOutcome),
    /// No confirmed erase of the record waited when a writer re-proved it,
    /// before anything was published or torn.
    Cancelled,
}

/// Who the confirmed erase of `record` that waits names as confirming it,
/// as a hold's refusal names them: the owner its row records, else no one.
/// `None` when no erase of it waits.
pub(crate) fn due_erase_requester_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<HoldActor>> {
    Ok(match pending_erase_by_in_txn(&vault.store, txn, record)? {
        None => None,
        Some(None) => Some(HoldActor::UNATTRIBUTED),
        Some(Some(by)) => Some(HoldActor::new(LegalHoldActorKind::Owner, Some(by))),
    })
}

/// A due confirmed erase on the hard-delete rail: the requester its writers
/// proved, and whether one of them found no erase waiting.
#[derive(Debug, Default)]
pub(crate) struct PendingConfirmedErase {
    requester: RefCell<Option<HoldActor>>,
    cancelled: Cell<bool>,
}

impl PendingConfirmedErase {
    /// Re-proves in `txn` that the confirmed erase of `id` still waits, and
    /// returns who its row names. None waiting cancels the erase: the error
    /// ends the rail where it stands, and [`Self::outcome`] reads it as
    /// cancelled.
    pub(crate) fn prove_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<HoldActor> {
        let Some(requester) = due_erase_requester_in_txn(vault, txn, id)? else {
            self.cancelled.set(true);
            return Err(Error::InvalidConfig(
                "no confirmed erase of this record waits".into(),
            ));
        };
        *self.requester.borrow_mut() = Some(requester.clone());
        Ok(requester)
    }

    /// [`Self::prove_in`] while nothing has settled the erase. Once its
    /// publication committed (`settled`), the requester that commit proved:
    /// a published erase is decided, and no later missing row cancels it.
    pub(crate) fn prove_when_unpublished(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        settled: bool,
    ) -> Result<HoldActor> {
        if settled {
            Ok(self.requester())
        } else {
            self.prove_in(vault, txn, id)
        }
    }

    /// The requester last proved, else no one.
    pub(crate) fn requester(&self) -> HoldActor {
        self.requester
            .borrow()
            .clone()
            .unwrap_or(HoldActor::UNATTRIBUTED)
    }

    /// The erase's outcome from its rail's result: cancelled when a writer
    /// found no erase waiting, whatever error that ended the rail with.
    pub(super) fn outcome(
        &self,
        deleted: Result<DeleteEntityOutcome>,
    ) -> Result<ConfirmedEraseOutcome> {
        match deleted {
            Ok(outcome) => Ok(ConfirmedEraseOutcome::Completed(outcome)),
            Err(_) if self.cancelled.get() => Ok(ConfirmedEraseOutcome::Cancelled),
            Err(error) => Err(error),
        }
    }
}

impl Vault {
    /// The legal-hold check of a destructive writer: a hold naming `id`
    /// refuses it in the name of `requester`, the owner a due confirmed
    /// erase's row records (FIX 6337); with none, unattributed, as before.
    pub(crate) fn reject_erase_hold_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        requester: Option<&HoldActor>,
    ) -> Result<()> {
        match requester {
            Some(actor) => self.store.reject_legal_holds_in_txn(txn, &[*id], actor),
            None => self.store.reject_legal_hold_in_txn(txn, id.as_bytes()),
        }
    }
}
