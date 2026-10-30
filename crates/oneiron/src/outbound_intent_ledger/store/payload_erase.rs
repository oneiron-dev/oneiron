//! What the owner's erase of an outbound call's request leaves (KS7-4b, FIX
//! 5688): evidence only.
//!
//! An erase that takes a call's frozen request (the owner's erase of that
//! one call, or its actor's or its recipient's erase, FIX 9283 and 10953)
//! keeps the row's id, attempt binding, accounting, state and delivery
//! knowledge, and in the same transaction erases the call's checkpoint
//! compartment and stages its leaf's retirement, so no old checkpoint opens
//! the request again either. The finishers retire the keys after the commit
//! and only warn when they cannot: the erase has committed, and its intents
//! stay for the next pass.
//!
//! The erase never waits for a sender in flight (Engine 10-20 08:4x, ruling
//! 5). A send that read its row before the erase stops at its next send
//! ([`IntentLedgerRecord::erased_since_read`]), and nothing becomes an empty
//! sendable request.

use heed::RwTxn;

use super::super::payload::{payload_erased, sealed_custody_ref};
use super::super::settlement::{forget_remote_task_in_txn, settle_reservation_in_txn};
use super::super::types::{
    IntentEscalationReason, IntentLedgerRecord, IntentLedgerResult, IntentState,
    RecordedOutboundOutcome,
};
use super::checkpoint::call;
use super::{AttemptCallKey, INTENT_ATTEMPT_INDEX, force_sync, get_ledger_record, put_erased_record};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::Error;
use crate::secret_custody::retire_connector_resume_in_txn;
use crate::store::checkpoint_payload::Subtype;
use crate::store::checkpoint_payload::retirement::{PayloadDisposition, settle_owner_in_txn};

/// The owner's erase of call `attempt_id`/`call_seq`'s frozen request, in
/// `wtxn`: the evidence-only disposition. The row keeps its id, attempt
/// binding, accounting, state and delivery knowledge and loses its request;
/// a sealed request's key retires with it, and the call's checkpoint
/// compartment goes too ([`put_erased_record`]). A send still Pending or
/// Deferred stops for [`IntentEscalationReason::OwnerErased`], keeping that
/// it may have crossed the wire; a settled send stays as it settled, and a
/// send that certainly never went gives its reserved budget back. `false`
/// for a call with no row here, or one whose request is already erased.
///
/// # Errors
///
/// A row that does not read; storage and custody faults.
pub(crate) fn erase_call_request_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    attempt_id: AttemptId,
    call_seq: u64,
) -> IntentLedgerResult<bool> {
    let key = AttemptCallKey {
        attempt_id,
        call_seq,
    };
    let Some(id) = INTENT_ATTEMPT_INDEX.get(&vault.store, &*wtxn, &key)? else {
        return Ok(false);
    };
    let Some(mut record) = get_ledger_record(vault, &*wtxn, &id)? else {
        return Ok(false);
    };
    if payload_erased(record.payload())? {
        return Ok(false);
    }
    if let Some(custody_ref) = sealed_custody_ref(record.payload())? {
        retire_connector_resume_in_txn(&vault.store, wtxn, &custody_ref)?;
    }
    if matches!(record.state, IntentState::Pending | IntentState::Deferred) {
        record.delivery_uncertain |=
            record.recorded_outcome.is_none() || record.state == IntentState::Deferred;
        record.state = IntentState::Abandoned;
        record.recorded_outcome = Some(RecordedOutboundOutcome::Abandoned(
            IntentEscalationReason::OwnerErased,
        ));
    }
    put_erased_record(vault, wtxn, record)?;
    forget_remote_task_in_txn(vault, wtxn, &id)?;
    if let Some(erased) = get_ledger_record(vault, &*wtxn, &id)? {
        settle_reservation_in_txn(vault, wtxn, &erased)?;
    }
    Ok(true)
}

impl Vault {
    /// [`erase_call_request_in_txn`] in a writer of its own: the owner's
    /// erase of one outbound call's request. After the commit the request
    /// key's and the compartment leaf's retirements run, each only warning
    /// when it cannot run now: its intent stays for the next housekeeping
    /// pass, and the erase that committed stands.
    ///
    /// # Errors
    ///
    /// A row that does not read; storage and custody faults, before the
    /// commit.
    #[allow(
        dead_code,
        reason = "the owner's per-call erase surface calls it; until it lands an actor's or a recipient's erase reaches calls (Engine 10-20 08:4x, ruling 4)"
    )]
    pub(crate) fn erase_outbound_call_request(
        &self,
        attempt_id: AttemptId,
        call_seq: u64,
    ) -> IntentLedgerResult<bool> {
        let mut wtxn = self.store.env.write_txn().map_err(Error::from)?;
        let erased = erase_call_request_in_txn(self, &mut wtxn, attempt_id, call_seq)?;
        wtxn.commit().map_err(Error::from)?;
        force_sync(self)?;
        if erased {
            self.finish_connector_resume_retirements_after_commit();
            self.store.finish_checkpoint_payload_retirements_after_commit();
        }
        Ok(erased)
    }
}

/// Erases call `attempt_id`/`call_seq`'s checkpoint compartment in `wtxn`,
/// the transaction whose erase took the call's request: every incarnation
/// is marked erased and its leaf's retirement staged. Nothing while KS-7 is
/// off, and nothing for a call no checkpoint sealed.
///
/// # Errors
///
/// Storage faults, and an incarnation row that does not decode.
pub(crate) fn erase_call_compartment_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    attempt_id: &AttemptId,
    call_seq: u64,
) -> crate::Result<()> {
    let owner = call(attempt_id, call_seq)?;
    settle_owner_in_txn(
        &vault.store,
        wtxn,
        Subtype::OutboundCall,
        &owner.owner32,
        PayloadDisposition::Erase,
    )?;
    Ok(())
}

impl IntentLedgerRecord {
    /// This row as stored, when an owner's erase took its request since this
    /// copy, a send about to go, was read: the row as the erase left it,
    /// settled (an erased request never stays Pending), whose replay says
    /// why the send stops. `None` lets the send go.
    ///
    /// # Errors
    ///
    /// A stored row that does not read.
    pub(crate) fn erased_since_read(&self, vault: &Vault) -> IntentLedgerResult<Option<Self>> {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let Some(stored) = get_ledger_record(vault, &txn, &self.id)? else {
            return Ok(None);
        };
        Ok(payload_erased(stored.payload())?.then_some(stored))
    }
}
