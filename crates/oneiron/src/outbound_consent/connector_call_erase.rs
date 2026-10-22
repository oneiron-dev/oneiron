//! What a connector call row keeps, and how it goes. An actor's erase
//! reaches every row that keeps what the actor asked (FIX 9159): the held or
//! pending row with the caller's exact arguments, and the acknowledged
//! caller a status read keeps. An off-record caller's arguments are kept
//! sealed under the call's own resume custody, never in the clear, and each
//! row's resume keys retire with it (FIX 9157, 9159).

use heed::RwTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{
    open_connector_resume_in_txn, retire_connector_resume_in_txn, seal_connector_resume_in_txn,
};
use crate::store::Store;

use super::connector_call::{ACKNOWLEDGED_CALLS, PENDING_CALLS, PendingConnectorCall};

/// The custody generation an off-record caller's sealed arguments take.
const ARGUMENTS_GENERATION: u32 = 0;

impl PendingConnectorCall {
    /// Opens the sealed arguments of an off-record caller's row `call_ref`
    /// for a pass that resumes it (FIX 9159), opened only here, by the vault;
    /// any other row comes back as it was read.
    pub(super) fn opened(mut self, store: &Store, call_ref: &EntityId) -> Result<Self> {
        if let Some(sealed) = self.sealed_arguments.take() {
            let snapshot = store.custody_snapshot()?;
            let opened = open_connector_resume_in_txn(
                store,
                &snapshot,
                call_ref,
                ARGUMENTS_GENERATION,
                &sealed,
            )?;
            self.arguments = String::from_utf8(opened.to_vec())
                .map_err(|_| Error::CorruptedIndex("connector call sealed arguments"))?;
            self.off_record = true;
        }
        Ok(self)
    }
}

/// Writes the row of the call `call_ref` in `txn`. An off-record caller's
/// arguments go sealed under the call's resume custody, the stored row's own
/// arguments left empty (FIX 9159); every other row goes as it is.
pub(super) fn put_pending_call_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    call_ref: &EntityId,
    row: &PendingConnectorCall,
) -> Result<()> {
    if !row.off_record || row.arguments.is_empty() {
        return PENDING_CALLS.put(store, txn, call_ref, row);
    }
    let sealed = seal_connector_resume_in_txn(
        store,
        txn,
        call_ref,
        ARGUMENTS_GENERATION,
        row.arguments.as_bytes(),
    )?;
    let stored = PendingConnectorCall {
        arguments: String::new(),
        sealed_arguments: Some(sealed),
        off_record: false,
        ..row.clone()
    };
    PENDING_CALLS.put(store, txn, call_ref, &stored)
}

/// Deletes the row of the call `call_ref` in `txn`, staging the retirement
/// of its resume custody keys in the same writer (FIX 9157, 9159): whatever
/// it kept sealed goes with it. `true` when a row was there.
pub(super) fn delete_pending_call_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    call_ref: &EntityId,
) -> Result<bool> {
    retire_connector_resume_in_txn(store, txn, call_ref)?;
    PENDING_CALLS.delete(store, txn, call_ref)
}

/// Erasing `actor` from the connector calls (FIX 9159): every call row the
/// actor made goes, held, pending delivery, awaiting input or settled, and
/// with it the request it kept and the keys it was sealed under; so does
/// every acknowledged caller that names the actor. A send stays in the
/// intent ledger, so dropping its row never sends it again, and a held call
/// of the actor's is never resumed. Runs in the erase's own transaction;
/// housekeeping finishes the staged key retirements.
pub(crate) fn erase_connector_call_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let principal = actor.to_hex();
    let pending: Vec<EntityId> = PENDING_CALLS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, row)| row.principal_ref == principal)
        .map(|(call_ref, _)| call_ref)
        .collect();
    for call_ref in pending {
        delete_pending_call_in_txn(&vault.store, wtxn, &call_ref)?;
    }
    let acknowledged: Vec<EntityId> = ACKNOWLEDGED_CALLS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, row)| row.principal_ref == principal)
        .map(|(call_ref, _)| call_ref)
        .collect();
    for call_ref in acknowledged {
        ACKNOWLEDGED_CALLS.delete(&vault.store, wtxn, &call_ref)?;
    }
    Ok(())
}

impl Vault {
    /// Carries out the connector resume key retirements a row's delete
    /// staged (FIX 9157), after its writer committed. The intent is durable:
    /// one that cannot run now is logged and runs on the next housekeeping
    /// pass, never failing the delete that already landed.
    pub(crate) fn finish_connector_resume_retirements_after_commit(&self) {
        if let Err(error) = self.store.finish_connector_resume_retirements() {
            tracing::warn!(
                error = %error,
                "connector resume key retirement deferred to the next housekeeping pass"
            );
        }
    }
}
