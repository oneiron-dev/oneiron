//! Test-only hook for the REDACTION_AUDIT rematerialization race pin. The
//! armed writes land just before the same-txn recheck+verify+put path starts,
//! so production code must observe mid-flight lease revocation or local
//! divergent receipt bytes before admitting the remote receipt.

use std::cell::RefCell;

use crate::entity_id::EntityId;
use crate::{Error, Result, Vault};

thread_local! {
    static RECEIPT_REVOCATION: RefCell<Option<(String, Vec<u8>)>> = const { RefCell::new(None) };
    static RECEIPT_LOCAL_WRITE: RefCell<Option<(EntityId, Vec<u8>)>> = const { RefCell::new(None) };
}

pub fn arm_receipt_revocation_race(lease_key: String, revoked_row: Vec<u8>) {
    RECEIPT_REVOCATION.with(|slot| {
        *slot.borrow_mut() = Some((lease_key, revoked_row));
    });
}

pub fn arm_receipt_local_write_race(id: EntityId, local_blob: Vec<u8>) {
    RECEIPT_LOCAL_WRITE.with(|slot| {
        *slot.borrow_mut() = Some((id, local_blob));
    });
}

pub(crate) fn run_receipt_revocation_race(vault: &Vault) -> Result<()> {
    let armed = RECEIPT_REVOCATION.with(|slot| slot.borrow_mut().take());
    if let Some((lease_key, revoked_row)) = armed {
        if revoked_row.is_empty() {
            return Err(Error::InvariantViolation("empty revoked lease test row"));
        }
        vault.sync_state_put(&lease_key, &revoked_row)?;
    }
    let armed = RECEIPT_LOCAL_WRITE.with(|slot| slot.borrow_mut().take());
    if let Some((id, local_blob)) = armed {
        if local_blob.is_empty() {
            return Err(Error::InvariantViolation("empty local receipt test row"));
        }
        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &local_blob)?;
            Ok(())
        })?;
    }
    Ok(())
}
