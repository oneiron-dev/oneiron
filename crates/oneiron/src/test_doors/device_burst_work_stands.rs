//! Door for `tests/device_burst_admission.rs`: whether an own device's
//! retained batch the burst core handed back still stands, as the writer
//! that persists its replay judges it (#9226 review), read in a transaction
//! of its own.

use crate::sync::federation_burst::DeviceBurstWork;
use crate::{Result, Vault};

/// [`DeviceBurstWork::stands_in_txn`] in a read of its own.
///
/// # Errors
/// What it returns, or a store error opening the read.
pub fn device_burst_work_stands(vault: &Vault, work: &DeviceBurstWork) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    work.stands_in_txn(vault, &txn)
}
