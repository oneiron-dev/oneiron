//! The signature-verification door (FIX 2095): a T0 door on a read
//! snapshot, so checking an unauthenticated request's signature never takes
//! the vault's writer.

use super::storage::read_record_for_ref_in_txn;
use super::types::DoorInjectionReceipt;
use crate::error::Result;
use crate::vault::Vault;

impl Vault {
    /// [`Vault::inject_secret_at_door`] for verifying an inbound request's
    /// signature: the same name resolution, live floor, T0 admission, door
    /// policy, revocation, status and read-scope checks, on one read
    /// snapshot instead of the write transaction. A flood of forged requests
    /// contends nothing. The snapshot is released before `apply` runs, the
    /// value stays [`Zeroizing`](zeroize::Zeroizing) for the door's own
    /// lifetime and is never returned or kept, and no lease row is read or
    /// written. Nothing is written, as on every T0 door.
    pub fn inject_secret_for_verification_at_door(
        &self,
        secret_ref: &str,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let rtxn = self.store.env.read_txn()?;
        let (id, rec) = read_record_for_ref_in_txn(&self.store, &rtxn, secret_ref)?;
        let (generation, value) = self.admit_t0_value_in_txn(&rtxn, &id, &rec, effector)?;
        drop(rtxn);
        apply(&value)?;
        Ok(self.door_injection_receipt(secret_ref, effector, generation))
    }
}
