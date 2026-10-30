//! The reap freeze's admission for each batch the device sync connection
//! applies or sends (FIX 12036). Each batch holds one admission until it is
//! done; while the vault is frozen the connection pauses with its socket
//! open, and runs on after the thaw rather than reconnecting. A batch in
//! flight at the freeze holds its admission and finishes.
#![cfg(feature = "mesh")]

use oneiron::sync::connection::{
    SyncBatchAdmission, SyncBatchAdmit, SyncBatchThaw, SyncBatchVerdict,
};

use super::ReapFreeze;

/// The reap freeze as the connection asks it per batch: `Pause` while the
/// vault is frozen, until the freeze's own thaw.
pub(super) struct FreezeAdmission(pub(super) ReapFreeze);

impl SyncBatchAdmission for FreezeAdmission {
    fn admit(&self) -> SyncBatchAdmit<'_> {
        let verdict = match self.0.admit() {
            Some(admitted) => SyncBatchVerdict::Admitted(admitted),
            None => SyncBatchVerdict::Pause,
        };
        Box::pin(std::future::ready(verdict))
    }

    fn thawed(&self) -> SyncBatchThaw<'_> {
        let mut freeze = self.0.clone();
        Box::pin(async move { freeze.thawed().await })
    }
}
