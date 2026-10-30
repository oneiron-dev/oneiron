//! The reap freeze's admission for each batch the device sync connection
//! applies or sends (FIX 12036). Each batch holds one admission until it is
//! done; while the vault is frozen the connection pauses with its socket
//! open, and runs on after the thaw rather than reconnecting. A batch in
//! flight at the freeze holds its admission and finishes.
#![cfg(feature = "mesh")]

use std::time::Duration;

use oneiron::sync::connection::{
    SyncBatchAdmission, SyncBatchAdmit, SyncBatchThaw, SyncBatchVerdict,
};

use crate::server::HousekeepingAdmission;

/// How often a paused connection asks the freeze again: the admission it
/// holds names no thaw of its own.
const THAW_POLL: Duration = Duration::from_secs(1);

/// The host's admission as the connection asks it per batch: `Pause` while
/// it refuses.
pub(super) struct FreezeAdmission(pub(super) HousekeepingAdmission);

impl SyncBatchAdmission for FreezeAdmission {
    fn admit(&self) -> SyncBatchAdmit<'_> {
        let verdict = match (self.0)() {
            Some(admitted) => SyncBatchVerdict::Admitted(admitted),
            None => SyncBatchVerdict::Pause,
        };
        Box::pin(std::future::ready(verdict))
    }

    /// Resolves once the freeze admits again; that probe's admission goes
    /// at once, and the next batch asks for its own.
    fn thawed(&self) -> SyncBatchThaw<'_> {
        Box::pin(async move {
            loop {
                tokio::time::sleep(THAW_POLL).await;
                if (self.0)().is_some() {
                    return;
                }
            }
        })
    }
}
