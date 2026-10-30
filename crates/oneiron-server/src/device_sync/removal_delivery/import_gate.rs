//! The admission each removal archive import takes (FIX 11796), and the
//! reap freeze's thaw that takes in again the archives it refused, in the
//! same run (FIX 12154). The thaw is the freeze's own signal: its epoch,
//! which a thaw closes as it starts the next.

use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{FreezeEpoch, import_kept};
use crate::server::HousekeepingAdmission;

/// The host's import admission, noting each import the reap freeze refuses,
/// and the freeze's epoch where the host has one.
pub(super) struct ImportGate {
    pub(super) admit: HousekeepingAdmission,
    refused: Arc<AtomicBool>,
    freeze: Option<FreezeEpoch>,
}

impl ImportGate {
    /// `admit`, the host's gate, with each refusal noted; `freeze`, the
    /// host's freeze epoch where it has one.
    pub(super) fn new(admit: HousekeepingAdmission, freeze: Option<FreezeEpoch>) -> Self {
        let refused = Arc::new(AtomicBool::new(false));
        let noted = Arc::clone(&refused);
        let admit: HousekeepingAdmission = Arc::new(move || {
            let admission = admit();
            if admission.is_none() {
                noted.store(true, Ordering::SeqCst);
            }
            admission
        });
        Self {
            admit,
            refused,
            freeze,
        }
    }

    /// Each time the freeze that refused an import lifts, takes in the
    /// archives kept on disk again. It never returns: the receiver polls it
    /// beside the session in flight, which it never cancels, and drops it
    /// when that session ends; a sweep under way runs to its end.
    pub(super) async fn retry_after_thaws(
        &self,
        vault: &Arc<oneiron::Vault>,
        credential_file: &Path,
        archives: &Path,
    ) -> Infallible {
        loop {
            self.thawed().await;
            self.refused.store(false, Ordering::SeqCst);
            tracing::info!("the reap freeze lifted; kept removal archives are taken in again");
            import_kept(vault, &self.admit, credential_file, archives).await;
        }
    }

    /// Returns once an import the freeze refused may be tried again: the
    /// freeze has lifted. Pending while none was refused, or with no epoch
    /// to watch. Cancel-safe: it only reads the epoch.
    async fn thawed(&self) {
        match &self.freeze {
            Some(epoch) if self.refused.load(Ordering::SeqCst) => {
                // A thaw closes the frozen epoch; an epoch that reads
                // unpaused holds no freeze.
                let _ = epoch().wait_for(|paused| !*paused).await;
            }
            _ => std::future::pending().await,
        }
    }
}
