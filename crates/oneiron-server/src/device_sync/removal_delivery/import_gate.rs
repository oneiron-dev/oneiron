//! The admission each removal archive import takes (FIX 11796, a device sync
//! admission, FIX 12038), and the reap freeze's thaw that takes in again the
//! archives it refused, in the same run (FIX 12154). The thaw is the
//! freeze's own signal ([`ReapFreeze::thawed`]).

use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::import_kept;
use crate::device_sync::ReapFreeze;
use crate::server::HousekeepingAdmission;

/// The freeze's import admission, noting each import it refuses, and the
/// freeze whose thaw retries them.
pub(super) struct ImportGate {
    pub(super) admit: HousekeepingAdmission,
    refused: Arc<AtomicBool>,
    freeze: ReapFreeze,
}

impl ImportGate {
    /// `freeze`'s admission, with each refusal noted.
    pub(super) fn new(freeze: ReapFreeze) -> Self {
        let refused = Arc::new(AtomicBool::new(false));
        let noted = Arc::clone(&refused);
        let inner = freeze.admission();
        let admit: HousekeepingAdmission = Arc::new(move || {
            let admission = inner();
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

    /// The freeze, for the receiver's own pause between sessions.
    pub(super) fn freeze(&self) -> ReapFreeze {
        self.freeze.clone()
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
            tracing::info!("the reap freeze lifted; kept removal archives are taken in again");
            self.import_after_thaw(vault, credential_file, archives)
                .await;
        }
    }

    /// Takes in the archives kept on disk, the freeze lifted: every import
    /// a refusal left waits there, so none is owed a retry after this one.
    pub(super) async fn import_after_thaw(
        &self,
        vault: &Arc<oneiron::Vault>,
        credential_file: &Path,
        archives: &Path,
    ) {
        self.refused.store(false, Ordering::SeqCst);
        import_kept(vault, &self.admit, credential_file, archives).await;
    }

    /// Returns once an import the freeze refused may be tried again: the
    /// freeze has lifted. Pending while none was refused. Cancel-safe: it
    /// only reads the freeze.
    async fn thawed(&self) {
        if self.refused.load(Ordering::SeqCst) {
            self.freeze.clone().thawed().await;
        } else {
            std::future::pending::<()>().await;
        }
    }
}
