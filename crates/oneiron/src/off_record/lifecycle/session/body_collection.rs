//! Session-local collection after a body operation releases its pins.

use super::OffRecordSession;

impl OffRecordSession<'_> {
    /// Retries only the digests of pins returned by this save's imports,
    /// after the save has released its state lock and all its body guards.
    pub(in crate::off_record) fn with_imported_body_collection<R>(
        &self,
        operation: impl FnOnce(&mut Vec<[u8; 32]>) -> R,
    ) -> R {
        let mut digests = Vec::new();
        let result = operation(&mut digests);
        for digest in digests {
            self.with_released_body_collection(digest, || ());
        }
        result
    }

    /// Runs after the operation's pins, read transactions and custody guards
    /// have ended. Collection failure never changes its value or error.
    pub(crate) fn with_released_body_collection<R>(
        &self,
        digest: [u8; 32],
        operation: impl FnOnce() -> R,
    ) -> R {
        let result = operation();
        if let Err(error) = self.vault.collect_released_session_body(
            &self.session_ref,
            &self.entry.overlay,
            &digest,
        ) {
            tracing::warn!(
                kind = ?error.kind(),
                "released room body left for the next collector pass or room close"
            );
        }
        result
    }
}
