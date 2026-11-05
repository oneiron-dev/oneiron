//! A committed consent answer wakes the connector-call settler. The durable
//! answer remains the authority; this in-memory signal only starts a recheck.

use crate::Vault;

impl Vault {
    /// The connector-call settler waits here beside its periodic repair tick.
    /// Wakes coalesce, including an answer committed while a pass is running.
    pub fn connector_consent_wake(&self) -> &tokio::sync::Notify {
        &self.store.consent_answers
    }

    pub(crate) fn notify_consent_answer(&self) {
        self.store.consent_answers.notify_one();
    }
}
