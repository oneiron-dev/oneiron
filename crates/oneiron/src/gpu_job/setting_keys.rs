//! The GPU job step's Setting keys (pass 34, 9.3; row W1; the lead's POLICY AS SETTINGS, 25 Nov
//! 00:04): each number the step decides by is a key with its design value as its default, read
//! here and nowhere else.

use crate::Vault;
use crate::error::Result;
use crate::setting::Kind;

fn five_minutes_secs() -> u64 {
    super::SESSION_RENEW_LEAD_DEFAULT_SECS
}

crate::setting::setting_keys! {
    /// How long before a session chunk's maximum, in seconds of that chunk's run time, the host's
    /// step quotes, admits and sends the session's next paid chunk (pass 34, 9.3; row W1).
    /// Default 300. It must exceed the host's step, its send timeout, the node's stop grace and
    /// the node's renewal margin; a value at or below that floor renews nothing, so the session
    /// ends at the end of its chunk. Longer holds the next chunk's money sooner; shorter risks a
    /// renewal the node refuses as too late. Neither is tighter.
    pub(crate) JOBS_SESSIONS_RENEW_LEAD_SECS: u64 = "jobs.sessions.renew_lead_secs" {
        kind: Kind::new(five_minutes_secs).neutral(),
    };
}

impl Vault {
    /// `jobs.sessions.renew_lead_secs`, read once per renewal the step considers.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn gpu_session_renew_lead_secs(&self) -> Result<u64> {
        self.with_read_snapshot(|txn| {
            Ok(JOBS_SESSIONS_RENEW_LEAD_SECS
                .read_in_txn(self, txn, &[], None)?
                .value)
        })
    }
}
