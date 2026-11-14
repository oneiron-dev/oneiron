//! Moved from `crates/oneiron/src/outbound/reply_job.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Where a reply job ended. The outbound receipt stays the authority on
/// the send itself; this names which way the job went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorReplyStage {
    /// The event is not one the agent answers, or it wrote no reply.
    NoReply,
    /// The reply left through the recorded dispatch (delivered, degraded,
    /// suppressed or let go: see `outcome`).
    Dispatched,
    /// The Gate held the reply; the job runs again after a backoff, and
    /// the send goes once the hold is gone.
    Held,
    /// The send failed; the job runs again after a backoff.
    Failed,
    /// The send may have landed; the job ends failed and waits for a look,
    /// never a resend.
    Ambiguous,
    /// The job could not run: the agent, the model or the vault failed. It
    /// runs again after a backoff, unless the failure waits on the owner
    /// (`waits_on_owner`), which ends it failed.
    Fault,
}
