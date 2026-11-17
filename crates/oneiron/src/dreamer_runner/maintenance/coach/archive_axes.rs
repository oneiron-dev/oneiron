//! The Coach's output-archive axes job (ARM05 P2): one per request, queued by
//! `vault.research.archive.propose_axes` and run by the host at once, on the
//! wake beside the host Coach worker's tick.

use std::sync::Arc;

use rmpv::Value;

use super::{COACH_ARCHIVE_AXES_FACET, COACH_HOST_QUEUE_KIND, invalid};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::{EntityId, Result, Vault};

/// The job input's one key: the request id, as hex.
const INPUT_KEY: &str = "request";

/// Queues the host's job for the axes request `request`, under the caller's
/// writer. Its dedupe key keeps one job per request.
pub(crate) fn enqueue_coach_archive_axes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &EntityId,
    now: u64,
) -> Result<()> {
    let hex = request.to_hex();
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HOST_QUEUE_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_ARCHIVE_AXES_FACET.into(),
            input: Value::Map(vec![(Value::from(INPUT_KEY), Value::from(hex.as_str()))]),
            parent_attempt: None,
        },
        Some(format!("{COACH_ARCHIVE_AXES_FACET}:{hex}")),
        None,
        now,
    )?;
    Ok(())
}

impl Vault {
    /// The axes request a leased `coach.archive_axes` attempt answers.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, or a payload that
    /// names no request.
    pub fn coach_archive_axes_target(&self, attempt: &DreamerAdmittedAttempt) -> Result<EntityId> {
        self.require_coach_attempt(attempt, COACH_ARCHIVE_AXES_FACET)?;
        match &attempt.status.payload.input {
            Value::Map(fields) if fields.len() == 1 && fields[0].0.as_str() == Some(INPUT_KEY) => {
                let hex = fields[0].1.as_str().ok_or_else(invalid)?;
                EntityId::from_hex(hex).map_err(|_| invalid())
            }
            _ => Err(invalid()),
        }
    }

    /// What the host's Coach worker waits on beside its tick: a per-request
    /// Coach host job committed since its last round. Wakes coalesce, and one
    /// that comes while a round runs starts the next round when it ends.
    pub fn coach_host_wake(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.store.coach_host_requests)
    }

    /// Wakes the host's Coach worker, after the commit that queued its job.
    pub(crate) fn wake_coach_host(&self) {
        self.store.coach_host_requests.notify_one();
    }
}
