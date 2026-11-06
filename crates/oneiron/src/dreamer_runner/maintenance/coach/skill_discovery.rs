//! Caller-requested output placement for one queued skill-discovery pass.

use rmpv::Value;

use super::{COACH_HOST_QUEUE_KIND, COACH_SKILL_DISCOVERY_FACET, invalid};
use crate::Result;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::skill_attribution::AttributionOutputReadRequests;

impl DreamerRunnerStore<'_> {
    /// Queues a skill-discovery pass with the caller's independent per-output
    /// placement requests. No scope is inferred, and no declaration grants a read.
    /// A caller-supplied dedupe key keeps the queue's ordinary coalescing behavior.
    pub fn enqueue_coach_skill_discovery(
        &self,
        requests: &AttributionOutputReadRequests,
        parent_attempt: Option<AttemptId>,
        dedupe_key: Option<String>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let input = rmpv::ext::to_value(requests).map_err(|_| invalid())?;
        self.vault.with_write_txn_grouped(|txn| {
            self.enqueue_kind_in_txn(
                txn,
                COACH_HOST_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: COACH_SKILL_DISCOVERY_FACET.into(),
                    input,
                    parent_attempt,
                },
                dedupe_key,
                run_id,
                now,
            )
        })
    }
}

/// Nil is the ordinary nightly job. An unknown optional request never refuses
/// the pass or supplies placement to a row.
pub(super) fn output_requests(input: &Value) -> Option<AttributionOutputReadRequests> {
    rmpv::ext::from_value(input.clone()).ok()
}
