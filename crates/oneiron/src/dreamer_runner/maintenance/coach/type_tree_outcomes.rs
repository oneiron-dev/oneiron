//! Explicit output placement for a queued type-tree upkeep or fork pass.

use std::collections::BTreeMap;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{
    COACH_FORK_PROMOTE_FACET, COACH_HOST_QUEUE_KIND, COACH_TYPE_TREE_UPKEEP_FACET, invalid,
};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::skill_reliability::OutcomeReadPosition;
use crate::{EntityId, Result};

/// Each key names the exact skill head and leader pack receipt passed to the
/// native outcome door. Placement is independent caller data, never a read grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeTreeOutcomeReadRequests {
    pub outcomes: BTreeMap<(EntityId, String), OutcomeReadPosition>,
}

impl TypeTreeOutcomeReadRequests {
    pub(crate) fn from_input(input: &Value) -> Option<Self> {
        rmpv::ext::from_value(input.clone()).ok()
    }
}

impl DreamerRunnerStore<'_> {
    /// Queues the project fork, upkeep and leaf-promotion pass with explicit
    /// placement for individual new outcomes. The ordinary advisory dedupe applies.
    pub fn enqueue_coach_fork_promote_with_requests(
        &self,
        requests: &TypeTreeOutcomeReadRequests,
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
                    attempt_type: COACH_FORK_PROMOTE_FACET.into(),
                    input,
                    parent_attempt,
                },
                dedupe_key,
                run_id,
                now,
            )
        })
    }

    /// Queues type-tree upkeep with explicit placement for individual new
    /// settled-team outcomes. The caller controls the ordinary advisory dedupe.
    pub fn enqueue_coach_type_tree_upkeep_with_requests(
        &self,
        requests: &TypeTreeOutcomeReadRequests,
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
                    attempt_type: COACH_TYPE_TREE_UPKEEP_FACET.into(),
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
