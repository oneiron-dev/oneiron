//! Budget legibility envelope derived from one BudgetGuard read.

use crate::llm::BudgetRead;

use super::deadline::{DREAMER_WRAP_UP_NOTICE_PERCENT, WakePassDeadline};

/// Budget legibility attached to EVERY host-call response inside a wake
/// pass (1184-D4-D): remaining budget, remaining wall-clock, the wrap-up
/// notice, and the finalize deadline once the graceful-wrap window opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BudgetLegibilityEnvelope {
    pub remaining_units: u64,
    pub limit_units: u64,
    pub remaining_ms: u64,
    pub wrap_up: bool,
    pub finalize_by_ms: Option<u64>,
}

/// Composes the legibility envelope from the ONE wake-budget counter read
/// ([`BudgetRead`]) and the pass deadline. The runner-store reservation
/// ledger is NOT consulted (design §D5).
#[must_use]
pub fn legibility_envelope(
    read: &BudgetRead,
    deadline: &WakePassDeadline,
    wrap_fired: bool,
    finalize: bool,
) -> BudgetLegibilityEnvelope {
    BudgetLegibilityEnvelope {
        remaining_units: read.remaining_units,
        limit_units: read.limit_units,
        remaining_ms: deadline.remaining_ms(),
        wrap_up: wrap_fired,
        finalize_by_ms: finalize.then(|| deadline.remaining_ms()),
    }
}

/// [`legibility_envelope`] with wrap/finalize derived from the same read:
/// wrap-up once `max(counter_percent, clock_percent) >= 80`, finalize once
/// the deadline enters its graceful-wrap window.
#[must_use]
pub fn current_legibility(
    read: &BudgetRead,
    deadline: &WakePassDeadline,
) -> BudgetLegibilityEnvelope {
    let wrap_fired =
        read.depleted_percent().max(deadline.elapsed_percent()) >= DREAMER_WRAP_UP_NOTICE_PERCENT;
    legibility_envelope(read, deadline, wrap_fired, deadline.in_finalize_window())
}
