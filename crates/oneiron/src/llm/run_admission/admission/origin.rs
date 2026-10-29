//! Where a run's calls come from: what a bound run serves (FIX 4453), what
//! a handle names about its calls (FIX 5760, FIX 8970), the resident whose
//! share they draw on (FIX 7767), and the memory-work mark a host sets on a
//! run (FIX 11003).
use std::sync::atomic::Ordering;

use serde::Serialize;

use super::{RunAdmission, RunInner};

/// What a bound run's calls serve, as the engine stamped it before the run
/// began (FIX 4453): the agent, its free-time cycle and item, the label every
/// call carries and the spend scope its spend lands on. Fixed for the run's
/// life; never read from a prompt or from the run's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunAttribution {
    pub agent: crate::EntityId,
    pub cycle: crate::EntityId,
    pub item: crate::EntityId,
    pub purpose: crate::llm::CallPurpose,
    pub spend_scope: String,
}

/// What a handle names about the calls admitted through it: the rows their
/// input was assembled from ([`RunAdmission::sourced`]) and who acted to
/// start them ([`RunAdmission::initiated_by`]).
pub(in crate::llm::run_admission) struct CallOrigin {
    pub(in crate::llm::run_admission) sources: Option<Vec<crate::EntityId>>,
    pub(in crate::llm::run_admission) initiator: Option<crate::EntityId>,
}

impl RunAdmission {
    /// What this handle names about its calls.
    pub(super) fn origin(&self) -> CallOrigin {
        CallOrigin {
            sources: self.sources.clone(),
            initiator: self.initiator,
        }
    }

    /// This run, marked as memory work by the host that started it (FIX
    /// 11003): writes, recall and retrieval are free for everyone (ARCH-0011
    /// `#budget-lease`), so a host-paid call of the run takes no hold on the
    /// vault's allocation, and draws on no resident's share. Every other rule
    /// holds: the run's line, its one-use permits, their receipts and the
    /// usage each settlement reports. Host code marks a run it starts, before
    /// its first call; no caller can name the mark.
    #[must_use]
    pub fn for_memory_work(self) -> Self {
        self.inner.memory_work.store(true, Ordering::Relaxed);
        self
    }
}

impl RunInner {
    /// The resident whose share a call draws on: the handle's initiator,
    /// else the agent a bound run serves. `None` is the vault's own work,
    /// which draws on the allocation alone.
    pub(in crate::llm::run_admission) fn resident(
        &self,
        origin: &CallOrigin,
    ) -> Option<crate::EntityId> {
        origin
            .initiator
            .or_else(|| self.attribution.as_ref().map(|bound| bound.agent))
    }

    /// Whether the host marked this run as memory work.
    pub(in crate::llm::run_admission) fn memory_work(&self) -> bool {
        self.memory_work.load(Ordering::Relaxed)
    }
}
