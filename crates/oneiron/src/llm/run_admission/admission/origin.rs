//! Where a run's calls come from: what a bound run serves (FIX 4453), what
//! a handle names about its calls (FIX 5760, FIX 8970), the worlds their
//! receipts name (DEC-0005 fix 12), the resident whose share they draw on
//! (FIX 7767), and the memory-work mark a host sets on a run (FIX 11003).
use std::sync::atomic::Ordering;

use super::{RunAdmission, RunInner};

#[doc(hidden)]
pub use oneiron_records::llm::run_admission::admission::origin::RunAttribution;

/// What a handle names about the calls admitted through it: the rows their
/// input was assembled from ([`RunAdmission::sourced`]), the worlds of those
/// rows, and who acted to start them ([`RunAdmission::initiated_by`]).
pub(in crate::llm::run_admission) struct CallOrigin {
    pub(in crate::llm::run_admission) sources: Option<Vec<crate::EntityId>>,
    /// The live worlds of `sources` as the run's receipt sink read them when
    /// the call was admitted ([`super::RunReceiptSink::source_worlds`]).
    pub(in crate::llm::run_admission) source_worlds: Option<Vec<crate::EntityId>>,
    pub(in crate::llm::run_admission) initiator: Option<crate::EntityId>,
}

/// The worlds every receipt of one call names (DEC-0005 world privacy, fix
/// 12): its `Admitted` row's, and the same on its `Dispatched`, `Settled`
/// and `Denied` rows, which join it by lease.
#[derive(Debug, Clone, Default)]
pub(in crate::llm::run_admission) struct CallWorlds {
    /// The world the call named in its scope; `None` for a paid connector.
    pub(in crate::llm::run_admission) world: Option<crate::EntityId>,
    /// The live worlds of the rows its input was assembled from.
    pub(in crate::llm::run_admission) source_worlds: Option<Vec<crate::EntityId>>,
}

impl RunAdmission {
    /// What this handle names about its calls. The worlds of its source rows
    /// are read here, once per admission.
    pub(super) fn origin(&self) -> CallOrigin {
        CallOrigin {
            sources: self.sources.clone(),
            source_worlds: self.source_worlds(),
            initiator: self.initiator,
        }
    }

    /// The live worlds of the rows this handle names as its calls' input,
    /// as the run's receipt sink reads them now; `None`, unknown, when the
    /// handle names no rows or the sink proves no world for one of them.
    pub(super) fn source_worlds(&self) -> Option<Vec<crate::EntityId>> {
        self.sources
            .as_deref()
            .and_then(|rows| self.inner.receipts.source_worlds(rows))
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
