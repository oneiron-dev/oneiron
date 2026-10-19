//! The one Frontier-tier binding a compaction may wear (FIX 4465 C, Engine
//! 10-19): an agent whose profile names `self`, under a row that selects the
//! live fork, forks its own live request on the rung that admitted it. The
//! registry still refuses every frontier backend; this admits one capture,
//! per flight, for the run that made it.

use super::CompactionDriver;
use crate::WriteActor;
use crate::agent_def::CompactionOwnership;
use crate::code_run::{AdmittedLiveFork, LiveCompactionFork};
use crate::compaction::SelfCompactionUnavailable;
use crate::llm::SelfCompactionSource;

impl CompactionDriver {
    /// Admits `captured`, the live fork its backend captured at the flight's
    /// breakpoint, as the flight's binding: the narrow Frontier exception.
    /// It holds only for an engine-owned profile whose writer is `self`, for
    /// a capture taken under a row that selects the live fork, for `byline`,
    /// the run's own actor. Anything else is refused, typed, and the flight
    /// keeps its window; a capture that failed keeps its own reason.
    pub(crate) fn admit_self_live_binding(
        &self,
        byline: WriteActor,
        captured: Result<LiveCompactionFork, SelfCompactionUnavailable>,
    ) -> Result<AdmittedLiveFork, SelfCompactionUnavailable> {
        let fork = captured?;
        let admitted = self.profile.compaction == CompactionOwnership::Engine
            && self.profile.writes_as_self()
            && fork.source() == SelfCompactionSource::LiveFork
            && fork.writer() == byline.entity_ref();
        if admitted {
            Ok(AdmittedLiveFork::admitted(fork))
        } else {
            Err(SelfCompactionUnavailable::LiveForkNotAdmitted)
        }
    }
}
