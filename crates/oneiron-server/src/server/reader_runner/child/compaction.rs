//! The child's ordinary host-metered compaction, on its own spend scope.

use oneiron::agent_dispatch::SpendScopeId;
use oneiron::claim::CallerLocality;
use oneiron::code_run::{
    HostSelfDispatcher, ReaderRunEnd, ScopedChildProfile, bind_compaction_caller,
};
use oneiron::engine_executor::{EngineNativeExecutor, RunCompaction, WindowFullReason};
use std::time::Duration;

use super::{Child, unix_millis_now};

pub(in crate::server::reader_runner) struct CompactionBinding {
    pub(super) caller: CallerLocality,
    pub(super) spend: Option<SpendScopeId>,
}

impl Child {
    pub(in crate::server::reader_runner) fn profiled_compaction_binding(
        caller: CallerLocality,
    ) -> CompactionBinding {
        CompactionBinding {
            caller,
            spend: None,
        }
    }

    pub(super) fn compaction(
        &self,
        dispatcher: &HostSelfDispatcher<'_>,
        binding: CompactionBinding,
        profile: Option<&ScopedChildProfile>,
    ) -> Option<RunCompaction> {
        let host = bind_compaction_caller(dispatcher.actor(), binding.caller, None);
        // A nominal queue label, never a credential or a grant. Siblings take
        // one parent's turn; the job's actor and scope bind authority and spend.
        let queue = format!("reader:{}", self.job.binding.parent_run.to_hex());
        match profile {
            Some(profile) => self.provider.profiled_compaction(host, &queue, profile),
            None => self
                .provider
                .compaction(host, &queue, binding.spend.as_ref()),
        }
    }

    pub(super) fn join_compaction(
        &self,
        executor: &mut EngineNativeExecutor<'_>,
        reason: WindowFullReason,
    ) -> Result<(), ReaderRunEnd> {
        if reason != WindowFullReason::InFlight {
            return Err(ReaderRunEnd::Failed("window_full".to_owned()));
        }
        let left = self.left_ms(unix_millis_now());
        if left == 0 || !executor.wait_for_compaction(Duration::from_millis(left)) {
            return Err(ReaderRunEnd::Cutoff);
        }
        Ok(())
    }
}
