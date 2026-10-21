//! A host-profiled scoped child at the runner (FIX 7508): a child its own
//! host registered a profile for runs on that profile's backend, meter and
//! model, with its lent ports bound as every scoped child's are, never on
//! the host's shared code-mode meter. Its seat is born as every child's is,
//! so a vault that requires one keeps its list, route and cutoff rules. A
//! child whose host stopped it settles with the stop's code.

use std::sync::Arc;

use oneiron::Vault;
use oneiron::code_run::{AgentVerbDoor, ReaderRunEnd, ScopedChildProfile};
use oneiron::off_record::OffRecordSession;

use super::Child;
use crate::ai_host::scoped_child::scoped_child_service;

impl Child {
    /// The profile this job's host registered for it, if any; only a scoped
    /// child is ever profiled.
    pub(super) fn profile(&self) -> Option<ScopedChildProfile> {
        if self.job.scoped_spec().is_none() {
            return None;
        }
        self.provider.scoped_child_hosts()?.profile(self.job.task)
    }

    /// Runs the child on `profile`: its backend and its parent's guard, its
    /// model bound before the seat, its ports once its authority and
    /// registration hold. A child its host stopped ends `Trapped` with the
    /// stop's code, however its run ended short.
    pub(super) fn metered_on_profile(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        door: Arc<dyn AgentVerbDoor>,
        profile: &ScopedChildProfile,
    ) -> ReaderRunEnd {
        let end = match scoped_child_service(vault, self.provider.as_ref(), &self.job) {
            Ok(ports) => self.run(
                vault,
                session,
                profile.backend.as_ref(),
                &profile.guard,
                door,
                ports,
                Some(profile),
            ),
            Err(end) => end,
        };
        match profile.stop.code() {
            Some(code) if end != ReaderRunEnd::Completed => ReaderRunEnd::Trapped(code.to_owned()),
            _ => end,
        }
    }
}
