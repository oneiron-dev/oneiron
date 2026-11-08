//! A host-profiled scoped child at the runner (FIX 7508): a child its own
//! host registered a profile for runs on that profile's backend, meter and
//! model, with its lent ports bound as every scoped child's are, never on
//! the host's shared code-mode meter. Its seat is born as every child's is,
//! so a vault that requires one keeps its list, route and cutoff rules. A
//! child whose host stopped it settles with the stop's code.
//!
//! Every scoped child's run is also bound to its live cutoff (FIX 8233): a
//! [`ScopedCallControl`] made from what [`Child::left_ms`] reads. Its port
//! calls and reads stop at it, and an entry in which one did ends at its
//! cutoff, never as a failed run.

use std::sync::Arc;

use oneiron::Vault;
use oneiron::claim::CallerLocality;
use oneiron::code_run::{
    AgentVerbDoor, HostSelfDispatcher, ReaderRunEnd, ScopedCallControl, ScopedChildPorts,
    ScopedChildProfile,
};
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

    /// The live cutoff a scoped child's port calls and reads stop at (FIX
    /// 8233), made from what [`Child::left_ms`] reads: its job's frozen
    /// cutoff and, while its parent's host lends a live clock, that clock's
    /// due instant less the fold reserve its first spawn froze, taken once
    /// ([`Child::fold_reserve_ms`]). A clockless child keeps its stored
    /// cutoff alone. No time is added and no window is made. `None` for a
    /// job that is no scoped child.
    pub(super) fn scoped_call_control(&self) -> Option<ScopedCallControl> {
        if self.job.scoped_spec().is_none() {
            return None;
        }
        let deadline = self
            .clock
            .and_then(|clock| clock.due_at(self.fold_reserve_ms()));
        Some(ScopedCallControl::new(
            deadline,
            self.job.binding.child_cutoff_unix_ms,
        ))
    }

    /// `dispatcher`, bound to a scoped child's live cutoff `control` (FIX
    /// 8233) and its lent `ports` (FIX 7507), each when there is one.
    pub(super) fn bind_scoped<'s>(
        dispatcher: HostSelfDispatcher<'s>,
        control: Option<&ScopedCallControl>,
        ports: Option<Arc<dyn ScopedChildPorts>>,
    ) -> oneiron::Result<HostSelfDispatcher<'s>> {
        let dispatcher = match control {
            Some(control) => dispatcher.with_scoped_call_control(control.clone())?,
            None => dispatcher,
        };
        match ports {
            Some(ports) => dispatcher.with_scoped_child_ports(ports),
            None => Ok(dispatcher),
        }
    }

    /// How an entry ends in which a port call or read of the scoped child
    /// saw its live cutoff (FIX 8233): at its cutoff, before its runner
    /// takes the entry's end as it stands, so a refusal the run took never
    /// ends it `reader_run_failed`. A borrowed lease lost still settles
    /// `scoped_child_parent_lease_lost`, and a host's stop still ends it
    /// with its code ([`Child::metered_on_profile`]). `None` while no cut
    /// was seen.
    pub(super) fn scoped_cut(control: Option<&ScopedCallControl>) -> Option<ReaderRunEnd> {
        control
            .is_some_and(ScopedCallControl::is_cut)
            .then_some(ReaderRunEnd::Cutoff)
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
        caller: CallerLocality,
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
                Some(Self::profiled_compaction_binding(caller)),
            ),
            Err(end) => end,
        };
        match profile.stop.code() {
            Some(code) if end != ReaderRunEnd::Completed => ReaderRunEnd::Trapped(code.to_owned()),
            _ => end,
        }
    }
}
