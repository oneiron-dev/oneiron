//! Scoped children at the host (FIX 7507 PR2): the door a scoped child runs
//! behind, the binding of its lent ports to the host's registered adapters,
//! and the host-only enqueue a host queues one through (the Dreamer's, in
//! FIX 7508).
//!
//! A scoped child's door is its parent's loan. It admits the child's own
//! lifecycle calls, its reads of what it was lent and its lent ports, each
//! only while its parent actor's authority stands (`scoped_child_authority`:
//! a live person, or a live agent one live Grant of the owner's stands
//! for). It refuses only on that Grant, the job or its route, never on where
//! anyone runs: it reads no caller locality, withholds nothing by
//! destination, and the read child's door (`ReaderChildDoor`) never stands
//! in for it. No tagger or extraction port is registered here; a host
//! registers its own through `McpCodeModeProvider::scoped_child_ports`.

use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, ReaderJob, ReaderJobs, ReaderRunEnd,
    ReaderSpawnReceipt, RunCall, SCOPED_CHILD_PORT_NOT_LENT, SCOPED_CHILD_SERVICE_UNBOUND,
    ScopedChildLoan, ScopedChildPorts, SelfAgentVerbCall, SelfEffect, SpawnHostSeat,
    scoped_child_authority,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EntityId, Vault};

use crate::mcp::McpCodeModeProvider;

/// The door a scoped child's run is bound to: its job, Grant-checked in its
/// vault at every call it admits.
pub(crate) struct ScopedChildDoor {
    vault: Arc<Vault>,
    job: ReaderJob,
}

impl ScopedChildDoor {
    pub(crate) fn new(vault: Arc<Vault>, job: ReaderJob) -> Self {
        Self { vault, job }
    }

    /// The door's Grant check: whether the child's authority stands now
    /// (`scoped_child_authority`). A check that fails to read refuses.
    fn stands(&self) -> Result<(), AgentVerbRefusal> {
        match scoped_child_authority(&self.vault, &self.job) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(code)) => Err(AgentVerbRefusal {
                code: code.to_owned(),
            }),
            Err(error) => {
                tracing::warn!(%error, task = %self.job.task.to_hex(), "a scoped child's authority was not read");
                Err(AgentVerbRefusal {
                    code: "engine_error".to_owned(),
                })
            }
        }
    }
}

impl AgentVerbDoor for ScopedChildDoor {
    /// A lent port runs on its host's adapter (`ScopedChildPorts`), never
    /// through this door.
    fn call(
        &self,
        _: &SelfAgentVerbCall,
        _: &HostWriteOrigin,
        _: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(AgentVerbRefusal {
            code: SCOPED_CHILD_PORT_NOT_LENT.to_owned(),
        }))
    }

    /// The child's report, `self.context`, `self.think`, its lent ports
    /// (each checked by name in its dispatcher first) and its reads, while
    /// its authority stands; any other call is the read child's word.
    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        self.stands()?;
        match call {
            RunCall::RecordedOutput
            | RunCall::Bridge(
                SelfEffect::ReaderReport
                | SelfEffect::Context
                | SelfEffect::Think
                | SelfEffect::AgentVerb,
            ) => Ok(None),
            _ => Err(AgentVerbRefusal {
                code: crate::server::READER_CHILD_READ_ONLY.to_owned(),
            }),
        }
    }

    /// Nothing is withheld by where anyone runs: a lent input the child's
    /// authority stands for is read, and one it no longer stands for is
    /// refused.
    fn withholds_retained(&self, _: Option<&[EntityId]>) -> Result<bool, AgentVerbRefusal> {
        self.stands().map(|()| false)
    }
}

/// `scoped_child_service_admission` at the runner (FIX 7507): the ports
/// scoped job `job` runs with, its host's registered adapters
/// (`McpCodeModeProvider::scoped_child_ports`), once its authority stands in
/// `vault`. A job whose authority does not stand ends with its refusal, and
/// one that lends a port no adapter serves ends
/// `scoped_child_service_unbound`, before any call: neither ever runs as a
/// read child in its place.
pub(crate) fn scoped_child_service(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    job: &ReaderJob,
) -> Result<Option<Arc<dyn ScopedChildPorts>>, ReaderRunEnd> {
    let Some(spec) = job.scoped_spec() else {
        return Err(ReaderRunEnd::Failed(
            SCOPED_CHILD_SERVICE_UNBOUND.to_owned(),
        ));
    };
    match scoped_child_authority(vault, job) {
        Ok(Ok(())) => {}
        Ok(Err(code)) => return Err(ReaderRunEnd::Failed(code.to_owned())),
        Err(error) => {
            tracing::warn!(%error, task = %job.task.to_hex(), "a scoped child's authority was not read");
            return Err(ReaderRunEnd::Failed(
                "scoped_child_authority_unread".to_owned(),
            ));
        }
    }
    let ports = provider.scoped_child_ports(job);
    if spec.unbound_port(ports.as_deref()).is_some() {
        return Err(ReaderRunEnd::Failed(
            SCOPED_CHILD_SERVICE_UNBOUND.to_owned(),
        ));
    }
    Ok(ports)
}

/// The host-only enqueue of one scoped child (FIX 7507; the Dreamer's
/// consolidation calls it in FIX 7508): the child `loan` lends, queued
/// under `intent_key` on `jobs`, its parent's reader rows on the loan's own
/// route, under `seat`, asked `ask`, at `now_ms`. A loan is only ever the
/// host's ([`ScopedChildLoan::from_parent`]), so no guest call reaches
/// this. The answer's `Err` names why nothing was queued
/// ([`ReaderJobs::spawn_scoped`]).
///
/// # Errors
///
/// The route's own read and write errors.
pub fn enqueue_scoped_child(
    jobs: &ReaderJobs<'_>,
    seat: &SpawnHostSeat,
    loan: &ScopedChildLoan,
    intent_key: &str,
    ask: String,
    now_ms: u64,
) -> oneiron::Result<Result<ReaderSpawnReceipt, &'static str>> {
    jobs.spawn_scoped(seat, loan, intent_key, ask, now_ms)
}
