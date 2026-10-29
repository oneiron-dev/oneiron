//! The served agent's own generation and the session its parent waits on
//! (FIX 7508).
//!
//! The generation's backend is the extraction route's ladder on a run of
//! the parent's own wake guard: each call it answers is counted, so the
//! parent charges the child's spend to its attempt once, and once the
//! parent stops the child no further call is admitted. A call admitted
//! before that settles after it is charged to the attempt's line when it
//! settles (FIX 9015). The session reduces the child's one-child wait each
//! beat and hands the parent each port call as it comes.

use std::sync::Arc;
use std::time::Duration;

use oneiron::code_run::{ScopedChildStop, collect_scoped_child, read_scoped_finding};
use oneiron::dreamer_consolidation::{
    PortFuture, ThingChildEvent, ThingChildSession, ThingChildSettled, ThingPortCall,
};
use oneiron::llm::BudgetDenied;
use oneiron::{
    BudgetLease, EntityId, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, ModelId, Vault,
};
use tokio::sync::mpsc::UnboundedReceiver;

use super::generation::GenerationCount;
use super::unix_millis_now;
use crate::mcp::McpCodeModeProvider;
use crate::models::RunBackend;

/// How long a waiting parent lets pass between two reductions of its
/// child's wait when no port call comes: a cadence, never a deadline.
const COLLECT_BEAT: Duration = Duration::from_millis(200);

/// The agent's generation backend: the route's run on its parent's guard,
/// counted, and closed once its parent stopped it.
pub(super) struct CountedBackend {
    inner: RunBackend,
    count: Arc<GenerationCount>,
    stop: ScopedChildStop,
}

impl CountedBackend {
    pub(super) fn new(
        inner: RunBackend,
        count: Arc<GenerationCount>,
        stop: ScopedChildStop,
    ) -> Self {
        Self { inner, count, stop }
    }
}

impl LlmBackend for CountedBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.inner.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            if self.stop.code().is_some() || !self.count.admit() {
                return Err(LlmError::BudgetDenied(BudgetDenied::AdmissionDenied));
            }
            // An admitted call runs to its end, a stop meanwhile included,
            // and settles once on the count (FIX 9015).
            let generated = self.inner.generate(request, lease).await;
            let units = generated.as_ref().map_or(0, |response| {
                response
                    .usage
                    .input
                    .total
                    .saturating_add(response.usage.output.total)
            });
            self.count.settle(units);
            generated
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.inner.stream(request, lease)
    }
}

/// One launched agent as its parent waits on it. Dropped, it forgets the
/// child's profile.
pub(super) struct ThingSession {
    vault: Arc<Vault>,
    provider: Arc<dyn McpCodeModeProvider>,
    task: EntityId,
    parent_run: EntityId,
    /// The child's run, once it is queued; its task until then.
    run: EntityId,
    calls: UnboundedReceiver<ThingPortCall>,
    stop: ScopedChildStop,
    count: Arc<GenerationCount>,
}

impl ThingSession {
    pub(super) fn new(
        vault: Arc<Vault>,
        provider: Arc<dyn McpCodeModeProvider>,
        task: EntityId,
        parent_run: EntityId,
        calls: UnboundedReceiver<ThingPortCall>,
        stop: ScopedChildStop,
        count: Arc<GenerationCount>,
    ) -> Self {
        Self {
            vault,
            provider,
            task,
            parent_run,
            run: task,
            calls,
            stop,
            count,
        }
    }

    /// The run the child was queued as.
    pub(super) fn bind_run(&mut self, run: EntityId) {
        self.run = run;
    }

    /// The child's settlement once its one-child wait is done, else its
    /// next port call within one beat.
    async fn next_event(&mut self) -> oneiron::Result<Option<ThingChildEvent>> {
        if let Some((job, wait)) =
            collect_scoped_child(&self.vault, self.parent_run, self.task, unix_millis_now())?
        {
            let report = read_scoped_finding(&self.vault, &job)?;
            return Ok(Some(ThingChildEvent::Settled(ThingChildSettled {
                state: job.state,
                reason: wait.reason,
                report,
            })));
        }
        tokio::select! {
            call = self.calls.recv() => match call {
                Some(call) => return Ok(Some(ThingChildEvent::Port(call))),
                None => tokio::time::sleep(COLLECT_BEAT).await,
            },
            () = tokio::time::sleep(COLLECT_BEAT) => {}
        }
        Ok(None)
    }
}

impl Drop for ThingSession {
    fn drop(&mut self) {
        if let Some(hosts) = self.provider.scoped_child_hosts() {
            hosts.remove(self.task);
        }
    }
}

impl ThingChildSession for ThingSession {
    fn child_run(&self) -> EntityId {
        self.run
    }

    fn next(&mut self) -> PortFuture<'_, oneiron::Result<Option<ThingChildEvent>>> {
        Box::pin(self.next_event())
    }

    fn stop(&mut self, code: &'static str) {
        self.stop.stop(code);
    }

    fn close_generation(&self) -> u64 {
        self.count.close()
    }
}
