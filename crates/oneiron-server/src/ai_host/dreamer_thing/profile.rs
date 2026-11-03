//! The served agent's own generation and the session its parent waits on
//! (FIX 7508, 11449).
//!
//! The generation's backend is the extraction route's ladder on a run of
//! the parent's own wake guard: each call it answers, streamed or not, is
//! counted, so the parent charges the child's spend to its attempt once,
//! and once the parent stops the child no further call is admitted. A call
//! admitted before that settles after it is charged to the attempt's line
//! when it settles (FIX 9015). A session dropped without its close charges
//! what its count still holds there too. The session reduces the child's
//! one-child wait on each vault commit and at the child's cutoff, and hands
//! the parent each port call as it comes (FIX 9018).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::Stream;
use oneiron::attempt_queue::AttemptQueue;
use oneiron::code_run::{ReaderJobs, ScopedChildStop, collect_scoped_child, read_scoped_finding};
use oneiron::dreamer_consolidation::{
    PortFuture, ThingChildEvent, ThingChildSession, ThingChildSettled, ThingPortCall,
};
use oneiron::llm::BudgetDenied;
use oneiron::{
    BudgetLease, EntityId, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmRequest,
    LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, ModelId, Vault,
};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::mpsc::UnboundedReceiver;

use super::generation::GenerationCount;
use super::unix_millis_now;
use crate::mcp::McpCodeModeProvider;
use crate::models::RunBackend;

/// How long a waiting parent lets pass between two reductions of its
/// child's wait once the vault's commit stream is gone, so no commit wakes
/// it: a cadence, never a deadline.
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
        if self.stop.code().is_some() || !self.count.admit() {
            return Err(LlmError::BudgetDenied(BudgetDenied::AdmissionDenied));
        }
        // An admitted stream runs to its end, a stop meanwhile included,
        // and settles once on the count: its terminal usage, or 0 when it
        // ends in an error, reports none, or drops early (FIX 11449). A
        // stream the route refuses never starts, so its guard's drop
        // settles 0.
        let guard = CountedStreamGuard::new(Arc::clone(&self.count));
        let inner = self.inner.stream(request, lease)?;
        Ok(LlmStream::new(CountedStream { inner, guard }))
    }
}

/// One counted stream: its terminal usage settles on the count, once.
struct CountedStream<'a> {
    inner: LlmStream<'a>,
    guard: CountedStreamGuard,
}

impl Stream for CountedStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_next(cx);
        match &polled {
            Poll::Ready(Some(Ok(LlmStreamEvent::Done { usage, .. }))) => {
                let units = usage.input.total.saturating_add(usage.output.total);
                this.guard.settle(units);
            }
            Poll::Ready(Some(Err(_)) | None) => this.guard.settle(0),
            Poll::Ready(Some(Ok(_))) | Poll::Pending => {}
        }
        polled
    }
}

/// A streamed call's settlement, once: at its terminal, or 0 when the
/// caller drops it early.
struct CountedStreamGuard {
    count: Option<Arc<GenerationCount>>,
}

impl CountedStreamGuard {
    fn new(count: Arc<GenerationCount>) -> Self {
        Self { count: Some(count) }
    }

    fn settle(&mut self, units: u64) {
        if let Some(count) = self.count.take() {
            count.settle(units);
        }
    }
}

impl Drop for CountedStreamGuard {
    fn drop(&mut self) {
        self.settle(0);
    }
}

/// One launched agent as its parent waits on it. Dropped, it charges what
/// its count still holds and forgets the child's profile.
pub(super) struct ThingSession {
    vault: Arc<Vault>,
    provider: Arc<dyn McpCodeModeProvider>,
    task: EntityId,
    parent_run: EntityId,
    /// The child's run, once it is queued; its task until then.
    run: EntityId,
    calls: UnboundedReceiver<ThingPortCall>,
    /// Whether the port calls' sender is gone, so no call comes.
    calls_closed: bool,
    /// The vault's commit signal, taken before the first reduction so no
    /// commit falls between a reduction and the wait; `None` once gone.
    commits: Option<broadcast::Receiver<()>>,
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
        let commits = Some(AttemptQueue::new(&vault).subscribe());
        Self {
            vault,
            provider,
            task,
            parent_run,
            run: task,
            calls,
            calls_closed: false,
            commits,
            stop,
            count,
        }
    }

    /// The run the child was queued as.
    pub(super) fn bind_run(&mut self, run: EntityId) {
        self.run = run;
    }

    /// The child's settlement once its one-child wait is done, else its
    /// next port call, or `None` once a commit or the child's cutoff may
    /// have settled it. Only a commit (the child's settle or row) or its
    /// cutoff passing changes the wait, so nothing polls while the commit
    /// stream stands (FIX 9018).
    async fn next_event(&mut self) -> oneiron::Result<Option<ThingChildEvent>> {
        let now_ms = unix_millis_now();
        if let Some((job, wait)) =
            collect_scoped_child(&self.vault, self.parent_run, self.task, now_ms)?
        {
            let report = read_scoped_finding(&self.vault, &job)?;
            return Ok(Some(ThingChildEvent::Settled(ThingChildSettled {
                state: job.state,
                reason: wait.reason,
                report,
            })));
        }
        let cutoff = ReaderJobs::canonical(&self.vault)
            .job(self.task)?
            .map(|job| {
                let left = job.binding.child_cutoff_unix_ms.saturating_sub(now_ms);
                Duration::from_millis(left.saturating_add(1))
            });
        let timer = match self.commits {
            Some(_) => cutoff,
            None => Some(cutoff.map_or(COLLECT_BEAT, |cutoff| cutoff.min(COLLECT_BEAT))),
        };
        let mut commits_gone = false;
        tokio::select! {
            call = self.calls.recv(), if !self.calls_closed => match call {
                Some(call) => return Ok(Some(ThingChildEvent::Port(call))),
                None => self.calls_closed = true,
            },
            gone = next_commit(self.commits.as_mut()) => commits_gone = gone,
            () = sleep_for(timer) => {}
        }
        if commits_gone {
            self.commits = None;
        }
        Ok(None)
    }
}

/// Waits for the vault's next commit; `true` once its stream is gone. A
/// receiver that lagged has missed commits, which a fresh reduction reads.
/// With no stream it never wakes.
async fn next_commit(commits: Option<&mut broadcast::Receiver<()>>) -> bool {
    match commits {
        Some(receiver) => matches!(receiver.recv().await, Err(RecvError::Closed)),
        None => std::future::pending().await,
    }
}

/// Sleeps for `wait`; with none it never wakes.
async fn sleep_for(wait: Option<Duration>) {
    match wait {
        Some(wait) => tokio::time::sleep(wait).await,
        None => std::future::pending().await,
    }
}

impl Drop for ThingSession {
    fn drop(&mut self) {
        // A session dropped without its close still charges its settled
        // units to the attempt's own line (FIX 11449); a closed one holds
        // nothing more, so this charges nothing.
        self.count.close_dropped();
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
