//! A thing agent's two lent ports (FIX 7508, FIX 7733): the adapter its
//! host registers for exactly `self.dreamer.thing.extract` and
//! `self.dreamer.thing.decide`, served on its parent's own wake.
//!
//! A call is synchronous on the child's own reactor. The adapter reads the
//! lent input the call names through the child's enforced read (its job
//! live, its authority and its parent's lease, the occurrence clean and in
//! range), and hands an owned request to its parent's wake, which runs it
//! under the parent's guard, deadline and durable-step identity. It waits
//! for the answer on a plain channel and never blocks on a runtime.
//!
//! The wait stops at the child's live cutoff (FIX 8233): the earlier of its
//! runner's [`oneiron::code_run::ScopedCallControl`] and its stored cutoff.
//! It waits in slices of `CANCEL_POLL_SLICE` and, between them, reads the
//! host's stop, the child's job and its parent's lease again. A wait its
//! cutoff ends answers `reader_task_settled`; only a parent that is gone
//! answers `thing_child_parent_gone`. The parent's admitted step is not
//! cancelled: it finishes and settles its spend, and its late answer goes
//! to a channel no one reads.

use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbRefusal, READER_TASK_SETTLED, SCOPED_CHILD_SERVICE_UNBOUND,
    ScopedChildCallContext, ScopedChildPorts, ScopedChildStop, SelfAgentVerbCall,
};
use oneiron::dreamer_consolidation::{
    THING_CHILD_PARENT_GONE, THING_DECIDE_PORT, THING_EXTRACT_PORT, THING_PORT_INPUT_INVALID,
    ThingDecideInput, ThingExtractInput, ThingPortCall, ThingPortReply, ThingPortRequest,
};
use oneiron::engine_executor::CANCEL_POLL_SLICE;
use oneiron::memory::HostWriteOrigin;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::AgentVerb;
use tokio::sync::mpsc::UnboundedSender;

use super::unix_millis_now;

/// The ports one thing agent is lent: where its calls go, its stop, and
/// its cutoff.
pub(super) struct ThingChildPorts {
    calls: UnboundedSender<ThingPortCall>,
    stop: ScopedChildStop,
    cutoff_unix_ms: u64,
}

impl ThingChildPorts {
    pub(super) fn new(
        calls: UnboundedSender<ThingPortCall>,
        stop: ScopedChildStop,
        cutoff_unix_ms: u64,
    ) -> Self {
        Self {
            calls,
            stop,
            cutoff_unix_ms,
        }
    }

    /// Hands `request` to the parent's wake and waits for its answer, for
    /// the child `ctx` holds (FIX 8233): only while [`Self::wait_left`]
    /// leaves time, read before the request is handed over and again
    /// between slices of `CANCEL_POLL_SLICE`. Its refusal is the stop's, the
    /// job's or the lease's code; a closed channel is the parent gone.
    fn ask_parent(
        &self,
        ctx: &ScopedChildCallContext<'_, '_>,
        request: ThingPortRequest,
    ) -> oneiron::Result<ThingPortReply> {
        if let Err(code) = self.wait_left(ctx)? {
            return Ok(Err(code));
        }
        let (reply, answered) = sync_channel::<ThingPortReply>(1);
        let call = ThingPortCall::new(
            request,
            Box::new(move |answer: ThingPortReply| {
                let _ = reply.send(answer);
            }),
        );
        if self.calls.send(call).is_err() {
            return Ok(Err(THING_CHILD_PARENT_GONE));
        }
        loop {
            let left = match self.wait_left(ctx)? {
                Ok(left) => left,
                Err(code) => return Ok(Err(code)),
            };
            match answered.recv_timeout(left.min(CANCEL_POLL_SLICE)) {
                Ok(answer) => return Ok(answer),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Ok(Err(THING_CHILD_PARENT_GONE)),
            }
        }
    }

    /// What is left of the child's wait now (FIX 8233): the time to the
    /// earlier of its live cutoff and its stored cutoff, the monotonic clock
    /// read first; a cut by either latches in the child's control, for its
    /// runner to end the entry at. The answer's `Err` is the host's stop
    /// code, the job's or its lease's refusal
    /// (`ScopedChildCallContext::standing`), or `reader_task_settled` once
    /// no time is left.
    fn wait_left(
        &self,
        ctx: &ScopedChildCallContext<'_, '_>,
    ) -> oneiron::Result<Result<Duration, &'static str>> {
        if let Some(code) = self.stop.code() {
            return Ok(Err(code));
        }
        if let Err(code) = ctx.standing()? {
            return Ok(Err(code));
        }
        let now = Instant::now();
        let left = match ctx.control() {
            Some(control) => control.left_before(now, self.cutoff_unix_ms),
            None => Duration::from_millis(self.cutoff_unix_ms.saturating_sub(unix_millis_now())),
        };
        Ok(if left.is_zero() {
            Err(READER_TASK_SETTLED)
        } else {
            Ok(left)
        })
    }
}

impl ScopedChildPorts for ThingChildPorts {
    fn serves(&self, verb: AgentVerb) -> bool {
        matches!(verb.as_str(), THING_EXTRACT_PORT | THING_DECIDE_PORT)
    }

    fn call(
        &self,
        ctx: &ScopedChildCallContext<'_, '_>,
        call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        if let Some(code) = self.stop.code() {
            return Ok(Err(refusal(code)));
        }
        let named = match call.verb.as_str() {
            THING_EXTRACT_PORT => serde_json::from_value::<ThingExtractInput>(call.input.clone())
                .map(|input| (true, input.input)),
            THING_DECIDE_PORT => serde_json::from_value::<ThingDecideInput>(call.input.clone())
                .map(|input| (false, input.pack)),
            _ => return Ok(Err(refusal(SCOPED_CHILD_SERVICE_UNBOUND))),
        };
        let Ok((extract, reference)) = named else {
            return Ok(Err(refusal(THING_PORT_INPUT_INVALID)));
        };
        // Only a lent input resolves, read as the child's own read is.
        let read = match ctx.read_input(&reference)? {
            Ok(read) => read,
            Err(code) => return Ok(Err(refusal(code))),
        };
        let rows = read.rows.unwrap_or_default();
        let request = if extract {
            ThingPortRequest::Extract { input: read.name }
        } else {
            ThingPortRequest::Decide { pack: read.name }
        };
        Ok(self
            .ask_parent(ctx, request)?
            .map(|output| AgentVerbAnswer::new(output, Some(rows)))
            .map_err(refusal))
    }
}

fn refusal(code: &str) -> AgentVerbRefusal {
    AgentVerbRefusal {
        code: code.to_owned(),
    }
}
