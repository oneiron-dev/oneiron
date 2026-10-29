//! A thing agent's two lent ports (FIX 7508, FIX 7733): the adapter its
//! host registers for exactly `self.dreamer.thing.extract` and
//! `self.dreamer.thing.decide`, served on its parent's own wake.
//!
//! A call is synchronous on the child's own reactor. The adapter reads the
//! lent input the call names through the child's enforced read (its job
//! live, its authority and its parent's lease, the occurrence clean and in
//! range), lets go of the call's context, and hands the owned request to its
//! parent's wake, which runs it under the parent's guard, deadline and
//! durable-step identity. It waits for the answer on a plain channel, never
//! past the child's own cutoff, and never blocks on a runtime.

use std::sync::mpsc::sync_channel;
use std::time::Duration;

use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbRefusal, SCOPED_CHILD_SERVICE_UNBOUND, ScopedChildCallContext,
    ScopedChildPorts, ScopedChildStop, SelfAgentVerbCall,
};
use oneiron::dreamer_consolidation::{
    THING_CHILD_PARENT_GONE, THING_DECIDE_PORT, THING_EXTRACT_PORT, THING_PORT_INPUT_INVALID,
    ThingDecideInput, ThingExtractInput, ThingPortCall, ThingPortReply, ThingPortRequest,
};
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

    /// Hands `request` to the parent's wake and waits for its answer, until
    /// the child's cutoff at the latest.
    fn ask_parent(&self, request: ThingPortRequest) -> ThingPortReply {
        let (reply, answered) = sync_channel::<ThingPortReply>(1);
        let call = ThingPortCall::new(
            request,
            Box::new(move |answer: ThingPortReply| {
                let _ = reply.send(answer);
            }),
        );
        if self.calls.send(call).is_err() {
            return Err(THING_CHILD_PARENT_GONE);
        }
        let left = self.cutoff_unix_ms.saturating_sub(unix_millis_now());
        answered
            .recv_timeout(Duration::from_millis(left))
            .unwrap_or(Err(THING_CHILD_PARENT_GONE))
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
            .ask_parent(request)
            .map(|output| AgentVerbAnswer::new(output, Some(rows)))
            .map_err(refusal))
    }
}

fn refusal(code: &str) -> AgentVerbRefusal {
    AgentVerbRefusal {
        code: code.to_owned(),
    }
}
