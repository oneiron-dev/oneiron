//! A dispatched call's reply as the guest gets it: its JSON measured, and
//! stored as a result of the run when it is too large for one message. Once
//! the reply is made, the host hears that its guest got it (FIX 3608).

use serde_json::{Value, json};

use super::admitted;
use crate::Result;
use crate::engine_executor::{
    JsCodeModeHost, RESULT_REPLY_INLINE_BYTES, SelfDispatchResponse, StepCancellation,
};

/// The guest's reply to `answered`, the call `host` answered last: its body
/// fit to one message ([`fit_reply`]), with its budget envelope and a verb
/// hook's view in the body's place ([`SelfDispatchResponse::guest_json`]).
/// Once it is made and fits `message_bytes`, the bound the typed bridge
/// holds every host reply to before the guest reads it, `host` hears that
/// its guest got the reply, so a host keeps a skill body the call's answer
/// carries as delivered only then (FIX 3608). A reply past that bound
/// reaches the guest as `host_response_over_budget`, with no body.
pub(super) fn guest_reply(
    host: &mut dyn JsCodeModeHost,
    cancel: &StepCancellation,
    answered: &SelfDispatchResponse,
    message_bytes: usize,
) -> Result<String> {
    let body = fit_reply(host, cancel, super::reply_body(&answered.outcome)?)?;
    let reply = answered.guest_json(body).to_string();
    if reply.len() <= message_bytes {
        host.guest_reply_delivered();
    }
    Ok(reply)
}

/// Bytes `value` takes as JSON, holding none of them.
fn encoded_len(value: &Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    match serde_json::to_writer(&mut count, value) {
        Ok(()) => count.0,
        Err(_) => usize::MAX,
    }
}

/// A reply as the guest gets it: one whose JSON is past
/// `RESULT_REPLY_INLINE_BYTES` is stored as a result of the run, and its
/// card stands under `output` in place of what was stored (the output, or
/// the whole reply when it has none). No answer is refused for its size; a
/// host with no result store sends it as it is, for the message bound to
/// judge.
fn fit_reply(
    host: &mut dyn JsCodeModeHost,
    cancel: &StepCancellation,
    mut body: Value,
) -> Result<Value> {
    if encoded_len(&body) <= RESULT_REPLY_INLINE_BYTES {
        return Ok(body);
    }
    let has_output = body.get("output").is_some();
    let stored = if has_output { &body["output"] } else { &body };
    if let Some(card) = admitted(cancel, || host.store_reply(stored))? {
        if has_output {
            body["output"] = card;
        } else {
            body = json!({ "output": card });
        }
    }
    Ok(body)
}
