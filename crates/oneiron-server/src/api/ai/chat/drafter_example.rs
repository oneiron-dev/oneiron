//! The drafter's training example of each answered reply (FIX 15128, FIX
//! 15129): every live chat turn's and every queued Continue's or Retry's,
//! whatever its agent, apart from the self agent's breakpoint. Once the reply
//! is saved whole and its outcome handed on, its request as the answering
//! rung sent it and the span the reply generated go to
//! [`Vault::keep_drafter_example`], with the rows its call was read from.
//! None for a reply that failed or was not saved whole, a reused prefix that
//! fell back to today's call, a call whose model-call record is not kept (a
//! turn that keeps no durable record or runs off the record), a call whose
//! rows are not known whole, or a rung that is not the drafter target this
//! host serves.

use oneiron::drafter::{DrafterExampleKept, DrafterTrafficReply};
use oneiron::memory::{MessageStreamReceipt, StreamFinality};
use oneiron::{EntityId, Vault};

use super::model_call::{AnsweredCall, AnsweredSlot};

/// One saved reply's example, ready to keep.
pub(super) struct ReplyExample {
    agent: EntityId,
    requester: EntityId,
    sources: Vec<EntityId>,
    reply: EntityId,
    generation: EntityId,
    call: AnsweredCall,
}

/// What a reply's producer ended with, as its example reads it.
pub(super) struct ReplyEnd<'a> {
    /// The reply's MESSAGE.
    pub(super) message: EntityId,
    pub(super) result: &'a Result<(), String>,
    pub(super) saved: Option<&'a MessageStreamReceipt>,
    /// Whether a reused prefix's captured rung gave way to today's call.
    pub(super) fell_back: bool,
}

/// Who asked for a reply and what its call was read from.
pub(super) struct ReplyCall {
    pub(super) agent: EntityId,
    pub(super) requester: EntityId,
    /// The rows the captured call was read from; `None` is unknown.
    pub(super) sources: Option<Vec<EntityId>>,
    /// The rows today's fallback call was read from, the call that answers
    /// once a reused prefix gives way; `None` is unknown.
    pub(super) today_sources: Option<Vec<EntityId>>,
}

/// The example `end` leaves from the call `answered` holds, when the reply
/// is one.
pub(super) fn reply_example(
    answered: &AnsweredSlot,
    end: &ReplyEnd<'_>,
    call: ReplyCall,
) -> Option<ReplyExample> {
    let saved = end.saved?;
    let whole = end.result.is_ok()
        && saved.message_id == end.message
        && saved.finality == StreamFinality::Final;
    if !whole {
        return None;
    }
    // A reused prefix that gave way answered with today's call: the
    // captured request is today's, read from today's rows (FIX 16232).
    let sources = if end.fell_back {
        call.today_sources?
    } else {
        call.sources?
    };
    let answered = answered.lock().ok().and_then(|mut slot| slot.take())?;
    // The worker's reported weights identity, never the wire's model name,
    // is what a drafter target names.
    let served = crate::models::drafter_retrain_target()
        .is_some_and(|target| answered.target_model.as_deref() == Some(target.model.as_str()));
    if !served {
        return None;
    }
    Some(ReplyExample {
        agent: call.agent,
        requester: call.requester,
        sources,
        reply: saved.message_id,
        generation: saved.generation,
        call: answered,
    })
}

/// Keeps `example` in `vault`, off the answer's path. A fault is logged
/// without content, and the reply stands as saved.
pub(super) fn keep_reply_example(vault: &Vault, example: ReplyExample) {
    let ReplyExample {
        agent,
        requester,
        sources,
        reply,
        generation,
        call,
    } = example;
    // `reply_example` kept only a call whose worker named the target.
    let Some(target_model) = call.target_model else {
        return;
    };
    let kept = crate::server::blocking(|| {
        vault.keep_drafter_example(DrafterTrafficReply {
            reply,
            generation,
            agent,
            requester,
            sources,
            wire_model: call.wire_model,
            target_model,
            request: call.request,
            generated: call.generated,
            finish_reason: call.finish_reason,
        })
    });
    match kept {
        Ok(DrafterExampleKept::Kept(_)) => {}
        Ok(DrafterExampleKept::Skipped(reason)) => {
            tracing::debug!(reason, "a chat reply kept no drafter example");
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a chat reply's drafter example was not kept");
        }
    }
}
