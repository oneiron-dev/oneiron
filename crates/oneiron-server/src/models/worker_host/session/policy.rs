//! The coordinator's calls, one fn or constant each: which workers get
//! sessions, which calls may use one, what keys it, where the canonical cut
//! falls, when a suffix commit runs, and why a session is dropped.
use std::collections::BTreeMap;

use oneiron::llm::{
    CanonicalCheckpointRef, ConditioningDigest, MessageStamp, SegmentClass, SegmentKind,
    SegmentManifest, SessionAppended, SessionCapability, SessionForked, SessionInvalidation,
    SessionKey, SessionOp, message_digest,
};
use serde_json::Value as JsonValue;

/// Every op a turn and its commit send: a worker that does not serve them
/// all gets no session. `session.restore` is sent only where served.
pub(super) const REQUIRED_OPS: [SessionOp; 7] = [
    SessionOp::Create,
    SessionOp::Fork,
    SessionOp::Generate,
    SessionOp::Append,
    SessionOp::SuffixCommit,
    SessionOp::Checkpoint,
    SessionOp::Drop,
];

/// Whether a worker that advertises `capability` gets sessions.
pub(super) fn serves_sessions(capability: &SessionCapability) -> bool {
    REQUIRED_OPS.iter().all(|op| capability.serves(*op))
}

/// Call fields that steer sampling or the reply's length alone, never the
/// prompt's tokens or what a prefix computes. Every other field (template
/// arguments, reasoning switches, the response format, anything unknown)
/// is conditioning, and keys the session.
const SAMPLING_FIELDS: [&str; 18] = [
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "typical_p",
    "seed",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "stop",
    "presence_penalty",
    "frequency_penalty",
    "repetition_penalty",
    "logit_bias",
    "logprobs",
    "top_logprobs",
    "user",
    "metadata",
];

/// The call's non-token conditioning: its fields less [`SAMPLING_FIELDS`],
/// and its tool definitions, so token equality alone never claims a match.
pub(super) fn conditioning(params: &JsonValue, tools: Option<&JsonValue>) -> ConditioningDigest {
    let kept: BTreeMap<&str, &JsonValue> = params
        .as_object()
        .map(|fields| {
            fields
                .iter()
                .filter(|(key, _)| !SAMPLING_FIELDS.contains(&key.as_str()))
                .map(|(key, value)| (key.as_str(), value))
                .collect()
        })
        .unwrap_or_default();
    let bytes = serde_json::to_vec(&(kept, tools)).unwrap_or_default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.llm.session.conditioning.v1\0");
    hasher.update(&bytes);
    ConditioningDigest(*hasher.finalize().as_bytes())
}

/// One wire message as a manifest binds it: the same digest the host took
/// of the request's message. A part that is not text (or reasoning, tool
/// framing or a tool result) makes it not plain.
fn wire_stamp(message: &JsonValue) -> MessageStamp {
    let role = message
        .get("role")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    let framed = ["tool_calls", "reasoning_content", "tool_call_id"]
        .iter()
        .any(|key| message.get(key).is_some());
    let mut plain = role != "tool" && !framed;
    let mut text = String::new();
    match message.get("content") {
        Some(JsonValue::String(content)) => text.push_str(content),
        Some(JsonValue::Array(parts)) => {
            for part in parts {
                match (
                    part.get("type").and_then(JsonValue::as_str),
                    part.get("text"),
                ) {
                    (Some("text"), Some(JsonValue::String(piece))) => text.push_str(piece),
                    _ => plain = false,
                }
            }
        }
        _ => plain = false,
    }
    MessageStamp {
        digest: message_digest(role, plain, &text),
        plain,
    }
}

/// Whether `manifest` describes exactly the wire `messages` the call
/// sends: a rung that reshaped them gets no session.
pub(super) fn describes(manifest: &SegmentManifest, messages: &[JsonValue]) -> bool {
    messages.len() == manifest.messages().len()
        && messages
            .iter()
            .zip(manifest.messages())
            .all(|(message, stamp)| wire_stamp(message) == *stamp)
}

/// Where the canonical path ends: the manifest's canonical prefix, when it
/// holds at least one message and everything after it is the ephemeral
/// tail (the board and the newest user message). A canonical message past
/// the cut (a log line of unknown provenance) gets the call no session.
pub(super) fn canonical_cut(manifest: &SegmentManifest) -> Option<usize> {
    let cut = manifest.canonical_prefix();
    let tail_ephemeral = manifest
        .segments()
        .iter()
        .filter(|segment| segment.message >= cut)
        .all(|segment| segment.class == SegmentClass::Ephemeral);
    (cut > 0 && cut < manifest.messages().len() && tail_ephemeral).then_some(cut)
}

/// The newest user message's index, which joins the canonical path once
/// the reply is committed.
pub(super) fn newest_user(manifest: &SegmentManifest) -> Option<usize> {
    manifest
        .segments()
        .iter()
        .find(|segment| segment.kind == SegmentKind::NewestUser)
        .map(|segment| segment.message)
}

/// Why a session of `old`'s key no longer serves a turn keyed `new` in the
/// same conversation: the read, the fold, or the model and its conditioning.
pub(super) fn replaced(old: &SessionKey, new: &SessionKey) -> SessionInvalidation {
    if old.anchor.read_scope != new.anchor.read_scope || old.anchor.vault != new.anchor.vault {
        SessionInvalidation::DisclosureOrScope
    } else if old.anchor.fold_epoch != new.anchor.fold_epoch {
        SessionInvalidation::FoldBeforeFrontier
    } else {
        SessionInvalidation::Identity
    }
}

/// Whether a fork showed the published checkpoint stale: the turn's
/// canonical path keeps less than its frontier (another path selected, or
/// the prefix's tokens changed), or the worker lost it. The turn still runs
/// on its branch, at the frontier the worker verified; the session goes.
pub(super) fn stale_after_fork(
    published: Option<&CanonicalCheckpointRef>,
    head: Option<oneiron::EntityId>,
    forked: &SessionForked,
) -> Option<SessionInvalidation> {
    let published = published?;
    if !forked.residency.resident {
        Some(SessionInvalidation::ResidencyLost)
    } else if forked.canonical_lcp_tokens >= published.frontier_tokens {
        None
    } else if published.head != head {
        Some(SessionInvalidation::PathChanged)
    } else {
        Some(SessionInvalidation::PrefixTokens)
    }
}

/// Why a refused session op drops its session: a stale generation means
/// another publish moved it; anything else, that the worker no longer
/// holds it as the host does.
pub(super) fn refused(code: &str) -> SessionInvalidation {
    match code {
        "stale_generation" => SessionInvalidation::StaleHead,
        "binding_mismatch" => SessionInvalidation::DisclosureOrScope,
        "lost_residency" => SessionInvalidation::ResidencyLost,
        _ => SessionInvalidation::Evicted,
    }
}

/// What a staged successor calls for.
pub(super) enum SuffixPlan {
    /// Compute its new suffix and publish it.
    Compute,
    /// It adds no token to what is published.
    Nothing,
    /// It does not extend what is published: the session goes.
    Drop(SessionInvalidation),
}

/// The suffix commit runs only when the staged path keeps the whole
/// published checkpoint and adds to it.
pub(super) fn suffix_plan(
    base: Option<&CanonicalCheckpointRef>,
    appended: &SessionAppended,
) -> SuffixPlan {
    let kept = base.map_or(0, |base| base.frontier_tokens);
    if appended.lcp_tokens < kept {
        SuffixPlan::Drop(SessionInvalidation::PrefixTokens)
    } else if appended.staged_tokens <= appended.lcp_tokens {
        SuffixPlan::Nothing
    } else {
        SuffixPlan::Compute
    }
}

/// An op id, unique in this process (the native channel's own request
/// ids): a retried op names the same one.
pub(super) fn next_op_id() -> u64 {
    crate::models::native_exl3::next_request_id()
}
