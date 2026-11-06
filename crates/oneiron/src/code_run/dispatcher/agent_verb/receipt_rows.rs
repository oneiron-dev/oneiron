//! How a write's receipt row and the run's own row of the same write are
//! read: the verb call each recorded, its identity, and whether the run's
//! row carries the answer the receipt kept.

use crate::code_run::payload::{
    agent_verb_call_identity as call_identity, decode_self_dispatch_outcome,
};
use crate::code_run::replay::CodeRunBridgeCall;
use crate::code_run::types::{SelfDispatchOutcome, SelfEffect};
use crate::task_verb::sdk::AgentVerb;

/// The identity of the verb call a receipt row recorded, if the row is one.
pub(super) fn row_identity(row: &CodeRunBridgeCall) -> Option<Vec<u8>> {
    let (verb, input) = recorded_call(row)?;
    if crate::verb_catalog::CUSTODY_VALUE_ROWS.contains(&verb) {
        if !input.is_empty() {
            return None;
        }
        let rmpv::Value::Map(fields) = &row.request else {
            return None;
        };
        let (_, rmpv::Value::Binary(digest)) = fields
            .iter()
            .find(|(key, _)| key.as_str() == Some("input_identity"))?
        else {
            return None;
        };
        if digest.len() != 32 {
            return None;
        }
        let mut identity = verb.as_bytes().to_vec();
        identity.push(0);
        identity.extend_from_slice(digest);
        return Some(identity);
    }
    Some(call_identity(verb, &serde_json::from_str(input).ok()?))
}

/// Whether a write row carries the answer its receipt kept: a verb's answer,
/// which only this door gives a write (fresh, or read back from the
/// receipt), or the same refusal. A row the bridge recorded without
/// dispatching it carries neither. A verb's answer is matched by kind: its
/// JSON text need not survive a decode exactly, as a float may move by one
/// unit in the last place.
pub(super) fn answered_as_kept(kept: &CodeRunBridgeCall, made: &CodeRunBridgeCall) -> bool {
    match (
        decode_self_dispatch_outcome(&kept.outcome),
        decode_self_dispatch_outcome(&made.outcome),
    ) {
        (Ok(SelfDispatchOutcome::AgentVerb(_)), Ok(SelfDispatchOutcome::AgentVerb(_))) => true,
        (Ok(SelfDispatchOutcome::Denied(kept)), Ok(SelfDispatchOutcome::Denied(made))) => {
            kept == made
        }
        // A held connector call's park (ONE-2510).
        (
            Ok(SelfDispatchOutcome::DurableWait(kept)),
            Ok(SelfDispatchOutcome::DurableWait(made)),
        ) => kept == made,
        _ => false,
    }
}

/// Whether a recorded call is a verb write.
pub(super) fn is_write(row: &&CodeRunBridgeCall) -> bool {
    recorded_call(row)
        .is_some_and(|(verb, _)| AgentVerb::from_name(verb).is_some_and(AgentVerb::writes))
}

/// The verb name and JSON input of a recorded verb call, if the row is one.
pub(crate) fn recorded_call(row: &CodeRunBridgeCall) -> Option<(&str, &str)> {
    if row.effect != SelfEffect::AgentVerb {
        return None;
    }
    let rmpv::Value::Map(fields) = &row.request else {
        return None;
    };
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .and_then(|(_, value)| value.as_str())
    };
    Some((field("verb")?, field("input")?))
}
