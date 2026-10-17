//! OF-568: the input versions a `self.*` call reads, captured before the
//! host dispatches it, for its bridge row's action digest
//! ([`super::CodeRunBridgeCall::with_inputs`]).

use std::collections::BTreeSet;

use rmpv::Value;

use super::payload::self_call_request_value;
use super::types::{SelfCall, SelfEffect};
use crate::receipt::{ActionInputs, call_reads_world, json_entity_refs};
use crate::{EntityId, Result, Vault};

/// The input versions `call` reads on `vault`, captured before it runs: the
/// vault's state and each entity its request names
/// ([`Vault::action_inputs`]). `None` for a call that is no tool run (speech,
/// a wait, an ask of a person, a fixture) or one that reads the world
/// outside the vault.
pub(crate) fn self_call_inputs(vault: &Vault, call: &SelfCall) -> Result<Option<ActionInputs>> {
    let world = match call {
        SelfCall::AgentVerb(verb) => call_reads_world(verb.verb.as_str()),
        _ => matches!(
            call.effect(),
            SelfEffect::Speak
                | SelfEffect::Think
                | SelfEffect::Express
                | SelfEffect::TasksWait
                | SelfEffect::TasksWaitSet
                | SelfEffect::Ask
                | SelfEffect::TasksAsk
                | SelfEffect::DestructiveFixture
                | SelfEffect::OutboundFixture
        ),
    };
    if world {
        return Ok(None);
    }
    let mut named = BTreeSet::new();
    entity_refs(&self_call_request_value(call)?, &mut named);
    vault.action_inputs(&named)
}

/// Collects the entity ids `value` names: 16-byte binaries, 32-hex strings
/// and the ids inside an embedded JSON string, at any depth.
fn entity_refs(value: &Value, named: &mut BTreeSet<EntityId>) {
    match value {
        Value::Binary(bytes) => {
            if let Ok(bytes) = <[u8; 16]>::try_from(bytes.as_slice()) {
                named.extend(EntityId::from_bytes(bytes).ok());
            }
        }
        Value::String(text) => match text.as_str() {
            Some(hex) if hex.len() == 32 => named.extend(EntityId::from_hex(hex).ok()),
            Some(json) if json.starts_with(['{', '[']) => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(json) {
                    named.extend(json_entity_refs(&json));
                }
            }
            _ => {}
        },
        Value::Array(items) => items.iter().for_each(|item| entity_refs(item, named)),
        Value::Map(entries) => entries
            .iter()
            .for_each(|(_, value)| entity_refs(value, named)),
        _ => {}
    }
}
