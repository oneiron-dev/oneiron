//! Code mode's `self.memory.<verb>`: the run's write origin and the receipt a write keeps.

use serde_json::Value;

use crate::code_run::payload::decode_self_dispatch_outcome;
use crate::code_run::replay::{CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord};
use crate::code_run::storage::derived_executor_id;
use crate::code_run::types::{
    AgentVerbRefusal, SelfAgentVerbCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome,
    SelfEffect,
};
use crate::error::{Error, Result};
use crate::memory::HostWriteOrigin;

use super::{ExecutorCallSite, HostSelfDispatcher};

const AGENT_VERB_RECEIPT_DOMAIN: &[u8] = b"oneiron:executor-agent-verb-receipt:v1";

impl HostSelfDispatcher<'_> {
    /// A refused verb is the guest's to handle, like any typed refusal: it
    /// does not halt the run, and the verb's own gate owns its writes.
    ///
    /// Every call carries the run's host-owned write origin. A write in a
    /// durable run also keeps its receipt, reserved before the door runs and
    /// keyed by the call itself within its step: the step's first position,
    /// the verb, the input, and how many times this attempt has already made
    /// the same call. A step resumed after the write committed but before its
    /// checkpoint gets the first receipt back wherever the re-run places the
    /// call; a write that may have committed without its receipt fails
    /// closed, never repeats.
    pub(super) fn dispatch_agent_verb(
        &self,
        call: SelfAgentVerbCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let Some(door) = &self.agent_verbs else {
            return Ok(answered(Err(AgentVerbRefusal {
                code: "agent_verb_door_unbound".to_owned(),
                message: "this run's host binds no SDK verb door".to_owned(),
            })));
        };
        let origin =
            HostWriteOrigin::new(self.agent_verb_envelope(call.verb, site.map(|site| site.seq))?);
        let Some(site) = site.filter(|_| call.verb.writes()) else {
            return Ok(answered(door.call(&call, &origin)));
        };
        let identity = call_identity(call.verb.as_str(), &call.input);
        let repeats = site
            .earlier
            .iter()
            .filter(|row| row_identity(row).as_ref() == Some(&identity))
            .count();
        let receipt_id = derived_executor_id(
            AGENT_VERB_RECEIPT_DOMAIN,
            &[
                self.run_ref.as_bytes(),
                site.run_id.as_bytes(),
                &site.step_start.to_le_bytes(),
                &identity,
                &(repeats as u64).to_le_bytes(),
            ],
        )?;
        if let Some(receipt) = self.storage.get_code_run_replay_record(&receipt_id)? {
            let Some(row) = receipt.bridge_calls.first() else {
                return Err(Error::ConcurrentWrite(
                    "agent verb write is in flight or needs reconciliation",
                ));
            };
            return decode_self_dispatch_outcome(&row.outcome);
        }
        let mut receipt = CodeRunReplayRecord::new(receipt_id, CodeRunDeterminism::new(0, [0; 32]));
        let generation = self
            .storage
            .put_code_run_replay_record_if_generation_with_heal(&receipt, None, None)?;
        let outcome = answered(door.call(&call, &origin));
        receipt.bridge_calls.push(CodeRunBridgeCall::record(
            site.seq,
            &SelfCall::AgentVerb(call),
            &outcome,
            0,
            0,
        )?);
        self.storage
            .put_code_run_replay_record_if_generation_with_heal(&receipt, Some(generation), None)?;
        Ok(outcome)
    }
}

fn answered(
    outcome: std::result::Result<serde_json::Value, AgentVerbRefusal>,
) -> SelfDispatchOutcome {
    outcome.map_or_else(
        |refusal| {
            SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect: SelfEffect::AgentVerb,
                outcome: refusal.code,
                reason_codes: vec![refusal.message],
            })
        },
        SelfDispatchOutcome::AgentVerb,
    )
}

/// A verb call's identity: the verb and its input with object keys sorted, so
/// a re-run that writes the same fields in another order makes the same call.
fn call_identity(verb: &str, input: &Value) -> Vec<u8> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(fields) => {
                let mut fields: Vec<_> = fields.iter().collect();
                fields.sort_unstable_by_key(|(name, _)| *name);
                Value::Object(
                    fields
                        .into_iter()
                        .map(|(name, value)| (name.clone(), sorted(value)))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    let mut identity = verb.as_bytes().to_vec();
    identity.push(0);
    identity.extend(sorted(input).to_string().into_bytes());
    identity
}

/// The identity of an earlier verb call this attempt recorded, if the row is one.
fn row_identity(row: &CodeRunBridgeCall) -> Option<Vec<u8>> {
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
    let input = serde_json::from_str(field("input")?).ok()?;
    Some(call_identity(field("verb")?, &input))
}
