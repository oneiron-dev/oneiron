//! Code mode's `self.memory.<verb>`: the run's write origin and the receipt a write keeps.

use serde_json::Value;

use crate::EntityId;
use crate::code_run::payload::decode_self_dispatch_outcome;
use crate::code_run::replay::{CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord};
use crate::code_run::storage::derived_executor_id;
use crate::code_run::types::{
    AgentVerbRefusal, SelfAgentVerbCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome,
    SelfEffect,
};
use crate::error::{Error, Result};
use crate::memory::HostWriteOrigin;
use crate::task_verb::sdk::AgentVerb;

use super::{ExecutorCallSite, HostSelfDispatcher};

const AGENT_VERB_RECEIPT_DOMAIN: &[u8] = b"oneiron:executor-agent-verb-receipt:v1";

impl HostSelfDispatcher<'_> {
    /// A refused verb is the guest's to handle, like any typed refusal: it
    /// does not halt the run, and the verb's own gate owns its writes.
    ///
    /// Every call carries the run's host-owned write origin. A write in a
    /// durable run also keeps its receipt, reserved before the door runs and
    /// keyed by the write's place in its step: the step's first position and
    /// how many writes the step made before it. Reads do not count, so a
    /// re-generated step may move them. A step resumed after the write
    /// committed but before its checkpoint gets the first receipt back when it
    /// makes the same call there; a changed call, or a write that may have
    /// committed without its receipt, fails closed, never repeats.
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
        let receipt_id = self.write_receipt_id(site.run_id, site.step_start, site.earlier)?;
        if let Some(receipt) = self.storage.get_code_run_replay_record(&receipt_id)? {
            let Some(row) = receipt.bridge_calls.first() else {
                return Err(Error::ConcurrentWrite(
                    "agent verb write is in flight or needs reconciliation",
                ));
            };
            if row_identity(row) != Some(call_identity(call.verb.as_str(), &call.input)) {
                return Err(Error::InvariantViolation(
                    "a resumed step changed a write it already made",
                ));
            }
            return decode_self_dispatch_outcome(&row.outcome);
        }
        let mut receipt = CodeRunReplayRecord::new(receipt_id, CodeRunDeterminism::new(0, [0; 32]));
        let generation = self
            .storage
            .put_code_run_replay_record_if_generation_with_heal(&receipt, None, None)?;
        let outcome = answered(door.call(&call, &origin));
        // A receipt is a one-call record, so its row is that record's first.
        receipt.bridge_calls.push(CodeRunBridgeCall::record(
            0,
            &SelfCall::AgentVerb(call),
            &outcome,
            0,
            0,
        )?);
        self.storage
            .put_code_run_replay_record_if_generation_with_heal(&receipt, Some(generation), None)?;
        Ok(outcome)
    }

    /// Refuses to close a step that left out a write an earlier attempt of it
    /// made. A resumed step makes the step's writes again in order, each
    /// meeting its receipt; a receipt past the last of them means the step
    /// would checkpoint without that write, and a later step could make it
    /// again under a fresh receipt.
    pub(crate) fn refuse_a_step_that_dropped_a_write(
        &self,
        run_id: EntityId,
        step_start: u64,
        calls: &[CodeRunBridgeCall],
    ) -> Result<()> {
        let next = self.write_receipt_id(run_id, step_start, calls)?;
        if self.storage.get_code_run_replay_record(&next)?.is_some() {
            return Err(Error::InvariantViolation(
                "a resumed step left out a write it already made",
            ));
        }
        Ok(())
    }

    /// The receipt of the step's next write: the run, the step's first bridge
    /// position, and how many verb writes `earlier` (the step's calls so far)
    /// holds.
    fn write_receipt_id(
        &self,
        run_id: EntityId,
        step_start: u64,
        earlier: &[CodeRunBridgeCall],
    ) -> Result<EntityId> {
        let writes = earlier
            .iter()
            .filter_map(recorded_call)
            .filter(|(verb, _)| AgentVerb::from_name(verb).is_some_and(AgentVerb::writes))
            .count();
        derived_executor_id(
            AGENT_VERB_RECEIPT_DOMAIN,
            &[
                self.run_ref.as_bytes(),
                run_id.as_bytes(),
                &step_start.to_le_bytes(),
                &(writes as u64).to_le_bytes(),
            ],
        )
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

/// The identity of the verb call a receipt row recorded, if the row is one.
fn row_identity(row: &CodeRunBridgeCall) -> Option<Vec<u8>> {
    let (verb, input) = recorded_call(row)?;
    Some(call_identity(verb, &serde_json::from_str(input).ok()?))
}

/// The verb name and JSON input of a recorded verb call, if the row is one.
fn recorded_call(row: &CodeRunBridgeCall) -> Option<(&str, &str)> {
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
