//! Code mode's `self.memory.<verb>`: the run's write origin and the receipt a write keeps.

use serde_json::Value;

use crate::EntityId;
use crate::code_run::payload::decode_self_dispatch_outcome;
use crate::code_run::replay::{CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord};
use crate::code_run::storage::{ExecutorStorage, derived_executor_id};
use crate::code_run::types::{
    AGENT_VERB_DOOR_UNBOUND, AGENT_VERB_SESSION_BOUND, AgentVerbRefusal, RunCall,
    SelfAgentVerbCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome, SelfEffect,
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
    ///
    /// A run bound to an off-record session forwards no verb, read or write:
    /// the door runs on the canonical vault, outside the session's route and,
    /// in a room on record, its saver, so none of the session's checks would
    /// hold in the transactions it opens.
    pub(super) fn dispatch_agent_verb(
        &self,
        call: SelfAgentVerbCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        if matches!(self.storage, ExecutorStorage::Session(_)) {
            return Ok(answered(Err(AgentVerbRefusal {
                code: AGENT_VERB_SESSION_BOUND.to_owned(),
            })));
        }
        let Some(door) = &self.agent_verbs else {
            return Ok(answered(Err(AgentVerbRefusal {
                code: AGENT_VERB_DOOR_UNBOUND.to_owned(),
            })));
        };
        let origin =
            HostWriteOrigin::new(self.agent_verb_envelope(call.verb, site.map(|site| site.seq))?);
        let Some(site) = site.filter(|_| call.verb.writes()) else {
            return Ok(answered(door.call(&call, &origin)));
        };
        // Every write before this one in the step met its receipt: a write
        // that does not (refused at the gate, or recorded after the bridge
        // halted) halts the bridge, and `dispatch_bound` refuses every call
        // past one whose kept answer the door refused, so no later call
        // reaches this door.
        let ordinal = site.earlier.iter().filter(is_write).count() as u64;
        let receipt_id = self.write_receipt_id(site.run_id, site.step_start, ordinal)?;
        if let Some(receipt) = self.storage.get_code_run_replay_record(&receipt_id)? {
            let Some(row) = receipt.bridge_calls.first() else {
                return Err(Error::ConcurrentWrite(
                    "agent verb write is in flight or needs reconciliation",
                ));
            };
            // The kept answer is a result the run recorded: the door rules on
            // reading it back, as on the run's other recorded outputs. Its
            // refusal stands on the receipt until an admitted read of the
            // answer reconciles it, so no later attempt of the step goes on
            // past it either.
            if let Err(refusal) = door.admit_run_call(RunCall::RecordedOutput) {
                let rejected = super::gate_rejection(&refusal.code);
                let refused = answered(Err(refusal));
                let row = CodeRunBridgeCall::record(1, &SelfCall::AgentVerb(call), &refused, 0, 0)?;
                self.keep_refusal(&receipt, Some(row))?;
                if let Some(rejected) = rejected {
                    return Err(rejected);
                }
                return Ok(refused);
            }
            if row_identity(row) != Some(call_identity(call.verb.as_str(), &call.input)) {
                return Err(Error::InvariantViolation(
                    "a resumed step changed a write it already made",
                ));
            }
            self.keep_refusal(&receipt, None)?;
            return decode_self_dispatch_outcome(&row.outcome);
        }
        let mut receipt = CodeRunReplayRecord::new(receipt_id, CodeRunDeterminism::new(0, [0; 32]));
        let generation = self
            .storage
            .put_code_run_replay_record_if_generation_with_heal(&receipt, None, None)?;
        let outcome = answered(door.call(&call, &origin));
        // A receipt keeps its call's answer as its record's first row.
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

    /// A step past a write that did not meet its receipt can no longer close,
    /// so it commits nothing more: every later call gets the refusal that
    /// write got in place of its kept answer, or an error where it got none.
    /// A write that kept no receipt (refused before its door ran) made
    /// nothing to meet.
    ///
    /// A kept answer's refusal also stands on its receipt, so it holds in
    /// every later attempt of the step until an admitted read of the answer
    /// reconciles it. Until then `call` gets it too, unless `call` is a write
    /// the step already made: its receipt answers it, never writes again, and
    /// the door rules on that answer once more. `None` is a read of the run's
    /// recorded outputs.
    pub(crate) fn refusal_past_an_unmet_write(
        &self,
        site: ExecutorCallSite<'_>,
        call: Option<&SelfCall>,
    ) -> Result<Option<SelfDeniedResult>> {
        let receipt_at = |ordinal: u64| {
            self.storage.get_code_run_replay_record(&self.write_receipt_id(
                site.run_id,
                site.step_start,
                ordinal,
            )?)
        };
        for (ordinal, made) in (0_u64..).zip(site.earlier.iter().filter(is_write)) {
            let Some(receipt) = receipt_at(ordinal)? else {
                continue;
            };
            let met = receipt.bridge_calls.first().is_some_and(|kept| {
                row_identity(kept) == row_identity(made) && answered_as_kept(kept, made)
            });
            if met {
                continue;
            }
            return match decode_self_dispatch_outcome(&made.outcome) {
                Ok(SelfDispatchOutcome::Denied(refused)) => Ok(Some(refused)),
                _ => Err(Error::InvariantViolation(
                    "a step went on past a write that did not meet its receipt",
                )),
            };
        }
        let writes = matches!(call, Some(SelfCall::AgentVerb(call)) if call.verb.writes());
        let made = site.earlier.iter().filter(is_write).count() as u64;
        if writes && receipt_at(made)?.is_some() {
            return Ok(None);
        }
        let mut ordinal = 0;
        while let Some(receipt) = receipt_at(ordinal)? {
            if let Some(refused) = receipt.bridge_calls.get(1) {
                return kept_refusal(refused).map(Some);
            }
            ordinal += 1;
        }
        Ok(None)
    }

    /// Keeps the refusal a write's kept answer got on its receipt, beside the
    /// answer, as the row the guest got; `None` clears it once the answer is
    /// read back admitted. One transaction writes it, and a restart keeps it.
    fn keep_refusal(
        &self,
        receipt: &CodeRunReplayRecord,
        refused: Option<CodeRunBridgeCall>,
    ) -> Result<()> {
        let mut kept = receipt.clone();
        kept.bridge_calls.truncate(1);
        kept.bridge_calls.extend(refused);
        if kept.bridge_calls != receipt.bridge_calls {
            self.storage.put_code_run_replay_record_if_generation_with_heal(
                &kept,
                Some(receipt.generation()?),
                None,
            )?;
        }
        Ok(())
    }

    /// Refuses to close a step that left out a write an earlier attempt of it
    /// made. A resumed step makes the step's writes again in order, each
    /// answered from its receipt: the step's writes, in order, must be the
    /// receipts' calls with the receipts' answers. A receipt the step did not
    /// meet so (a write left out, or one the bridge recorded after halting
    /// and never dispatched) means the step would checkpoint without that
    /// write, and a later step could make it again under a fresh receipt.
    pub(crate) fn refuse_a_step_that_dropped_a_write(
        &self,
        run_id: EntityId,
        step_start: u64,
        calls: &[CodeRunBridgeCall],
    ) -> Result<()> {
        let mut made = calls.iter().filter(is_write);
        let mut ordinal = 0;
        while let Some(receipt) = self
            .storage
            .get_code_run_replay_record(&self.write_receipt_id(run_id, step_start, ordinal)?)?
        {
            let met = receipt
                .bridge_calls
                .first()
                .zip(made.next())
                .is_some_and(|(kept, made)| {
                    row_identity(kept) == row_identity(made) && answered_as_kept(kept, made)
                });
            if !met {
                return Err(Error::InvariantViolation(
                    "a resumed step left out a write it already made",
                ));
            }
            ordinal += 1;
        }
        Ok(())
    }

    /// The receipt of the step's write at `ordinal`: the run, the step's first
    /// bridge position, and how many verb writes the step made before it.
    fn write_receipt_id(
        &self,
        run_id: EntityId,
        step_start: u64,
        ordinal: u64,
    ) -> Result<EntityId> {
        derived_executor_id(
            AGENT_VERB_RECEIPT_DOMAIN,
            &[
                self.run_ref.as_bytes(),
                run_id.as_bytes(),
                &step_start.to_le_bytes(),
                &ordinal.to_le_bytes(),
            ],
        )
    }
}

/// The refusal a receipt keeps beside its answer, as the run takes it: one
/// spelled as a gate's outcome word halts the bridge as that gate does.
fn kept_refusal(row: &CodeRunBridgeCall) -> Result<SelfDeniedResult> {
    let Ok(SelfDispatchOutcome::Denied(refused)) = decode_self_dispatch_outcome(&row.outcome)
    else {
        return Err(Error::CorruptedIndex("agent verb receipt refusal"));
    };
    if let Some(rejected) = super::gate_rejection(&refused.outcome) {
        return Err(rejected);
    }
    Ok(refused)
}

/// A refusal reaches the guest as its stable code alone; the host or prompt
/// layer words it.
fn answered(
    outcome: std::result::Result<serde_json::Value, AgentVerbRefusal>,
) -> SelfDispatchOutcome {
    outcome.map_or_else(
        |refusal| {
            SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect: SelfEffect::AgentVerb,
                outcome: refusal.code,
                reason_codes: Vec::new(),
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

/// Whether a write row carries the answer its receipt kept: a verb's answer,
/// which only this door gives a write (fresh, or read back from the
/// receipt), or the same refusal. A row the bridge recorded without
/// dispatching it carries neither. A verb's answer is matched by kind: its
/// JSON text need not survive a decode exactly, as a float may move by one
/// unit in the last place.
fn answered_as_kept(kept: &CodeRunBridgeCall, made: &CodeRunBridgeCall) -> bool {
    match (
        decode_self_dispatch_outcome(&kept.outcome),
        decode_self_dispatch_outcome(&made.outcome),
    ) {
        (Ok(SelfDispatchOutcome::AgentVerb(_)), Ok(SelfDispatchOutcome::AgentVerb(_))) => true,
        (Ok(SelfDispatchOutcome::Denied(kept)), Ok(SelfDispatchOutcome::Denied(made))) => {
            kept == made
        }
        _ => false,
    }
}

/// Whether a recorded call is a verb write.
fn is_write(row: &&CodeRunBridgeCall) -> bool {
    recorded_call(row)
        .is_some_and(|(verb, _)| AgentVerb::from_name(verb).is_some_and(AgentVerb::writes))
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
