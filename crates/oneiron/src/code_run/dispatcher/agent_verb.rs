//! Code mode's verb-table calls: the run's write origin and the receipt a write keeps.

use serde_json::Value;

use crate::EntityId;
use crate::code_run::payload::decode_self_dispatch_outcome;
use crate::code_run::replay::{CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord};
use crate::code_run::storage::{ExecutorStorage, derived_executor_id};
use crate::code_run::types::{
    AGENT_VERB_DOOR_UNBOUND, AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, AgentVerbRefusal, RunCall,
    SelfAgentVerbCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome, SelfDurableWait,
    SelfDurableWaitReason, SelfEffect,
};
use crate::error::{Error, Result};
use crate::memory::HostWriteOrigin;
use crate::runtime_hooks::VerbHookStop;
use crate::secret_custody::SECRET_USE_CONNECTOR_CALL;
use crate::task_verb::sdk::{AgentVerb, ConnectorCallReply, SecretUseAnswer};

use super::{ExecutorCallSite, HostSelfDispatcher};

const AGENT_VERB_RECEIPT_DOMAIN: &[u8] = b"oneiron:executor-agent-verb-receipt:v1";

/// The reason a receipt's refusal row carries, so that no row read back from
/// the receipt's answer, a refusal or not, is ever taken for one.
const KEPT_ANSWER_REFUSED: &str = "kept_answer_refused";

/// The mark a receipt keeps when a verb hook stopped its write before the
/// write ran (ARCH-0080 §3): nothing was written, so a replay of the step
/// asks the door again.
const VERB_HOOK_STOPPED: &str = "verb_hook_stopped";

/// The answer a write's receipt keeps when a verb hook hid its result after
/// the write ran: kept, so a replay never writes again.
const VERB_HOOK_HIDDEN: &str = "verb_hook_hidden";

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
    /// on record, its saver, so none of the session's checks would
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
        // A write carries the run's TASK creator, so a TASK it creates runs
        // inside the creator's lease tree (OF-532).
        let task_host = if call.verb.writes() {
            self.task_host_binding()?
        } else {
            None
        };
        let origin =
            HostWriteOrigin::new(self.agent_verb_envelope(call.verb, site.map(|site| site.seq))?)
                .with_task_host(task_host)
                .with_model_provider(self.model_provider());
        // The call's step names the logical verb its hooks fire once for, the
        // same across replays of the step, and a call a hook's ask parked
        // keeps its invocation into a later step (ARCH-0080 §3). A hook's
        // stop goes back to the dispatcher as `Error::VerbHook`.
        let invocation = self.verb_invocation(&SelfCall::AgentVerb(call.clone()), site)?;
        let Some(site) = site.filter(|_| call.verb.writes()) else {
            let answer = door.call(&call, &origin, invocation)?;
            return Ok(connector_call_answer(
                call.verb,
                answered(self.keep_no_secret_value(call.verb, answer)),
            ));
        };
        // Every write before this one in the step met its receipt: a write
        // that does not (refused at the gate, or recorded after the bridge
        // halted) halts the bridge, and `dispatch_bound` refuses every call
        // past one whose kept answer the door refused, so no later call
        // reaches this door.
        let ordinal = site.earlier.iter().filter(is_write).count() as u64;
        let receipt_id = self.write_receipt_id(site.run_id, site.step_start, ordinal)?;
        let kept = self.storage.get_code_run_replay_record(&receipt_id)?;
        // A hook stopped this write before it ran, so nothing was written:
        // the door is asked again, under a fresh reservation.
        let stopped = match &kept {
            Some(receipt) if receipt.bridge_calls.first().is_some_and(hook_stopped) => {
                Some(receipt.generation()?)
            }
            _ => None,
        };
        if let Some(receipt) = kept.filter(|_| stopped.is_none()) {
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
                let ruling = SelfDispatchOutcome::Denied(SelfDeniedResult {
                    effect: SelfEffect::AgentVerb,
                    outcome: refusal.code.clone(),
                    reason_codes: vec![KEPT_ANSWER_REFUSED.to_owned()],
                });
                let ruling =
                    CodeRunBridgeCall::record(0, &SelfCall::AgentVerb(call), &ruling, 0, 0)?;
                self.append_ruling(&receipt, ruling)?;
                if let Some(rejected) = rejected {
                    return Err(rejected);
                }
                return Ok(answered(Err(refusal)));
            }
            if row_identity(row) != Some(call_identity(call.verb.as_str(), &call.input)) {
                return Err(Error::InvariantViolation(
                    "a resumed step changed a write it already made",
                ));
            }
            if standing_refusal(&receipt).is_some() {
                self.append_ruling(&receipt, row.clone())?;
            }
            return decode_self_dispatch_outcome(&row.outcome);
        }
        let mut receipt = CodeRunReplayRecord::new(receipt_id, CodeRunDeterminism::new(0, [0; 32]));
        let generation = self
            .storage
            .put_code_run_replay_record_if_generation_with_heal(&receipt, stopped, None)?;
        let outcome = match door.call(&call, &origin, invocation) {
            // A held connector call parks before its receipt keeps it, so a
            // resumed step parks on the same call again.
            Ok(answer) => connector_call_answer(call.verb, answered(answer)),
            Err(Error::VerbHook(stop)) if matches!(*stop, VerbHookStop::Hidden { .. }) => {
                answered(Err(AgentVerbRefusal {
                    code: VERB_HOOK_HIDDEN.to_owned(),
                }))
            }
            // A skip or an ask stopped the write before it ran: the receipt
            // keeps the stop's mark, and the stop goes to the dispatcher.
            Err(Error::VerbHook(stop)) => {
                receipt.bridge_calls.push(CodeRunBridgeCall::record(
                    0,
                    &SelfCall::AgentVerb(call),
                    &hook_stop_mark(),
                    0,
                    0,
                )?);
                self.storage
                    .put_code_run_replay_record_if_generation_with_heal(
                        &receipt,
                        Some(generation),
                        None,
                    )?;
                return Err(Error::VerbHook(stop));
            }
            Err(error) => return Err(error),
        };
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

    /// A `reveal.wait` answer carries a secret's value (OF-560): the guest
    /// reads it through this call's view, and the run's record keeps the
    /// answer without it, so a step row holds the handle, never the value.
    fn keep_no_secret_value(
        &self,
        verb: AgentVerb,
        answer: std::result::Result<AgentVerbAnswer, AgentVerbRefusal>,
    ) -> std::result::Result<AgentVerbAnswer, AgentVerbRefusal> {
        match answer {
            Ok(mut answer) if verb == AgentVerb::RevealWait => {
                let kept = crate::task_verb::sdk::kept_reveal_answer(&answer.output);
                if kept != answer.output {
                    let output = std::mem::replace(&mut answer.output, kept);
                    *self.hook_view.borrow_mut() = Some(serde_json::json!({ "output": output }));
                }
                Ok(answer)
            }
            other => other,
        }
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
            self.storage
                .get_code_run_replay_record(&self.write_receipt_id(
                    site.run_id,
                    site.step_start,
                    ordinal,
                )?)
        };
        for (ordinal, made) in (0_u64..).zip(site.earlier.iter().filter(is_write)) {
            let Some(receipt) = receipt_at(ordinal)? else {
                continue;
            };
            if meets(&receipt, made) {
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
            if let Some(refused) = standing_refusal(&receipt) {
                return kept_refusal(refused).map(Some);
            }
            ordinal += 1;
        }
        Ok(None)
    }

    /// Appends one ruling on a write's kept answer to its receipt, in one
    /// transaction a restart keeps: each refusal, or, once an admitted read
    /// reconciles a standing refusal, the answer read back. Every ruling
    /// appends, so one decided on an older receipt fails the receipt's
    /// generation compare instead of overwriting a newer one.
    fn append_ruling(
        &self,
        receipt: &CodeRunReplayRecord,
        mut ruling: CodeRunBridgeCall,
    ) -> Result<()> {
        let mut ruled = receipt.clone();
        ruling.seq = ruled.bridge_calls.len() as u64;
        ruled.bridge_calls.push(ruling);
        self.storage
            .put_code_run_replay_record_if_generation_with_heal(
                &ruled,
                Some(receipt.generation()?),
                None,
            )?;
        Ok(())
    }

    /// Refuses to close a step that left out a write an earlier attempt of it
    /// made. A resumed step makes the step's writes again in order, each
    /// answered from its receipt: the step's writes, in order, must be the
    /// receipts' calls with the receipts' answers. A receipt the step did not
    /// meet so (a write left out, one the bridge recorded after halting and
    /// never dispatched, or one whose kept answer stands refused) means the
    /// step would checkpoint without that write, and a later step could make
    /// it again under a fresh receipt.
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
            if !made.next().is_some_and(|made| meets(&receipt, made)) {
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

/// The refusal a write's kept answer stands under, if any. A receipt's first
/// row is its call's answer; the rows after it are the rulings on reading that
/// answer back, each a refusal or the admitted read that reconciled one, so
/// the answer stands refused while the last of them is a refusal.
fn standing_refusal(receipt: &CodeRunReplayRecord) -> Option<&CodeRunBridgeCall> {
    let ruling = receipt.bridge_calls.get(1..)?.last()?;
    let Ok(SelfDispatchOutcome::Denied(refused)) = decode_self_dispatch_outcome(&ruling.outcome)
    else {
        return None;
    };
    (refused.reason_codes == [KEPT_ANSWER_REFUSED]).then_some(ruling)
}

/// Whether a write row met its receipt: it is the receipt's call with the
/// answer the receipt kept, and no refusal of that answer stands. A write a
/// hook stopped before it ran meets its mark whatever the run made of the
/// stop.
fn meets(receipt: &CodeRunReplayRecord, made: &CodeRunBridgeCall) -> bool {
    standing_refusal(receipt).is_none()
        && receipt.bridge_calls.first().is_some_and(|kept| {
            row_identity(kept) == row_identity(made)
                && (hook_stopped(kept) || answered_as_kept(kept, made))
        })
}

/// The mark a write's receipt keeps when a verb hook stopped it before it ran.
fn hook_stop_mark() -> SelfDispatchOutcome {
    SelfDispatchOutcome::Denied(SelfDeniedResult {
        effect: SelfEffect::AgentVerb,
        outcome: VERB_HOOK_STOPPED.to_owned(),
        reason_codes: vec![VERB_HOOK_STOPPED.to_owned()],
    })
}

/// Whether a receipt's row is [`hook_stop_mark`]: the write never ran.
fn hook_stopped(row: &CodeRunBridgeCall) -> bool {
    matches!(
        decode_self_dispatch_outcome(&row.outcome),
        Ok(SelfDispatchOutcome::Denied(refused)) if refused.reason_codes == [VERB_HOOK_STOPPED]
    )
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
    Ok(SelfDeniedResult {
        reason_codes: Vec::new(),
        ..refused
    })
}

/// A refusal reaches the guest as its stable code alone; the host or prompt
/// layer words it.
fn answered(
    outcome: std::result::Result<AgentVerbAnswer, AgentVerbRefusal>,
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

/// `connector.call`'s answer as the run takes it (ONE-2510): a call held for
/// consent or governance, or a delivery the same send retries, parks the run
/// on the call's ref as an outbound-effect wait, which the connector settler
/// answers with the call's settled reply. `self.use`'s `connector.call`
/// parks the same way on the call its answer holds (OF-560). Any other
/// answer, and any other verb's, stands.
fn connector_call_answer(verb: AgentVerb, outcome: SelfDispatchOutcome) -> SelfDispatchOutcome {
    let wait_id = match &outcome {
        SelfDispatchOutcome::AgentVerb(answer) => held_call_ref(verb, &answer.output),
        _ => None,
    };
    let Some(wait_id) = wait_id else {
        return outcome;
    };
    SelfDispatchOutcome::DurableWait(SelfDurableWait {
        wait_id,
        effect: SelfEffect::AgentVerb,
        reason: SelfDurableWaitReason::OutboundEffect,
        prompt: Some(format!("connector_call:{}", wait_id.to_hex())),
    })
}

/// The ref of the connector call a verb's answer holds or retries: a
/// `connector.call` reply's, or the one inside a `self.use` answer whose
/// operation was `connector.call`.
fn held_call_ref(verb: AgentVerb, output: &Value) -> Option<EntityId> {
    let reply = match verb {
        AgentVerb::ConnectorCall => output.clone(),
        AgentVerb::SelfUse => {
            let answer = serde_json::from_value::<SecretUseAnswer>(output.clone()).ok()?;
            if answer.receipt.operation != SECRET_USE_CONNECTOR_CALL {
                return None;
            }
            answer.result?
        }
        _ => return None,
    };
    serde_json::from_value::<ConnectorCallReply>(reply)
        .ok()?
        .wait_ref()
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
        // A held connector call's park (ONE-2510).
        (
            Ok(SelfDispatchOutcome::DurableWait(kept)),
            Ok(SelfDispatchOutcome::DurableWait(made)),
        ) => kept == made,
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
