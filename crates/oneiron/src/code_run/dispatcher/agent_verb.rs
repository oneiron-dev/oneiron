//! Code mode's verb-table calls: the run's write origin and the receipt a write keeps.

mod connector_wait;
mod consent;
mod receipts;
mod scoped_port;
mod session_write;
mod stored_answer;

use serde_json::Value;

use self::connector_wait::connector_call_answer;
use crate::EntityId;
use crate::code_run::payload::{
    agent_verb_call_identity as call_identity, decode_self_dispatch_outcome,
    self_call_request_value,
};
use crate::code_run::replay::{CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord};
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_DOOR_UNBOUND, AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, AgentVerbDoor,
    AgentVerbRefusal, SelfAgentVerbCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome,
    SelfEffect,
};
use crate::error::{Error, Result};
use crate::memory::HostWriteOrigin;
use crate::memory::read_capture::ReadCapture;
use crate::runtime_hooks::VerbHookStop;
use crate::task_verb::sdk::AgentVerb;
use serde::{Deserialize, Serialize};

use super::{ExecutorCallSite, ExecutorReply, HostSelfDispatcher};

use self::receipts::{
    KEPT_ANSWER_REFUSED, KeptWrite, MEDIA_STEP_TRAPPED, PROVIDER_UNAVAILABLE, VERB_HOOK_HIDDEN,
    VERB_HOOK_STOPPED, is_write, meets, never_ran_mark, row_identity, standing_refusal,
};
pub(crate) use self::receipts::{recorded_call, write_receipt_may_have_run};

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
    /// A run bound to an off-record session forwards no verb through the
    /// door: the door runs on the canonical vault, outside the session's
    /// route and, on record, its saver, so none of the session's checks
    /// would hold in the transactions it opens. While the room is off record
    /// a `vault.notes.create` or `vault.claims.upsert` call stages in the
    /// room's overlay instead (DOOR-127, Engine ruling 10-18), as the door
    /// admits it for its caller, through the run's captured route and under
    /// this same receipt (WILL L11-01 S01-2a, `session_write`).
    /// `vault.get`, `vault.hydrate`, `vault.refs.resolve`, `vault.search.bm25`
    /// and `vault.receipts` read the room's view on the key the door admits
    /// for its caller (WILL L11-01, `session_verbs`); every other call is
    /// refused.
    ///
    /// A scoped child (FIX 7507) calls only the ports its parent lent it,
    /// on its host's adapters and its own route (`scoped_port`), before
    /// either rule above: never the session's verbs, nor the host's door.
    pub(super) fn dispatch_agent_verb(
        &self,
        call: SelfAgentVerbCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        if self.scoped_child_spec().is_some() {
            return self.dispatch_scoped_port(call, site);
        }
        if matches!(self.storage, ExecutorStorage::Session(_)) {
            if let Some(read) = call.verb.session_read() {
                return self.dispatch_session_read(read, &call, site);
            }
            if !call.verb.overlay_write() {
                return Ok(answered(Err(AgentVerbRefusal {
                    hook_notice: None,
                    code: AGENT_VERB_SESSION_BOUND.to_owned(),
                })));
            }
            return self.dispatch_session_write(call, site);
        }
        let Some(door) = &self.agent_verbs else {
            return Ok(answered(Err(AgentVerbRefusal {
                hook_notice: None,
                code: AGENT_VERB_DOOR_UNBOUND.to_owned(),
            })));
        };
        // A write carries the run's TASK creator, so a TASK it creates runs
        // inside the creator's lease tree (OF-532). `reveal.describe` judges
        // grants with the run's project as `reveal` does (FIX 2359), and
        // `reveal.wait` finds the reveal its run asked under that project and
        // run (FIX 2360); a run whose binding cannot be read calls without
        // one, as before.
        let task_host = if call.verb.writes() {
            self.task_host_binding()?
        } else if matches!(call.verb, AgentVerb::RevealDescribe | AgentVerb::RevealWait) {
            self.task_host_binding().ok().flatten()
        } else {
            None
        };
        let origin =
            HostWriteOrigin::new(self.agent_verb_envelope(call.verb, site.map(|site| site.seq))?)
                .with_task_host(task_host)
                .with_model_provider(self.model_provider())
                .with_read_proof(self.program_proof().cloned())
                .with_bound_run(self.bound_run);
        // The call's step names the logical verb its hooks fire once for, the
        // same across replays of the step, and a call a hook's ask parked
        // keeps its invocation into a later step (ARCH-0080 §3). A hook's
        // stop goes back to the dispatcher as `Error::VerbHook`. That call
        // names the ask it parked on beside its invocation, as an HTTP retry
        // names its pause (FIX 5526): the door's memory resumes that pause,
        // or refuses one that is gone rather than running a new call. A
        // durable call's origin names that step (FIX 11683).
        let parked = SelfCall::AgentVerb(call.clone());
        let invocation = self.verb_invocation(&parked, site)?;
        let origin = origin
            .with_hook_ask(self.parked_ask(&parked, site)?)
            .with_step(site.map(|_| invocation));
        // Only the native point-view producer is covered here. Other verbs
        // keep their existing unknown ledger until their reads are captured.
        let read_capture =
            (call.verb == AgentVerb::VaultGet && site.is_some()).then(ReadCapture::default);
        let origin = match &read_capture {
            Some(capture) => origin.with_read_capture(capture.clone()),
            None => origin,
        };
        // A skill-library answer's producer witnesses the skill bodies it
        // carries, which the run's host keeps once its guest reads them (FIX
        // 3608).
        let origin = self.with_skill_body_capture(origin, call.verb, site);
        let read_site = site;
        let Some(site) = site.filter(|_| call.verb.writes()) else {
            let answer = self.program_door_call(&**door, &call, &origin, invocation);
            let captured = read_capture.and_then(|capture| capture.finish());
            let outcome = connector_call_answer(
                call.verb,
                worded(
                    answered(self.keep_no_secret_value(call.verb, answer?)),
                    &**door,
                ),
            );
            if let (Some(site), SelfDispatchOutcome::AgentVerb(answer)) = (read_site, &outcome) {
                self.note_verb_read_worlds(site, answer, captured);
            }
            return Ok(outcome);
        };
        // Every write before this one in the step met its receipt: a write
        // that does not (refused at the gate, or recorded after the bridge
        // halted) halts the bridge, and `dispatch_bound` refuses every call
        // past one whose kept answer the door refused, so no later call
        // reaches this door.
        let (ordinal, receipt_id, kept) = self.write_receipt(site)?;
        // A turn program's write is one of its steps (DOOR-141 PR2): bound
        // before it runs, settled with its answer, never sent again.
        let program = self.program_write(site, ordinal, receipt_id, &call)?;
        let stopped = match kept {
            KeptWrite::Ran(receipt) => {
                if let Some(write) = &program
                    && receipt.bridge_calls.is_empty()
                {
                    self.note_program_write_uncertain(write);
                }
                return self.kept_write_answer(Some(&**door), *receipt, call, site);
            }
            KeptWrite::Fresh(stopped) => stopped,
        };
        // The action's own call, when its host holds its input's base64
        // member as a file (FIX 22096): the door takes the file, and every
        // row of the receipt keeps the whole input's digests.
        let held = self
            .action_blob
            .clone()
            .filter(|held| held.holds(call.verb, &call.input));
        let row = |call: SelfAgentVerbCall, outcome: &SelfDispatchOutcome| {
            let mut row = CodeRunBridgeCall::record(0, &SelfCall::AgentVerb(call), outcome, 0, 0)?;
            if let Some(held) = &held {
                row.request = held.request_value();
            }
            Ok::<_, Error>(row)
        };
        let mut receipt = CodeRunReplayRecord::new(receipt_id, CodeRunDeterminism::new(0, [0; 32]));
        let mut generation =
            self.put_write_receipt(&receipt, stopped, program.as_ref(), false, site.run_id)?;
        // A call a code consent wait may bind carries its place in the run
        // (DOOR-079 1a), so a hold for consent alone binds the wait to it.
        let consent_site = self.code_consent_site(&call, site, ordinal, receipt_id)?;
        let origin = match &consent_site {
            Some(consent_site) => origin.with_code_consent(consent_site.clone()),
            None => origin,
        };
        let mut outcome =
            match self.program_door_call_held(&**door, &call, &origin, invocation, held.as_ref()) {
                // A held connector call parks before its receipt keeps it, so a
                // resumed step parks on the same call again: on its code consent
                // wait when one was bound to it, else on the call itself.
                Ok(answer) => self.code_consent_answer(
                    consent_site.as_ref(),
                    call.verb,
                    worded(answered(answer), &**door),
                )?,
                Err(Error::VerbHook(stop)) if matches!(*stop, VerbHookStop::Hidden { .. }) => {
                    answered(Err(AgentVerbRefusal {
                        hook_notice: None,
                        code: VERB_HOOK_HIDDEN.to_owned(),
                    }))
                }
                // A skip or an ask stopped the write before it ran: the receipt
                // keeps the stop's mark, and the stop goes to the dispatcher.
                Err(Error::VerbHook(stop)) => {
                    receipt
                        .bridge_calls
                        .push(row(call, &never_ran_mark(VERB_HOOK_STOPPED))?);
                    self.storage
                        .put_code_run_replay_record_if_generation_with_heal(
                            &receipt,
                            Some(generation),
                            None,
                        )?;
                    return Err(Error::VerbHook(stop));
                }
                // No provider answered: the receipt keeps the outage's mark, and
                // the outage goes to the dispatcher, which parks the run on it.
                Err(error @ Error::ProviderUnavailable { .. }) => {
                    receipt
                        .bridge_calls
                        .push(row(call, &never_ran_mark(PROVIDER_UNAVAILABLE))?);
                    self.storage
                        .put_code_run_replay_record_if_generation_with_heal(
                            &receipt,
                            Some(generation),
                            None,
                        )?;
                    return Err(error);
                }
                Err(error @ Error::DurableStepTrapped) => {
                    receipt
                        .bridge_calls
                        .push(row(call, &never_ran_mark(MEDIA_STEP_TRAPPED))?);
                    self.storage
                        .put_code_run_replay_record_if_generation_with_heal(
                            &receipt,
                            Some(generation),
                            None,
                        )?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
        // Only a delivered connector reply spills here. Holds already parked;
        // questions and self.use's outer envelope keep their existing paths.
        let published = match (&mut outcome, site.reply_publisher) {
            (SelfDispatchOutcome::AgentVerb(answer), Some(publisher))
                if call.verb == AgentVerb::ConnectorCall
                    && answer.output.get("outcome").and_then(Value::as_str)
                        == Some("delivered") =>
            {
                // Every field of the answer but its output, which the
                // publisher replaces with the stored body's card: the large
                // reply is never cloned.
                let output = std::mem::take(&mut answer.output);
                let template = AgentVerbAnswer {
                    stored_output: None,
                    ..answer.clone()
                };
                answer.output = output;
                publisher.publish(&mut answer.output, &mut |wtxn, card, reply| {
                    let answer = SelfDispatchOutcome::AgentVerb(AgentVerbAnswer {
                        output: card.clone(),
                        ..template.clone()
                    });
                    let mut row = row(call.clone(), &answer)?;
                    reply.keep(&mut row.outcome)?;
                    receipt.bridge_calls.push(row);
                    self.put_write_receipt_in_txn(wtxn, &receipt, generation, program.as_ref())?;
                    Ok(())
                })?
            }
            _ => None,
        };
        // A placed body already committed its receipt in the publishing writer.
        // Inline and unplaceable answers keep their original receipt path; a
        // large answer of any other write is stored before its receipt (#5996).
        if published.is_none() {
            stored_answer::store(
                &self.storage,
                site.run_id,
                &mut receipt,
                &mut generation,
                &mut outcome,
            )?;
            // A receipt keeps its call's answer as its record's first row.
            receipt.bridge_calls.push(row(call, &outcome)?);
            self.put_write_receipt(
                &receipt,
                Some(generation),
                program.as_ref(),
                true,
                site.run_id,
            )?;
        }
        // The replay row is persisted; the door releases what the answer held (FIX 10633).
        door.answer_recorded();
        if let (Some(reply), Some(publisher), SelfDispatchOutcome::AgentVerb(answer)) =
            (published, site.reply_publisher, &outcome)
        {
            publisher.adopt(reply, &answer.output)?;
        }
        Ok(outcome)
    }

    /// The answer `receipt` kept for `call`, a write the step already made,
    /// made again at its place in a resumed step: it is never written again,
    /// and a changed call fails closed. An empty receipt is a write in
    /// flight, or one that needs reconciliation.
    ///
    /// The kept answer is a result the run recorded: `door` rules on reading
    /// it back, as on the run's other recorded outputs, and a run whose
    /// host binds no door reads its own. Its refusal stands on the receipt
    /// until an admitted read of the answer reconciles it, so no later
    /// attempt of the step goes on past it either.
    fn kept_write_answer(
        &self,
        door: Option<&dyn AgentVerbDoor>,
        receipt: CodeRunReplayRecord,
        call: SelfAgentVerbCall,
        site: ExecutorCallSite<'_>,
    ) -> Result<SelfDispatchOutcome> {
        let Some(row) = receipt.bridge_calls.first() else {
            return Err(Error::ConcurrentWrite(
                "agent verb write is in flight or needs reconciliation",
            ));
        };
        if let Err(refusal) = super::admit_recorded_answer(door) {
            let rejected = super::gate_rejection(&refusal.code);
            let ruling = SelfDispatchOutcome::Denied(SelfDeniedResult {
                hook_notice: None,
                effect: SelfEffect::AgentVerb,
                outcome: refusal.code.clone(),
                reason_codes: vec![KEPT_ANSWER_REFUSED.to_owned()],
            });
            let ruling = CodeRunBridgeCall::record(0, &SelfCall::AgentVerb(call), &ruling, 0, 0)?;
            self.append_ruling(&receipt, ruling)?;
            if let Some(rejected) = rejected {
                return Err(rejected);
            }
            return Ok(answered(Err(refusal)));
        }
        // A receipt an erase took the request words of meets the write by
        // that request's identity alone, and answers with what it kept
        // (FIX 6534): `response_erased` for an erased answer.
        let recorded = if row.request_erased() {
            row.request_identity_is(&self_call_request_value(&SelfCall::AgentVerb(
                call.clone(),
            ))?)?
        } else {
            row_identity(row) == Some(call_identity(call.verb.as_str(), &call.input))
        };
        if !recorded {
            return Err(Error::InvariantViolation(
                "a resumed step changed a write it already made",
            ));
        }
        if standing_refusal(&receipt).is_some() {
            self.append_ruling(&receipt, row.clone())?;
        }
        let mut outcome = decode_self_dispatch_outcome(&row.outcome)?;
        stored_answer::restore(&receipt, &mut outcome);
        if let (Some(publisher), SelfDispatchOutcome::AgentVerb(answer)) =
            (site.reply_publisher, &outcome)
            && let Some(reply) = ExecutorReply::kept(&row.outcome, site.run_id)?
        {
            publisher.adopt(reply, &answer.output)?;
        }
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
                let kept = crate::code_run::kept_reveal_answer(&answer.output);
                if kept != answer.output {
                    let output = std::mem::replace(&mut answer.output, kept);
                    *self.hook_view.borrow_mut() = Some(serde_json::json!({ "output": output }));
                }
                Ok(answer)
            }
            other => other,
        }
    }

    /// The guest's view of a granted `reveal.wait` a resumed turn program's
    /// settled row answers (FIX 2360): its value read again through the door
    /// under the lease `kept` names, as the call's view. The row keeps its
    /// value-free answer. `None` for any other call or answer, or when the
    /// door serves no replay or refuses it: the kept answer stands.
    pub(crate) fn replay_reveal_view(
        &self,
        call: &SelfCall,
        kept: &SelfDispatchOutcome,
    ) -> Result<Option<Value>> {
        let (SelfCall::AgentVerb(wait), SelfDispatchOutcome::AgentVerb(answer)) = (call, kept)
        else {
            return Ok(None);
        };
        let (true, Some(door)) = (wait.verb == AgentVerb::RevealWait, &self.agent_verbs) else {
            return Ok(None);
        };
        let Some(lease) = crate::code_run::kept_reveal_lease(&answer.output) else {
            return Ok(None);
        };
        let origin = HostWriteOrigin::new(self.agent_verb_envelope(wait.verb, None)?)
            .with_task_host(self.task_host_binding().ok().flatten())
            .with_model_provider(self.model_provider())
            .with_read_proof(self.program_proof().cloned())
            .with_bound_run(self.bound_run);
        let invocation = self.verb_invocation(call, None)?;
        Ok(door
            .replay_reveal(wait, lease, &origin, invocation)?
            .ok()
            .map(|answer| serde_json::json!({ "output": answer.output })))
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
                hook_notice: refusal.hook_notice,
                effect: SelfEffect::AgentVerb,
                outcome: refusal.code,
                reason_codes: Vec::new(),
            })
        },
        SelfDispatchOutcome::AgentVerb,
    )
}

/// A `browser_unsupported` refusal its door worded (FIX 6887) carries those
/// words as its reason codes: they name the verb that serves what was
/// refused (`self.browser.switch_engine` to the other engine). Every other
/// answer stands as [`answered`] made it.
fn worded(outcome: SelfDispatchOutcome, door: &dyn AgentVerbDoor) -> SelfDispatchOutcome {
    match outcome {
        SelfDispatchOutcome::Denied(mut denied)
            if denied.outcome
                == oneiron_browser::BrowserError::Unsupported(String::new()).code() =>
        {
            if let Some(words) = door
                .refusal_words()
                .filter(|words| words.code == denied.outcome)
            {
                denied.reason_codes = std::iter::once(words.message)
                    .chain(words.suggestions)
                    .collect();
            }
            SelfDispatchOutcome::Denied(denied)
        }
        outcome => outcome,
    }
}

#[doc(hidden)]
pub use oneiron_verb_wire::code_run::dispatcher::agent_verb::{
    SecretUseAnswer, SecretUseRecord, SecretUseStatus,
};

/// The answer of a `reveal.wait` as a run's record keeps it: without the
/// value. The guest reads the full answer; its step row and any receipt keep
/// this one.
#[must_use]
pub fn kept_reveal_answer(output: &serde_json::Value) -> serde_json::Value {
    let mut kept = output.clone();
    if let Some(fields) = kept.as_object_mut() {
        fields.remove("value");
        fields.remove("value_base64");
    }
    kept
}

/// The lease a kept `granted` answer of `reveal.wait` names: the lease a
/// replay of its step reads the value again under (FIX 2360). `None` for any
/// other answer.
pub(crate) fn kept_reveal_lease(output: &serde_json::Value) -> Option<EntityId> {
    if output.get("decision")?.as_str()? != "granted" {
        return None;
    }
    let lease = output.get("receipt")?.get("lease")?.as_str()?;
    EntityId::from_hex(lease).ok()
}
