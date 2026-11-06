//! The two writes a run bound to an off-record session stages in its room
//! (DOOR-127; WILL L11-01, S01-2a): `vault.notes.create` and
//! `vault.claims.upsert`, while the room the run entered is off record.
//!
//! Each meets the run's write protocol ([`super`]), with the room in the
//! door's place:
//! - its receipt is the run's AgentVerb write receipt at its place in its
//!   step (`session_write_identity`, CALLS-5): the same write made again in
//!   a resumed step gets the kept answer back, read again as the door
//!   rules, and stages nothing; a changed write fails closed; an empty
//!   receipt keeps its indeterminate refusal and is never staged over;
//! - it lands under what the run's door admits for its caller now
//!   (`session_write_admission`, CALLS-6), and the door's ceiling is checked
//!   again in the transaction that lands it; the caller's key, when its
//!   credential grants a read, opens the room's view a claim's subject
//!   resolves in. A run whose host binds no door writes under the run
//!   actor's own handle, as before (Engine ruling 10-19);
//! - it stages through the run's captured route, never a fresh one, in one
//!   segment that compares the receipt, stages the rows and keeps the
//!   answer, so a room row never stands without its receipt;
//! - a write the room or the door refuses stages nothing and keeps no
//!   receipt, as a write refused before its door ran keeps none.
//!
//! - it runs inside its row's verb hooks, in the room (FIX 5426), as a
//!   forwarded read does: the pre chain on the call's own input before it is
//!   prepared, the write prepared on the args every rewrite left, and the
//!   post chain over the staged answer. The receipt keeps the caller's view
//!   of the answer and what each hook did, settled once the post chain ran
//!   (`settle_session_write_view`). A kept write is never made again and
//!   runs no hook again, so a hook's ask is never entered twice: it answers
//!   the kept view, and a view never settled reads withheld. What each hook
//!   did rides the answer (FIX 5425); the run's record keeps the staged
//!   answer, never a hook's changed view, as for every hooked call.
//!
//! Its rows ride no turn of the room (`SESSION_WRITES_RIDE_NO_TURN`, CALLS-7,
//! unchanged). Nothing here asks where the caller or the vault runs.

use std::cell::Cell;

use crate::code_run::CODE_RUN_OUTPUT_PREVIEW_WITHHELD;
use crate::code_run::replay::{CodeRunDeterminism, CodeRunReplayRecord};
use crate::code_run::storage::{ExecutorStorage, KeptCallerView, kept_caller_view};
use crate::code_run::types::{
    AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, AgentVerbRefusal, SelfAgentVerbCall,
    SelfDispatchOutcome, SessionWriteAdmission,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{HostWriteOrigin, MemoryError};
use crate::session_overlay::RouteTarget;
use crate::task_verb::sdk::AgentVerb;

use super::super::{ExecutorCallSite, HostSelfDispatcher};
use super::{KeptWrite, answered};

impl HostSelfDispatcher<'_> {
    /// `call`, a `vault.notes.create` or `vault.claims.upsert` call of a run
    /// bound to an off-record session, staged in its room: its kept answer
    /// when the step already made it, else admitted, prepared and staged
    /// with its receipt in one segment of the run's captured route.
    pub(super) fn dispatch_session_write(
        &self,
        call: SelfAgentVerbCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let ExecutorStorage::Session(binding) = &self.storage else {
            return Err(Error::InvariantViolation(
                "a session write needs a run bound to a session",
            ));
        };
        // The run-entry route must still stand: a flip since the run
        // entered refuses here, as every other write of the run does.
        binding.route.revalidate()?;
        // A room on record when the run entered keeps no such write: its
        // writes are the vault's, through the vault's own doors.
        if binding.route.target() != RouteTarget::Overlay {
            return Ok(session_bound());
        }
        let receipt = match site {
            Some(site) => match self.session_write_identity(site)? {
                (_, KeptWrite::Ran(kept)) => {
                    return self.kept_session_write_answer(*kept, call);
                }
                (id, KeptWrite::Fresh(stopped)) => Some((
                    CodeRunReplayRecord::new(id, CodeRunDeterminism::new(0, [0; 32])),
                    stopped,
                )),
            },
            None => None,
        };
        let admission = match self.session_write_admission(call.verb) {
            Ok(admission) => admission,
            Err(refused) => return Ok(answered(Err(refused))),
        };
        let origin =
            HostWriteOrigin::new(self.agent_verb_envelope(call.verb, site.map(|site| site.seq))?)
                .with_executor_run(site.and_then(|site| site.executor_run))
                .with_model_provider(self.model_provider())
                .with_bound_run(self.bound_run);
        let key = admission
            .as_ref()
            .and_then(SessionWriteAdmission::key)
            .cloned();
        let reader = key
            .clone()
            .map(|key| binding.session.read_context(&binding.route, key))
            .transpose()?;
        // The row's verb hooks, in the room, before the write is prepared: a
        // stop is the answer, and a rewrite is what the write prepares.
        let (pre, mut hooks) = self.session_write_pre(&call, key, site)?;
        let stage = match binding.session.prepare_session_write(
            &binding.route,
            self.actor,
            origin,
            call.verb,
            &pre.args,
            reader.as_ref(),
        ) {
            Some(Ok(stage)) => stage,
            Some(Err(refused)) => {
                self.session_write_keep(call.verb.as_str(), pre)?;
                return Ok(answered(Err(AgentVerbRefusal { code: refused.code })));
            }
            None => {
                self.session_write_keep(call.verb.as_str(), pre)?;
                return Ok(session_bound());
            }
        };
        // The door's ceiling, checked again in the transaction that lands
        // the write: a caller whose credential stopped holding since it was
        // admitted writes nothing.
        let ceiling = Cell::new(None);
        let written = binding.stage_session_write(
            &call,
            receipt
                .as_ref()
                .map(|(receipt, stopped)| (receipt, *stopped)),
            |wtxn, apply| {
                if let Some(admitted) = &admission
                    && let Err(refused) = admitted.holds_in(wtxn)
                {
                    ceiling.set(Some(refused));
                    return Err(Error::InvariantViolation(
                        "the door's caller no longer holds this write",
                    ));
                }
                Ok(SelfDispatchOutcome::AgentVerb(
                    AgentVerbAnswer::new(stage(wtxn, apply)?, Some(Vec::new()))
                        .with_hooks(hooks.clone()),
                ))
            },
        )?;
        let outcome = match written {
            Ok(outcome) => outcome,
            // Nothing staged: the refusal reaches the guest as its code, the
            // room's as its Memory code, and the pre chain's records are kept.
            Err(refused) => {
                self.session_write_keep(call.verb.as_str(), pre)?;
                return Ok(answered(Err(ceiling.take().unwrap_or_else(|| {
                    AgentVerbRefusal {
                        code: MemoryError::from(refused).code,
                    }
                }))));
            }
        };
        let SelfDispatchOutcome::AgentVerb(mut answer) = outcome else {
            return Ok(outcome);
        };
        // The post chain over the staged answer, in the room: the caller
        // reads its view, and the run's record keeps the staged answer.
        let (view, post) =
            self.session_write_post(call.verb.as_str(), pre, answer.output.clone())?;
        hooks.extend(post);
        answer.hooks = hooks;
        let caller_view = (view != answer.output).then(|| {
            let mut shown = answer.clone();
            shown.output = view;
            shown.guest_reply()
        });
        // The receipt keeps the caller's view for a resumed step. One not
        // kept stays pending, and a resumed step then reads it withheld.
        if let Some((receipt, _)) = &receipt
            && let Err(error) = binding.settle_session_write_view(
                receipt.run_id,
                &call,
                &answer,
                caller_view.as_ref(),
            )
        {
            tracing::warn!(verb = call.verb.as_str(), %error, "a room write's caller view was not kept");
        }
        if let Some(reply) = caller_view {
            *self.hook_view.borrow_mut() = Some(reply);
        }
        Ok(SelfDispatchOutcome::AgentVerb(answer))
    }

    /// A room write the step already made: its kept answer, read again as
    /// the door rules, with the caller's view and hook dispositions its
    /// receipt keeps. The write is never made again and no hook runs again.
    /// A view whose post chain never settled answers the output withheld:
    /// a post hook may have hidden part of it.
    fn kept_session_write_answer(
        &self,
        kept: CodeRunReplayRecord,
        call: SelfAgentVerbCall,
    ) -> Result<SelfDispatchOutcome> {
        let view = match kept.bridge_calls.first() {
            Some(row) => kept_caller_view(&row.outcome)?,
            None => KeptCallerView::Unchanged,
        };
        let outcome = self.kept_write_answer(self.agent_verbs.as_deref(), kept, call)?;
        let SelfDispatchOutcome::AgentVerb(answer) = &outcome else {
            return Ok(outcome);
        };
        let reply = match view {
            KeptCallerView::Unchanged => None,
            KeptCallerView::Changed(reply) => Some(reply),
            KeptCallerView::Pending => {
                let mut shown = answer.clone();
                shown.output = serde_json::Value::from(CODE_RUN_OUTPUT_PREVIEW_WITHHELD);
                Some(shown.guest_reply())
            }
        };
        if let Some(reply) = reply {
            *self.hook_view.borrow_mut() = Some(reply);
        }
        Ok(outcome)
    }

    /// CALLS-5 `session_write_identity`: a room write's receipt is the run's
    /// AgentVerb write receipt, the same identity a canonical run's write
    /// keeps (the run, its id, the step's first position and how many writes
    /// the step made before this one), with its sorted verb-and-input check
    /// on replay. No second ledger.
    fn session_write_identity(&self, site: ExecutorCallSite<'_>) -> Result<(EntityId, KeptWrite)> {
        let (_, receipt_id, kept) = self.write_receipt(site)?;
        Ok((receipt_id, kept))
    }

    /// CALLS-6 `session_write_admission`: what a room write lands under. A
    /// run whose host binds a door writes only as that door admits the write
    /// for its caller now: its credential and ceiling, never the run actor's
    /// wider handle (Engine ruling 10-19 14:1x). A run whose host binds no
    /// door has no caller to bind, and writes under the run actor's own
    /// handle, as before (`None`).
    fn session_write_admission(
        &self,
        verb: AgentVerb,
    ) -> std::result::Result<Option<SessionWriteAdmission>, AgentVerbRefusal> {
        match &self.agent_verbs {
            Some(door) => door.admit_session_write(verb).map(Some),
            None => Ok(None),
        }
    }
}

/// A session-bound run's verb call that its room keeps no write for.
fn session_bound() -> SelfDispatchOutcome {
    answered(Err(AgentVerbRefusal {
        code: AGENT_VERB_SESSION_BOUND.to_owned(),
    }))
}
