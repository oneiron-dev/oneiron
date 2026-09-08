//! Ask-human durable waits and executor speech witnessing.

use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    SelfAskHumanCall, SelfDispatchOutcome, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    SelfSpeechCall, SelfSpeechResult,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::TrapRef;

use super::HostSelfDispatcher;

#[derive(Debug, Clone, Copy)]
pub(crate) struct HumanWaitDispatchTarget {
    pub(super) task_ref: EntityId,
    pub(super) trap: TrapRef,
}

impl HostSelfDispatcher<'_> {
    pub(super) fn dispatch_ask_human(&self, call: SelfAskHumanCall) -> Result<SelfDispatchOutcome> {
        if let Some(target) = self.human_wait_target {
            let ExecutorStorage::Canonical(vault) = &self.storage else {
                return Err(Error::InvalidClaimBody(
                    "self.ask_human task wait requires canonical storage",
                ));
            };
            let responder_ref = crate::task_verb::task_human_assignee(vault, target.task_ref)?
                .ok_or(Error::InvalidClaimBody(
                    "self.ask_human task is not assigned to a human",
                ))?;
            crate::human_task::bind_human_wait(vault, target.task_ref, responder_ref, &target.trap)
                .map_err(|error| match error {
                    crate::human_task::HumanTaskError::Engine(error) => error,
                    _ => Error::InvalidClaimBody("self.ask_human wait binding was refused"),
                })?;
            return Ok(SelfDispatchOutcome::DurableWait(SelfDurableWait {
                wait_id: target.task_ref,
                effect: SelfEffect::AskHuman,
                reason: SelfDurableWaitReason::HumanInput,
                prompt: Some(call.prompt),
            }));
        }

        // Unit fixtures exercise generic replay/wait encoding without creating a
        // TASK. Production dispatch fails closed unless the host supplied the
        // real task and trap through `for_human_task`.
        #[cfg(test)]
        {
            Ok(self.durable_wait(
                SelfEffect::AskHuman,
                SelfDurableWaitReason::HumanInput,
                Some(call.prompt),
            ))
        }
        #[cfg(not(test))]
        {
            let _ = call;
            Err(Error::InvalidClaimBody(
                "self.ask_human missing human task wait target",
            ))
        }
    }

    /// One speech call — one durable MESSAGE bubble (ONE-1686, RT-04).
    ///
    /// Speech is an EFFECT, dispatched where every other `self.*` effect is
    /// dispatched, at the moment the guest calls it. Nothing is buffered for a
    /// final response, so a step that speaks, searches, speaks again and then
    /// writes lands those four things in that order.
    ///
    /// The bubble's author, message type and visibility are the host's: the
    /// actor is the one bound at construction, the type comes from the
    /// utterance the effect names, and `is_visible` is
    /// [`ExecutorUtterance::is_visible`]. Only the text is the guest's.
    ///
    /// A `Speech` OUTCOME therefore means one thing and nothing else: the
    /// bubble exists. Both storage arms materialize it, and a refusal — a
    /// stale route after a mid-run mode flip, a ceiling denial — leaves through
    /// `Err`, which the bridge records as the `Denied`/`Failed` row the
    /// fail-closed barrier already understands. `emitted` is `true` on every
    /// value this constructor can build; the decoder refuses any other
    /// combination, so no replay row can claim speech that never happened.
    ///
    /// # Replay identity (ONE-1929)
    ///
    /// The bubble's TURN and MESSAGE ids are DERIVED from the run's host ref,
    /// the durable run id, and the bridge position the host stamped — never
    /// minted fresh per dispatch. Explicit speech commits at the moment the
    /// guest calls it, so a step whose replay append then fails (a generation
    /// conflict, an output-recording error, a crash between the two) is retried
    /// from a replay state that still names the same bridge position. Under
    /// fresh ids that retry minted a SECOND bubble for one utterance; under the
    /// derived ids the witness door recognizes the row it already wrote and the
    /// retry converges on it. A retry that would put DIFFERENT bytes at that
    /// position is a divergence, not a duplicate, and the door refuses it typed
    /// rather than speaking twice.
    pub(super) fn dispatch_speech(
        &self,
        effect: SelfEffect,
        call: SelfSpeechCall,
        run_id: Option<EntityId>,
    ) -> Result<SelfDispatchOutcome> {
        let kind = effect.speech_utterance().ok_or(Error::InvariantViolation(
            "speech dispatch on a non-speech effect",
        ))?;
        let _receipt = self.storage.witness_executor_utterance(
            &self.run_ref,
            run_id,
            kind,
            &call.text,
            call.occurred_at,
            call.order,
            self.actor,
        )?;
        Ok(SelfDispatchOutcome::Speech(SelfSpeechResult {
            effect,
            order: call.order,
            is_visible: kind.is_visible(),
            emitted: true,
        }))
    }

    pub(super) fn durable_wait(
        &self,
        effect: SelfEffect,
        reason: SelfDurableWaitReason,
        prompt: Option<String>,
    ) -> SelfDispatchOutcome {
        SelfDispatchOutcome::DurableWait(SelfDurableWait {
            wait_id: EntityId::now(),
            effect,
            reason,
            prompt,
        })
    }
}
