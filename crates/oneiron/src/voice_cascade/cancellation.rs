//! One stop fan-out for interruption, policy enforcement and explicit teardown.

use crate::error::Error;
use crate::policy_model::PolicyBargeInKill;

use super::{Brain, CascadeControl, ControlEvent, GenerationEpoch, TtsCommand, TtsSeamClient};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    UserBargeIn,
    Safeguard,
    /// Normal end is never presented as a user interruption.
    SessionEnd,
}

/// Session state is already invalidated when this is returned. Dispatch this
/// before another playback dequeue. Retrying delivery is safe: adapters must
/// make cancellation/flush idempotent for an epoch. Errors never skip other arms.
#[must_use = "dispatch the stop to the brain, TTS, server queue and client control"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputStop {
    pub generation: Option<GenerationEpoch>,
    pub reason: StopReason,
    pub kill: PolicyBargeInKill,
}

impl OutputStop {
    pub(super) fn new(
        generation: Option<GenerationEpoch>,
        reason: StopReason,
        cancel_llm: bool,
    ) -> Self {
        Self {
            generation,
            reason,
            kill: PolicyBargeInKill {
                cancel_tts: true,
                flush_playout_buffer: true,
                cancel_llm,
            },
        }
    }

    /// Submission only, not a cross-process completion acknowledgement. A host
    /// receiving any errors must keep playout closed and retry or end the call.
    /// No arm uses `?`: one broken provider must not prevent the client flush.
    pub fn dispatch(
        &self,
        brain: &mut impl Brain,
        tts: &mut impl TtsSeamClient,
        control: &mut impl CascadeControl,
    ) -> Vec<Error> {
        let mut errors = Vec::new();
        if let Some(generation) = self.generation {
            if self.kill.flush_playout_buffer
                && let Err(error) = control.flush_queued_pcm(generation)
            {
                errors.push(error);
            }
            if self.kill.cancel_llm
                && let Err(error) = brain.cancel(generation)
            {
                errors.push(error);
            }
            if self.kill.cancel_tts
                && let Err(error) = tts.submit(TtsCommand::Cancel { generation })
            {
                errors.push(error);
            }
            if self.reason != StopReason::SessionEnd
                && let Err(error) = control.submit(ControlEvent::PlayoutStop {
                    generation,
                    reason: self.reason,
                })
            {
                errors.push(error);
            }
        }
        if self.reason == StopReason::SessionEnd
            && let Err(error) = control.submit(ControlEvent::SessionEnded)
        {
            errors.push(error);
        }
        errors
    }
}
