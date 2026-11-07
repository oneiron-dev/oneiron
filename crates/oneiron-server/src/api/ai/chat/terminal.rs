//! Truthful terminal identity and completion, independent of retention.

use super::*;
use oneiron::memory::{MessageCompletion, SessionStreamOutcome};

impl AnswerOutcome {
    pub(crate) fn turn_id(&self, recorded: EntityId) -> Option<EntityId> {
        self.native
            .as_ref()
            .map_or(Some(recorded), |finished| finished.turn_id)
    }

    pub(crate) fn completion(&self) -> MessageCompletion {
        match &self.native {
            Some(finished) => match &finished.outcome {
                SessionStreamOutcome::Unretained(end) => MessageCompletion {
                    incomplete: end.finality != oneiron::memory::StreamFinality::Final
                        || !matches!(
                            end.finish_reason,
                            None | Some(
                                oneiron::FinishReason::Stop | oneiron::FinishReason::ToolCalls
                            )
                        ),
                    generating: false,
                    finish_reason: end.finish_reason.clone(),
                },
                SessionStreamOutcome::Retained(receipt) => receipt_completion(receipt),
            },
            None => self.saved.as_ref().map_or(
                MessageCompletion {
                    incomplete: true,
                    generating: false,
                    finish_reason: None,
                },
                receipt_completion,
            ),
        }
    }

    pub(crate) fn unretained(&self) -> bool {
        matches!(&self.native, Some(finished) if matches!(finished.outcome, SessionStreamOutcome::Unretained(_)))
    }

    /// Disclosure is a fresh read through the original caller capability.
    pub(crate) fn reproject(&mut self, handle: &AnswerStream, vault: &Vault) -> Result<(), String> {
        if !handle.is_session() {
            return Ok(());
        }
        let finished = handle
            .finished(vault)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "the native stream has no resolved terminal".to_owned())?;
        self.text = finished.text.clone();
        self.saved = match &finished.outcome {
            SessionStreamOutcome::Retained(receipt) => Some(receipt.clone()),
            SessionStreamOutcome::Unretained(_) => None,
        };
        self.native = Some(finished);
        Ok(())
    }
}

fn receipt_completion(receipt: &MessageStreamReceipt) -> MessageCompletion {
    MessageCompletion {
        incomplete: !receipt.complete(),
        generating: false,
        finish_reason: receipt.finish_reason.clone(),
    }
}
