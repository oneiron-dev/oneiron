//! One claimed marker's attempt: its payload and turn read, the tagger
//! called outside any write transaction, and its answer checked.

use super::coordinator::{TaggingPass, TaggingReconciler};
use super::settle::unreadable_trace;
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::error::{Error, Result};
use crate::tagging::input::{TurnInput, turn_input_in_txn, turn_text_in_txn};
use crate::tagging::marker::{MarkerPayload, TaggingMode, enqueue_marker_in_txn};
use crate::tagging::output::check_output;
use crate::tagging::save::{self, Answer};
use crate::tagging::tags::tagged_messages_absent_in_txn;
use crate::tagging::trace::{SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace};

impl TaggingReconciler {
    pub(super) fn attempt(
        &self,
        queue: &AttemptQueue<'_>,
        record: &AttemptRecord,
        pass: &mut TaggingPass,
    ) -> Result<TaggingTrace> {
        let prior_retries = queue.retry_chain_depth(record.id)?;
        let mut trace = unreadable_trace(record, prior_retries);
        let Some(payload) = MarkerPayload::decode(&record.payload) else {
            self.vault.try_with_write_txn_grouped(|txn| {
                self.fail_unreadable_in_txn(txn, record, &trace)
            })?;
            return Ok(trace);
        };
        trace.turn = Some(payload.turn);
        trace.checkpoint.clone_from(&payload.checkpoint);
        trace.stack.clone_from(&payload.stack);
        if !payload.owed_to(&self.config) {
            // Owed to another checkpoint or stack: the active tagger owes the
            // turn now.
            trace.outcome = TaggingOutcome::Rekeyed;
            self.vault.try_with_write_txn_grouped(|txn| -> Result<()> {
                let now = self.stamp_in_txn(txn)?;
                let work = self.persisted_work_in_txn(txn, record.id, &payload)?;
                enqueue_marker_in_txn(&self.vault, txn, payload.turn, &self.config, now, work)?;
                self.settle_in_txn(txn, record, &trace)
            })?;
            return Ok(trace);
        }
        // A MESSAGE the turn's saved tags were read from is away from this
        // replica (OF-534): the turn reads only partly here, so neither a
        // fragment's answer nor an empty turn's skip may replace its set.
        let read = {
            let txn = self.vault.store.env.read_txn()?;
            if tagged_messages_absent_in_txn(&self.vault.store, &txn, &payload.turn)? {
                None
            } else {
                Some(turn_input_in_txn(&self.vault, &txn, &payload.turn)?)
            }
        };
        #[cfg(test)]
        super::run_after_turn_read_hook();
        let Some(read) = read else {
            return self.defer(record, prior_retries, trace);
        };
        let (input, hash, text_hash) = match read {
            TurnInput::Gone => {
                return self.skip(record, &payload.turn, SkipReason::TurnGone, trace);
            }
            TurnInput::Empty => {
                return self.skip(record, &payload.turn, SkipReason::NoText, trace);
            }
            TurnInput::Ready {
                input,
                hash,
                text_hash,
            } => (input, hash, text_hash),
        };
        trace.input_hash = Some(hash.clone());
        trace.model = Some(self.encoder.model_id().as_str().to_owned());
        pass.calls += 1;
        let work = payload.effective_work(&self.vault);
        let called = trace.record_call(|| self.encoder.infer(&input, work));
        let output = match called {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                pass.failed_calls += 1;
                let failure = TaggingFailure::Call {
                    code: failure_code(&error),
                };
                return self.retry(record, prior_retries, failure, trace);
            }
            Err(_) => {
                pass.failed_calls += 1;
                return self.retry(record, prior_retries, TaggingFailure::Panicked, trace);
            }
        };
        if let Err(refusal) = check_output(&input, &output, self.config.stack.as_deref()) {
            let failure = TaggingFailure::Refused { refusal };
            return self.retry(record, prior_retries, failure, trace);
        }
        // The answer stands only for the text it tagged: settle against the
        // turn's own text as the settling transaction sees it. The window was
        // context; the settling write never reads it. In save mode the tags
        // land in that same write, so a turn's marker settles exactly when
        // its tags are saved.
        let made_by = self.encoder.model_id().as_str().to_owned();
        let mut away = false;
        let settled =
            self.vault
                .try_with_write_txn_grouped(|txn| -> Result<Option<TaggingTrace>> {
                    // Inference ran outside this writer: a MESSAGE the saved
                    // set was read from may have left this replica since.
                    if tagged_messages_absent_in_txn(&self.vault.store, txn, &payload.turn)? {
                        away = true;
                        return Ok(None);
                    }
                    let current = matches!(
                        turn_text_in_txn(&self.vault, txn, &payload.turn)?,
                        TurnInput::Ready { text_hash: ref now, .. } if *now == text_hash
                    );
                    if !current {
                        return Ok(None);
                    }
                    let mut settled = trace.clone();
                    settled.outcome = match self.config.mode {
                        TaggingMode::Shadow => self.shadowed(&output),
                        TaggingMode::Save => {
                            let answer = Answer {
                                turn: payload.turn,
                                input: &input,
                                output: &output,
                                envelope: save::envelope(
                                    &hash,
                                    &made_by,
                                    &self.config,
                                    output.stack_sha16.as_deref(),
                                ),
                            };
                            let now = self.stamp_in_txn(txn)?;
                            let saved =
                                save::save_in_txn(&self.vault, txn, answer, &self.config, now)?;
                            TaggingOutcome::Saved {
                                spans: output.spans.len(),
                                links: output.links.len(),
                                mood: output.vad.is_some(),
                                linked: saved.linked,
                                minted: saved.minted,
                                context_links: output.context_links.len(),
                                speaker_links: output.speaker_links.len(),
                                unresolved_context_links: saved.unresolved_context_links,
                                unresolved_speaker_links: saved.unresolved_speaker_links,
                                surprise: saved.surprise,
                            }
                        }
                    };
                    self.settle_in_txn(txn, record, &settled)?;
                    Ok(Some(settled))
                })?;
        if let Some(settled) = settled {
            return Ok(settled);
        }
        if away {
            return self.defer(record, prior_retries, trace);
        }
        self.retry_traced(record, 0, "superseded", trace, |retry_at| {
            TaggingOutcome::Superseded { retry_at }
        })
    }
}

/// A host failure code is caller-safe by contract (the host builds it with no
/// vault text); every other error reports only its stable kind.
fn failure_code(error: &Error) -> String {
    match error {
        Error::UpstreamToolFailure { code, .. } => code.clone(),
        other => format!("{:?}", other.kind()),
    }
}
