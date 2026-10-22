//! Checkpointed implicit speech and its retry-safe delivery.
//! Entry: `EngineNativeExecutor::emit_trailing_speak_fallback`.
//! `ImplicitSpeechIntent` is defined by `engine_executor::store`.

use super::*;

impl EngineNativeExecutor<'_> {
    /// Selects the IMPLICIT speak payload BEFORE the terminal checkpoint
    /// (ONE-1686 policy, ONE-1929 checkpointing).
    ///
    /// # What is said
    ///
    /// A completed run's trailing plaintext becomes its last word. With
    /// bare-wire healing (ONE-1929) that plaintext is the HEALED trailing
    /// prose when the reply carried one, and the raw observation otherwise, so
    /// a model that wrapped its answer in a fence or forged a `<console>`
    /// block still speaks the words it actually meant.
    ///
    /// # What suppresses it
    ///
    /// Explicit speech is CANONICAL, and "canonical" is about the TEXT, not
    /// about whether the run happened to speak at all. A run that spoke and
    /// then finished with the SAME words has already said them, so a trailing
    /// bubble would be a duplicate; a run that spoke and then finished with
    /// DIFFERENT words has a last word nobody has heard, and dropping it loses
    /// the answer. So the suppression is per-text: the fallback is skipped only
    /// when an emitted speech row in the durable record carries exactly this
    /// trailing text. The check is over the DURABLE record, not a per-step
    /// flag, so a run that spoke in step 0 and completed in step 3 is still
    /// judged against everything it said.
    ///
    /// A speech row that did NOT emit — a barrier-parked wait, a denied or
    /// failed trap — never suppresses anything: no bubble exists for it, so
    /// its text was not said.
    ///
    /// It fires on `Complete` only: a run parked on a durable wait has not
    /// finished speaking, and a yielded or step-limited run has not finished
    /// at all. Both storage arms answer here, because ONE-1686 gave a
    /// canonical run a derived shell and turn of its own; the arm choice lives
    /// at the witness door, not in this policy.
    ///
    /// # How much is said
    ///
    /// An answer has no size limit, and a bubble is no place for a large one:
    /// it says the answer whole up to [`IMPLICIT_SPEECH_TEXT_BYTES`], and past
    /// that says none of it as prose. The bubble carries the stored answer
    /// as a typed result instead: a bounded preview, the run and occurrence
    /// that produced it, and the facets that read the rest (FIX 365).
    pub(super) fn prepare_trailing_speak_fallback(
        &self,
        record: &CodeRunReplayRecord,
        observation: &CodeRunRawOutput,
        trailing_speak: Option<&str>,
    ) -> EngineExecutorResult<Option<ImplicitSpeechIntent>> {
        let answer;
        let text = match trailing_speak {
            Some(text) => text,
            None if observation.raw_len > IMPLICIT_SPEECH_TEXT_BYTES => {
                let attachment = message_result_attachment(&self.storage, record, observation)?;
                return Ok(Some(ImplicitSpeechIntent::Result { attachment }));
            }
            None => {
                answer = load_observation_window(
                    &self.storage,
                    record,
                    &observation.path,
                    COMPACTION_OBSERVATION_WINDOW_BYTES,
                )?;
                &answer
            }
        }
        .trim();
        if text.is_empty() {
            return Ok(None);
        }
        if record
            .bridge_calls
            .iter()
            .filter_map(CodeRunBridgeCall::emitted_visible_speech_text)
            .any(|spoken| spoken.trim() == text)
        {
            return Ok(None);
        }
        Ok(Some(ImplicitSpeechIntent::Text {
            text: text.to_owned(),
        }))
    }

    /// Recovers a terminal checkpoint's implicit speech intent (ONE-1929).
    ///
    /// The payload is content-addressed into the replay record BEFORE the
    /// terminal commit, so a retry that resumes a committed-but-unspoken run
    /// replays the exact words from durable storage and never needs provider
    /// bytes: a fresh session, a restarted process, or a prompt
    /// deployment/fingerprint drift recovers the same bubble. The bubble's
    /// identity is derived from the durable run identity and its order, and
    /// the durable marker below makes the delivery at-most-once, so recovery
    /// converges on the row that already exists instead of minting a second.
    pub(super) fn recover_checkpointed_implicit_speak(
        &mut self,
        record: &CodeRunReplayRecord,
        status: &EngineExecutorStatus,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<()> {
        if !matches!(status, EngineExecutorStatus::Complete) {
            return Ok(());
        }
        let Some(seq) = completed_step_count(record)?.checked_sub(1) else {
            return Ok(());
        };
        let path = implicit_speak_output_path(seq);
        if !record.outputs.iter().any(|output| output.path == path) {
            return Ok(());
        }
        let stored = load_utf8_output(&self.storage, record, &path)?;
        let intent = ImplicitSpeechIntent::decode(&stored)?;
        self.emit_trailing_speak_fallback(record, seq, &intent, config)
    }

    /// Materializes ONE already-checkpointed implicit bubble, at most once.
    ///
    /// # Crash and retry
    ///
    /// The bubble is downstream of its checkpoint commit, so the window
    /// between them is real: a crash, or a post-commit witness failure, sends
    /// the caller back through terminal recovery. Two things close it, and
    /// both are needed. The DURABLE MARKER below is written straight after the
    /// bubble, keyed by content into the same routed raw-output store the run
    /// already uses, so a recovery that runs after a successful emit says
    /// nothing a second time. And the bubble's own IDENTITY is derived from
    /// the durable run identity and this order (`code_run::storage`), so even
    /// a crash landing between the witness and the marker re-puts THAT row
    /// rather than adding a second one: the witness door verifies the existing
    /// materialization exactly and refuses a divergent one typed. There is no
    /// window in which the transcript grows twice.
    pub(super) fn emit_trailing_speak_fallback(
        &mut self,
        record: &CodeRunReplayRecord,
        step_seq: u64,
        intent: &ImplicitSpeechIntent,
        config: &EngineExecutorConfig,
    ) -> EngineExecutorResult<()> {
        let order = u32::try_from(record.bridge_calls.len()).unwrap_or(u32::MAX);
        let (marker, marker_bytes) = fallback_speech_marker(config.run_id, step_seq, order)?;
        if self.storage.get_code_run_raw_output(&marker)?.is_some() {
            return Ok(());
        }
        // The bubble is the run's own `self.speak`: a bound door rules on it
        // as on any other, answered as a call is. A refused bubble stays a
        // checkpointed intent that a later admitted retry delivers.
        self.storage
            .answered(|| {
                self.gated_write
                    .admit_run_call(crate::code_run::RunCall::Bridge(
                        crate::code_run::SelfEffect::Speak,
                    ))
            })?
            .map_err(|refusal| super::types::EngineExecutorError::HostRefused {
                code: refusal.code,
            })?;
        let occurred_at = config
            .determinism
            .frozen_unix_ms
            .saturating_add(u64::from(order))
            / 1000;
        #[cfg(test)]
        if self.fail_before_implicit_speak_once {
            self.fail_before_implicit_speak_once = false;
            return Err(Error::InvariantViolation(
                "injected failure before implicit speech materialization",
            )
            .into());
        }
        match intent {
            ImplicitSpeechIntent::Text { text } => self.witness_turn_for_run_at(
                Some(config.run_id),
                ExecutorUtterance::Speak,
                text,
                occurred_at,
                order,
            )?,
            ImplicitSpeechIntent::Result { attachment } => self.witness_result_for_run_at(
                config.run_id,
                attachment,
                record.agent_verb_rows().as_deref(),
                occurred_at,
                order,
            )?,
        };
        // Written AFTER the bubble, deliberately: a marker written first and
        // then orphaned by a crash would silence a run that never spoke, which
        // is the failure the fallback exists to prevent. Written second, the
        // worst case is a re-emission that lands on the same derived MESSAGE
        // id.
        self.storage
            .put_code_run_raw_output(config.run_id, &marker, &marker_bytes)?;
        Ok(())
    }
}
